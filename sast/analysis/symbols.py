"""Symbol table: index user-defined functions, classes and methods.

Functions are indexed by fully-qualified name (namespace-aware) with a
short-name fallback, so `Foo\\bar()` and `Baz\\bar()` do not collide.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from ..parsing.source import SourceFile
from . import ast_utils as au


def _norm(name: str) -> str:
    return name.lstrip("\\") if name else ""


@dataclass
class FunctionSymbol:
    name: str                       # fully-qualified name
    short: str                      # short name
    namespace: str
    node: Node
    source: SourceFile
    params: list[str] = field(default_factory=list)


@dataclass
class MethodSymbol:
    class_name: str                 # short class name
    namespace: str
    name: str
    node: Node
    source: SourceFile
    params: list[str] = field(default_factory=list)
    is_static: bool = False
    visibility: str = "public"


@dataclass
class ClassSymbol:
    name: str                       # short name
    namespace: str
    node: Node
    source: SourceFile
    parent: str = ""
    methods: dict = field(default_factory=dict)
    # Every method declaration, overloads and redeclarations included.
    all_methods: list = field(default_factory=list)


def file_namespace(sf: SourceFile) -> str:
    """Return the namespace declared by a PHP file ('' if global)."""
    for child in sf.root.named_children:
        if child.type == "namespace_definition":
            for c in child.named_children:
                if c.type == "namespace_name":
                    return _norm(au.text(c))
            return ""
    return ""


class SymbolTable:
    def __init__(self) -> None:
        self.functions: dict[str, FunctionSymbol] = {}          # fqn -> symbol
        self.short_functions: dict[str, list] = {}              # short -> [symbols]
        self.classes: dict[str, ClassSymbol] = {}               # short -> symbol
        self.class_aliases: dict[str, str] = {}                 # fqn -> short
        # Every declaration, including ones sharing a name. The dicts above
        # are keyed for *resolution* and so keep one entry per name; analysing
        # from them alone skipped a second `function handle()` in another file
        # outright, and an unnamespaced helper repeated across files is
        # ordinary PHP.
        self.all_functions: list = []
        self.all_classes: list = []

    def add_function(self, short: str, namespace: str, node: Node, source: SourceFile) -> None:
        fqn = f"{namespace}\\{short}" if namespace else short
        if fqn in self.functions:
            # Keep it for analysis even though resolution already has one.
            self.all_functions.append(FunctionSymbol(
                name=fqn, short=short, namespace=namespace, node=node,
                source=source, params=au.params_of(node)))
            return
        sym = FunctionSymbol(name=fqn, short=short, namespace=namespace,
                             node=node, source=source, params=au.params_of(node))
        self.functions[fqn] = sym
        self.short_functions.setdefault(short, []).append(sym)
        self.all_functions.append(sym)

    def add_method(self, class_name: str, namespace: str, name: str, node: Node,
                   source: SourceFile, is_static: bool = False, visibility: str = "public") -> None:
        cls = self.classes.setdefault(
            class_name,
            ClassSymbol(name=class_name, namespace=namespace, node=node, source=source),
        )
        if not name:
            return
        method = MethodSymbol(
            class_name=class_name, namespace=namespace, name=name, node=node,
            source=source, params=au.params_of(node), is_static=is_static,
            visibility=visibility,
        )
        cls.all_methods.append(method)
        if name not in cls.methods:
            cls.methods[name] = method

    def register_class_alias(self, short: str, namespace: str) -> None:
        if namespace:
            self.class_aliases[f"{namespace}\\{short}"] = short

    def lookup_function(self, name: str, namespace: str = ""):
        c = _norm(name)
        if "\\" in c:
            return self.functions.get(c)
        if namespace:
            f = self.functions.get(f"{namespace}\\{c}")
            if f is not None:
                return f
        f = self.functions.get(c)
        if f is not None:
            return f
        candidates = self.short_functions.get(c, [])
        return candidates[0] if len(candidates) == 1 else None

    def unique_method(self, method_name: str):
        """The one method of this name in the project, if only one class has it.

        A receiver whose class the engine cannot see — a global built in an
        included file, a property assigned in a constructor — still resolves
        when the name leaves no choice: Mutillidae's pages call
        `$SQLQueryHandler->getUserAccount()` on an object made elsewhere.
        """
        index = getattr(self, "_methods_by_name", None)
        if index is None:
            index = self._methods_by_name = {}
            for cls in self.classes.values():
                for name, m in cls.methods.items():
                    index.setdefault(name.lower(), []).append(m)
        if method_name.startswith("__"):
            return None
        found = index.get(method_name.lower(), [])
        return found[0] if len(found) == 1 else None

    def resolve_class(self, name: str, namespace: str = ""):
        c = _norm(name)
        if "\\" in c:
            return self.classes.get(self.class_aliases.get(c, ""))
        if namespace and f"{namespace}\\{c}" in self.class_aliases:
            return self.classes.get(self.class_aliases[f"{namespace}\\{c}"])
        return self.classes.get(c)

    def lookup_method(self, class_name: str, method_name: str, namespace: str = ""):
        """Look up a method, walking the inheritance chain."""
        cls = self.resolve_class(class_name, namespace)
        seen = 0
        while cls is not None and seen < 20:
            if method_name in cls.methods:
                return cls.methods[method_name]
            if cls.parent:
                cls = self.resolve_class(cls.parent, namespace)
            else:
                cls = None
            seen += 1
        return None


def build_symbol_table(files: list[SourceFile]) -> SymbolTable:
    """Index every function, class and method in the scanned sources."""
    table = SymbolTable()
    for sf in files:
        if sf.language != "php":
            continue
        ns = file_namespace(sf)
        for node in sf.walk():
            t = node.type
            if t == "function_definition":
                table.add_function(au.method_name(node) or "", ns, node, sf)
            elif t == "class_declaration":
                cls_name = au.method_name(node) or ""
                parent = au.class_parent(node) or ""
                table.register_class_alias(cls_name, ns)
                cls = table.classes.setdefault(
                    cls_name, ClassSymbol(name=cls_name, namespace=ns, node=node,
                                          source=sf, parent=parent)
                )
                if parent:
                    cls.parent = parent
                table.all_classes.append(cls)
                for child in node.named_children:
                    if child.type == "declaration_list":
                        for member in child.named_children:
                            if member.type == "method_declaration":
                                mname = au.method_name(member) or ""
                                is_static = False
                                vis = "public"
                                for mc in member.named_children:
                                    if mc.type == "visibility_modifier":
                                        vis = au.text(mc)
                                    elif mc.type == "static_modifier" or au.text(mc).strip() == "static":
                                        is_static = True
                                table.add_method(cls_name, ns, mname, member, sf, is_static, vis)
    return table
