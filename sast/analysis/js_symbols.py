"""JavaScript/TypeScript symbol table for interprocedural analysis."""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from ..parsing.source import SourceFile
from . import js_ast as ja


@dataclass
class JsFunction:
    name: str
    node: Node
    source: SourceFile
    params: list = field(default_factory=list)
    class_name: str = ""


@dataclass
class JsClass:
    name: str
    node: Node
    source: SourceFile
    methods: dict = field(default_factory=dict)
    parent: str = ""
    all_methods: list = field(default_factory=list)


class JsSymbolTable:
    def __init__(self) -> None:
        self.functions: dict[str, JsFunction] = {}
        self.classes: dict[str, JsClass] = {}
        # Every declaration, including ones sharing a name. The dicts above
        # are keyed for resolution and keep one entry per name, so analysing
        # from them alone skipped a second `function handle()` in another
        # module — and two modules exporting the same name is the norm, since
        # module scoping is deliberately ignored here.
        self.all_functions: list = []
        self.all_classes: list = []

    def lookup_function(self, name: str):
        return self.functions.get(name)

    def lookup_method(self, class_name: str, method: str):
        cls = self.classes.get(class_name)
        seen = 0
        while cls is not None and seen < 20:
            if method in cls.methods:
                return cls.methods[method]
            cls = self.classes.get(cls.parent) if cls.parent else None
            seen += 1
        return None


def _record_function(table: JsSymbolTable, name: str, fn_node: Node,
                     sf: SourceFile, class_name: str = "") -> None:
    if not name or fn_node is None:
        return
    sym = JsFunction(name=name, node=fn_node, source=sf,
                     params=ja.param_names(fn_node), class_name=class_name)
    if class_name:
        cls = table.classes.get(class_name)
        if cls is not None:
            cls.all_methods.append(sym)
            cls.methods[name] = sym
    else:
        table.all_functions.append(sym)
        table.functions.setdefault(name, sym)


def build_js_symbols(files: list[SourceFile]) -> JsSymbolTable:
    """Index top-level and nested function/class declarations across files.

    Module scoping is deliberately ignored: identifiers are indexed globally by
    name, which resolves the common case (an imported helper called by the same
    name it was defined under) without implementing module resolution.
    """
    table = JsSymbolTable()
    for sf in files:
        _walk(sf.root, sf, table, "")
    return table


def _walk(node: Node, sf: SourceFile, table: JsSymbolTable, class_name: str) -> None:
    for child in node.named_children:
        t = child.type

        if t in ("class_declaration", "class"):
            name_node = child.child_by_field_name("name")
            cname = ja.text(name_node) if name_node is not None else ""
            parent = ""
            heritage = child.child_by_field_name("superclass")
            if heritage is not None:
                parent = ja.text(heritage).replace("extends", "").strip()
            if cname:
                registered = table.classes.setdefault(
                    cname, JsClass(name=cname, node=child, source=sf, parent=parent))
                if registered not in table.all_classes:
                    table.all_classes.append(registered)
                body = child.child_by_field_name("body")
                if body is not None:
                    for m in body.named_children:
                        if m.type == "method_definition":
                            mname = m.child_by_field_name("name")
                            _record_function(table, ja.text(mname), m, sf, cname)
                    _walk(body, sf, table, cname)
            continue

        if t in ("function_declaration", "generator_function_declaration"):
            name_node = child.child_by_field_name("name")
            _record_function(table, ja.text(name_node), child, sf, "")

        elif t == "variable_declarator":
            # `const f = (x) => ...` / `const f = function (x) {...}`
            name_node, value = ja.declarator_parts(child)
            value = ja.strip(value) if value is not None else None
            if (name_node is not None and name_node.type == "identifier"
                    and value is not None and value.type in ja.FUNCTION_NODES):
                _record_function(table, ja.text(name_node), value, sf, "")

        _walk(child, sf, table, class_name)
