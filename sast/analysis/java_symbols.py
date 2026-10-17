"""Java symbol table: index classes and methods for interprocedural analysis."""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from ..parsing.source import SourceFile
from . import java_ast as ja


@dataclass
class JavaMethod:
    class_name: str
    name: str
    node: Node
    source: SourceFile
    params: list = field(default_factory=list)  # [(name, tainted_by_annotation)]


@dataclass
class JavaClass:
    name: str
    node: Node
    source: SourceFile
    parent: str = ""
    methods: dict = field(default_factory=dict)
    taintable_fields: set = field(default_factory=set)


class JavaSymbolTable:
    def __init__(self) -> None:
        self.classes: dict[str, JavaClass] = {}

    def lookup_method(self, class_name: str, method_name: str):
        cls = self.classes.get(class_name)
        seen = 0
        while cls is not None and seen < 20:
            if method_name in cls.methods:
                return cls.methods[method_name]
            cls = self.classes.get(cls.parent) if cls.parent else None
            seen += 1
        return None


def build_java_symbols(files: list[SourceFile]) -> JavaSymbolTable:
    table = JavaSymbolTable()
    for sf in files:
        if sf.language != "java":
            continue
        for node in sf.walk():
            t = node.type
            if t in ("class_declaration", "interface_declaration", "enum_declaration"):
                cname = ja.class_name(node) or ""
                parent = ja.class_parent(node) or ""
                cls = table.classes.setdefault(
                    cname, JavaClass(name=cname, node=node, source=sf, parent=parent)
                )
                if parent:
                    cls.parent = parent
                for child in node.named_children:
                    if child.type in ("class_body", "interface_body", "enum_body"):
                        for member in child.named_children:
                            if member.type in ("method_declaration", "constructor_declaration"):
                                mname = ja.method_name(member) or ("<init>" if member.type == "constructor_declaration" else "")
                                params = ja.formal_params(member)
                                if mname and mname not in cls.methods:
                                    cls.methods[mname] = JavaMethod(
                                        class_name=cname, name=mname, node=member,
                                        source=sf, params=params,
                                    )
    # Second pass: compute which instance fields can carry tainted data.
    for cls in table.classes.values():
        _compute_taintable_fields(cls)
    return table


def _iter_descendants(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.named_children)


def _compute_taintable_fields(cls: JavaClass) -> None:
    fields = set(ja.field_declarations(cls.node))
    for m in cls.methods.values():
        param_names = {p for p, _t, _ta in m.params}
        for n in _iter_descendants(m.node):
            if n.type == "assignment_expression":
                nc = n.named_children
                if len(nc) < 2:
                    continue
                lhs, rhs = nc[0], nc[-1]
                fname = None
                if lhs.type == "field_access" and lhs.named_children \
                        and ja.text(lhs.named_children[0]) == "this":
                    fname = ja.field_name(lhs)
                elif lhs.type == "identifier" and ja.text(lhs) in fields:
                    fname = ja.text(lhs)
                if fname and rhs.type == "identifier" and ja.text(rhs) in param_names:
                    cls.taintable_fields.add(fname)
