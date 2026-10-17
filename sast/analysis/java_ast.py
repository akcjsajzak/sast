"""AST node helpers for the Java tree-sitter grammar."""
from __future__ import annotations

from tree_sitter import Node

from ..parsing.source import SourceFile


def text(node: Node) -> str:
    return node.text.decode("utf-8", "replace")


def is_identifier(node: Node) -> bool:
    return node.type == "identifier"


def is_method_invocation(node: Node) -> bool:
    return node.type == "method_invocation"


def mi_parts(node: Node):
    """Return (object_node_or_None, method_name, arg_nodes) for a method_invocation."""
    children = node.named_children
    args_idx = None
    for i, c in enumerate(children):
        if c.type == "argument_list":
            args_idx = i
            break
    if args_idx is None:
        return None, None, []
    args = list(children[args_idx].named_children)
    # method name = identifier just before argument_list
    method = None
    obj = None
    if args_idx >= 1 and children[args_idx - 1].type == "identifier":
        method = text(children[args_idx - 1])
        if args_idx >= 2:
            obj = children[args_idx - 2]
    elif args_idx >= 1:
        method = text(children[args_idx - 1])
        if args_idx >= 2:
            obj = children[args_idx - 2]
    return obj, method, args


def method_name_of(node: Node):
    """Return the method name of a method_invocation."""
    _, m, _ = mi_parts(node)
    return m


def args_of(node: Node):
    _, _, a = mi_parts(node)
    return a


def object_of(node: Node):
    obj, _, _ = mi_parts(node)
    return obj


def receiver_text(node: Node) -> str:
    """Full text of the receiver (object) part of a method invocation."""
    obj, _, _ = mi_parts(node)
    return text(obj) if obj is not None else ""


def formal_params(node: Node):
    """Return [(param_name, param_type, has_taint_annotation)] for a method_declaration."""
    result = []
    for c in node.named_children:
        if c.type == "formal_parameters":
            for p in c.named_children:
                if p.type == "formal_parameter":
                    name = None
                    ptype = None
                    tainted = False
                    for pc in p.named_children:
                        if pc.type == "identifier":
                            name = text(pc)
                        elif pc.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
                            ptype = _base_type(pc)
                        elif pc.type == "modifiers":
                            for m in pc.named_children:
                                if m.type in ("marker_annotation", "annotation"):
                                    ann = _annotation_name(m)
                                    if ann in ("RequestParam", "PathVariable",
                                               "RequestBody", "RequestHeader",
                                               "ModelAttribute", "CookieValue",
                                               "RequestPart"):
                                        tainted = True
                    if name:
                        result.append((name, ptype, tainted))
    return result


def _base_type(node: Node) -> str:
    t = text(node)
    if "<" in t:
        t = t.split("<", 1)[0]
    return t


def declared_type(node: Node):
    """Return the base type name of a local_variable_declaration / field_declaration."""
    for c in node.named_children:
        if c.type in ("type_identifier", "generic_type", "scoped_type_identifier",
                      "integral_type", "floating_point_type", "boolean_type",
                      "void_type", "array_type"):
            return _base_type(c)
    return None


def _annotation_name(node: Node):
    for c in node.named_children:
        if c.type == "identifier":
            return text(c)
    return ""


def method_name(node: Node):
    """Method/class name for a declaration node."""
    for c in node.named_children:
        if c.type == "identifier":
            return text(c)
    return None


def class_name(node: Node):
    """Class/interface name for a declaration node."""
    return method_name(node)


def class_parent(node: Node):
    """Return superclass/interface name for a class_declaration, or None."""
    for c in node.named_children:
        if c.type == "superclass":
            for sc in c.named_children:
                return text(sc)
        if c.type == "super_interfaces":
            for si in c.named_children:
                return text(si)
    return None


def declarators(node: Node):
    """Return variable_declarator nodes under a local_variable_declaration."""
    return [c for c in node.named_children if c.type == "variable_declarator"]


def declarator_parts(node: Node):
    """Return (name, value_node_or_None) for a variable_declarator.

    Uses the grammar's own `name`/`value` fields. Matching positionally
    instead would misread `String s = q;`, whose initializer is itself an
    identifier, as having no initializer at all — silently dropping taint
    across the most ordinary assignment in Java.
    """
    name_node = node.child_by_field_name("name")
    value = node.child_by_field_name("value")
    name = text(name_node) if name_node is not None else None
    if name is None:
        # Defensive fallback for grammar versions without named fields.
        for c in node.named_children:
            if c.type == "identifier":
                name = text(c)
                break
    return name, value


def literal_string(node: Node):
    """Return string value of a string_literal node, or None."""
    if node.type == "string_literal":
        return "".join(text(c) for c in node.named_children if c.type == "string_fragment")
    return None


def field_name(node: Node):
    """Return the field name of a field_access node (e.g. 'this.cmd' -> 'cmd')."""
    if node.type != "field_access":
        return None
    for c in reversed(node.named_children):
        if c.type == "identifier":
            return text(c)
    return None


def field_declarations(node: Node):
    """Return declared field names under a class/interface body."""
    names = []
    for member in node.named_children:
        if member.type == "field_declaration":
            for d in member.named_children:
                if d.type == "variable_declarator":
                    name, _ = declarator_parts(d)
                    if name:
                        names.append(name)
    return names
