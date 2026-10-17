"""AST helpers for the JavaScript/TypeScript taint engine."""
from __future__ import annotations

from tree_sitter import Node

# Nodes that wrap an expression without changing its taint.
_TRANSPARENT = {
    "parenthesized_expression", "await_expression", "non_null_expression",
    "as_expression", "satisfies_expression", "type_assertion",
    "expression_statement",
}

FUNCTION_NODES = {
    "function_declaration", "function_expression", "function", "arrow_function",
    "method_definition", "generator_function", "generator_function_declaration",
}


def text(node: Node) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


def strip(node: Node) -> Node:
    """Unwrap parentheses, `await`, and TypeScript-only expression wrappers."""
    seen = 0
    while node is not None and node.type in _TRANSPARENT and seen < 12:
        named = node.named_children
        inner = None
        for c in named:
            # `x as Foo` / `<Foo>x`: the value is the non-type child.
            if "type" not in c.type:
                inner = c
                break
        if inner is None:
            return node
        node = inner
        seen += 1
    return node


def literal_string(node: Node):
    """The value of a string / template literal with no substitutions."""
    node = strip(node)
    if node is None:
        return None
    if node.type == "string":
        return "".join(text(c) for c in node.named_children
                       if c.type == "string_fragment")
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return "".join(text(c) for c in node.named_children
                       if c.type == "string_fragment")
    return None


def member_parts(node: Node):
    """Split a member expression into (object_node, property_name)."""
    if node is None or node.type not in ("member_expression", "subscript_expression"):
        return None, ""
    obj = node.child_by_field_name("object")
    if node.type == "subscript_expression":
        idx = node.child_by_field_name("index")
        return obj, literal_string(idx) or ""
    prop = node.child_by_field_name("property")
    return obj, text(prop)


def root_object(node: Node) -> str:
    """Left-most identifier of a member chain: `a.b.c` -> 'a'."""
    node = strip(node)
    seen = 0
    while node is not None and seen < 24:
        if node.type in ("member_expression", "subscript_expression"):
            node = node.child_by_field_name("object")
        elif node.type == "call_expression":
            node = node.child_by_field_name("function")
        elif node.type in _TRANSPARENT:
            node = strip(node)
            if node is not None and node.type in _TRANSPARENT:
                return ""
        else:
            break
        seen += 1
    if node is not None and node.type in ("identifier", "this",
                                          "shorthand_property_identifier"):
        return text(node)
    return ""


def member_path(node: Node) -> str:
    """Dotted source path of a member chain, e.g. `req.query.id`."""
    node = strip(node)
    parts = []
    seen = 0
    while node is not None and seen < 24:
        if node.type in ("member_expression", "subscript_expression"):
            obj, prop = member_parts(node)
            if prop:
                parts.append(prop)
            node = obj
        else:
            break
        seen += 1
    if node is not None and node.type in ("identifier", "this"):
        parts.append(text(node))
    return ".".join(reversed(parts))


def call_parts(node: Node):
    """Return (callee_name, receiver_node_or_None, [arg_nodes]) for a call."""
    if node is None or node.type not in ("call_expression", "new_expression"):
        return "", None, []
    fn = node.child_by_field_name("function")
    if fn is None:
        fn = node.child_by_field_name("constructor")
    args_node = node.child_by_field_name("arguments")
    args = [c for c in (args_node.named_children if args_node is not None else [])
            if c.type != "comment"]
    fn = strip(fn)
    if fn is None:
        return "", None, args
    if fn.type in ("member_expression", "subscript_expression"):
        obj, prop = member_parts(fn)
        return prop, obj, args
    return text(fn), None, args


def is_call(node: Node) -> bool:
    return node is not None and node.type in ("call_expression", "new_expression")


def body_of(node: Node):
    """Statement block (or expression body) of a function-like node."""
    if node is None:
        return None
    body = node.child_by_field_name("body")
    if body is not None:
        return body
    for c in node.named_children:
        if c.type == "statement_block":
            return c
    return None


def param_names(node: Node) -> list:
    """Parameter names of a function-like node, destructuring included.

    A destructured parameter contributes both the binding names and the
    parameter as a whole, so `({ id })` and `(req)` both resolve.
    """
    names: list = []
    params = node.child_by_field_name("parameters") if node is not None else None
    if params is None and node is not None:
        for c in node.named_children:
            if c.type == "formal_parameters":
                params = c
                break
            # Single-identifier arrow parameter: `v => ...`
            if c.type == "identifier":
                return [text(c)]
    if params is None:
        return names
    for p in params.named_children:
        names.extend(binding_names(p))
    return names


def binding_names(node: Node) -> list:
    """Every identifier bound by a (possibly destructuring) pattern."""
    if node is None:
        return []
    t = node.type
    if t in ("identifier", "shorthand_property_identifier_pattern",
             "shorthand_property_identifier"):
        return [text(node)]
    if t in ("required_parameter", "optional_parameter"):
        pat = node.child_by_field_name("pattern")
        return binding_names(pat) if pat is not None else []
    if t in ("object_pattern", "array_pattern"):
        out = []
        for c in node.named_children:
            out.extend(binding_names(c))
        return out
    if t == "pair_pattern":
        value = node.child_by_field_name("value")
        return binding_names(value)
    if t in ("assignment_pattern", "rest_pattern", "spread_element"):
        left = node.child_by_field_name("left")
        return binding_names(left if left is not None else
                             (node.named_children[0] if node.named_children else None))
    return []


def iter_statements(block: Node):
    if block is None:
        return []
    return [c for c in block.named_children if c.type != "comment"]


def declarators(node: Node):
    return [c for c in node.named_children if c.type == "variable_declarator"]


def declarator_parts(node: Node):
    """(name_node, value_node) of a variable_declarator, using grammar fields."""
    return node.child_by_field_name("name"), node.child_by_field_name("value")


def jsx_attributes(node: Node):
    """Yield (attribute_name, value_node) for a JSX element's attributes."""
    out = []
    for c in node.named_children:
        if c.type != "jsx_attribute":
            continue
        kids = c.named_children
        if not kids:
            continue
        name = text(kids[0])
        value = kids[1] if len(kids) > 1 else None
        if value is not None and value.type == "jsx_expression":
            inner = [k for k in value.named_children if k.type != "comment"]
            value = inner[0] if inner else None
        out.append((name, value))
    return out
