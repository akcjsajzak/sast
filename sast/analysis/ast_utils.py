"""AST node helpers for the PHP tree-sitter grammar."""
from __future__ import annotations

from tree_sitter import Node

from ..parsing.source import SourceFile


def text(node: Node) -> str:
    return node.text.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

SUPERGLOBALS = {
    "$_GET": "_GET", "$_POST": "_POST", "$_REQUEST": "_REQUEST",
    "$_COOKIE": "_COOKIE", "$_SERVER": "_SERVER", "$_FILES": "_FILES",
    "$_ENV": "_ENV", "$_SESSION": "_SESSION", "$GLOBALS": "GLOBALS",
}


def is_variable(node: Node) -> bool:
    return node.type == "variable_name"


def var_name(node: Node):
    """Return the canonical variable name ('$id', '$_GET') or None."""
    if node.type == "variable_name":
        return text(node)
    return None


def superglobal(node: Node):
    """Return the superglobal name ('_GET', '_POST', ...) or None."""
    if node.type == "variable_name":
        return SUPERGLOBALS.get(text(node))
    return None


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------

def is_call(node: Node) -> bool:
    return node.type in (
        "function_call_expression",
        "member_call_expression",
        "scoped_call_expression",
    )


def call_callee(node: Node):
    """Return the name of the function/method being called, or None."""
    if node.type == "function_call_expression":
        for c in node.named_children:
            if c.type in ("name", "qualified_name", "namespace_name"):
                return text(c)
    elif node.type == "member_call_expression":
        # object -> name (method)
        names = [c for c in node.named_children if c.type == "name"]
        if names:
            return text(names[-1])
    elif node.type == "scoped_call_expression":
        names = [c for c in node.named_children if c.type == "name"]
        if names:
            return text(names[-1])
    return None


def call_full_name(node: Node):
    """Return Class::method / Class->method / function, best effort."""
    if node.type == "function_call_expression":
        return call_callee(node)
    if node.type == "member_call_expression":
        obj = node.named_children[0] if node.named_children else None
        method = call_callee(node)
        base = text(obj) if obj is not None else "?"
        return f"{base}->{method}"
    if node.type == "scoped_call_expression":
        parts = [c for c in node.named_children if c.type == "name"]
        if len(parts) >= 2:
            return f"{text(parts[0])}::{text(parts[1])}"
    return call_callee(node)


def is_method_call(node: Node) -> bool:
    return node.type in ("member_call_expression", "scoped_call_expression")


def is_static_call(node: Node) -> bool:
    return node.type == "scoped_call_expression"


def callee_parts(node: Node):
    """Return (class_or_none, method_name) for method/static calls."""
    if node.type == "member_call_expression":
        names = [c for c in node.named_children if c.type == "name"]
        if not names:
            return None, None
        return None, text(names[-1])
    if node.type == "scoped_call_expression":
        parts = [c for c in node.named_children if c.type == "name"]
        if len(parts) < 2:
            return None, None
        return text(parts[0]), text(parts[1])
    return None, None


def argument_values(node: Node):
    """Return the value-expression of each argument of a call node."""
    results = []
    for c in node.named_children:
        if c.type == "arguments":
            for a in c.named_children:
                if a.type == "argument":
                    inner = a.named_children
                    if inner:
                        results.append(inner[0])
                elif a.type == "named_argument":
                    # name: value
                    for nc in a.named_children:
                        if nc.type != "name":
                            results.append(nc)
    return results


# ---------------------------------------------------------------------------
# Literals & expressions
# ---------------------------------------------------------------------------

def strip_wrappers(node: Node) -> Node:
    """Unwrap parenthesized/cast/argument wrappers."""
    while node.type in ("parenthesized_expression", "argument"):
        inner = node.named_children
        if not inner:
            break
        node = inner[0]
    return node


def literal_string(node: Node):
    """Return the string value of a string/encapsed_string node, or None."""
    node = strip_wrappers(node)
    if node.type == "string":
        content = "".join(text(c) for c in node.named_children if c.type == "string_content")
        return content
    if node.type == "encapsed_string":
        return text(node)[1:-1] if len(text(node)) >= 2 else text(node)
    return None


def is_string_literal(node: Node) -> bool:
    return strip_wrappers(node).type in ("string", "encapsed_string")


# ---------------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------------

def iter_statements(body: Node):
    """Yield the top-level statements of a compound_statement or other body."""
    if body is None:
        return
    if body.type == "compound_statement":
        for c in body.named_children:
            if c.type == "expression_statement":
                inner = c.named_children
                if inner:
                    yield inner[0]
            else:
                yield c
    elif body.type == "expression_statement":
        inner = body.named_children
        if inner:
            yield inner[0]
    else:
        yield body


def method_name(node: Node):
    """Return the method/function name for a *_declaration node."""
    for c in node.named_children:
        if c.type == "name":
            return text(c)
    return None


def params_of(node: Node):
    """Return parameter variable names of a function/method declaration."""
    result = []
    for c in node.named_children:
        if c.type == "formal_parameters":
            for p in c.named_children:
                if p.type == "simple_parameter":
                    for pc in p.named_children:
                        if pc.type == "variable_name":
                            result.append(text(pc))
                elif p.type == "variadic_parameter":
                    for pc in p.named_children:
                        if pc.type == "variable_name":
                            result.append(text(pc))
    return result


def body_of(node: Node):
    """Return the compound_statement body of a function/method/closure."""
    for c in node.named_children:
        if c.type in ("compound_statement",):
            return c
    return None


def class_parent(node: Node):
    """Return the parent class name of a class_declaration, or None."""
    for c in node.named_children:
        if c.type == "base_clause":
            for bc in c.named_children:
                if bc.type == "name" or bc.type == "qualified_name":
                    return text(bc)
    return None
