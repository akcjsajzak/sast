"""Syntax highlighting for the code browser, from the parse tree.

The tool runs offline with nothing to install, so a JavaScript highlighter
fetched from a CDN is out. tree-sitter is already here, with a grammar for
every language the scanner analyses, so a file is highlighted from the same
parse the analysis used: keywords are the grammar's anonymous word tokens,
and strings, comments, numbers, types, function names, constants and
annotations are recognised by node type. One rule set serves all eight
languages, because the grammars name these things alike (string_literal,
interpreted_string_literal and encapsed_string are all "string").

Files with no grammar here (templates, YAML, JSON, Dockerfiles, ...) get a
small regex pass for comments, strings and numbers, and template files
additionally have their expressions marked, since `{{ x|safe }}` and
`<%- x %>` are where template XSS findings point.
"""
from __future__ import annotations

import html
import os
import re

# Files past this size are shown plain: highlighting walks every node.
MAX_HIGHLIGHT_BYTES = 1024 * 1024

# Class names, kept short: one span per token adds up over a large file.
KEYWORD, STRING, COMMENT, NUMBER, TYPE, FUNCTION, CONSTANT, ANNOTATION, \
    VARIABLE, TAG = "k", "s", "c", "n", "t", "f", "o", "a", "v", "g"

_CONSTANTS = {"true", "false", "null", "none", "nil", "null_literal", "undefined",
              "boolean", "boolean_literal", "this", "self", "super", "iota"}
_TYPES = {"type_identifier", "primitive_type", "predefined_type", "builtin_type",
          "integral_type", "floating_point_type", "void_type", "sized_type_specifier",
          "primitive_type_identifier"}
# Not `attribute`: that is member access in Python's grammar (`os.path`).
# C#'s `[HttpGet]` attributes always sit in an attribute_list.
_ANNOTATIONS = {"decorator", "annotation", "marker_annotation", "attribute_list"}
# Nodes whose `name` (or `function`) child is a function being defined or
# called.
_DEFINES = ("function", "method", "constructor", "def", "func")
_CALLS = ("call", "invocation")


def highlight_lines(rel: str, content: bytes):
    """HTML for each line of `content`, or None to show it plain.

    Lines split on newline only, as tree-sitter counts rows, so the line
    numbers match the ones findings report.
    """
    if len(content) > MAX_HIGHLIGHT_BYTES:
        return None
    try:
        spans = _tree_spans(rel, content)
        if spans is None:
            spans = _regex_spans(rel, content)
    except Exception:  # noqa: BLE001 — highlighting must never break viewing
        return None
    if spans is None:
        return None
    return _render(content, spans)


# ---------------------------------------------------------------------------
# Parse-tree highlighting
# ---------------------------------------------------------------------------
def _parser_for(rel: str):
    from ..detection.language import LANGUAGE_EXTENSIONS
    ext = os.path.splitext(rel)[1].lower()
    language = next((lang for lang, exts in LANGUAGE_EXTENSIONS.items()
                     if ext in exts), None)
    if language is None:
        return None
    if language == "php":
        from ..parsing.php import PhpParser
        return PhpParser()
    if language == "java":
        from ..parsing.java import JavaParser
        return JavaParser()
    if language == "javascript":
        from ..parsing.javascript import JsParser
        return JsParser()
    from ..parsing.generic import GenericParser
    parser = GenericParser(language)
    return parser if parser.available else None


def _tree_spans(rel: str, content: bytes):
    """[(start_byte, end_byte, cls)] from the parse tree, or None."""
    parser = _parser_for(rel)
    if parser is None:
        return None
    sf = parser.parse(rel, content)
    spans: list = []
    stack = [sf.root]
    while stack:
        node = stack.pop()
        cls = _classify(node)
        if cls is not None:
            spans.append((node.start_byte, node.end_byte, cls))
            if cls in (STRING, COMMENT):
                # Interpolations inside a string keep their own colours.
                for c in node.named_children:
                    if "interpolation" in c.type or c.type in (
                            "template_substitution", "string_interpolation"):
                        spans.append((c.start_byte, c.end_byte, None))
                        stack.extend(c.named_children)
            continue
        stack.extend(node.children)
    return _flatten(spans)


def _classify(node):
    t = node.type
    if "comment" in t:
        return COMMENT
    if not node.is_named:
        # Keywords are the grammar's anonymous word tokens: `if`, `def`, ...
        if t.isidentifier() and t.lower() not in _CONSTANTS:
            return KEYWORD
        if t.lower() in _CONSTANTS:
            return CONSTANT
        return None
    if t in _ANNOTATIONS:
        return ANNOTATION
    if (("string" in t or t in ("char_literal", "character_literal", "heredoc",
                                "nowdoc", "regex", "template_string",
                                "rune_literal", "verbatim_string_literal"))
            and "interpolation" not in t and t != "string_content"
            and node.parent is not None and not _inside_string(node)):
        return STRING
    if ("number" in t or "integer" in t or "float" in t or t.startswith("int_")
            or t in ("decimal_integer_literal", "hex_integer_literal",
                     "real_literal", "imaginary_literal")):
        return NUMBER
    if t.lower() in _CONSTANTS or t in ("true", "false", "nil", "none"):
        return CONSTANT
    if t in _TYPES:
        return TYPE
    if t == "variable_name" or (t == "name" and node.parent is not None
                                and node.parent.type == "variable_name"):
        return VARIABLE if t == "variable_name" else None
    if t in ("identifier", "property_identifier", "field_identifier", "name"):
        return _identifier_role(node)
    return None


def _inside_string(node) -> bool:
    p = node.parent
    while p is not None:
        if "string" in p.type and "interpolation" not in p.type:
            return True
        if "interpolation" in p.type or p.type == "template_substitution":
            return False
        p = p.parent
    return False


def _identifier_role(node):
    """FUNCTION for a name being defined or called, else None."""
    parent = node.parent
    if parent is None:
        return None
    pt = parent.type
    if any(k in pt for k in _DEFINES) and _is_field(parent, node, "name"):
        return FUNCTION
    # C and C++ hang the name off a declarator: `int main(void)`.
    if pt == "function_declarator" and _is_field(parent, node, "declarator"):
        return FUNCTION
    if any(k in pt for k in _CALLS):
        fn = parent.child_by_field_name("function") or \
            parent.child_by_field_name("name")
        if fn is not None and fn.id == node.id:
            return FUNCTION
    # `obj.method(...)`: the member's property, when the member is called.
    grand = parent.parent
    if grand is not None and any(k in grand.type for k in _CALLS):
        fn = grand.child_by_field_name("function")
        if fn is not None and fn.id == parent.id:
            prop = (parent.child_by_field_name("property")
                    or parent.child_by_field_name("field")
                    or parent.child_by_field_name("attribute")
                    or parent.child_by_field_name("name"))
            if prop is not None and prop.id == node.id:
                return FUNCTION
    if pt == "class_declaration" or pt == "class_definition":
        if _is_field(parent, node, "name"):
            return TYPE
    return None


def _is_field(parent, node, field: str) -> bool:
    child = parent.child_by_field_name(field)
    return child is not None and child.id == node.id


def _flatten(spans: list) -> list:
    """Nested spans to flat, non-overlapping (start, end, cls) segments.

    The innermost span covering a byte decides its class. A `None` span is a
    hole: an interpolation inside a string, reset so its own tokens show.
    """
    starts: dict = {}
    for s, e, c in spans:
        if e > s:
            starts.setdefault(s, []).append((e, c))
    boundaries = sorted({b for s, e, _ in spans for b in (s, e)})
    out: list = []
    active: list = []  # (end, cls), outermost first
    for i, b in enumerate(boundaries[:-1]):
        active = [(e, c) for e, c in active if e > b]
        active.extend(sorted(starts.get(b, []), key=lambda x: -x[0]))
        if not active or active[-1][1] is None:
            continue
        cls, nxt = active[-1][1], boundaries[i + 1]
        if out and out[-1][1] == b and out[-1][2] == cls:
            out[-1] = (out[-1][0], nxt, cls)
        else:
            out.append((b, nxt, cls))
    return out


# ---------------------------------------------------------------------------
# Regex fallback for files without a grammar
# ---------------------------------------------------------------------------
_HASH_COMMENT = {".yml", ".yaml", ".sh", ".bash", ".toml", ".ini", ".cfg", ".conf",
                 ".properties", ".env", ".tf", ".tfvars", ".hcl", ".rb", ".pl",
                 ".r", ".dockerfile", ".gitignore", ".service"}
_HASH_NAMES = {"dockerfile", "makefile", "procfile", ".env", "jenkinsfile",
               "vagrantfile"}
_SLASH_COMMENT = {".tf", ".hcl", ".kt", ".swift", ".scala", ".gradle", ".jsonc"}
_MARKUP = {".html", ".htm", ".xhtml", ".xml", ".jsp", ".jspx", ".jspf", ".tag",
           ".twig", ".jinja", ".jinja2", ".j2", ".njk", ".ejs", ".hbs",
           ".handlebars", ".vue", ".svelte", ".ftl", ".blade.php", ".svg",
           ".config", ".csproj"}
_TEMPLATE_EXPR = re.compile(rb"\{\{.*?\}\}|\{%.*?%\}|<%.*?%>|\{!!.*?!!\}|\$\{.*?\}"
                            rb"|#\{.*?\}|!\{.*?\}", re.DOTALL)
_STRING = re.compile(rb"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")
_NUMBER = re.compile(rb"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])")
_TAG = re.compile(rb"</?[A-Za-z][\w:.-]*|/?>")


def _regex_spans(rel: str, content: bytes):
    name = os.path.basename(rel).lower()
    ext = os.path.splitext(name)[1]
    if name.endswith(".blade.php"):
        ext = ".blade.php"
    spans: list = []
    if ext in _MARKUP:
        spans += [(m.start(), m.end(), COMMENT)
                  for m in re.finditer(rb"<!--.*?-->|<%--.*?--%>|\{#.*?#\}",
                                       content, re.DOTALL)]
        spans += [(m.start(), m.end(), ANNOTATION)
                  for m in _TEMPLATE_EXPR.finditer(content)]
        spans += [(m.start(), m.end(), TAG) for m in _TAG.finditer(content)]
        spans += [(m.start(), m.end(), STRING) for m in _STRING.finditer(content)]
        return _first_wins(spans)
    hash_comments = ext in _HASH_COMMENT or name in _HASH_NAMES \
        or name.startswith((".env", "dockerfile"))
    if hash_comments:
        spans += [(m.start(), m.end(), COMMENT)
                  for m in re.finditer(rb"(?m)(?:^|(?<=\s))#.*$", content)]
    if ext in _SLASH_COMMENT:
        spans += [(m.start(), m.end(), COMMENT)
                  for m in re.finditer(rb"//[^\n]*|/\*.*?\*/", content, re.DOTALL)]
    if ext in (".json", ".jsonc", ".yml", ".yaml", ".toml") or hash_comments:
        spans += [(m.start(), m.end(), STRING) for m in _STRING.finditer(content)]
        spans += [(m.start(), m.end(), NUMBER) for m in _NUMBER.finditer(content)]
        if name.startswith("dockerfile") or ext == ".dockerfile":
            spans += [(m.start(), m.end(), KEYWORD) for m in re.finditer(
                rb"(?mi)^\s*(?:FROM|RUN|CMD|COPY|ADD|ENV|ARG|USER|WORKDIR|EXPOSE|"
                rb"ENTRYPOINT|LABEL|VOLUME|HEALTHCHECK|SHELL|ONBUILD|STOPSIGNAL)\b",
                content)]
        return _first_wins(spans)
    return None


def _first_wins(spans: list) -> list:
    """Earliest span wins an overlap, and comments beat what they contain."""
    rank = {COMMENT: 0, ANNOTATION: 1, STRING: 2}
    spans.sort(key=lambda s: (s[0], rank.get(s[2], 3), -(s[1] - s[0])))
    out: list = []
    end = -1
    for s, e, c in spans:
        if s >= end:
            out.append((s, e, c))
            end = e
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _render(content: bytes, spans: list) -> list:
    """Split highlighted segments into per-line HTML."""
    lines: list = [[]]
    pos = 0

    def emit(chunk: bytes, cls):
        for i, part in enumerate(chunk.split(b"\n")):
            if i:
                lines.append([])
            if part:
                text = html.escape(part.decode("utf-8", "replace"))
                lines[-1].append(f'<span class="hl-{cls}">{text}</span>'
                                 if cls else text)

    for start, end, cls in spans:
        if start < pos:
            continue
        if start > pos:
            emit(content[pos:start], None)
        emit(content[start:end], cls)
        pos = end
    if pos < len(content):
        emit(content[pos:], None)
    rendered = ["".join(parts) for parts in lines]
    # A file ending in a newline has no line after it.
    if len(rendered) > 1 and content.endswith(b"\n") and rendered[-1] == "":
        rendered.pop()
    return [line.replace("\r", "") for line in rendered]
