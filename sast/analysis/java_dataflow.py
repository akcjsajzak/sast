"""Source-to-sink taint analysis engine for Java."""
from __future__ import annotations

import re

from tree_sitter import Node

from ..models import Finding, Severity, TaintStep
from ..parsing.source import SourceFile
from ..rules.base import RuleSet
from . import java_ast as ja
from .dataflow import Ctx, Taint, _merge_taint, _taint_key, make_loc, match_callee, pattern_loc
from .java_symbols import JavaSymbolTable

MAX_DEPTH = 8
MAX_STEPS = 15

_ALL_TAGS = ["sql", "xss", "cmd", "ssrf", "lfi", "path", "deser", "xxe", "ldap",
             "redirect", "code", "log", "ssti", "jndi", "el", "xpath", "redos"]

# Nodes whose children must not contribute taint: declarations and types
# describe shape, not values.
_OPAQUE = frozenset({
    "class_declaration", "interface_declaration", "enum_declaration",
    "method_declaration", "constructor_declaration", "field_declaration",
    "annotation_type_declaration", "import_declaration", "package_declaration",
    "type_identifier", "scoped_type_identifier", "generic_type",
    "formal_parameters", "type_arguments", "dimensions", "modifiers",
    "marker_annotation", "annotation", "block", "class_body",
})

_COMMENTS = {"comment", "line_comment", "block_comment"}

_SKIP_TOP = {"package_declaration", "import_declaration", "class_declaration",
             "interface_declaration", "enum_declaration", "annotation_type_declaration",
             "comment", "block_comment", "line_comment", "record_declaration"}

# Calls that write their arguments into the receiver, making the receiver
# (a collection, map, or builder) carry the arguments' taint.
MUTATING_WRITES = frozenset({
    "append", "concat", "insert", "write", "add", "addAll", "addFirst",
    "addLast", "put", "putAll", "putIfAbsent", "set", "setAll", "push",
    "offer", "offerFirst", "offerLast", "merge", "replace",
})

# Static/utility calls whose result carries their arguments' taint, used when
# the receiver itself is a class rather than a tainted value
# (Base64.getDecoder().decode(x), URLDecoder.decode(x), String.join(...)).
ARG_PROPAGATORS = frozenset({
    "decode", "encode", "encodeToString", "join", "valueOf", "copyValueOf",
    "parseString", "readValue", "fromJson", "deserialize", "unescapeHtml",
    "unescapeHtml4", "toString",
    # Commons Codec, reached as a static on the Base64 class rather than on a
    # tainted receiver. Round-tripping a value through Base64 does not launder
    # it, but losing it here made the round trip look like a sanitizer.
    "encodeBase64", "decodeBase64", "encodeBase64String", "encodeBase64URLSafe",
    "encodeBase64URLSafeString", "encodeHexString", "decodeHex",
    "newStringUtf8", "getBytesUtf8",
    # Collection factories — the collection inherits its elements' taint.
    "asList", "of", "singletonList", "singleton", "copyOf",
    "unmodifiableList", "unmodifiableCollection", "nCopies",
})

# Calls on a tainted receiver that yield a size, index or boolean rather than
# attacker-controlled bytes — propagating through these only adds noise.
NON_PROPAGATING = frozenset({
    "size", "length", "isEmpty", "hashCode", "equals", "equalsIgnoreCase",
    "compareTo", "compareToIgnoreCase", "indexOf", "lastIndexOf", "contains",
    "containsKey", "containsValue", "startsWith", "endsWith", "matches",
    "count", "hasNext", "canRead", "canWrite", "exists", "isDirectory",
    "isFile", "charAt", "codePointAt", "ordinal", "compare",
})


# Constant folding
#
# A branch whose condition is decidable at compile time has one live arm, and
# merging both arms' environments is what made a sanitized value look tainted:
# `if ((7 * 42) - num > 200) bar = "safe"; else bar = param;` always takes the
# first arm, yet the merge handed `bar` the taint from the second. Folding the
# condition and walking only the live arm is a pure precision gain — anything
# not decidable stays UNKNOWN and both arms are walked exactly as before, so
# this can never hide a real flow.
#
# Constants live in the type environment under a prefix no Java identifier can
# carry, which gets them branch scoping and merging for free.
_CONST_PREFIX = "\0const:"

UNKNOWN = object()

_INT_MIN, _INT_MAX = -(2 ** 31), 2 ** 31 - 1


def _wrap_int(n: int) -> int:
    """Java int arithmetic wraps at 32 bits; Python's does not."""
    return (n + 2 ** 31) % 2 ** 32 - 2 ** 31


def const_get(tenv: dict, name: str):
    return tenv.get(_CONST_PREFIX + name, UNKNOWN)


def const_set(tenv: dict, name: str, value) -> None:
    key = _CONST_PREFIX + name
    if value is UNKNOWN:
        tenv.pop(key, None)
    else:
        tenv[key] = value


def _parse_int_literal(text: str):
    text = text.replace("_", "").rstrip("lL")
    try:
        if text[:2].lower() in ("0x", "0b"):
            return int(text, 0)
        if len(text) > 1 and text.startswith("0"):
            return int(text, 8)
        return int(text, 10)
    except ValueError:
        return UNKNOWN


def _unquote(text: str):
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        body = text[1:-1]
        if "\\" in body:
            return UNKNOWN  # escapes are not worth decoding for this
        return body
    return UNKNOWN


def const_eval(node: Node, tenv: dict, depth: int = 0, props: dict = None):
    """Evaluate a Java expression to a Python value, or UNKNOWN.

    Deliberately narrow: integers, booleans and plain string literals, with
    the operators Java gives them. Anything else — a method call, a field, a
    float, an escaped string — is UNKNOWN, and every caller treats UNKNOWN as
    "assume nothing".
    """
    if node is None or depth > 16:
        return UNKNOWN
    t = node.type
    if t in ("decimal_integer_literal", "hex_integer_literal",
             "octal_integer_literal", "binary_integer_literal"):
        return _parse_int_literal(ja.text(node))
    if t in ("true", "false"):
        return t == "true"
    if t in ("true_literal", "false_literal"):
        return t.startswith("true")
    if t == "boolean_literal":
        return ja.text(node) == "true"
    if t == "string_literal":
        return _unquote(ja.text(node))
    if t == "character_literal":
        return _unquote(ja.text(node))
    if t == "identifier":
        return const_get(tenv, ja.text(node))
    if t == "method_invocation":
        return _const_method(node, tenv, depth, props)
    if t == "parenthesized_expression":
        kids = [c for c in node.named_children if c.type not in _COMMENTS]
        return const_eval(kids[0], tenv, depth + 1, props) if kids else UNKNOWN
    if t == "unary_expression":
        op = node.child_by_field_name("operator")
        operand = node.child_by_field_name("operand")
        v = const_eval(operand, tenv, depth + 1, props)
        if v is UNKNOWN or op is None:
            return UNKNOWN
        o = ja.text(op)
        if o == "-" and isinstance(v, int) and not isinstance(v, bool):
            return _wrap_int(-v)
        if o == "+" and isinstance(v, int) and not isinstance(v, bool):
            return v
        if o == "!" and isinstance(v, bool):
            return not v
        return UNKNOWN
    if t == "binary_expression":
        return _const_binary(node, tenv, depth, props)
    return UNKNOWN


# String methods that are pure and total, so calling one on a constant
# receiver with constant arguments gives a constant. `"ABC".charAt(1)` is how
# the Benchmark picks a switch label, and without it the selector is unknown
# and every case has to be treated as reachable.
_CONST_STRING_METHODS = {
    "charAt", "length", "substring", "trim", "strip", "toUpperCase",
    "toLowerCase", "concat", "indexOf", "lastIndexOf", "isEmpty", "isBlank",
    "equals", "equalsIgnoreCase", "startsWith", "endsWith", "contains",
    "replace", "hashCode", "compareTo",
}


def _const_method(node: Node, tenv: dict, depth: int, props: dict = None):
    obj, mname, args = ja.mi_parts(node)
    if mname in ("getProperty", "getString", "get") and props:
        # `props.getProperty("hashAlg1")` resolves against the .properties
        # files in the repository. Without this the algorithm is just "some
        # string decided at runtime" and the call cannot be judged at all,
        # even though the value sits a directory away. A second argument is
        # the default, used only when the key is absent.
        vals = [const_eval(a, tenv, depth + 1, props) for a in (args or [])]
        if vals and isinstance(vals[0], str):
            if vals[0] in props:
                return props[vals[0]]
            if len(vals) > 1 and isinstance(vals[1], str):
                return vals[1]
        return UNKNOWN
    if mname not in _CONST_STRING_METHODS:
        return UNKNOWN
    recv = const_eval(obj, tenv, depth + 1, props)
    if not isinstance(recv, str):
        return UNKNOWN
    vals = [const_eval(a, tenv, depth + 1, props) for a in (args or [])]
    if any(v is UNKNOWN for v in vals):
        return UNKNOWN
    try:
        if mname == "charAt" and len(vals) == 1:
            return recv[vals[0]]
        if mname == "length" and not vals:
            return len(recv)
        if mname == "substring":
            return recv[vals[0]:] if len(vals) == 1 else recv[vals[0]:vals[1]]
        if mname in ("trim", "strip") and not vals:
            return recv.strip()
        if mname == "toUpperCase" and not vals:
            return recv.upper()
        if mname == "toLowerCase" and not vals:
            return recv.lower()
        if mname == "concat" and len(vals) == 1:
            return recv + str(vals[0])
        if mname == "indexOf" and len(vals) == 1:
            return recv.find(str(vals[0]))
        if mname == "lastIndexOf" and len(vals) == 1:
            return recv.rfind(str(vals[0]))
        if mname in ("isEmpty", "isBlank") and not vals:
            return not recv.strip() if mname == "isBlank" else recv == ""
        if mname == "equals" and len(vals) == 1:
            return recv == vals[0]
        if mname == "equalsIgnoreCase" and len(vals) == 1:
            return isinstance(vals[0], str) and recv.lower() == vals[0].lower()
        if mname == "startsWith" and len(vals) == 1:
            return recv.startswith(str(vals[0]))
        if mname == "endsWith" and len(vals) == 1:
            return recv.endswith(str(vals[0]))
        if mname == "contains" and len(vals) == 1:
            return str(vals[0]) in recv
        if mname == "replace" and len(vals) == 2:
            return recv.replace(str(vals[0]), str(vals[1]))
        if mname == "compareTo" and len(vals) == 1 and isinstance(vals[0], str):
            return (recv > vals[0]) - (recv < vals[0])
    except (IndexError, TypeError, ValueError):
        return UNKNOWN
    return UNKNOWN


def _const_binary(node: Node, tenv: dict, depth: int, props: dict = None):
    op_node = node.child_by_field_name("operator")
    if op_node is None:
        return UNKNOWN
    op = ja.text(op_node)
    left = const_eval(node.child_by_field_name("left"), tenv, depth + 1, props)
    right = const_eval(node.child_by_field_name("right"), tenv, depth + 1, props)

    # Short-circuit operators can decide on one side alone.
    if op == "&&":
        if left is False or right is False:
            return False
        if left is True and right is True:
            return True
        return UNKNOWN
    if op == "||":
        if left is True or right is True:
            return True
        if left is False and right is False:
            return False
        return UNKNOWN
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN

    if op == "==":
        return left == right
    if op == "!=":
        return left != right

    both_str = isinstance(left, str) and isinstance(right, str)
    if op == "+" and both_str:
        return left + right
    both_int = (isinstance(left, int) and isinstance(right, int)
                and not isinstance(left, bool) and not isinstance(right, bool))
    if not both_int:
        return UNKNOWN
    if op in ("<", "<=", ">", ">="):
        return {"<": left < right, "<=": left <= right,
                ">": left > right, ">=": left >= right}[op]
    if op == "+":
        return _wrap_int(left + right)
    if op == "-":
        return _wrap_int(left - right)
    if op == "*":
        return _wrap_int(left * right)
    if op in ("/", "%"):
        if right == 0:
            return UNKNOWN  # would throw at runtime; decide nothing
        # Java truncates toward zero; Python floors.
        q = abs(left) // abs(right)
        if op == "/":
            return _wrap_int(q if (left >= 0) == (right >= 0) else -q)
        return _wrap_int(left - right * (q if (left >= 0) == (right >= 0) else -q))
    if op in ("&", "|", "^"):
        return _wrap_int({"&": left & right, "|": left | right,
                          "^": left ^ right}[op])
    if op in ("<<", ">>"):
        if not 0 <= right < 32:
            return UNKNOWN
        return _wrap_int(left << right if op == "<<" else left >> right)
    return UNKNOWN


# getInstance families and what counts as weak for each. The value is the
# resolved algorithm string, so these match it whole rather than searching
# source text the way the pattern rules do.
#
# The hash and cipher entries deliberately reuse the pattern rules' ids. A
# weak algorithm named literally in the source and one resolved through a
# config lookup are the same finding at the same line, and the per-location
# dedup then reports it once however it was found.
_ALGORITHM_FAMILIES = {
    "messagedigest": (
        "java-crypto-weak-hash-algorithm",
        re.compile(r"(?:MD2|MD4|MD5|SHA-?1)$", re.IGNORECASE),
        "Weak cryptographic hash (MD5/SHA-1)", "low", "CWE-328",
        "MD2, MD4, MD5 and SHA-1 are collision-prone and unfit for "
        "signatures, integrity checks or password storage.",
    ),
    "signature": (
        "java-crypto-weak-signature",
        re.compile(r"(?:MD2|MD5|SHA-?1)with\w+$", re.IGNORECASE),
        "Weak signature algorithm", "medium", "CWE-328",
        "A signature over MD5 or SHA-1 can be forged by finding a collision.",
    ),
    "mac": (
        "java-crypto-weak-mac",
        re.compile(r"Hmac(?:MD5|SHA1)$", re.IGNORECASE),
        "Weak MAC algorithm", "medium", "CWE-328",
        "HMAC-MD5 and HMAC-SHA1 are deprecated for new designs.",
    ),
}
for _f in ("cipher", "keygenerator", "secretkeyfactory"):
    _ALGORITHM_FAMILIES[_f] = (
        "java-crypto-weak-cipher",
        re.compile(r"(?:DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish|IDEA)"
                   r"(?:/|$)|[A-Za-z0-9]+/ECB", re.IGNORECASE),
        "Weak or broken cipher algorithm", "medium", "CWE-327",
        "DES, 3DES, RC2, RC4, Blowfish and IDEA are broken or too weak for "
        "current use, and ECB mode leaks plaintext structure.",
    )


def _constructed_type(value: Node):
    """Class name from `new Foo(...)`, or None."""
    if value is None or value.type != "object_creation_expression":
        return None
    for c in value.named_children:
        if c.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
            return ja._base_type(c)
    return None


class JavaTaintEngine:
    def __init__(self, symbols: JavaSymbolTable, rules: RuleSet,
                 framework: str, language: str = "java",
                 properties: dict = None) -> None:
        self.symbols = symbols
        self.rules = rules
        self.framework = framework
        self.language = language
        self.findings: list[Finding] = []
        self._seen: set = set()
        self._call_memo: dict = {}
        # Values read from the repository's .properties files, so a crypto
        # algorithm chosen in configuration can be resolved at the call site.
        self.properties = properties or {}

    # ------------------------------------------------------------------
    def analyze(self, files: list[SourceFile]) -> list[Finding]:
        # Every declaration and every overload. Iterating `classes` and
        # `cls.methods` walked one class per bare name and one method per
        # name, so a second class called `Test` and a second `doGet` overload
        # were never analysed at all.
        for cls in self.symbols.all_classes:
            for m in cls.all_methods:
                env: dict = {}
                tenv: dict = {}
                for (name, typ, tainted) in m.params:
                    if typ:
                        tenv[name] = typ
                    if tainted:
                        env[name] = self._annotation_taint(m.node, m.source, name)
                # Seed taintable instance fields (set via setters/params elsewhere).
                for f in cls.taintable_fields:
                    if f not in env:
                        env[f"this.{f}"] = self._field_taint(cls, f)
                body = self._method_body(m.node)
                if body is not None:
                    self.process_block(body, m.source, env, tenv,
                                       Ctx(current_class=cls.name))
        for sf in files:
            self.run_patterns(sf)
        return self.findings

    def _field_taint(self, cls, field_name: str) -> Taint:
        loc = make_loc(cls.source, cls.node)
        return Taint(
            tags=set(_ALL_TAGS),
            origins=[loc],
            steps=[TaintStep(
                location=loc,
                description=f"taint stored in field {cls.name}.{field_name}",
                code=cls.source.node_line(cls.node),
            )],
        )

    def _annotation_taint(self, node: Node, sf: SourceFile, pname: str) -> Taint:
        loc = make_loc(sf, node)
        return Taint(
            tags=set(_ALL_TAGS),
            origins=[loc],
            steps=[TaintStep(
                location=loc,
                description=f"Untrusted request data bound to parameter {pname}",
                code=sf.node_line(node),
            )],
        )

    @staticmethod
    def _method_body(node: Node):
        for c in node.named_children:
            if c.type in ("block", "constructor_body"):
                return c
        return None

    # ------------------------------------------------------------------
    def process_block(self, body: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        ret = None
        for stmt in body.named_children:
            r = self.process_stmt(stmt, sf, env, tenv, ctx)
            if r is not None:
                ret = r if ret is None else ret.merge(r)
        return ret

    def process_any(self, body: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        if body is None:
            return None
        if body.type in ("block", "constructor_body"):
            return self.process_block(body, sf, env, tenv, ctx)
        return self.process_stmt(body, sf, env, tenv, ctx)

    def process_stmt(self, stmt: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        t = stmt.type
        if t == "local_variable_declaration":
            typ = ja.declared_type(stmt)
            for d in ja.declarators(stmt):
                name, value = ja.declarator_parts(d)
                if name:
                    # Prefer the constructed type over the declared one, so
                    # `I i = new Impl()` dispatches to Impl rather than to the
                    # interface, whose method has no body to analyse.
                    concrete = _constructed_type(value)
                    if concrete:
                        tenv[name] = concrete
                    elif typ:
                        tenv[name] = typ
                    if value is not None:
                        vt = self.taint_of(value, sf, env, tenv, ctx)
                        self._assign(name, vt, sf, env, d)
                        const_set(tenv, name,
                                  const_eval(value, tenv, 0, self.properties))
                    else:
                        const_set(tenv, name, UNKNOWN)
            return None
        if t == "expression_statement":
            nc = stmt.named_children
            if nc:
                inner = nc[0]
                if inner.type == "assignment_expression":
                    self.handle_assignment(inner, sf, env, tenv, ctx)
                else:
                    self.taint_of(inner, sf, env, tenv, ctx)
            return None
        if t == "assignment_expression":
            self.handle_assignment(stmt, sf, env, tenv, ctx)
            return None
        if t == "return_statement":
            nc = stmt.named_children
            if nc:
                return self.taint_of(nc[-1], sf, env, tenv, ctx)
            return None
        if t == "if_statement":
            return self.handle_if(stmt, sf, env, tenv, ctx)
        if t in ("for_statement", "enhanced_for_statement", "while_statement"):
            return self.handle_loop(stmt, sf, env, tenv, ctx)
        if t == "try_statement":
            return self.handle_try(stmt, sf, env, tenv, ctx)
        if t in ("switch_expression", "switch_statement"):
            return self.handle_switch(stmt, sf, env, tenv, ctx)
        if t == "block":
            return self.process_block(stmt, sf, env, tenv, ctx)
        # Fallback: evaluate for embedded sinks.
        self.taint_of(stmt, sf, env, tenv, ctx)
        return None

    def handle_assignment(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        nc = node.named_children
        if len(nc) < 2:
            return
        lhs, rhs = nc[0], nc[-1]
        if lhs.type == "identifier":
            vt = self.taint_of(rhs, sf, env, tenv, ctx)
            self._assign(ja.text(lhs), vt, sf, env, lhs)
            # A compound assignment (`x += y`) is not a new constant value
            # unless both sides are known, which const_eval of the bare rhs
            # cannot tell us — so clear it rather than guess.
            op = node.child_by_field_name("operator")
            simple = op is None or ja.text(op) == "="
            const_set(tenv, ja.text(lhs),
                      const_eval(rhs, tenv, 0, self.properties)
                      if simple else UNKNOWN)
        elif lhs.type in ("field_access",):
            vt = self.taint_of(rhs, sf, env, tenv, ctx)
            self._assign(ja.text(lhs), vt, sf, env, lhs)
        elif lhs.type == "array_access":
            # `arr[i] = tainted` taints the array as a whole; element-level
            # precision is not worth the complexity here.
            vt = self.taint_of(rhs, sf, env, tenv, ctx)
            base = lhs.named_children[0] if lhs.named_children else None
            if base is not None and vt is not None:
                root = ja.text(base)
                existing = env.get(root)
                self._assign(root, vt if existing is None else existing.merge(vt),
                             sf, env, lhs)

    def _assign(self, name, t, sf, env, node):
        if t is not None:
            env[name] = t.with_step(TaintStep(
                location=make_loc(sf, node),
                description=f"taint stored in {name}",
                code=sf.node_line(node),
            ))
        else:
            env.pop(name, None)

    def handle_if(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        ret = None
        branch_envs = []
        # A decidable condition leaves one live arm. Walking the dead one too
        # and merging its environment is what let a constant assignment be
        # overwritten by the taint from a branch that never runs.
        verdict = const_eval(node.child_by_field_name("condition"), tenv, 0,
                             self.properties)
        live = None
        if verdict is True:
            live = node.child_by_field_name("consequence")
        elif verdict is False:
            live = node.child_by_field_name("alternative")
        if verdict in (True, False):
            self.taint_of(node.child_by_field_name("condition"), sf, env, tenv, ctx)
            if live is None:
                return None  # `if (false) ...` with no else: nothing runs
            be, bte = dict(env), dict(tenv)
            ret = self.process_any(live, sf, be, bte, ctx)
            # The one live arm runs unconditionally, so its environment
            # replaces the outer one rather than merging with it.
            env.clear()
            env.update(be)
            tenv.clear()
            tenv.update(bte)
            return ret
        for c in node.named_children:
            if c.type == "parenthesized_expression":
                self.taint_of(c, sf, env, tenv, ctx)
            elif c.type not in _COMMENTS:
                # A braceless branch body is the statement itself — an
                # `expression_statement`, a declaration, a nested if — and
                # never a node called "statement", so matching on that name
                # skipped `if (v != null) x = v[0];` outright. The Benchmark's
                # whole getParameterMap shape ends in exactly that line, which
                # is why so many of its flows stopped at the null guard.
                be, bte = dict(env), dict(tenv)
                r = self.process_any(c, sf, be, bte, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append((be, bte))
        for be, bte in branch_envs:
            _merge_env(env, be)
            _merge_tenv(tenv, bte)
        return ret

    def handle_switch(self, node: Node, sf: SourceFile, env: dict, tenv: dict,
                      ctx: Ctx):
        """Walk a switch's case bodies as statements.

        Without this a switch fell through to the expression fallback, which
        reads its children for taint but never writes to the environment — so
        `case 7: bar = param;` did not taint `bar` and `case 8: bar = "safe";`
        did not clear it. Both directions were wrong, and the second is why a
        safe switch still reported.

        A constant selector picks one group, counting fall-through from it.
        Otherwise every group is a separate branch, as in handle_if.
        """
        cond = node.child_by_field_name("condition")
        self.taint_of(cond, sf, env, tenv, ctx)
        body = node.child_by_field_name("body")
        if body is None:
            return None
        groups = [c for c in body.named_children
                  if c.type in ("switch_block_statement_group", "switch_rule")]
        if not groups:
            return None

        selector = const_eval(cond, tenv, 0, self.properties)
        live = None
        if selector is not UNKNOWN:
            live = self._switch_live_groups(groups, selector)

        ret = None
        if live is not None:
            # Exactly one path runs, so its environment replaces the outer one.
            be, bte = dict(env), dict(tenv)
            for g in live:
                ret = _merge_taint(ret, self._switch_group(g, sf, be, bte, ctx))
            env.clear()
            env.update(be)
            tenv.clear()
            tenv.update(bte)
            return ret

        branch_envs = []
        for g in groups:
            be, bte = dict(env), dict(tenv)
            ret = _merge_taint(ret, self._switch_group(g, sf, be, bte, ctx))
            branch_envs.append((be, bte))
        for be, bte in branch_envs:
            _merge_env(env, be)
            _merge_tenv(tenv, bte)
        return ret

    def _switch_group(self, group: Node, sf, env, tenv, ctx):
        ret = None
        for c in group.named_children:
            if c.type in _COMMENTS or c.type == "switch_label":
                continue
            ret = _merge_taint(ret, self.process_stmt(c, sf, env, tenv, ctx))
        return ret

    @staticmethod
    def _switch_live_groups(groups: list, selector):
        """The groups that run for a known selector, or None if undecidable.

        Returns the matching group plus everything it falls through into, so
        a `case` without a `break` is still accounted for. A `default` is used
        only when no label matches. Any label this cannot evaluate makes the
        whole switch undecidable rather than guessing.
        """
        match_at = None
        default_at = None
        for i, g in enumerate(groups):
            for label in g.named_children:
                if label.type != "switch_label":
                    continue
                values = [c for c in label.named_children
                          if c.type not in _COMMENTS]
                if not values:
                    if default_at is None:
                        default_at = i
                    continue
                for v in values:
                    cv = const_eval(v, {})
                    if cv is UNKNOWN:
                        return None  # an unreadable label: decide nothing
                    if cv == selector and match_at is None:
                        match_at = i
        start = match_at if match_at is not None else default_at
        if start is None:
            return []  # nothing matches and there is no default
        live = []
        for g in groups[start:]:
            live.append(g)
            text = ja.text(g)
            if "break" in text or "return" in text or "->" in text:
                break
        return live

    def handle_loop(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        ret = None
        be, bte = dict(env), dict(tenv)
        if node.type == "enhanced_for_statement":
            self.bind_enhanced_for(node, sf, be, bte, ctx)
        bound = self._loop_header_nodes(node)
        for c in node.named_children:
            if c in bound:
                continue
            if c.type == "parenthesized_expression":
                self.taint_of(c, sf, be, bte, ctx)
            elif c.type not in _COMMENTS:
                # As in handle_if: a braceless loop body is the bare statement.
                r = self.process_any(c, sf, be, bte, ctx)
                ret = _merge_taint(ret, r)
        _merge_env(env, be)
        _merge_tenv(tenv, bte)
        return ret

    @staticmethod
    def _loop_header_nodes(node: Node) -> set:
        """Children of a for/foreach that belong to its header, not its body.

        `for (int i = 0; i < n; i++) body;` keeps the init, condition and
        update as siblings of the body, and a foreach keeps its element type,
        name and iterable the same way. Processing those as statements would
        both double-count them and, for a foreach, overwrite the element
        binding that `bind_enhanced_for` just made.
        """
        header = set()
        fields = (("type", "name", "value")
                  if node.type == "enhanced_for_statement"
                  else ("init", "condition", "update"))
        for field in fields:
            child = node.child_by_field_name(field)
            if child is not None:
                header.add(child)
        return header

    def bind_enhanced_for(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        named = node.named_children
        if len(named) < 3:
            return
        # enhanced_for_statement: type, name, iterable, body
        typ = ja._base_type(named[0]) if named[0].type in ("type_identifier", "generic_type") else None
        varname = ja.text(named[1]) if named[1].type == "identifier" else None
        iterable = named[2]
        if varname:
            if typ:
                tenv[varname] = typ
            it = self.taint_of(iterable, sf, env, tenv, ctx)
            if it is not None:
                env[varname] = it

    def handle_try(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        ret = None
        branch_envs = []
        for c in node.named_children:
            if c.type in ("block", "catch_clause", "finally_clause"):
                be, bte = dict(env), dict(tenv)
                r = self.process_any(c, sf, be, bte, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append((be, bte))
        for be, bte in branch_envs:
            _merge_env(env, be)
            _merge_tenv(tenv, bte)
        return ret

    # ------------------------------------------------------------------
    def taint_of(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        if node is None:
            return None
        t = node.type
        if t == "identifier":
            return env.get(ja.text(node))
        if t in ("string_literal", "character_literal", "decimal_integer_literal",
                 "hex_integer_literal", "floating_point_literal", "null_literal",
                 "true", "false", "boolean_literal"):
            return None
        if t == "binary_expression":
            return self.binary_taint(node, sf, env, tenv, ctx)
        if t == "method_invocation":
            return self.method_invocation_taint(node, sf, env, tenv, ctx)
        if t == "object_creation_expression":
            self.check_constructor_sink(node, sf, env, tenv, ctx)
            # A constructor wraps its arguments rather than cleansing them:
            # `new String(bytes)`, `new StringBuilder(s)`, `new File(path)`,
            # `new URL(u)` all carry the value straight through. Returning
            # nothing here ended the trace at any such wrapper, so a value that
            # merely round-tripped through Base64 and back into a String looked
            # as though it had been sanitized.
            lists = [c for c in node.named_children if c.type == "argument_list"]
            merged = None
            for a in (lists[0].named_children if lists else []):
                tt = self.taint_of(a, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        if t == "field_access":
            return env.get(ja.text(node))
        if t == "array_access":
            nc = node.named_children
            return self.taint_of(nc[0], sf, env, tenv, ctx) if nc else None
        if t == "parenthesized_expression":
            nc = node.named_children
            return self.taint_of(nc[0], sf, env, tenv, ctx) if nc else None
        if t == "ternary_expression":
            cond = node.child_by_field_name("condition")
            verdict = const_eval(cond, tenv, 0, self.properties)
            if verdict in (True, False):
                # Same reasoning as handle_if: only the live arm contributes.
                self.taint_of(cond, sf, env, tenv, ctx)
                arm = node.child_by_field_name(
                    "consequence" if verdict is True else "alternative")
                return self.taint_of(arm, sf, env, tenv, ctx)
            merged = None
            kids = node.named_children
            if kids:
                # Evaluated for its sinks; a condition is not the value.
                self.taint_of(kids[0], sf, env, tenv, ctx)
            for c in kids[1:]:
                tt = self.taint_of(c, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        if t == "cast_expression":
            return self.cast_taint(node, sf, env, tenv, ctx)
        if t == "assignment_expression":
            nc = node.named_children
            return self.taint_of(nc[-1], sf, env, tenv, ctx) if nc else None
        if t in ("array_creation_expression", "array_initializer"):
            # `new String[]{x}` and the bare `{x}` of `String[] a = {x};` are
            # different nodes; missing the second dropped taint on a very
            # common shape.
            merged = None
            for c in node.named_children:
                tt = self.taint_of(c, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged

        # Anything else composite: carry the taint of whatever it contains.
        # Returning None here instead meant every unmodelled expression
        # silently terminated a trace, which is the dominant cause of false
        # negatives — a missed sink is far more costly than an over-tainted
        # intermediate value, which still has to reach a sink to be reported.
        if node.named_children and t not in _OPAQUE:
            merged = None
            for c in node.named_children:
                if c.type in ("comment", "line_comment", "block_comment"):
                    continue
                tt = self.taint_of(c, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        return None

    def binary_taint(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        op = ""
        for c in node.children:
            if not c.is_named and c.text and c.text.strip():
                op = c.text.decode("utf-8", "replace").strip()
                break
        if op != "+":
            return None
        # Only treat '+' as string concatenation when at least one side is a
        # string literal or a String-typed variable.
        is_str = False
        for c in node.named_children:
            if c.type == "string_literal":
                is_str = True
            elif c.type == "identifier" and tenv.get(ja.text(c)) == "String":
                is_str = True
        if not is_str:
            return None
        merged = None
        for c in node.named_children:
            tt = self.taint_of(c, sf, env, tenv, ctx)
            if tt is not None:
                merged = tt if merged is None else merged.merge(tt)
        return merged

    def cast_taint(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        numeric = False
        for c in node.named_children:
            if c.type in ("integral_type", "floating_point_type"):
                numeric = True
        nc = [c for c in node.named_children if c.type not in
              ("integral_type", "floating_point_type", "type_identifier",
               "generic_type", "scoped_type_identifier")]
        t = self.taint_of(nc[0], sf, env, tenv, ctx) if nc else None
        if t is None:
            return None
        if numeric:
            return Taint(tags=t.tags - {"sql", "cmd", "xss", "ssrf", "lfi", "xxe", "ldap"},
                         origins=list(t.origins), steps=list(t.steps))
        return t

    # ------------------------------------------------------------------
    def method_invocation_taint(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        obj, mname, args = ja.mi_parts(node)
        # Evaluate receiver for embedded sinks.
        if obj is not None:
            self.taint_of(obj, sf, env, tenv, ctx)

        # Sink before source: a call can be both (reading a file with an
        # attacker-controlled path is an SSRF/traversal sink *and* returns
        # attacker-influenced data). Returning the source taint first would
        # silently drop the sink.
        self.check_algorithm(mname, obj, args, node, sf, tenv)
        san = self.match_sanitizer(mname)
        if san is None:
            self.check_method_sink(mname, obj, args, node, sf, env, tenv, ctx)

        st = self.source_taint(mname, obj, args, node, sf, env, tenv, ctx)
        if st is not None:
            return st

        if san is not None:
            return self.sanitized_taint(san, args, sf, env, tenv, ctx)

        ut = self.user_method_taint(obj, mname, args, node, sf, env, tenv, ctx)
        if ut is not None:
            return ut

        # Lambda arguments (stream/forEach/map/...): bind the lambda parameter
        # to the receiver's taint and analyse its body, so a sink reached only
        # inside the lambda is still found.
        if obj is not None and ctx.depth < MAX_DEPTH:
            lam = next((a for a in args if a.type == "lambda_expression"), None)
            if lam is not None:
                recv = self.taint_of(obj, sf, env, tenv, ctx)
                if recv is not None:
                    lt = self._invoke_lambda(lam, recv, node, sf, env, tenv, ctx)
                    if lt is not None:
                        return lt

        # Mutating writes: the container/builder itself becomes tainted.
        if mname in MUTATING_WRITES:
            merged = None
            for a in args:
                tt = self.taint_of(a, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            root = self._root_receiver(obj)
            if root and merged is not None:
                self._assign(root, merged, sf, env, node)
            return merged

        if mname == "format" and obj is not None and ja.text(obj) == "String":
            merged = None
            for a in args:
                tt = self.taint_of(a, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged

        # Static decoders: Base64.getDecoder().decode(x), URLDecoder.decode(x).
        if mname in ARG_PROPAGATORS:
            merged = None
            for a in args:
                tt = self.taint_of(a, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            if merged is not None:
                return merged

        # Anything read off a tainted receiver stays tainted: DTO getters
        # (@RequestBody), collection reads, String transforms and decoders all
        # fall out of this one rule. Predicates returning a size or a boolean
        # carry no attacker bytes, so they are excluded.
        if obj is not None and mname not in NON_PROPAGATING:
            recv = self.taint_of(obj, sf, env, tenv, ctx)
            if recv is not None:
                return recv

        # A call this analysis could not resolve — a helper in a class that was
        # not scanned, or a method reached through an interface whose concrete
        # type is unknown — still returns something derived from its arguments.
        # Dropping the taint here made every flow through such a helper
        # invisible, which is the single largest source of false negatives.
        # Sanitizers are matched earlier, so an escaping helper is unaffected.
        if mname not in NON_PROPAGATING:
            merged = None
            for a in args:
                tt = self.taint_of(a, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            if merged is not None:
                return merged

        return None

    def _invoke_lambda(self, lam: Node, recv, node, sf, env, tenv, ctx):
        """Analyse a lambda body with its parameters bound to `recv` taint."""
        params = []
        body = None
        for c in lam.named_children:
            if c.type == "identifier" and body is None:
                params.append(ja.text(c))
            elif c.type in ("inferred_parameters", "formal_parameters"):
                for p in c.named_children:
                    if p.type == "identifier":
                        params.append(ja.text(p))
                    else:
                        nm = p.child_by_field_name("name")
                        if nm is not None:
                            params.append(ja.text(nm))
            else:
                body = c

        new_env = dict(env)
        for p in params:
            new_env[p] = recv.with_step(TaintStep(
                location=make_loc(sf, node),
                description=f"element flows into lambda parameter {p}",
                code=sf.node_line(node),
            ))
        if body is None:
            return None
        sub = Ctx(depth=ctx.depth + 1, current_class=ctx.current_class)
        if body.type == "block":
            return self.process_block(body, sf, new_env, dict(tenv), sub)
        return self.taint_of(body, sf, new_env, dict(tenv), sub)

    def source_taint(self, mname, obj, args, node, sf, env, tenv, ctx):
        for src in self.rules.sources:
            if src.kind != "method":
                continue
            if not match_callee(mname, src.match):
                continue
            if src.obj_hint:
                rkey = self._receiver_key(obj, tenv)
                full = ja.text(node).lower()
                if src.obj_hint.lower() not in rkey and src.obj_hint.lower() not in full:
                    continue
            if not src.arg_allows([ja.text(a) for a in (args or [])]):
                continue
            return Taint(
                tags=set(src.tags),
                origins=[make_loc(sf, node)],
                steps=[TaintStep(
                    location=make_loc(sf, node),
                    description=src.description,
                    code=sf.node_line(node),
                )],
                # A source's own confidence was being dropped here, so a
                # second-order or merely-influenced source reported as though
                # it were direct request input.
                confidence=src.confidence,
            )
        return None

    def match_sanitizer(self, mname):
        for san in self.rules.sanitizers:
            if san.kind == "method" and match_callee(mname, san.match):
                return san
        return None

    def sanitized_taint(self, san, args, sf, env, tenv, ctx):
        if san.arg_index < 0 or san.arg_index >= len(args):
            return None
        t = self.taint_of(args[san.arg_index], sf, env, tenv, ctx)
        if t is None:
            return None
        if "*" in san.neutralize:
            return None
        remaining = t.tags - set(san.neutralize)
        if not remaining:
            return None
        return Taint(tags=remaining, origins=list(t.origins), steps=list(t.steps))

    def _receiver_key(self, obj, tenv):
        """Return a string for obj_hint matching: identifier names + their
        inferred types, so e.g. a receiver typed HttpServletResponse matches
        an obj_hint of 'response' regardless of the variable's name."""
        if obj is None:
            return ""
        parts = []

        def visit(n):
            if n.type == "identifier":
                parts.append(ja.text(n))
                typ = tenv.get(ja.text(n))
                if typ:
                    parts.append(typ)
            for c in n.named_children:
                visit(c)

        visit(obj)
        return " ".join(parts).lower()

    def check_method_sink(self, mname, obj, args, node, sf, env, tenv, ctx):
        rkey = self._receiver_key(obj, tenv).lower()
        full = ja.text(node).lower()
        for sink in self.rules.sinks:
            if sink.kind != "method":
                continue
            if not match_callee(mname, sink.match):
                continue
            if sink.obj_hint and sink.obj_hint.lower() not in rkey and sink.obj_hint.lower() not in full:
                continue
            if sink.type_arg and not _declares_type_arg(node, sink.type_arg):
                continue
            indices = range(len(args)) if sink.arg_index < 0 else [sink.arg_index]
            for i in indices:
                if i >= len(args):
                    continue
                t = self.taint_of(args[i], sf, env, tenv, ctx)
                if t is not None and (t.tags & set(sink.tags)):
                    self.emit_finding(sink, t, node, sf)
                    break

    def check_constructor_sink(self, node, sf, env, tenv, ctx):
        cls = None
        for c in node.named_children:
            if c.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                cls = ja._base_type(c)
                break
        args = [c for c in node.named_children if c.type == "argument_list"]
        args = list(args[0].named_children) if args else []
        for sink in self.rules.sinks:
            if sink.kind != "object_create":
                continue
            if not match_callee(cls, sink.match):
                continue
            if sink.type_arg and not _declares_type_arg(node, sink.type_arg):
                continue
            indices = range(len(args)) if sink.arg_index < 0 else [sink.arg_index]
            for i, a in ((i, args[i]) for i in indices if i < len(args)):
                t = self.taint_of(a, sf, env, tenv, ctx)
                if t is not None and (t.tags & set(sink.tags)):
                    self.emit_finding(sink, t, node, sf)
                    break

    def _root_receiver(self, obj):
        """Walk a chained receiver down to its base identifier variable name."""
        while obj is not None and obj.type == "method_invocation":
            obj, _, _ = ja.mi_parts(obj)
        if obj is not None and obj.type == "identifier":
            return ja.text(obj)
        return None

    def _resolve_receiver_class(self, obj, tenv, ctx):
        if obj is None:
            return ctx.current_class
        # tree-sitter-java gives `this` and `super` node types of their own,
        # so the identifier branch below never saw them and every
        # `this.helper(x)` call went unresolved. lookup_method walks up to
        # the parent class, which covers `super.m()` too.
        if obj.type in ("this", "super"):
            return ctx.current_class
        if obj.type == "identifier":
            name = ja.text(obj)
            if name == "this":
                return ctx.current_class
            if name in self.symbols.classes:
                return name  # static call Class.method()
            typ = tenv.get(name)
            if typ and typ in self.symbols.classes:
                return typ
        return None

    def user_method_taint(self, obj, mname, args, node, sf, env, tenv, ctx):
        if ctx.depth >= MAX_DEPTH:
            return None
        target_class = self._resolve_receiver_class(obj, tenv, ctx)
        if target_class is None:
            return None
        m = self.symbols.lookup_method(target_class, mname)
        if m is None:
            return None
        new_env, new_tenv = {}, {}
        sig = []
        for i, (pname, ptype, _tainted) in enumerate(m.params):
            if ptype:
                new_tenv[pname] = ptype
            if i < len(args):
                t = self.taint_of(args[i], sf, env, tenv, ctx)
                if t is not None:
                    new_env[pname] = t.with_step(TaintStep(
                        location=make_loc(sf, node),
                        description=f"argument flows into parameter {pname} of {m.name}()",
                        code=sf.node_line(node),
                    ))
                    sig.append((i, _taint_key(t)))
        key = (id(m.node), ctx.depth, tuple(sig))
        if key in self._call_memo:
            return self._call_memo[key]
        body = self._method_body(m.node)
        if body is None:
            result = None
        else:
            result = self.process_block(body, m.source, new_env, new_tenv,
                                        Ctx(depth=ctx.depth + 1, current_class=m.class_name))
        self._call_memo[key] = result
        return result

    def check_algorithm(self, mname, obj, args, node, sf, tenv) -> None:
        """Report a weak algorithm whose name is only known after folding.

        `MessageDigest.getInstance("MD5")` is caught by a pattern rule reading
        the source text. `MessageDigest.getInstance(props.getProperty(
        "hashAlg1"))` is not, and no amount of taint tracking helps: the
        question is what the algorithm *is*, not where it came from. Folding
        the argument — through locals, string methods and the repository's own
        .properties files — answers it.
        """
        if mname != "getInstance" or not args:
            return
        family = _ALGORITHM_FAMILIES.get(self._algorithm_family(obj, node))
        if family is None:
            return
        value = const_eval(args[0], tenv, 0, self.properties)
        if not isinstance(value, str):
            return
        rule_id, pattern, title, severity, cwe, description = family
        if not pattern.match(value.strip()):
            return
        loc = make_loc(sf, node)
        # Keyed without the column, to match the pattern rules' key shape: a
        # weak algorithm named literally in the source and the same one
        # resolved through a config lookup are one finding at one line, and
        # the two paths must be able to collide.
        key = (rule_id, sf.path, loc.line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=Severity(severity),
            cwe=cwe, owasp="A02:2021 — Cryptographic Failures",
            category="weak-crypto",
            description=f"{description} The algorithm resolves to "
                        f"'{value.strip()}'.",
            remediation="Use SHA-256 or better for hashing, and "
                        "AES/GCM/NoPadding for encryption. Change the "
                        "configured value as well as the call site.",
            confidence="high", framework=self.framework,
            language=self.language, location=loc, source=None,
            trace=[TaintStep(location=loc, description=title,
                             code=sf.node_line(node))],
            tags=["weak-crypto"],
        ))

    @staticmethod
    def _algorithm_family(obj, node) -> str:
        """Which getInstance this is: MessageDigest, Cipher, or neither."""
        text = (ja.text(obj) if obj is not None else ja.text(node)).lower()
        for family in ("messagedigest", "cipher", "keygenerator",
                       "secretkeyfactory", "signature", "mac"):
            if family in text:
                return family
        return ""

    def emit_finding(self, sink, taint, node, sf):
        loc = make_loc(sf, node)
        source = taint.origins[0] if taint.origins else None
        # One finding per rule and location. The source used to be part of
        # this key, so a sink reached from several sources was reported once
        # per source — the same line appearing eight times in OpenDoor's
        # report. A reviewer fixes the sink once, and the trace still shows a
        # representative path, so the extra copies were pure noise.
        key = (sink.rule_id, sf.path, loc.line, loc.column)
        if key in self._seen:
            return
        self._seen.add(key)
        trace = list(taint.steps[-MAX_STEPS:])
        trace.append(TaintStep(location=loc, description=sink.title, code=sf.node_line(node)))
        self.findings.append(Finding(
            rule_id=sink.rule_id, title=sink.title, severity=Severity(sink.severity),
            cwe=sink.cwe, owasp=sink.owasp, category=sink.category,
            description=sink.description, remediation=sink.remediation,
            confidence=sink.confidence, framework=self.framework, language=self.language,
            location=loc, source=source, trace=trace,
            tags=list(taint.tags & set(sink.tags)),
        ))

    # ------------------------------------------------------------------
    def _absent_ok(self, rule, sf: SourceFile) -> bool:
        """True unless the rule's `absent` regex appears in the file."""
        if not getattr(rule, "absent", None):
            return True
        import re as _re
        cache = getattr(self, "_absent_cache", None)
        if cache is None:
            cache = self._absent_cache = {}
        key = (id(sf), rule.absent)
        if key not in cache:
            text = sf.content.decode("utf-8", "replace")
            cache[key] = _re.search(rule.absent, text) is None
        return cache[key]

    def run_patterns(self, sf: SourceFile) -> None:
        if not self.rules.patterns:
            return
        for node in sf.walk():
            for rule in self.rules.patterns:
                if rule.node_type != "*" and node.type != rule.node_type:
                    continue
                if not self._absent_ok(rule, sf):
                    continue
                value = ja.text(node) if rule.match_field == "text" else None
                if value is None:
                    continue
                if rule.regex:
                    m = rule.compiled().search(value)
                    if not m:
                        continue
                    idx = m.start()
                else:
                    idx = value.find(rule.match)
                    if idx < 0:
                        continue
                loc = pattern_loc(node, sf, idx)
                # Dedup by rule + line: '*' text patterns match ancestor nodes.
                key = (rule.rule_id, sf.path, loc.line)
                if key in self._seen:
                    continue
                self._seen.add(key)
                self.findings.append(Finding(
                    rule_id=rule.rule_id, title=rule.title,
                    severity=Severity(rule.severity), cwe=rule.cwe, owasp=rule.owasp,
                    category=rule.category, description=rule.description,
                    remediation=rule.remediation, confidence=rule.confidence,
                    framework=self.framework, language=self.language, location=loc,
                    source=None,
                    trace=[TaintStep(location=loc, description=rule.title, code=loc.code)],
                    tags=[rule.category],
                ))


def _merge_env(env: dict, other: dict) -> None:
    for k, t in other.items():
        if k in env:
            env[k] = env[k].merge(t)
        else:
            env[k] = t


def _merge_tenv(tenv: dict, other: dict) -> None:
    """Join a conditional branch's type/constant environment into the outer one.

    `other` started as a copy of `tenv`, so the two differ only where the
    branch changed something. A declared type is the same on every path, so
    first-one-wins is right for types.

    A constant is different: it survives a join only if it holds on *every*
    incoming path. The branch may not have run at all, so a value the branch
    introduced says nothing after the join, and one it changed or discarded
    says nothing either. Each of those cases has to drop the constant, or
    folding would prune a live branch and hide a real flow.
    """
    for k, v in other.items():
        if not k.startswith(_CONST_PREFIX):
            tenv.setdefault(k, v)
        elif k not in tenv:
            continue            # introduced by the branch: unknown on the other path
        elif tenv[k] != v:
            tenv.pop(k, None)   # changed by the branch: no single value holds
    for k in [k for k in tenv if k.startswith(_CONST_PREFIX) and k not in other]:
        tenv.pop(k, None)       # discarded by the branch


def _first_type_arg(text: str):
    """The outermost generic argument of `X<A<B>, C>`: `A<B>`. None for <>."""
    i = text.find("<")
    if i < 0:
        return None
    depth, buf = 0, []
    for ch in text[i:]:
        if ch == "<":
            depth += 1
            if depth == 1:
                continue
        elif ch == ">":
            depth -= 1
            if depth == 0:
                break
        elif ch == "," and depth == 1:
            break
        buf.append(ch)
    arg = "".join(buf).strip()
    return arg or None


def _declares_type_arg(node, wanted: str) -> bool:
    """Whether a generic construction or builder call is typed `<wanted>`.

    `new ResponseEntity<String>(...)` states it; `new ResponseEntity<>(...)`
    and `ResponseEntity.ok(...)` take it from the enclosing method's
    declared return type. Only the outermost argument counts:
    `ResponseEntity<Bean<String>>` is a bean, whatever it holds.
    """
    if node.type == "object_creation_expression":
        for c in node.named_children:
            if c.type == "generic_type":
                arg = _first_type_arg(ja.text(c))
                if arg is not None:
                    return arg == wanted
    parent = node.parent
    while parent is not None and parent.type not in (
            "method_declaration", "lambda_expression", "class_body"):
        parent = parent.parent
    if parent is None or parent.type != "method_declaration":
        return False
    rtype = parent.child_by_field_name("type")
    return rtype is not None and _first_type_arg(ja.text(rtype)) == wanted
