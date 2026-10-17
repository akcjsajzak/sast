"""Source-to-sink taint analysis engine for PHP."""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node

from ..models import Finding, Location, Severity, TaintStep
from ..parsing.source import SourceFile
from ..rules.base import RuleSet, SinkRule, SanitizerRule, TaintSource
from . import ast_utils as au
from .symbols import SymbolTable, file_namespace

MAX_DEPTH = 8
MAX_STEPS = 15

# Built-in functions that forward taint from their arguments to their result.
# Anything missing here silently terminates a trace, so this errs on the side
# of being generous: a transform that preserves attacker-controlled bytes in
# any form belongs in this set.
PROPAGATORS = frozenset({
    # Whitespace / case / slicing
    "trim", "ltrim", "rtrim", "substr", "strtolower", "strtoupper",
    "ucfirst", "ucwords", "lcfirst", "mb_strtolower", "mb_strtoupper",
    "mb_substr", "substr_replace", "strrev", "str_pad", "wordwrap", "nl2br",
    "chunk_split", "strtr", "stripslashes", "stripcslashes",
    # Formatting / joining
    "sprintf", "vsprintf", "implode", "join", "strval", "strip_tags",
    # Replacement
    "str_replace", "str_ireplace", "preg_replace", "preg_replace_callback",
    "preg_filter",
    # Splitting — the element is as tainted as the whole
    "explode", "preg_split", "str_split", "mb_str_split", "str_word_count",
    # Decoding: the decoded value is still attacker-controlled. Omitting
    # these is how `json_decode($_POST['x'])` used to lose its taint.
    "json_decode", "base64_decode", "urldecode", "rawurldecode",
    "html_entity_decode", "htmlspecialchars_decode", "unserialize",
    "hex2bin", "bin2hex", "quoted_printable_decode", "convert_uudecode",
    "gzinflate", "gzuncompress", "gzdecode", "utf8_decode", "utf8_encode",
    "mb_convert_encoding", "iconv", "unpack",
    # Array transforms that carry element taint through
    "array_map", "array_filter", "array_merge", "array_values", "array_keys",
    "array_slice", "array_splice", "array_reverse", "array_unique",
    "array_combine", "array_flip", "array_column", "array_pop",
    "array_shift", "current", "reset", "end", "next", "prev", "compact",
    "iterator_to_array",
    # filter_var only sanitizes when a filter is supplied; the single-argument
    # form is a no-op, so taint has to keep flowing through it.
    "filter_var",
})

# Numeric cast types neutralize string-based injection.
_NUMERIC_CASTS = {"int", "integer", "float", "double", "real", "bool", "boolean"}
_NUMERIC_NEUTRALIZE = ["sql", "cmd", "xss", "ssrf", "lfi", "xxe", "ldap", "redirect", "path"]

# Guard functions that prove a value is numeric on the guarded branch.
_NUMERIC_GUARDS = {
    "is_numeric", "ctype_digit", "is_int", "is_integer", "is_long",
    "is_float", "is_double", "is_bool",
}

_SKIP_TOP = {
    "php_tag", "inline_html", "comment", "namespace_definition",
    "use_declaration", "class_declaration", "interface_declaration",
    "trait_declaration", "enum_declaration", "function_definition",
    "const_declaration", "declare_statement",
}


def _short(name: str) -> str:
    """Last component of a qualified name.

    Qualifiers differ by language — PHP uses ``\\``, Java/C#/Python use ``.``
    and Go uses ``/`` — and a rule is written against the bare name. Splitting
    on only one of them meant a fully-qualified reference such as
    ``java.io.FileInputStream`` matched no rule at all, which is how every
    fully-qualified sink in OWASP Benchmark went undetected.
    """
    if not name:
        return ""
    for sep in ("\\", "/", "."):
        if sep in name:
            name = name.rsplit(sep, 1)[-1]
    return name


def match_callee(actual, wanted) -> bool:
    if not actual or not wanted:
        return False
    return actual == wanted or _short(actual) == wanted


def make_loc(sf: SourceFile, node: Node) -> Location:
    return Location(
        file=sf.path,
        line=node.start_point.row + 1,
        column=node.start_point.column + 1,
        end_line=node.end_point.row + 1,
        end_column=node.end_point.column + 1,
        code=sf.node_line(node),
    )


# Confidence lattice: lower index == more certain.
_CONFIDENCE = ("high", "medium", "low")


def _conf_rank(c: str) -> int:
    try:
        return _CONFIDENCE.index(c)
    except ValueError:
        return 0


def strongest_confidence(a: str, b: str) -> str:
    """The more certain of two confidences (used when taints merge)."""
    return a if _conf_rank(a) <= _conf_rank(b) else b


def weakest_confidence(a: str, b: str) -> str:
    """The less certain of two confidences (used when reporting a finding)."""
    return a if _conf_rank(a) >= _conf_rank(b) else b


@dataclass
class Taint:
    tags: set = field(default_factory=set)
    origins: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    confidence: str = "high"

    def merge(self, other: "Taint") -> "Taint":
        if other is None:
            return self
        tags = self.tags | other.tags
        origins = self.origins + other.origins
        steps = self.steps + other.steps
        # If any contributing value is certainly attacker-controlled, the
        # combined value is too.
        return Taint(tags=tags, origins=_dedup(origins), steps=_dedup(steps),
                     confidence=strongest_confidence(self.confidence, other.confidence))

    def with_step(self, step: TaintStep) -> "Taint":
        return Taint(
            tags=set(self.tags),
            origins=list(self.origins),
            steps=self.steps + [step],
            confidence=self.confidence,
        )


def _taint_key(t: "Taint"):
    """Hashable fingerprint of a taint's abstract value (tags + origins).

    Origins are included so that the same method called with two different
    sources (e.g. ``$_GET`` vs ``$_POST``) is not memoized into a single
    finding — both produce distinct findings.
    """
    origins = tuple(sorted((o.file, o.line, o.column) for o in t.origins))
    return (frozenset(t.tags), origins, t.confidence)


# Side-channel env keys. PHP variable names cannot contain NUL, so these
# never collide with a real variable. They let the engine remember facts that
# are not taint: the literal string a variable holds (for dynamic calls), the
# class a variable was constructed from (to resolve $obj->method()), and the
# closure a variable refers to.
_LIT = "\0lit:"
_TYPE = "\0type:"
_FN = "\0fn:"
_RESERVED = (_LIT, _TYPE, _FN)


def _is_reserved(key: str) -> bool:
    return isinstance(key, str) and key.startswith("\0")


# Sentinel distinguishing "could not resolve this call" from "resolved, no
# taint" — the latter must not fall through to the normal call handling.
_UNRESOLVED = object()

# Builtins taking a callable: name -> (callable arg index, first forwarded arg).
_CALLABLE_TAKERS = {
    "call_user_func": (0, 1),
    "call_user_func_array": (0, 1),
    "array_map": (0, 1),
    "array_filter": (1, 0),
    "array_walk": (1, 0),
    "array_reduce": (1, 0),
    "usort": (1, 0),
    "uasort": (1, 0),
    "uksort": (1, 0),
    "iterator_apply": (1, 0),
    "register_shutdown_function": (0, 1),
    "forward_static_call": (0, 1),
    "forward_static_call_array": (0, 1),
}


def _closure_params(closure: Node) -> list:
    """Parameter names of an anonymous/arrow function node."""
    names = []
    for c in closure.named_children:
        if c.type != "formal_parameters":
            continue
        for p in c.named_children:
            for pc in p.named_children:
                if pc.type == "variable_name":
                    names.append(au.var_name(pc))
                    break
    return names


def _is_property_key(key: str) -> bool:
    """True for env keys naming an object or static property ($this->p, C::$s)."""
    if _is_reserved(key):
        return False
    return key.startswith("$this->") or key.startswith("self::") or "::$" in key


def _dedup(items: list):
    seen = set()
    out = []
    for it in items:
        key = getattr(it, "location", None)
        key = (key.file, key.line, key.column) if key is not None else repr(it)
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


@dataclass
class Ctx:
    depth: int = 0
    current_class: str = None
    namespace: str = ""


class TaintEngine:
    """Performs taint analysis over a set of PHP source files."""

    def __init__(self, symbols: SymbolTable, rules: RuleSet,
                 framework: str, language: str) -> None:
        self.symbols = symbols
        self.rules = rules
        self.framework = framework
        self.language = language
        self.findings: list[Finding] = []
        self._seen: set = set()
        self._call_memo: dict = {}
        # Taint reaching module-level variables, so `global $g` can see it.
        self._globals: dict = {}

    # ------------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------------
    def analyze(self, files: list[SourceFile]) -> list[Finding]:
        for sf in files:
            self.analyze_top_level(sf)
        for fsym in self.symbols.functions.values():
            body = au.body_of(fsym.node)
            if body is not None:
                self.process_block(body, fsym.source, {}, Ctx(namespace=fsym.namespace))
        for cls in self.symbols.classes.values():
            self.analyze_class(cls)
        for sf in files:
            self.run_patterns(sf)
        return self.findings

    def analyze_class(self, cls) -> None:
        """Analyse a class's methods, carrying property taint between them.

        Methods are visited twice: the first pass records what each one stores
        into `$this->...` or a static property, the second re-runs them with
        those properties already tainted. That catches the common shape of a
        setter (or constructor) storing request data that a later method sinks,
        without needing a full call graph. Duplicate findings from the two
        passes are collapsed by the usual `_seen` de-duplication.
        """
        fields: dict = {}
        for _ in range(2):
            for msym in cls.methods.values():
                body = au.body_of(msym.node)
                if body is None:
                    continue
                env = dict(fields)
                self.process_block(body, msym.source, env,
                                   Ctx(current_class=cls.name, namespace=msym.namespace))
                for key, val in env.items():
                    if _is_property_key(key):
                        fields[key] = val if key not in fields else fields[key].merge(val)

    def analyze_top_level(self, sf: SourceFile) -> None:
        env: dict = {}
        ns = file_namespace(sf)
        for child in sf.root.named_children:
            if child.type in _SKIP_TOP:
                continue
            if child.type == "expression_statement":
                inner = child.named_children
                if inner:
                    self.process_stmt(inner[0], sf, env, Ctx(namespace=ns))
            else:
                self.process_stmt(child, sf, env, Ctx(namespace=ns))
        # Module-level variables are what `global $x` inside a function sees.
        _merge_env(self._globals, env)

    # ------------------------------------------------------------------
    # Statement handling
    # ------------------------------------------------------------------
    def process_block(self, body: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        for stmt in au.iter_statements(body):
            r = self.process_stmt(stmt, sf, env, ctx)
            if r is not None:
                ret = r if ret is None else ret.merge(r)
        return ret

    def process_any(self, body: Node, sf: SourceFile, env: dict, ctx: Ctx):
        if body is None:
            return None
        if body.type == "compound_statement":
            return self.process_block(body, sf, env, ctx)
        return self.process_stmt(body, sf, env, ctx)

    def process_stmt(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        t = stmt.type
        if t == "assignment_expression":
            self.handle_assignment(stmt, sf, env, ctx)
            return None
        if t == "augmented_assignment_expression":
            self.handle_augmented_assignment(stmt, sf, env, ctx)
            return None
        if t == "echo_statement":
            self.check_echo(stmt, sf, env, ctx)
            return None
        if t == "return_statement":
            nc = stmt.named_children
            if nc:
                return self.taint_of(nc[-1], sf, env, ctx)
            return None
        if t == "if_statement":
            return self.handle_if(stmt, sf, env, ctx)
        if t in ("while_statement", "do_while_statement", "for_statement", "foreach_statement"):
            return self.handle_loop(stmt, sf, env, ctx)
        if t == "switch_statement":
            return self.handle_switch(stmt, sf, env, ctx)
        if t == "try_statement":
            return self.handle_try(stmt, sf, env, ctx)
        if t in ("break_statement", "continue_statement", "throw_statement"):
            return None
        if t == "global_declaration":
            # `global $g;` pulls the module-level taint for $g into scope.
            for c in stmt.named_children:
                if c.type == "variable_name":
                    name = au.var_name(c)
                    gt = self._globals.get(name)
                    if gt is not None:
                        env[name] = gt
                    for prefix in _RESERVED:
                        if prefix + name in self._globals:
                            env[prefix + name] = self._globals[prefix + name]
            return None
        if t == "expression_statement":
            nc = stmt.named_children
            if nc:
                self.taint_of(nc[0], sf, env, ctx)
            return None
        # Fallback: evaluate expression for embedded sinks.
        self.taint_of(stmt, sf, env, ctx)
        return None

    def handle_assignment(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx) -> None:
        nc = node.named_children
        if len(nc) < 2:
            return
        lhs, rhs = nc[0], nc[-1]
        t = self.taint_of(rhs, sf, env, ctx)
        self.assign(lhs, t, sf, env)
        self._record_facts(lhs, rhs, env)

    def _record_facts(self, lhs: Node, rhs: Node, env: dict) -> None:
        """Remember non-taint facts about a variable: the literal string it
        holds, the class it was constructed from, or the closure it names.

        These make `$fn = 'system'; $fn($x)`, `$o = new C(); $o->m($x)` and
        `$f = function(...){...}; $f($x)` resolvable.
        """
        if lhs.type != "variable_name":
            return
        name = au.var_name(lhs)
        if not name:
            return
        for prefix in _RESERVED:
            env.pop(prefix + name, None)

        inner = au.strip_wrappers(rhs) if hasattr(au, "strip_wrappers") else rhs
        lit = au.literal_string(inner)
        if lit:
            env[_LIT + name] = lit
        elif inner.type == "object_creation_expression":
            for c in inner.named_children:
                if c.type in ("name", "qualified_name"):
                    env[_TYPE + name] = au.text(c)
                    break
        elif inner.type in ("anonymous_function", "arrow_function",
                            "anonymous_function_creation_expression"):
            env[_FN + name] = inner

    def assign(self, lhs: Node, t, sf: SourceFile, env: dict) -> None:
        if lhs.type == "variable_name":
            name = au.var_name(lhs)
            if not name:
                return
            if t is not None:
                env[name] = t.with_step(TaintStep(
                    location=make_loc(sf, lhs),
                    description=f"taint stored in {name}",
                    code=sf.node_line(lhs),
                ))
            else:
                env.pop(name, None)
        elif lhs.type == "subscript_expression":
            base = lhs.named_children[0] if lhs.named_children else None
            if base is not None and base.type == "variable_name" and t is not None:
                name = au.var_name(base)
                env[name] = t if name not in env else env[name].merge(t)
        elif lhs.type in ("member_access_expression",
                          "scoped_property_access_expression"):
            # $this->prop, $obj->prop, and C::$staticProp are all keyed by
            # their source text, so a later read of the same text matches.
            key = au.text(lhs)
            if t is not None:
                env[key] = t.with_step(TaintStep(
                    location=make_loc(sf, lhs),
                    description=f"taint stored in {key}",
                    code=sf.node_line(lhs),
                ))
            else:
                env.pop(key, None)

    def handle_augmented_assignment(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx) -> None:
        if ".=" not in au.text(node):
            return
        nc = node.named_children
        if len(nc) < 2:
            return
        lhs, rhs = nc[0], nc[-1]
        t = self.taint_of(rhs, sf, env, ctx)
        if t is None or lhs.type != "variable_name":
            return
        name = au.var_name(lhs)
        merged = t if name not in env else env[name].merge(t)
        env[name] = merged.with_step(TaintStep(
            location=make_loc(sf, lhs),
            description=f"taint concatenated into {name}",
            code=sf.node_line(lhs),
        ))

    def handle_if(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        branch_envs = []
        guard = None
        then_seen = False
        for c in node.named_children:
            if c.type == "parenthesized_expression":
                self.taint_of(c, sf, env, ctx)
                guard = self._guard_var(c)
            elif c.type == "compound_statement":
                be = dict(env)
                if guard is not None and not then_seen:
                    var, negated = guard
                    if not negated:
                        self._sanitize_var(be, var, _NUMERIC_NEUTRALIZE)
                r = self.process_block(c, sf, be, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append(be)
                then_seen = True
            elif c.type in ("else_if_clause", "elseif_clause"):
                be = dict(env)
                r = self.process_elseif(c, sf, be, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append(be)
            elif c.type == "else_clause":
                be = dict(env)
                if guard is not None:
                    var, negated = guard
                    if negated:
                        self._sanitize_var(be, var, _NUMERIC_NEUTRALIZE)
                r = self.process_else(c, sf, be, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append(be)
        for be in branch_envs:
            _merge_env(env, be)
        return ret

    def _guard_var(self, cond):
        """Return (var_name, negated) if `cond` is a numeric guard on a variable."""
        node = cond
        while node.type == "parenthesized_expression":
            nc = node.named_children
            if not nc:
                return None
            node = nc[0]
        negated = False
        if node.type == "unary_op_expression" and "!" in au.text(node):
            negated = True
            nc = [c for c in node.named_children if c.type != "name"]
            if not nc:
                return None
            node = nc[0]
        if node.type == "function_call_expression":
            name = au.call_callee(node)
            if name in _NUMERIC_GUARDS:
                args = au.argument_values(node)
                if len(args) == 1 and args[0].type == "variable_name":
                    return au.var_name(args[0]), negated
        return None

    def _sanitize_var(self, env: dict, var: str, tags: list) -> None:
        t = env.get(var)
        if t is None:
            return
        remaining = t.tags - set(tags)
        if remaining:
            env[var] = Taint(tags=remaining, origins=list(t.origins), steps=list(t.steps))
        else:
            env.pop(var, None)

    def process_elseif(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        for c in node.named_children:
            if c.type == "parenthesized_expression":
                self.taint_of(c, sf, env, ctx)
            else:
                r = self.process_any(c, sf, env, ctx)
                ret = _merge_taint(ret, r)
        return ret

    def process_else(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        for c in node.named_children:
            r = self.process_any(c, sf, env, ctx)
            ret = _merge_taint(ret, r)
        return ret

    def handle_loop(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        be = dict(env)
        if node.type == "foreach_statement":
            self.bind_foreach(node, sf, be, ctx)
        for c in node.named_children:
            if c.type == "compound_statement":
                r = self.process_block(c, sf, be, ctx)
                ret = _merge_taint(ret, r)
            elif c.type == "parenthesized_expression":
                self.taint_of(c, sf, be, ctx)
            elif c.type == "expression_statement":
                nc = c.named_children
                if nc:
                    self.taint_of(nc[0], sf, be, ctx)
        _merge_env(env, be)
        return ret

    def bind_foreach(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx) -> None:
        named = node.named_children
        if not named:
            return
        iterable = named[0]
        it = self.taint_of(iterable, sf, env, ctx)
        if it is None:
            return
        for c in named[1:]:
            # `foreach ($x as $k => $v)` — the value half carries the taint.
            if c.type == "pair":
                pc = c.named_children
                if pc and pc[-1].type == "variable_name":
                    env[au.var_name(pc[-1])] = it
                return
            # `foreach ($x as $v)` — a bare variable, by far the common form.
            if c.type == "variable_name":
                env[au.var_name(c)] = it
                return
            # `foreach ($x as [$a, $b])` / list(...) destructuring.
            if c.type in ("list_literal", "array_creation_expression"):
                for el in c.named_children:
                    target = el
                    if target.type == "array_element_initializer":
                        ec = target.named_children
                        target = ec[0] if ec else target
                    if target.type == "variable_name":
                        env[au.var_name(target)] = it
                return

    def handle_switch(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        branch_envs = []
        for c in node.named_children:
            if c.type == "parenthesized_expression":
                self.taint_of(c, sf, env, ctx)
            elif c.type == "switch_block":
                for cs in c.named_children:
                    if cs.type in ("case_statement", "default_statement"):
                        be = dict(env)
                        for st in cs.named_children:
                            r = self.process_stmt(st, sf, be, ctx)
                            ret = _merge_taint(ret, r)
                        branch_envs.append(be)
        for be in branch_envs:
            _merge_env(env, be)
        return ret

    def handle_try(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        branch_envs = []
        for c in node.named_children:
            if c.type == "compound_statement":
                be = dict(env)
                r = self.process_block(c, sf, be, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append(be)
            elif c.type in ("catch_clause", "finally_clause"):
                be = dict(env)
                for cc in c.named_children:
                    if cc.type == "compound_statement":
                        r = self.process_block(cc, sf, be, ctx)
                        ret = _merge_taint(ret, r)
                branch_envs.append(be)
        for be in branch_envs:
            _merge_env(env, be)
        return ret

    # ------------------------------------------------------------------
    # Expression taint evaluation
    # ------------------------------------------------------------------
    def taint_of(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        if node is None:
            return None
        t = node.type

        if t in ("string", "encapsed_string"):
            return self.string_taint(node, sf, env, ctx)
        if t == "variable_name":
            return self.variable_taint(node, sf, env, ctx)
        if t == "subscript_expression":
            return self.subscript_taint(node, sf, env, ctx)
        if t in ("member_access_expression", "scoped_property_access_expression"):
            return env.get(au.text(node))
        if t == "parenthesized_expression":
            nc = node.named_children
            return self.taint_of(nc[0], sf, env, ctx) if nc else None
        if t == "binary_expression":
            return self.binary_taint(node, sf, env, ctx)
        if t == "conditional_expression":
            merged = None
            for c in node.named_children[1:]:
                tt = self.taint_of(c, sf, env, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        if t == "cast_expression":
            return self.cast_taint(node, sf, env, ctx)
        if t in ("function_call_expression", "member_call_expression", "scoped_call_expression"):
            return self.call_taint(node, sf, env, ctx)
        if t == "object_creation_expression":
            self.check_object_creation(node, sf, env, ctx)
            return None
        if t in ("include_expression", "require_expression",
                 "include_once_expression", "require_once_expression"):
            self.check_include(node, sf, env, ctx)
            return None
        if t == "shell_command_expression":
            self.check_shell(node, sf, env, ctx)
            return None
        if t == "print_intrinsic":
            self.check_print(node, sf, env, ctx)
            return None
        if t == "array_creation_expression":
            merged = None
            for c in node.named_children:
                tt = self.taint_of(c, sf, env, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        if t == "array_element_initializer":
            merged = None
            for c in node.named_children:
                tt = self.taint_of(c, sf, env, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        if t == "list_literal":
            merged = None
            for c in node.named_children:
                tt = self.taint_of(c, sf, env, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        return None

    def variable_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        name = au.var_name(node)
        if name in env:
            return env[name]
        sg = au.superglobal(node)
        if sg:
            return self.source_taint("superglobal", sg, node, sf)
        return None

    def subscript_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        nc = node.named_children
        if not nc:
            return None
        base = nc[0]
        if base.type == "variable_name":
            sg = au.superglobal(base)
            if sg:
                # Literal subscript key, if any — lets rules model mixed
                # containers such as $_SERVER key by key.
                key = au.literal_string(nc[1]) if len(nc) > 1 else None
                return self.source_taint("superglobal", sg, node, sf, key=key)
            return env.get(au.var_name(base))
        return self.taint_of(base, sf, env, ctx)

    def string_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        if node.type == "string":
            return None
        # Interpolated string: propagate taint of embedded variables.
        merged = None
        for c in node.named_children:
            if c.type in ("variable_name", "string_interpolation", "member_access_expression"):
                tt = self.taint_of(c, sf, env, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
        return merged

    def binary_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        op = ""
        for c in node.children:
            if not c.is_named and c.text and c.text.strip():
                op = c.text.decode("utf-8", "replace").strip()
                break
        if op not in (".", "??"):
            return None
        merged = None
        for c in node.named_children:
            tt = self.taint_of(c, sf, env, ctx)
            if tt is not None:
                merged = tt if merged is None else merged.merge(tt)
        return merged

    def cast_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        # Determine cast type token.
        cast_type = ""
        for c in node.children:
            if not c.is_named and c.text:
                txt = c.text.decode("utf-8", "replace").strip()
                if txt and txt not in "()":
                    cast_type = txt.lower()
                    break
        inner = node.named_children
        t = self.taint_of(inner[0], sf, env, ctx) if inner else None
        if t is None:
            return None
        if cast_type in _NUMERIC_CASTS:
            return self._neutralize(t, _NUMERIC_NEUTRALIZE)
        return t

    # ------------------------------------------------------------------
    # Call handling
    # ------------------------------------------------------------------
    def call_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        kind = ("function" if node.type == "function_call_expression"
                else "method" if node.type == "member_call_expression"
                else "static")

        # Evaluate the receiver of a method call so sinks embedded in a
        # fluent chain (e.g. DB::table(...)->whereRaw($x)->get()) are found.
        if node.type == "member_call_expression":
            nc = node.named_children
            if nc:
                self.taint_of(nc[0], sf, env, ctx)

        callee = au.call_callee(node)
        cls = None
        if node.type == "scoped_call_expression":
            cls, callee = au.callee_parts(node)
        args = au.argument_values(node)

        if kind == "function" and not callee:
            # `$fn($x)` — resolve through a variable holding a function name
            # or a closure.
            resolved = self._resolve_dynamic_call(node, args, sf, env, ctx)
            if resolved is not _UNRESOLVED:
                return resolved
        elif kind == "method" and not ctx.current_class:
            # `$obj->m($x)` where $obj came from `new C()`.
            recv_cls = self._receiver_class(node, env)
            if recv_cls:
                msym = self.symbols.lookup_method(recv_cls, callee, ctx.namespace)
                if msym is not None and ctx.depth < MAX_DEPTH:
                    return self.analyze_method_call(msym, args, node, sf, env, ctx)

        # Builtins that take a callable: route the taint into the callee so
        # array_map('system', $_GET['a']) is seen as a call to system().
        if kind == "function" and callee in _CALLABLE_TAKERS:
            cb = self._callable_taint(callee, args, node, sf, env, ctx)
            if cb is not _UNRESOLVED:
                return cb

        # Sink check comes first: being a source is a fact about a call's
        # return value, being a sink is a fact about its arguments, and a call
        # can be both. file_get_contents($tainted) is an SSRF sink *and*
        # returns attacker-influenced data; checking the source first would
        # return early and silently lose the sink.
        san = self.match_sanitizer(kind, callee, cls, args)
        if san is None:
            self.check_call_sink(kind, callee, cls, args, node, sf, env, ctx)

        st = self.source_taint(kind, callee, node, sf, cls, args)
        if st is not None:
            return st

        if san is not None:
            return self.sanitized_taint(san, args, sf, env, ctx)

        ut = self.user_call_taint(kind, callee, cls, args, node, sf, env, ctx)
        if ut is not None:
            return ut

        if kind == "function" and callee in PROPAGATORS:
            return self._merge_args(args, sf, env, ctx)

        # A call this analysis could not resolve — a vendor helper, a framework
        # method, anything outside the scanned source — still returns something
        # derived from its arguments. Dropping the taint here made every flow
        # through such a helper invisible. Sanitizers are matched earlier, so
        # an escaping helper is unaffected.
        return self._merge_args(args, sf, env, ctx)

    def _receiver_class(self, node: Node, env: dict):
        """Class name of a method call's receiver, if it came from `new C()`."""
        nc = node.named_children
        if not nc or nc[0].type != "variable_name":
            return None
        name = au.var_name(nc[0])
        return env.get(_TYPE + name) if name else None

    def _resolve_dynamic_call(self, node: Node, args, sf, env, ctx):
        """Resolve `$fn(...)` to a named function or an inline closure."""
        nc = node.named_children
        if not nc or nc[0].type != "variable_name":
            return _UNRESOLVED
        name = au.var_name(nc[0])
        if not name:
            return _UNRESOLVED

        target = env.get(_LIT + name)
        if target:
            return self._dispatch_named(target, args, node, sf, env, ctx)

        closure = env.get(_FN + name)
        if closure is not None and ctx.depth < MAX_DEPTH:
            return self._invoke_closure(closure, args, node, sf, env, ctx)
        return _UNRESOLVED

    def _dispatch_named(self, callee: str, args, node, sf, env, ctx):
        """Treat `callee` as if it had been written literally at this call."""
        st = self.source_taint("function", callee, node, sf, None, args)
        if st is not None:
            return st
        san = self.match_sanitizer("function", callee, None, args)
        if san is not None:
            return self.sanitized_taint(san, args, sf, env, ctx)
        self.check_call_sink("function", callee, None, args, node, sf, env, ctx)
        ut = self.user_call_taint("function", callee, None, args, node, sf, env, ctx)
        if ut is not None:
            return ut
        if callee in PROPAGATORS:
            return self._merge_args(args, sf, env, ctx)
        return None

    def _invoke_closure(self, closure: Node, args, node, sf, env, ctx):
        """Analyse a closure body with the call's arguments bound to params."""
        params = au.param_names(closure) if hasattr(au, "param_names") else []
        if not params:
            params = _closure_params(closure)
        new_env = {}
        for i, p in enumerate(params):
            if i < len(args):
                t = self.taint_of(args[i], sf, env, ctx)
                if t is not None:
                    new_env[p] = t.with_step(TaintStep(
                        location=make_loc(sf, node),
                        description=f"argument flows into closure parameter {p}",
                        code=sf.node_line(node),
                    ))
        body = au.body_of(closure)
        sub = Ctx(depth=ctx.depth + 1, current_class=ctx.current_class,
                  namespace=ctx.namespace)
        if body is None:
            # Arrow function: the body is a bare expression.
            for c in closure.named_children:
                if c.type not in ("formal_parameters",):
                    return self.taint_of(c, sf, new_env, sub)
            return None
        return self.process_block(body, sf, new_env, sub)

    def _callable_taint(self, callee: str, args, node, sf, env, ctx):
        """Handle array_map/call_user_func style builtins.

        The callable argument is dispatched with the remaining arguments, so a
        sink reached only through a callback is still reported.
        """
        if not args:
            return _UNRESOLVED
        spec = _CALLABLE_TAKERS[callee]
        cb_index, arg_start = spec
        if len(args) <= cb_index:
            return _UNRESOLVED
        cb = au.strip_wrappers(args[cb_index]) if hasattr(au, "strip_wrappers") else args[cb_index]
        rest = list(args[arg_start:])

        target = au.literal_string(cb)
        if not target and cb.type == "variable_name":
            vname = au.var_name(cb)
            target = env.get(_LIT + vname) if vname else None
            if not target:
                closure = env.get(_FN + vname) if vname else None
                if closure is not None and ctx.depth < MAX_DEPTH:
                    return self._invoke_closure(closure, rest, node, sf, env, ctx)
        if not target and cb.type in ("anonymous_function", "arrow_function",
                                      "anonymous_function_creation_expression"):
            if ctx.depth < MAX_DEPTH:
                return self._invoke_closure(cb, rest, node, sf, env, ctx)
            return _UNRESOLVED
        if not target:
            return _UNRESOLVED
        return self._dispatch_named(target, rest, node, sf, env, ctx)

    def _merge_args(self, args, sf, env, ctx):
        merged = None
        for a in args:
            tt = self.taint_of(a, sf, env, ctx)
            if tt is not None:
                merged = tt if merged is None else merged.merge(tt)
        return merged

    def source_taint(self, kind, match, node, sf, cls=None, args=None, key=None):
        for src in self.rules.sources:
            if src.kind != kind:
                continue
            if not match_callee(match, src.match):
                continue
            if src.cls and not match_callee(cls, src.cls):
                continue
            if not src.key_matches(key):
                continue
            if src.arg_literal:
                idx, lit = src.arg_literal
                if not (args and len(args) > idx and au.literal_string(args[idx]) == lit):
                    continue
            return Taint(
                tags=set(src.tags),
                origins=[make_loc(sf, node)],
                steps=[TaintStep(
                    location=make_loc(sf, node),
                    description=src.description,
                    code=sf.node_line(node),
                )],
                confidence=src.confidence,
            )
        return None

    def match_sanitizer(self, kind, callee, cls, args=None):
        arg_texts = [au.text(a) for a in (args or [])]
        for san in self.rules.sanitizers:
            if san.kind != kind:
                continue
            if not match_callee(callee, san.match):
                continue
            if san.cls and not match_callee(cls, san.cls):
                continue
            # A rule whose preconditions are unmet does not sanitize; keep
            # looking, so a weaker fallback rule for the same function wins.
            if not san.args_satisfied(arg_texts):
                continue
            return san
        return None

    def sanitized_taint(self, san: SanitizerRule, args, sf, env, ctx):
        idx = san.arg_index
        if idx < 0 or idx >= len(args):
            return None
        t = self.taint_of(args[idx], sf, env, ctx)
        if t is None:
            return None
        if san.weak:
            # Escaping happened, but it is bypassable or context-dependent.
            # Keep the taint so the finding survives, at lower confidence.
            node = args[idx]
            step = TaintStep(
                location=make_loc(sf, node),
                description=san.note or f"weak sanitizer {san.match}() applied",
                code=sf.node_line(node),
            )
            return Taint(
                tags=set(t.tags), origins=list(t.origins),
                steps=t.steps + [step],
                confidence=weakest_confidence(t.confidence, "medium"),
            )
        if "*" in san.neutralize:
            return None
        return self._neutralize(t, san.neutralize)

    def _neutralize(self, t: Taint, tags: list) -> Taint:
        remaining = t.tags - set(tags)
        if not remaining:
            return None
        return Taint(tags=remaining, origins=list(t.origins), steps=list(t.steps),
                     confidence=t.confidence)

    def check_call_sink(self, kind, callee, cls, args, node, sf, env, ctx):
        for sink in self.rules.sinks:
            if sink.kind != kind:
                continue
            if not match_callee(callee, sink.match):
                continue
            if sink.cls and not match_callee(cls, sink.cls):
                continue
            indices = range(len(args)) if sink.arg_index < 0 else [sink.arg_index]
            for i in indices:
                if i >= len(args):
                    continue
                t = self.taint_of(args[i], sf, env, ctx)
                if t is not None and (t.tags & set(sink.tags)):
                    self.emit_finding(sink, t, node, sf)
                    break

    def user_call_taint(self, kind, callee, cls, args, node, sf, env, ctx):
        if ctx.depth >= MAX_DEPTH:
            return None
        if kind == "function":
            fsym = self.symbols.lookup_function(callee, ctx.namespace)
            if fsym is None:
                return None
            return self.analyze_function_call(fsym, args, node, sf, env, ctx)
        if kind == "static":
            if not cls:
                return None
            msym = self.symbols.lookup_method(cls, callee, ctx.namespace)
            if msym is None:
                return None
            return self.analyze_method_call(msym, args, node, sf, env, ctx)
        if kind == "method":
            if ctx.current_class:
                msym = self.symbols.lookup_method(ctx.current_class, callee, ctx.namespace)
                if msym is not None:
                    return self.analyze_method_call(msym, args, node, sf, env, ctx)
        return None

    def analyze_function_call(self, fsym, args, call_node, sf, env, ctx):
        new_env = {}
        sig = []
        for i, p in enumerate(fsym.params):
            if i < len(args):
                t = self.taint_of(args[i], sf, env, ctx)
                if t is not None:
                    new_env[p] = t.with_step(TaintStep(
                        location=make_loc(sf, call_node),
                        description=f"argument flows into parameter {p} of {fsym.name}()",
                        code=sf.node_line(call_node),
                    ))
                    sig.append((i, _taint_key(t)))
        key = (id(fsym.node), ctx.depth, tuple(sig))
        if key in self._call_memo:
            return self._call_memo[key]
        body = au.body_of(fsym.node)
        if body is None:
            result = None
        else:
            result = self.process_block(body, fsym.source, new_env,
                                        Ctx(depth=ctx.depth + 1, namespace=fsym.namespace))
        self._call_memo[key] = result
        return result

    def analyze_method_call(self, msym, args, call_node, sf, env, ctx):
        new_env = {}
        sig = []
        for i, p in enumerate(msym.params):
            if i < len(args):
                t = self.taint_of(args[i], sf, env, ctx)
                if t is not None:
                    new_env[p] = t.with_step(TaintStep(
                        location=make_loc(sf, call_node),
                        description=f"argument flows into parameter {p} of {msym.class_name}::{msym.name}()",
                        code=sf.node_line(call_node),
                    ))
                    sig.append((i, _taint_key(t)))
        key = (id(msym.node), ctx.depth, tuple(sig))
        if key in self._call_memo:
            return self._call_memo[key]
        body = au.body_of(msym.node)
        if body is None:
            result = None
        else:
            result = self.process_block(body, msym.source, new_env,
                                        Ctx(depth=ctx.depth + 1, current_class=msym.class_name,
                                            namespace=msym.namespace))
        self._call_memo[key] = result
        return result

    # ------------------------------------------------------------------
    # Sink checks (non-call)
    # ------------------------------------------------------------------
    def check_echo(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        for c in node.named_children:
            t = self.taint_of(c, sf, env, ctx)
            self._emit_sink("echo", "", t, c, sf)

    def check_print(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        for c in node.named_children:
            t = self.taint_of(c, sf, env, ctx)
            self._emit_sink("print", "", t, c, sf)

    def check_include(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        for c in node.named_children:
            t = self.taint_of(c, sf, env, ctx)
            self._emit_sink("include", "", t, c, sf)

    def check_shell(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        # Backtick shell command: interpolated variables are tainted.
        merged = None
        for c in node.named_children:
            tt = self.taint_of(c, sf, env, ctx)
            if tt is not None:
                merged = tt if merged is None else merged.merge(tt)
        self._emit_sink("shell", "", merged, node, sf)

    def check_object_creation(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        # 'new SimpleXMLElement($tainted)' etc. — class name is first 'name' child.
        cls = None
        for c in node.named_children:
            if c.type in ("name", "qualified_name"):
                cls = au.text(c)
                break
        args = au.argument_values(node)
        self.check_call_sink("object_create", cls, None, args, node, sf, env, ctx)

    def _emit_sink(self, kind, match, taint, node, sf):
        for sink in self.rules.sinks:
            if sink.kind != kind:
                continue
            if match and not match_callee(match, sink.match):
                continue
            if taint is not None and (taint.tags & set(sink.tags)):
                self.emit_finding(sink, taint, node, sf)
                break

    def emit_finding(self, sink: SinkRule, taint: Taint, node: Node, sf: SourceFile):
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
        trace.append(TaintStep(
            location=loc, description=sink.title, code=sf.node_line(node),
        ))
        self.findings.append(Finding(
            rule_id=sink.rule_id,
            title=sink.title,
            severity=Severity(sink.severity),
            cwe=sink.cwe,
            owasp=sink.owasp,
            category=sink.category,
            description=sink.description,
            remediation=sink.remediation,
            # A finding is only as certain as the weaker of "this sink is
            # dangerous" and "this data is attacker-controlled".
            confidence=weakest_confidence(sink.confidence, taint.confidence),
            framework=self.framework,
            language=self.language,
            location=loc,
            source=source,
            trace=trace,
            tags=list(taint.tags & set(sink.tags)),
        ))

    # ------------------------------------------------------------------
    # Pattern rules
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
                value = self._pattern_value(node, rule.match_field)
                if value is None:
                    continue
                if rule.regex:
                    if not rule.compiled().search(value):
                        continue
                else:
                    if value != rule.match:
                        continue
                self.emit_pattern(rule, node, sf)

    def _pattern_value(self, node: Node, field: str):
        if field == "text":
            return au.text(node)
        if field == "callee":
            if au.is_call(node):
                return au.call_callee(node)
            return None
        if field == "name":
            return au.method_name(node)
        return au.text(node)

    def emit_pattern(self, rule, node: Node, sf: SourceFile):
        loc = make_loc(sf, node)
        # Line-level dedup: '*' text patterns match ancestor nodes too.
        key = (rule.rule_id, sf.path, loc.line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            severity=Severity(rule.severity),
            cwe=rule.cwe,
            owasp=rule.owasp,
            category=rule.category,
            description=rule.description,
            remediation=rule.remediation,
            confidence=rule.confidence,
            framework=self.framework,
            language=self.language,
            location=loc,
            source=None,
            trace=[TaintStep(location=loc, description=rule.title, code=sf.node_line(node))],
            tags=[rule.category],
        ))


def pattern_loc(node: Node, sf: SourceFile, idx: int) -> Location:
    """Location of a text match at offset `idx` within `node`'s text."""
    prefix = node.text.decode("utf-8", "replace")[:idx]
    line_offset = prefix.count("\n")
    line = node.start_point.row + 1 + line_offset
    last_nl = prefix.rfind("\n")
    if last_nl == -1:
        column = node.start_point.column + 1 + idx
    else:
        column = idx - last_nl
    return Location(
        file=sf.path, line=line, column=column, end_line=line,
        end_column=column + 1, code=sf.line_text(line - 1),
    )


def _merge_taint(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a.merge(b)


def _merge_env(env: dict, other: dict) -> None:
    for k, t in other.items():
        # Side-channel facts are plain values, not taints — overwrite them.
        if _is_reserved(k) or k not in env:
            env[k] = t
        else:
            env[k] = env[k].merge(t)
