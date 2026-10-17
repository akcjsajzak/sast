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
PROPAGATORS = frozenset({
    "trim", "ltrim", "rtrim", "substr", "strtolower", "strtoupper",
    "ucfirst", "ucwords", "lcfirst", "sprintf", "vsprintf", "implode",
    "join", "strval", "str_replace", "str_ireplace", "preg_replace",
    "mb_strtolower", "mb_strtoupper", "mb_substr",
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
    return name.split("\\")[-1] if name else ""


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


@dataclass
class Taint:
    tags: set = field(default_factory=set)
    origins: list = field(default_factory=list)
    steps: list = field(default_factory=list)

    def merge(self, other: "Taint") -> "Taint":
        if other is None:
            return self
        tags = self.tags | other.tags
        origins = self.origins + other.origins
        steps = self.steps + other.steps
        return Taint(tags=tags, origins=_dedup(origins), steps=_dedup(steps))

    def with_step(self, step: TaintStep) -> "Taint":
        return Taint(
            tags=set(self.tags),
            origins=list(self.origins),
            steps=self.steps + [step],
        )


def _taint_key(t: "Taint"):
    """Hashable fingerprint of a taint's abstract value (tags + origins).

    Origins are included so that the same method called with two different
    sources (e.g. ``$_GET`` vs ``$_POST``) is not memoized into a single
    finding — both produce distinct findings.
    """
    origins = tuple(sorted((o.file, o.line, o.column) for o in t.origins))
    return (frozenset(t.tags), origins)


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
            for msym in cls.methods.values():
                body = au.body_of(msym.node)
                if body is not None:
                    self.process_block(body, msym.source, {},
                                       Ctx(current_class=cls.name, namespace=msym.namespace))
        for sf in files:
            self.run_patterns(sf)
        return self.findings

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
        elif lhs.type == "member_access_expression":
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
        for c in named:
            if c.type == "pair":
                pc = c.named_children
                if not pc:
                    continue
                value = pc[-1]
                if value.type == "variable_name":
                    env[au.var_name(value)] = it
                break

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
        if t == "member_access_expression":
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
                return self.source_taint("superglobal", sg, node, sf)
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

        st = self.source_taint(kind, callee, node, sf, cls, args)
        if st is not None:
            return st

        san = self.match_sanitizer(kind, callee, cls)
        if san is not None:
            return self.sanitized_taint(san, args, sf, env, ctx)

        self.check_call_sink(kind, callee, cls, args, node, sf, env, ctx)

        ut = self.user_call_taint(kind, callee, cls, args, node, sf, env, ctx)
        if ut is not None:
            return ut

        if kind == "function" and callee in PROPAGATORS:
            merged = None
            for a in args:
                tt = self.taint_of(a, sf, env, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged

        return None

    def source_taint(self, kind, match, node, sf, cls=None, args=None):
        for src in self.rules.sources:
            if src.kind != kind:
                continue
            if not match_callee(match, src.match):
                continue
            if src.cls and not match_callee(cls, src.cls):
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
            )
        return None

    def match_sanitizer(self, kind, callee, cls):
        for san in self.rules.sanitizers:
            if san.kind != kind:
                continue
            if not match_callee(callee, san.match):
                continue
            if san.cls and not match_callee(cls, san.cls):
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
        if "*" in san.neutralize:
            return None
        return self._neutralize(t, san.neutralize)

    def _neutralize(self, t: Taint, tags: list) -> Taint:
        remaining = t.tags - set(tags)
        if not remaining:
            return None
        return Taint(tags=remaining, origins=list(t.origins), steps=list(t.steps))

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
        key = (
            sink.rule_id, sf.path, loc.line, loc.column,
            source.file if source else "", source.line if source else 0,
        )
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
            confidence=sink.confidence,
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
    def run_patterns(self, sf: SourceFile) -> None:
        if not self.rules.patterns:
            return
        for node in sf.walk():
            for rule in self.rules.patterns:
                if rule.node_type != "*" and node.type != rule.node_type:
                    continue
                value = self._pattern_value(node, rule.match_field)
                if value is None:
                    continue
                if rule.regex:
                    import re
                    if not re.search(rule.match, value):
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
        if k in env:
            env[k] = env[k].merge(t)
        else:
            env[k] = t
