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
                 framework: str, language: str = "java") -> None:
        self.symbols = symbols
        self.rules = rules
        self.framework = framework
        self.language = language
        self.findings: list[Finding] = []
        self._seen: set = set()
        self._call_memo: dict = {}

    # ------------------------------------------------------------------
    def analyze(self, files: list[SourceFile]) -> list[Finding]:
        for cls in self.symbols.classes.values():
            for m in cls.methods.values():
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
        for c in node.named_children:
            if c.type == "parenthesized_expression":
                self.taint_of(c, sf, env, tenv, ctx)
            elif c.type in ("block", "statement"):
                be, bte = dict(env), dict(tenv)
                r = self.process_any(c, sf, be, bte, ctx)
                ret = _merge_taint(ret, r)
                branch_envs.append((be, bte))
        for be, bte in branch_envs:
            _merge_env(env, be)
            _merge_tenv(tenv, bte)
        return ret

    def handle_loop(self, node: Node, sf: SourceFile, env: dict, tenv: dict, ctx: Ctx):
        ret = None
        be, bte = dict(env), dict(tenv)
        if node.type == "enhanced_for_statement":
            self.bind_enhanced_for(node, sf, be, bte, ctx)
        for c in node.named_children:
            if c.type in ("block", "statement"):
                r = self.process_any(c, sf, be, bte, ctx)
                ret = _merge_taint(ret, r)
            elif c.type == "parenthesized_expression":
                self.taint_of(c, sf, be, bte, ctx)
        _merge_env(env, be)
        _merge_tenv(tenv, bte)
        return ret

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
            return None
        if t == "field_access":
            return env.get(ja.text(node))
        if t == "array_access":
            nc = node.named_children
            return self.taint_of(nc[0], sf, env, tenv, ctx) if nc else None
        if t == "parenthesized_expression":
            nc = node.named_children
            return self.taint_of(nc[0], sf, env, tenv, ctx) if nc else None
        if t == "ternary_expression":
            merged = None
            for c in node.named_children[1:]:
                tt = self.taint_of(c, sf, env, tenv, ctx)
                if tt is not None:
                    merged = tt if merged is None else merged.merge(tt)
            return merged
        if t == "cast_expression":
            return self.cast_taint(node, sf, env, tenv, ctx)
        if t == "assignment_expression":
            nc = node.named_children
            return self.taint_of(nc[-1], sf, env, tenv, ctx) if nc else None
        if t == "array_creation_expression":
            merged = None
            for c in node.named_children:
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
            for i, a in enumerate(args):
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

    def emit_finding(self, sink, taint, node, sf):
        loc = make_loc(sf, node)
        source = taint.origins[0] if taint.origins else None
        key = (sink.rule_id, sf.path, loc.line, loc.column,
               source.file if source else "", source.line if source else 0)
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
    def run_patterns(self, sf: SourceFile) -> None:
        if not self.rules.patterns:
            return
        for node in sf.walk():
            for rule in self.rules.patterns:
                if rule.node_type != "*" and node.type != rule.node_type:
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
    for k, v in other.items():
        tenv.setdefault(k, v)
