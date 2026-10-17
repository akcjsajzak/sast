"""A taint engine configurable for any language with a tree-sitter grammar.

PHP, Java and JavaScript have hand-written engines because each carries enough
framework-specific behaviour to justify one. Everything else differs mainly in
what the grammar *names* its nodes, so those languages share this engine and
supply a `LangProfile` instead.

The Taint value, confidence lattice, sanitizer soundness model and trace
format are the same ones the hand-written engines use, so findings from every
language are directly comparable in a report.
"""
from __future__ import annotations

from tree_sitter import Node

from ..models import Finding, Severity, TaintStep
from ..parsing.source import SourceFile
from ..rules.base import RuleSet, SanitizerRule
from .dataflow import (
    Ctx, Taint, _merge_taint, _taint_key, make_loc, match_callee,
    weakest_confidence,
)
from .lang_profile import LangProfile

MAX_DEPTH = 8
MAX_STEPS = 15


def _text(node: Node) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


class GenericTaintEngine:
    """Source-to-sink taint analysis driven by a language profile."""

    def __init__(self, profile: LangProfile, rules: RuleSet, framework: str,
                 language: str, symbols: dict = None) -> None:
        self.p = profile
        self.rules = rules
        self.framework = framework
        self.language = language
        self.symbols = symbols or {}
        self.findings: list[Finding] = []
        self._seen: set = set()
        self._call_memo: dict = {}

    # ------------------------------------------------------------------
    def analyze(self, files: list[SourceFile]) -> list[Finding]:
        for sf in files:
            self.walk_block(sf.root, sf, {}, Ctx())
        # Function bodies again with a clean environment, so a sink inside a
        # handler is found even when the top-level walk never called it.
        for sym in self.symbols.values():
            body = self._body(sym["node"])
            if body is not None:
                self.walk_block(body, sym["source"], {}, Ctx())
        for sf in files:
            self.run_patterns(sf)
        return self.findings

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------
    def walk_block(self, block: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        if block is None:
            return None
        for stmt in block.named_children:
            if stmt.type in self.p.comment:
                continue
            ret = _merge_taint(ret, self.walk_stmt(stmt, sf, env, ctx))
        return ret

    def walk_stmt(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        p = self.p
        t = stmt.type
        if t in p.comment:
            return None

        if t in p.expression_stmt:
            inner = [c for c in stmt.named_children if c.type not in p.comment]
            return self.walk_stmt(inner[0], sf, env, ctx) if inner else None

        if t in p.assignment:
            return self.handle_assignment(stmt, sf, env, ctx)

        if t in p.aug_assignment and t not in p.assignment:
            left = stmt.child_by_field_name(p.f_left)
            right = stmt.child_by_field_name(p.f_right)
            merged = _merge_taint(self.taint_of(left, sf, env, ctx),
                                  self.taint_of(right, sf, env, ctx))
            if left is not None:
                self.assign_to(left, merged, sf, env)
            return None

        if t in p.declaration:
            self.handle_declaration(stmt, sf, env, ctx)
            return None

        if t in p.return_stmt:
            kids = [c for c in stmt.named_children if c.type not in p.comment]
            return self.taint_of(kids[-1], sf, env, ctx) if kids else None

        if t in p.function or t in p.method or t in p.class_def:
            # Analysed separately from the symbol table.
            return None

        if t in p.block:
            return self.walk_block(stmt, sf, env, ctx)

        if t in p.branch or t in p.loop or t in p.try_stmt:
            return self.handle_compound(stmt, sf, env, ctx)

        # Anything else: evaluate as an expression to catch embedded sinks.
        return self.taint_of(stmt, sf, env, ctx)

    def handle_compound(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        p = self.p
        ret = None
        be = dict(env)
        # A loop that binds an iteration variable to a tainted sequence taints
        # the variable: `for row in request.form:`.
        if stmt.type in p.loop_binding:
            left = stmt.child_by_field_name(p.f_loop_left)
            right = stmt.child_by_field_name(p.f_loop_right)
            if right is not None:
                it = self.taint_of(right, sf, be, ctx)
                if left is not None and it is not None:
                    self.assign_to(left, it, sf, be)
        for c in stmt.named_children:
            if c.type in p.comment:
                continue
            if c.type in p.block:
                ret = _merge_taint(ret, self.walk_block(c, sf, be, ctx))
            else:
                ret = _merge_taint(ret, self.walk_stmt(c, sf, be, ctx))
        for k, v in be.items():
            env[k] = v if k not in env else env[k].merge(v)
        return ret

    def handle_declaration(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        p = self.p
        # Declarators can sit a level or two below the statement — C# wraps
        # them in a variable_declaration — so search rather than assume.
        declarators = self._find_declarators(stmt)
        if not declarators:
            declarators = [stmt]
        for d in declarators:
            name = d.child_by_field_name(p.f_name)
            value = d.child_by_field_name(p.f_value)
            if value is None:
                # Go's `x, y := f()` keeps values in a trailing list.
                kids = [c for c in d.named_children if c.type not in p.comment]
                if len(kids) >= 2:
                    name, value = kids[0], kids[-1]
            if value is None:
                continue
            vt = self.taint_of(value, sf, env, ctx)
            if name is not None:
                self.assign_to(name, vt, sf, env)

    def _find_declarators(self, node: Node, depth: int = 0) -> list:
        if depth > 3 or not self.p.declarator:
            return []
        found = []
        for c in node.named_children:
            if c.type in self.p.declarator:
                found.append(c)
            elif c.type not in self.p.comment:
                found.extend(self._find_declarators(c, depth + 1))
        return found

    def handle_assignment(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        p = self.p
        left = stmt.child_by_field_name(p.f_left)
        right = stmt.child_by_field_name(p.f_right)
        if left is None or right is None:
            kids = [c for c in stmt.named_children if c.type not in p.comment]
            if len(kids) < 2:
                return None
            left, right = kids[0], kids[-1]
        vt = self.taint_of(right, sf, env, ctx)
        self.check_property_sink(left, vt, stmt, sf)
        self.assign_to(left, vt, sf, env)
        return None

    def assign_to(self, left: Node, vt, sf: SourceFile, env: dict):
        p = self.p
        left = self.strip(left)
        if left is None:
            return
        # Tuple/multiple assignment: taint every bound name conservatively.
        if left.type in ("pattern_list", "tuple_pattern", "expression_list",
                         "tuple", "identifier_list"):
            for c in left.named_children:
                self.assign_to(c, vt, sf, env)
            return
        key = self.path_of(left)
        if not key:
            return
        if vt is None:
            env.pop(key, None)
            return
        env[key] = vt.with_step(TaintStep(
            location=make_loc(sf, left),
            description=f"taint stored in {key}",
            code=sf.node_line(left),
        ))
        # A tainted field also taints its container.
        if left.type in p.member or left.type in p.index:
            root = self.root_of(left)
            if root and root != key:
                env[root] = vt if root not in env else env[root].merge(vt)

    # ------------------------------------------------------------------
    # Expressions
    # ------------------------------------------------------------------
    def strip(self, node: Node) -> Node:
        seen = 0
        while node is not None and node.type in self.p.transparent and seen < 12:
            kids = [c for c in node.named_children if c.type not in self.p.comment]
            if not kids:
                return node
            node = kids[-1] if node.type in self.p.expression_stmt else kids[0]
            seen += 1
        return node

    def path_of(self, node: Node) -> str:
        """Dotted source path of a member chain, or the identifier itself."""
        node = self.strip(node)
        if node is None:
            return ""
        if node.type in self.p.identifier:
            return _text(node)
        if node.type in self.p.member or node.type in self.p.index:
            return _text(node).replace("\n", " ")
        return ""

    def root_of(self, node: Node) -> str:
        """Left-most identifier of a chain: `a.b.c` -> 'a'."""
        p = self.p
        node = self.strip(node)
        seen = 0
        while node is not None and seen < 24:
            if node.type in p.member:
                node = node.child_by_field_name(p.f_object) or (
                    node.named_children[0] if node.named_children else None)
            elif node.type in p.index:
                node = node.named_children[0] if node.named_children else None
            elif node.type in p.call:
                node = node.child_by_field_name(p.f_function) or (
                    node.named_children[0] if node.named_children else None)
            elif node.type in p.transparent:
                node = self.strip(node)
                if node is not None and node.type in p.transparent:
                    return ""
            else:
                break
            seen += 1
        return _text(node) if node is not None and node.type in p.identifier else ""

    def taint_of(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        p = self.p
        if node is None:
            return None
        node = self.strip(node)
        if node is None:
            return None
        t = node.type

        if t in p.identifier:
            known = env.get(_text(node))
            if known is not None:
                return known
            # Bare identifiers can themselves be sources: `argv` in C.
            return self.source_taint("identifier", _text(node), node, sf)
        if t in p.literal:
            # An interpolated string is a literal node in some grammars.
            if p.interpolation_hole and any(
                    c.type in p.interpolation_hole for c in node.named_children):
                merged = None
                for c in node.named_children:
                    if c.type in p.interpolation_hole:
                        kids = [k for k in c.named_children
                                if k.type not in p.comment]
                        if kids:
                            merged = _merge_taint(
                                merged, self.taint_of(kids[0], sf, env, ctx))
                return merged
            return None

        if t in p.interpolation and t not in p.literal:
            merged = None
            for c in node.named_children:
                if c.type in p.interpolation_hole:
                    kids = [k for k in c.named_children if k.type not in p.comment]
                    if kids:
                        merged = _merge_taint(
                            merged, self.taint_of(kids[0], sf, env, ctx))
            return merged

        if t in p.member or t in p.index:
            return self.member_taint(node, sf, env, ctx)

        if t in p.call:
            return self.call_taint(node, sf, env, ctx)

        if t in p.binary:
            op = node.child_by_field_name(p.f_operator)
            if op is not None and _text(op) not in p.concat_ops:
                return None
            merged = None
            for c in node.named_children:
                merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
            return merged

        if t in p.ternary:
            merged = None
            for c in node.named_children[1:]:
                merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
            return merged

        # Composite literals, argument lists, etc: walk children.
        merged = None
        for c in node.named_children:
            if c.type in p.comment:
                continue
            merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
        return merged

    def member_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        p = self.p
        path = self.path_of(node)
        if path and path in env:
            return env[path]

        prop = ""
        prop_node = node.child_by_field_name(p.f_property)
        if prop_node is not None:
            prop = _text(prop_node)
        elif node.named_children:
            prop = _text(node.named_children[-1])
        root = self.root_of(node)

        st = self.source_taint("member", prop, node, sf, root, path)
        if st is not None:
            return st

        obj = node.child_by_field_name(p.f_object)
        if obj is None and node.named_children:
            obj = node.named_children[0]
        return self.taint_of(obj, sf, env, ctx) if obj is not None else None

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------
    def call_parts(self, node: Node):
        """Return (name, receiver_root, dotted_path, [args])."""
        p = self.p
        fn = node.child_by_field_name(p.f_function)
        if fn is None:
            kids = [c for c in node.named_children if c.type not in p.comment]
            fn = kids[0] if kids else None
        args_node = node.child_by_field_name(p.f_arguments)
        args = []
        if args_node is not None:
            args = [c for c in args_node.named_children if c.type not in p.comment]
        elif fn is not None:
            args = [c for c in node.named_children[1:] if c.type not in p.comment]

        fn = self.strip(fn)
        if fn is None:
            return "", "", "", args
        if fn.type in p.member:
            prop_node = fn.child_by_field_name(p.f_property)
            name = _text(prop_node) if prop_node is not None else (
                _text(fn.named_children[-1]) if fn.named_children else "")
            return name, self.root_of(fn), _text(fn), args
        return _text(fn), "", _text(fn), args

    def call_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        name, recv_root, path, args = self.call_parts(node)
        # Evaluate the receiver as an expression rather than looking up its
        # root name: `request.args.get('q')` has receiver `request.args`,
        # which is itself the taint source.
        recv_taint = None
        recv_node = self._receiver_node(node)
        if recv_node is not None:
            recv_taint = self.taint_of(recv_node, sf, env, ctx)
        elif recv_root:
            recv_taint = env.get(recv_root)

        arg_texts = [_text(a) for a in args]
        san = self.match_sanitizer(name, recv_root, arg_texts)

        # Sink before source: a call can be both.
        if san is None:
            self.check_call_sink(name, recv_root, path, args, node, sf, env, ctx)

        st = self.source_taint("call", name, node, sf, recv_root, path, args)
        if st is not None:
            return st

        if san is not None:
            return self.sanitized_taint(san, args, sf, env, ctx)

        ut = self.user_call_taint(name, args, node, sf, env, ctx)
        if ut is not None:
            return ut

        # Unknown call: its result carries its arguments' taint. Over-tainting
        # here is far cheaper than terminating every trace at the first helper
        # the rule set does not know about.
        merged = None
        for a in args:
            merged = _merge_taint(merged, self.taint_of(a, sf, env, ctx))
        return merged if merged is not None else recv_taint

    def _receiver_node(self, call: Node):
        """The object a method call is made on, e.g. `a.b` in `a.b.c(x)`."""
        p = self.p
        fn = self.strip(call.child_by_field_name(p.f_function))
        if fn is None:
            kids = [c for c in call.named_children if c.type not in p.comment]
            fn = self.strip(kids[0]) if kids else None
        if fn is None or fn.type not in p.member:
            return None
        obj = fn.child_by_field_name(p.f_object)
        if obj is None and fn.named_children:
            obj = fn.named_children[0]
        return obj

    def user_call_taint(self, name, args, node, sf, env, ctx):
        if ctx.depth >= MAX_DEPTH or not name:
            return None
        sym = self.symbols.get(name)
        if sym is None:
            return None
        new_env = {}
        sig = []
        for i, pname in enumerate(sym["params"]):
            if i < len(args):
                t = self.taint_of(args[i], sf, env, ctx)
                if t is not None:
                    new_env[pname] = t.with_step(TaintStep(
                        location=make_loc(sf, node),
                        description=f"argument flows into parameter {pname} of {name}()",
                        code=sf.node_line(node),
                    ))
                    sig.append((i, _taint_key(t)))
        key = (id(sym["node"]), ctx.depth, tuple(sig))
        if key in self._call_memo:
            return self._call_memo[key]
        body = self._body(sym["node"])
        if body is None:
            result = None
        else:
            self._call_memo[key] = None  # recursion guard
            result = self.walk_block(body, sym["source"], new_env,
                                     Ctx(depth=ctx.depth + 1))
        self._call_memo[key] = result
        return result

    def _body(self, node: Node):
        body = node.child_by_field_name(self.p.f_body)
        if body is not None:
            return body
        for c in node.named_children:
            if c.type in self.p.block:
                return c
        return None

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------
    def source_taint(self, kind, name, node, sf, root="", path="", args=None):
        for src in self.rules.sources:
            if src.kind != kind:
                continue
            if not match_callee(name, src.match):
                continue
            if src.obj_hint and not _hint(src.obj_hint, root, path):
                continue
            if src.keys is not None and not src.key_matches(name):
                continue
            return Taint(
                tags=set(src.tags),
                origins=[make_loc(sf, node)],
                steps=[TaintStep(location=make_loc(sf, node),
                                 description=src.description,
                                 code=sf.node_line(node))],
                confidence=src.confidence,
            )
        return None

    def match_sanitizer(self, name, root, arg_texts):
        for san in self.rules.sanitizers:
            if san.kind != "call":
                continue
            if not match_callee(name, san.match):
                continue
            if san.cls and not _hint(san.cls, root, ""):
                continue
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
            node = args[idx]
            return Taint(
                tags=set(t.tags), origins=list(t.origins),
                steps=t.steps + [TaintStep(
                    location=make_loc(sf, node),
                    description=san.note or f"weak sanitizer {san.match}() applied",
                    code=sf.node_line(node))],
                confidence=weakest_confidence(t.confidence, "medium"),
            )
        if "*" in san.neutralize:
            return None
        remaining = t.tags - set(san.neutralize)
        if not remaining:
            return None
        return Taint(tags=remaining, origins=list(t.origins),
                     steps=list(t.steps), confidence=t.confidence)

    def check_call_sink(self, name, root, path, args, node, sf, env, ctx):
        for sink in self.rules.sinks:
            if sink.kind != "call":
                continue
            if not match_callee(name, sink.match):
                continue
            if sink.obj_hint and not _hint(sink.obj_hint, root, path):
                continue
            # A sink that needs no tainted argument (an inherently unsafe API
            # such as gets() or strcpy()) is reported on sight.
            if not sink.tags:
                self.report(sink, None, node, sf)
                return
            indices = range(len(args)) if sink.arg_index < 0 else [sink.arg_index]
            for i in indices:
                if i >= len(args):
                    continue
                t = self.taint_of(args[i], sf, env, ctx)
                if t is None:
                    continue
                if set(sink.tags) & t.tags:
                    self.report(sink, t, node, sf)
                    return

    def check_property_sink(self, left, vt, node, sf):
        if vt is None:
            return
        left = self.strip(left)
        if left is None or left.type not in self.p.member:
            return
        prop_node = left.child_by_field_name(self.p.f_property)
        prop = _text(prop_node) if prop_node is not None else ""
        root = self.root_of(left)
        for sink in self.rules.sinks:
            if sink.kind != "property_assign":
                continue
            if not match_callee(prop, sink.match):
                continue
            if sink.obj_hint and not _hint(sink.obj_hint, root, _text(left)):
                continue
            if set(sink.tags) & vt.tags:
                self.report(sink, vt, node, sf)
                return

    # ------------------------------------------------------------------
    def report(self, sink, taint, node: Node, sf: SourceFile) -> None:
        loc = make_loc(sf, node)
        origins = tuple(sorted((o.file, o.line, o.column)
                               for o in (taint.origins if taint else [])))
        key = (sink.rule_id, loc.file, loc.line, loc.column, origins)
        if key in self._seen:
            return
        self._seen.add(key)
        trace = list(taint.steps[-MAX_STEPS:]) if taint else []
        trace.append(TaintStep(location=loc, description=sink.title,
                               code=sf.node_line(node)))
        self.findings.append(Finding(
            rule_id=sink.rule_id,
            title=sink.title,
            severity=Severity(sink.severity),
            cwe=sink.cwe,
            owasp=sink.owasp,
            category=sink.category,
            description=sink.description,
            remediation=sink.remediation,
            confidence=weakest_confidence(
                sink.confidence, taint.confidence if taint else "high"),
            framework=self.framework,
            language=self.language,
            location=loc,
            source=taint.origins[0] if taint and taint.origins else None,
            trace=trace,
            tags=list(taint.tags & set(sink.tags)) if taint else list(sink.tags),
        ))

    def run_patterns(self, sf: SourceFile) -> None:
        if not self.rules.patterns:
            return
        matches: dict = {}
        for node in sf.walk():
            for rule in self.rules.patterns:
                if rule.node_type != "*" and node.type != rule.node_type:
                    continue
                value = self._pattern_value(node, rule.match_field)
                if value is None:
                    continue
                if rule.regex:
                    if not rule.compiled().search(value):
                        continue
                elif value != rule.match:
                    continue
                matches.setdefault(rule.rule_id, (rule, []))[1].append(node)

        for rule, nodes in matches.values():
            spans = [(n.start_byte, n.end_byte) for n in nodes]
            for node in nodes:
                start, end = node.start_byte, node.end_byte
                if any(start <= s and e <= end and (s, e) != (start, end)
                       for s, e in spans):
                    continue
                self.emit_pattern(rule, node, sf)

    def _pattern_value(self, node: Node, field: str):
        if field == "text":
            return _text(node)
        if field == "callee":
            if node.type in self.p.call:
                name, _root, path, _args = self.call_parts(node)
                return path or name
            return None
        if field == "name":
            n = node.child_by_field_name(self.p.f_name)
            return _text(n) if n is not None else None
        return None

    def emit_pattern(self, rule, node: Node, sf: SourceFile) -> None:
        loc = make_loc(sf, node)
        key = (rule.rule_id, loc.file, loc.line, loc.column)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            rule_id=rule.rule_id, title=rule.title,
            severity=Severity(rule.severity), cwe=rule.cwe, owasp=rule.owasp,
            category=rule.category, description=rule.description,
            remediation=rule.remediation, confidence=rule.confidence,
            framework=self.framework, language=self.language, location=loc,
            source=None,
            trace=[TaintStep(location=loc, description=rule.title,
                             code=sf.node_line(node))],
            tags=[rule.category],
        ))


def _hint(hint: str, root: str, path: str) -> bool:
    hint = hint.lower()
    if root and hint in root.lower():
        return True
    return bool(path) and hint in path.lower()


def build_symbols(files: list[SourceFile], profile: LangProfile) -> dict:
    """Index function and method definitions by name across all files."""
    symbols: dict = {}

    def params_of(node: Node) -> list:
        names = []
        for c in node.named_children:
            if c.type not in profile.params:
                continue
            for param in c.named_children:
                if param.type in profile.comment:
                    continue
                ident = param
                if param.type not in profile.identifier:
                    found = param.child_by_field_name(profile.f_name)
                    if found is None:
                        found = next((k for k in param.named_children
                                      if k.type in profile.identifier), None)
                    ident = found
                if ident is not None:
                    names.append(_text(ident))
        return names

    def walk(node: Node, sf: SourceFile):
        for child in node.named_children:
            if child.type in profile.function or child.type in profile.method:
                name_node = child.child_by_field_name(profile.f_name)
                name = _text(name_node) if name_node is not None else ""
                # C/C++ wrap the name inside a declarator.
                if name and "(" in name:
                    name = name.split("(", 1)[0].strip().lstrip("*")
                if name and name not in symbols:
                    symbols[name] = {"node": child, "source": sf,
                                     "params": params_of(child)}
            walk(child, sf)

    for sf in files:
        walk(sf.root, sf)
    return symbols
