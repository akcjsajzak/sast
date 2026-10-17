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
# How many implementations of one method name a call may be followed into.
# Interface dispatch needs more than one, but a generated codebase can declare
# the same name thousands of times, so the fan-out has to stay bounded.
MAX_IMPLEMENTATIONS = 6
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
        self._file_text_cache: dict = {}

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
        # `x = y = value` nests one assignment inside another, so the outer
        # right-hand side is itself an assignment rather than the value. Bind
        # the inner targets first, then give the outer target the same taint;
        # evaluating the nested node as an expression instead left every name
        # but the innermost one clean.
        inner = self.strip(right)
        if inner is not None and inner.type in p.assignment:
            self.handle_assignment(inner, sf, env, ctx)
            inner_right = inner.child_by_field_name(p.f_right)
            vt = self.taint_of(inner_right, sf, env, ctx) if inner_right else None
        else:
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
            # A wrapper that names a type first and the expression second —
            # a C cast, a Go type conversion — strips to the type if you just
            # take the first child, which loses the expression entirely:
            # `(char *)malloc(n)` became `char *` and `[]byte(q)` became
            # `[]byte`. Grammars disagree on what the expression field is
            # called, so try the names they actually use before falling back
            # to position.
            valued = None
            for field in (self.p.f_value, "operand", "argument", "expression"):
                if field:
                    valued = node.child_by_field_name(field)
                    if valued is not None:
                        break
            if valued is not None:
                node = valued
            else:
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
            merged = None
            for c in node.named_children:
                merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
            if op is not None and _text(op) not in p.concat_ops:
                # A comparison or arithmetic result is not the operand's data,
                # so it carries no taint — but the operands still had to be
                # evaluated. Returning early here skipped them outright, which
                # hid every sink written inside a condition
                # (`while (fread(&buf, ...) > 0)`, `if (system(cmd) == 0)`)
                # along with any buffer such a call fills in.
                return None
            return merged

        if t in p.ternary:
            merged = None
            kids = node.named_children
            if kids:
                # Evaluated for its sinks; a condition's truth value is not data.
                self.taint_of(kids[0], sf, env, ctx)
            for c in kids[1:]:
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
        fn = self._unwrap_generic(fn)
        if fn.type in p.member:
            prop_node = fn.child_by_field_name(p.f_property)
            if prop_node is None and fn.named_children:
                prop_node = fn.named_children[-1]
            # `ser.Deserialize<object>` keeps the method name inside a
            # generic_name on the member side too, so unwrap here as well.
            name = (_text(self._unwrap_generic(prop_node))
                    if prop_node is not None else "")
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

        src = self.match_source("call", name, recv_root, path, sf)
        if src is not None:
            st = self.taint_from_source(src, node, sf)
            if src.out_args:
                self.apply_out_args(src, args, node, sf, env)
            if not src.out_only:
                return st
            return None

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

    @staticmethod
    def _unwrap_generic(fn: Node) -> Node:
        """Drop the type arguments from a generic callee.

        `ser.Deserialize<object>(x)` puts the name and its type arguments in
        one `generic_name` node, so reading the callee's text gave
        "Deserialize<object>" and matched no rule — every generic call was
        invisible, which in C# includes most of the JSON and EF Core surface.
        """
        if fn.type != "generic_name":
            return fn
        for c in fn.named_children:
            if c.type == "identifier":
                return c
        return fn

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
        result = self._invoke_symbol(sym, name, args, node, sf, env, ctx)
        if result is not None:
            return result
        # The preferred implementation came back clean, but a call through an
        # interface or a base class can land on any of them, and a flow that
        # is injectable in one is a real flow. Only consulted when the first
        # choice found nothing, so the common case costs nothing extra.
        for alt in sym.get("alternatives", ()):
            result = self._invoke_symbol(alt, name, args, node, sf, env, ctx)
            if result is not None:
                return result
        return None

    def _invoke_symbol(self, sym, name, args, node, sf, env, ctx):
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
    def _file_text(self, sf: SourceFile) -> str:
        """The file's decoded text, cached — only needed by gated sources."""
        cache = self._file_text_cache
        key = sf.path
        text = cache.get(key)
        if text is None:
            text = sf.content.decode("utf-8", "replace")
            cache[key] = text
        return text

    def match_source(self, kind, name, root="", path="", sf=None):
        """The first source rule this expression satisfies, or None."""
        for src in self.rules.sources:
            if src.kind != kind:
                continue
            if src.file_requires and not (
                    sf is not None and src.file_allows(self._file_text(sf))):
                continue
            if not match_callee(name, src.match):
                continue
            if src.obj_hint and not _hint(src.obj_hint, root, path):
                continue
            if src.keys is not None and not src.key_matches(name):
                continue
            return src
        return None

    def taint_from_source(self, src, node: Node, sf: SourceFile) -> Taint:
        return Taint(
            tags=set(src.tags),
            origins=[make_loc(sf, node)],
            steps=[TaintStep(location=make_loc(sf, node),
                             description=src.description,
                             code=sf.node_line(node))],
            confidence=src.confidence,
        )

    def apply_out_args(self, src, args, node: Node, sf: SourceFile, env: dict):
        """Taint the variables a call fills in through its arguments.

        C reads input by handing a function somewhere to put it, so the
        interesting value is never the return: after `fread(&img, ...)` it is
        `img` that holds attacker bytes. Binding the taint to the argument's
        root name is what lets a later `malloc(img.width + img.height)` be
        seen as an attacker-controlled allocation.
        """
        for idx in src.out_args:
            if idx >= len(args):
                continue  # a varargs tail that this call did not use
            name = self.root_of(args[idx])
            if not name:
                continue
            env[name] = self.taint_from_source(src, args[idx], sf).with_step(
                TaintStep(location=make_loc(sf, node),
                          description=f"{name} is filled in by {_text(node)[:60]}",
                          code=sf.node_line(node)))

    def source_taint(self, kind, name, node, sf, root="", path="", args=None):
        src = self.match_source(kind, name, root, path, sf)
        if src is None:
            return None
        return self.taint_from_source(src, node, sf)

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
            if sink.receiver_tainted:
                recv = self._receiver_node(node)
                rt = self.taint_of(recv, sf, env, ctx) if recv is not None else None
                if rt is not None and set(sink.tags) & rt.tags:
                    self.report(sink, rt, node, sf)
                    return
                continue
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
        # One finding per rule and location. The source used to be part of
        # this key, so a sink reached from several sources was reported once
        # per source — the same line appearing eight times in OpenDoor's
        # report. A reviewer fixes the sink once, and the trace still shows a
        # representative path, so the extra copies were pure noise.
        key = (sink.rule_id, loc.file, loc.line, loc.column)
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
        matches: dict = {}
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
    """Index function and method definitions by name across all files.

    The returned mapping holds one preferred implementation per name, and each
    entry carries the other implementations of that name under
    ``alternatives`` so a call through an interface can be followed into any
    of them.
    """
    symbols: dict = {}
    alternatives: dict = {}

    def find_params(node: Node):
        """Locate the formal parameter list belonging to `node`.

        Most grammars hang it straight off the function node, but C and C++
        bury it inside the declarator — `function_definition` holds a
        `function_declarator`, which holds the `parameter_list`, and a
        pointer return type adds another wrapper on top. Looking only at the
        direct children therefore found nothing for C/C++, every function was
        recorded with no parameters, and no taint could cross a call: an
        argument had no name to bind to in the callee.

        The search skips the body so a nested closure's parameters are never
        mistaken for the enclosing function's.
        """
        # Ask the grammar first. A Go method declaration carries its receiver
        # in a `parameter_list` too, and the receiver comes first, so scanning
        # by node type bound the receiver's name instead of the real
        # parameters — which is why no taint crossed into a Go method and
        # govwa's `(p *Profile) UnsafeQueryGetData(uid string)` never saw its
        # argument.
        named = node.child_by_field_name(profile.f_parameters)
        if named is not None and named.type in profile.params:
            return named
        for c in node.named_children:
            if c.type in profile.params:
                return c
            if c.type in profile.block or c.type in profile.comment:
                continue
            found = find_params(c)
            if found is not None:
                return found
        return None

    def param_name(param: Node):
        """The bound name of one formal parameter.

        `char *filename` and `char buf[10]` wrap the identifier in a
        `pointer_declarator` or `array_declarator`, so the name is not a
        direct child; descend until an identifier turns up.
        """
        if param.type in profile.identifier:
            return param
        named = param.child_by_field_name(profile.f_name)
        if named is not None and named.type in profile.identifier:
            return named
        stack = list(param.named_children)
        while stack:
            cur = stack.pop(0)
            if cur.type in profile.identifier:
                return cur
            # A type name is not a parameter name; nothing useful is nested
            # inside one, so do not descend through it.
            if cur.type in ("primitive_type", "type_identifier",
                            "sized_type_specifier", "struct_specifier",
                            "type_descriptor", "qualified_identifier",
                            "template_type"):
                continue
            stack.extend(cur.named_children)
        return None

    def params_of(node: Node) -> list:
        container = find_params(node)
        if container is None:
            return []
        names = []
        for param in container.named_children:
            if param.type in profile.comment:
                continue
            ident = param_name(param)
            if ident is not None:
                names.append(_text(ident))
        return names

    def self_has_body(node: Node) -> bool:
        if node.child_by_field_name(profile.f_body) is not None:
            return True
        return any(c.type in profile.block for c in node.named_children)

    def walk(node: Node, sf: SourceFile):
        for child in node.named_children:
            if child.type in profile.function or child.type in profile.method:
                name_node = child.child_by_field_name(profile.f_name)
                name = _text(name_node) if name_node is not None else ""
                # C/C++ wrap the name inside a declarator.
                if name and "(" in name:
                    name = name.split("(", 1)[0].strip().lstrip("*")
                if not name:
                    continue
                # An interface or abstract declaration has no body, so
                # resolving a call to it yields nothing. Indexing by bare name
                # with first-one-wins let `IDbProvider.GetCustomerEmail` hide
                # the implementation that actually builds the SQL, which is
                # how a whole provider-backed data layer went untracked.
                # Prefer a declaration that can actually be analysed.
                entry = {"node": child, "source": sf,
                         "params": params_of(child),
                         "bodied": self_has_body(child)}
                existing = symbols.get(name)
                if existing is None or (entry["bodied"]
                                        and not existing["bodied"]):
                    symbols[name] = entry
                # Keep the other implementations too. A call through an
                # interface can dispatch to any of them, and picking one by
                # file order meant WebGoat.NET's SQL layer resolved to a stub
                # provider while the injectable one went unanalysed. The list
                # is capped because a generated codebase can declare the same
                # method name thousands of times.
                if entry["bodied"]:
                    others = alternatives.setdefault(name, [])
                    if len(others) < MAX_IMPLEMENTATIONS:
                        others.append(entry)
            walk(child, sf)

    for sf in files:
        walk(sf.root, sf)
    for name, entry in symbols.items():
        entry["alternatives"] = [e for e in alternatives.get(name, ())
                                 if e["node"] is not entry["node"]]
    return symbols
