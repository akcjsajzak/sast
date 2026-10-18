"""Source-to-sink taint analysis engine for JavaScript and TypeScript.

Shares the Taint value, confidence lattice and trace model with the PHP and
Java engines, so findings from every language look the same in a report.
"""
from __future__ import annotations

import os

from tree_sitter import Node

from ..models import Finding, Severity, TaintStep
from ..parsing.source import SourceFile
from ..rules.base import RuleSet, SanitizerRule
from . import js_ast as ja
from .dataflow import (
    Ctx, Taint, _merge_taint, _taint_key, make_loc, match_callee,
    weakest_confidence,
)
from .js_symbols import JsSymbolTable

MAX_DEPTH = 8
MAX_STEPS = 15

# Calls whose result carries their arguments' taint.
PROPAGATORS = frozenset({
    # String transforms
    "toString", "trim", "trimStart", "trimEnd", "substring", "substr", "slice",
    "toLowerCase", "toUpperCase", "replace", "replaceAll", "concat", "padStart",
    "padEnd", "repeat", "normalize", "split", "join", "at", "charAt",
    # Encoders/decoders — the bytes stay attacker-controlled
    "parse", "stringify", "decodeURI", "decodeURIComponent", "encodeURI",
    "encodeURIComponent", "atob", "btoa", "unescape", "escape", "from",
    # Collections
    "map", "filter", "flat", "flatMap", "concat", "values", "keys", "entries",
    "find", "pop", "shift", "reverse", "sort", "get",
    # Promise/async plumbing
    "then", "json", "text", "resolve", "all",
    # Object helpers
    "assign", "freeze", "entries", "fromEntries", "create",
    # Constructors that wrap a value without changing who controls it:
    # `new URLSearchParams(location.search)` stays attacker-controlled.
    "URLSearchParams", "URL", "FormData", "Headers", "Request", "Blob",
    "String", "Array", "Object",
})

# Calls on a tainted receiver that return a length, index or boolean.
NON_PROPAGATING = frozenset({
    "length", "indexOf", "lastIndexOf", "includes", "startsWith", "endsWith",
    "test", "has", "hasOwnProperty", "isArray", "size", "localeCompare",
    "charCodeAt", "codePointAt", "search", "every", "some",
})

_SKIP_TOP = {"comment", "import_statement", "export_statement_header"}

# Second handler parameter names that mark the first one as the request.
_RESPONSE_PARAMS = frozenset({"res", "response", "resp", "reply", "h"})


def _loc(sf: SourceFile, node: Node):
    return make_loc(sf, node)


class JsTaintEngine:
    """Taint analysis over a set of JavaScript/TypeScript files."""

    def __init__(self, symbols: JsSymbolTable, rules: RuleSet,
                 framework: str, language: str = "javascript") -> None:
        self.symbols = symbols
        self.rules = rules
        self.framework = framework
        self.language = language
        self.findings: list[Finding] = []
        self._seen: set = set()
        self._call_memo: dict = {}
        # Per file: local name -> resolved path of a relative require/import.
        self._modules: dict = {}
        # (path, function name) -> JsFunction, built on first use.
        self._by_file: dict = None

    # ------------------------------------------------------------------
    def analyze(self, files: list[SourceFile]) -> list[Finding]:
        for sf in files:
            self.process_block(sf.root, sf, {}, Ctx())
        # Route handlers and component bodies are nested in callbacks, so a
        # second pass over every function body catches anything the top-level
        # walk did not reach with its own environment.
        # Every declaration, not one per name: the symbol dicts are keyed for
        # resolution, so a second `function handle()` in another module was
        # never analysed — and with module scoping ignored, two modules
        # exporting the same name is the normal case.
        for fsym in self.symbols.all_functions:
            body = ja.body_of(fsym.node)
            if body is not None:
                self.process_block(body, fsym.source,
                                   self.request_params(fsym.node, fsym.source),
                                   Ctx())
        for cls in self.symbols.all_classes:
            fields: dict = {}
            for _ in range(2):
                for msym in (cls.all_methods or cls.methods.values()):
                    body = ja.body_of(msym.node)
                    if body is None:
                        continue
                    env = dict(fields)
                    self.process_block(body, msym.source, env,
                                       Ctx(current_class=cls.name))
                    for k, v in env.items():
                        if k.startswith("this."):
                            fields[k] = v if k not in fields else fields[k].merge(v)
        for sf in files:
            self.run_patterns(sf)
        return self.findings

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------
    def process_block(self, block: Node, sf: SourceFile, env: dict, ctx: Ctx):
        ret = None
        for stmt in ja.iter_statements(block):
            r = self.process_stmt(stmt, sf, env, ctx)
            if r is not None:
                ret = _merge_taint(ret, r)
        return ret

    def process_stmt(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        t = stmt.type
        if t in _SKIP_TOP:
            return None

        if t in ("lexical_declaration", "variable_declaration"):
            for d in ja.declarators(stmt):
                name_node, value = ja.declarator_parts(d)
                if value is None:
                    continue
                vt = self.taint_of(value, sf, env, ctx)
                self.bind_pattern(name_node, vt, sf, env)
            return None

        if t == "expression_statement":
            inner = [c for c in stmt.named_children if c.type != "comment"]
            if inner:
                return self.process_stmt(inner[0], sf, env, ctx)
            return None

        if t == "assignment_expression":
            self.handle_assignment(stmt, sf, env, ctx)
            return None

        if t == "augmented_assignment_expression":
            left = stmt.child_by_field_name("left")
            right = stmt.child_by_field_name("right")
            merged = _merge_taint(self.taint_of(left, sf, env, ctx),
                                  self.taint_of(right, sf, env, ctx))
            if left is not None:
                self.assign_target(left, merged, sf, env)
            return None

        if t == "return_statement":
            kids = [c for c in stmt.named_children if c.type != "comment"]
            return self.taint_of(kids[-1], sf, env, ctx) if kids else None

        if t == "if_statement":
            ret = None
            cond = stmt.child_by_field_name("condition")
            if cond is not None:
                self.taint_of(cond, sf, env, ctx)
            for field in ("consequence", "alternative"):
                branch = stmt.child_by_field_name(field)
                if branch is not None:
                    be = dict(env)
                    ret = _merge_taint(ret, self.process_any(branch, sf, be, ctx))
                    _merge_env(env, be)
            if (cond is not None and stmt.child_by_field_name("alternative") is None
                    and _always_exits(stmt.child_by_field_name("consequence"))):
                self._apply_exit_guard(ja.text(cond), env)
            return ret

        if t in ("for_statement", "for_in_statement", "while_statement",
                 "do_statement", "try_statement", "switch_statement",
                 "statement_block", "labeled_statement", "catch_clause",
                 "finally_clause", "switch_body", "switch_case", "switch_default",
                 "else_clause"):
            return self.handle_compound(stmt, sf, env, ctx)

        if t in ("function_declaration", "generator_function_declaration",
                 "class_declaration"):
            # Bodies are analysed from the symbol table pass.
            return None

        if t == "export_statement":
            ret = None
            for c in stmt.named_children:
                ret = _merge_taint(ret, self.process_stmt(c, sf, env, ctx))
            return ret

        # Fallback: evaluate as an expression so embedded sinks are seen.
        return self.taint_of(stmt, sf, env, ctx)

    def process_any(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        if node is None:
            return None
        if node.type == "statement_block":
            return self.process_block(node, sf, env, ctx)
        return self.process_stmt(node, sf, env, ctx)

    def handle_compound(self, stmt: Node, sf: SourceFile, env: dict, ctx: Ctx):
        """Loops, try/catch, switch: bind any iteration variable, then walk."""
        ret = None
        be = dict(env)
        if stmt.type == "for_in_statement":
            left = stmt.child_by_field_name("left")
            right = stmt.child_by_field_name("right")
            it = self.taint_of(right, sf, be, ctx) if right is not None else None
            if left is not None and it is not None:
                self.bind_pattern(left, it, sf, be)
        for c in stmt.named_children:
            if c.type == "comment":
                continue
            if c.type == "statement_block":
                ret = _merge_taint(ret, self.process_block(c, sf, be, ctx))
            else:
                ret = _merge_taint(ret, self.process_stmt(c, sf, be, ctx))
        _merge_env(env, be)
        return ret

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------
    def handle_assignment(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        vt = self.taint_of(right, sf, env, ctx)
        if left is None:
            return
        # `el.innerHTML = tainted` is a sink, not just a store.
        self.check_property_sink(left, right, vt, node, sf, env, ctx)
        self.assign_target(left, vt, sf, env)

    def assign_target(self, left: Node, vt, sf: SourceFile, env: dict):
        left = ja.strip(left)
        if left is None:
            return
        if left.type in ("member_expression", "subscript_expression"):
            key = ja.member_path(left)
            if not key:
                return
            if vt is not None:
                env[key] = vt.with_step(TaintStep(
                    location=_loc(sf, left),
                    description=f"taint stored in {key}",
                    code=sf.node_line(left),
                ))
                # A tainted property also taints its container, so
                # `obj.a = tainted; sink(obj)` is seen.
                root = ja.root_object(left)
                if root and root != key:
                    env[root] = vt if root not in env else env[root].merge(vt)
            else:
                env.pop(key, None)
            return
        self.bind_pattern(left, vt, sf, env)

    def bind_pattern(self, pattern: Node, vt, sf: SourceFile, env: dict):
        """Bind a (possibly destructuring) pattern to a taint value."""
        if pattern is None:
            return
        names = ja.binding_names(pattern)
        if not names:
            return
        for name in names:
            if vt is None:
                env.pop(name, None)
            else:
                env[name] = vt.with_step(TaintStep(
                    location=_loc(sf, pattern),
                    description=f"taint stored in {name}",
                    code=sf.node_line(pattern),
                ))

    # ------------------------------------------------------------------
    # Expressions
    # ------------------------------------------------------------------
    def taint_of(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        if node is None:
            return None
        node = ja.strip(node)
        if node is None:
            return None
        t = node.type

        if t == "identifier":
            return env.get(ja.text(node))
        if t in ("string", "number", "true", "false", "null", "undefined",
                 "regex", "this"):
            if t == "this":
                return env.get("this")
            return None

        if t in ("member_expression", "subscript_expression"):
            return self.member_taint(node, sf, env, ctx)

        if t in ("call_expression", "new_expression"):
            return self.call_taint(node, sf, env, ctx)

        if t == "template_string":
            merged = None
            for c in node.named_children:
                if c.type == "template_substitution":
                    inner = [k for k in c.named_children if k.type != "comment"]
                    if inner:
                        merged = _merge_taint(merged,
                                              self.taint_of(inner[0], sf, env, ctx))
            return merged

        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            if op is not None and ja.text(op) not in ("+", "??", "||", "&&"):
                return None
            return _merge_taint(
                self.taint_of(node.child_by_field_name("left"), sf, env, ctx),
                self.taint_of(node.child_by_field_name("right"), sf, env, ctx))

        if t == "ternary_expression":
            return _merge_taint(
                self.taint_of(node.child_by_field_name("consequence"), sf, env, ctx),
                self.taint_of(node.child_by_field_name("alternative"), sf, env, ctx))

        if t in ("object", "array"):
            merged = None
            for c in node.named_children:
                merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
            return merged
        if t in ("pair", "spread_element"):
            kids = [c for c in node.named_children if c.type != "property_identifier"]
            merged = None
            for c in kids:
                merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
            return merged
        if t == "shorthand_property_identifier":
            return env.get(ja.text(node))

        if t in ("jsx_element", "jsx_self_closing_element", "jsx_fragment"):
            return self.jsx_taint(node, sf, env, ctx)
        if t == "jsx_expression":
            inner = [c for c in node.named_children if c.type != "comment"]
            return self.taint_of(inner[0], sf, env, ctx) if inner else None

        if t in ("unary_expression", "update_expression"):
            return None

        if t in ja.FUNCTION_NODES:
            # A function used as a value (a callback): analyse its body so
            # sinks inside it are reported even with untainted parameters.
            body = ja.body_of(node)
            if body is not None and ctx.depth < MAX_DEPTH:
                self.process_any(body, sf,
                                 {**env, **self.request_params(node, sf)},
                                 Ctx(depth=ctx.depth + 1,
                                     current_class=ctx.current_class))
            return None

        # Unknown composite: walk children for embedded sinks.
        merged = None
        for c in node.named_children:
            merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
        return merged

    def member_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        path = ja.member_path(node)
        if path and path in env:
            return env[path]

        obj, prop = ja.member_parts(node)
        root = ja.root_object(node)

        st = self.source_taint("member", prop, node, sf, obj_name=root, path=path)
        if st is not None:
            return st

        if prop in NON_PROPAGATING:
            return None
        # Property of a tainted object stays tainted.
        if obj is not None:
            return self.taint_of(obj, sf, env, ctx)
        return None

    def jsx_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        """Check JSX attributes for sinks, and walk children."""
        opening = node
        if node.type == "jsx_element":
            for c in node.named_children:
                if c.type == "jsx_opening_element":
                    opening = c
                    break
        if opening.type in ("jsx_opening_element", "jsx_self_closing_element"):
            for name, value in ja.jsx_attributes(opening):
                if value is None:
                    continue
                vt = self.taint_of(value, sf, env, ctx)
                if vt is None:
                    continue
                for sink in self.rules.sinks:
                    if sink.kind != "jsx_attribute":
                        continue
                    if not match_callee(name, sink.match):
                        continue
                    if set(sink.tags) & vt.tags:
                        self.report(sink, vt, value, sf)
        merged = None
        for c in node.named_children:
            if c.type in ("jsx_expression", "jsx_element",
                          "jsx_self_closing_element", "jsx_fragment"):
                merged = _merge_taint(merged, self.taint_of(c, sf, env, ctx))
        return merged

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------
    def call_taint(self, node: Node, sf: SourceFile, env: dict, ctx: Ctx):
        callee, receiver, args = ja.call_parts(node)
        recv_path = ja.member_path(receiver) if receiver is not None else ""
        recv_root = ja.root_object(receiver) if receiver is not None else ""

        # Evaluate the receiver so sinks inside a fluent chain are found.
        if receiver is not None:
            recv_taint = self.taint_of(receiver, sf, env, ctx)
        else:
            recv_taint = None

        arg_texts = [ja.text(a) for a in args]
        san = self.match_sanitizer(callee, recv_root, arg_texts)

        # Sink before source: a call can be both.
        if san is None:
            self.check_call_sink(callee, recv_root, recv_path, args, node, sf,
                                 env, ctx, recv_taint=recv_taint)

        st = self.source_taint("call", callee, node, sf, obj_name=recv_root,
                               path=recv_path, args=args)
        if st is not None:
            return st

        if san is not None:
            return self.sanitized_taint(san, args, sf, env, ctx)

        # Callback arguments: analyse their bodies, binding parameters to the
        # receiver's taint where there is one (array.map, promise.then, and
        # Express `app.get('/x', (req,res) => ...)` all take this path).
        cb_taint = self.handle_callbacks(args, recv_taint, node, sf, env, ctx)

        ut = self.user_call_taint(callee, recv_root, args, node, sf, env, ctx)
        if ut is not None:
            return ut

        if callee in PROPAGATORS:
            merged = None
            for a in args:
                merged = _merge_taint(merged, self.taint_of(a, sf, env, ctx))
            if merged is not None:
                return merged
            if recv_taint is not None:
                return recv_taint
            return cb_taint

        if recv_taint is not None and callee not in NON_PROPAGATING:
            return recv_taint

        # Unresolved call: carry the arguments' taint rather than dropping it.
        # Sanitizers are matched earlier, so this does not defeat escaping.
        if callee not in NON_PROPAGATING:
            merged = None
            for a in args:
                merged = _merge_taint(merged, self.taint_of(a, sf, env, ctx))
            if merged is not None:
                return merged
        return cb_taint

    def handle_callbacks(self, args, recv_taint, node, sf, env, ctx):
        if ctx.depth >= MAX_DEPTH:
            return None
        merged = None
        for a in args:
            fn = ja.strip(a)
            if fn is None or fn.type not in ja.FUNCTION_NODES:
                continue
            body = ja.body_of(fn)
            if body is None:
                continue
            new_env = {**env, **self.request_params(fn, sf)}
            params = ja.param_names(fn)
            # An iteration/promise callback receives elements of the receiver.
            if recv_taint is not None and params:
                new_env[params[0]] = recv_taint.with_step(TaintStep(
                    location=_loc(sf, node),
                    description=f"value flows into callback parameter {params[0]}",
                    code=sf.node_line(node),
                ))
            sub = Ctx(depth=ctx.depth + 1, current_class=ctx.current_class)
            # Framework handler parameters (req/res) are sources by name, so
            # they need no binding here.
            merged = _merge_taint(merged, self.process_any(body, sf, new_env, sub))
        return merged

    def request_params(self, fn: Node, sf: SourceFile) -> dict:
        """Bindings for a handler that destructures the request object.

        `({ query, params }: Request, res) => ...` names no `req`, so the
        receiver hints never fire; each destructured key is matched as if it
        were read from `req.<key>`. The first parameter counts as the request
        when it is typed `Request` or a response parameter follows it.
        """
        params = fn.child_by_field_name("parameters")
        if params is None:
            return {}
        formals = [p for p in params.named_children if p.type != "comment"]
        if not formals:
            return {}
        first = formals[0]
        pattern = first.child_by_field_name("pattern") or first
        if pattern.type != "object_pattern":
            return {}
        annot = first.child_by_field_name("type")
        typed = annot is not None and "Request" in ja.text(annot)
        follows = (len(formals) > 1
                   and (ja.binding_names(formals[1]) or [""])[0] in _RESPONSE_PARAMS)
        if not (typed or follows):
            return {}
        env: dict = {}
        for c in pattern.named_children:
            if c.type == "shorthand_property_identifier_pattern":
                key, targets = ja.text(c), [ja.text(c)]
            elif c.type == "pair_pattern":
                k = c.child_by_field_name("key")
                key = ja.text(k) if k is not None else ""
                targets = ja.binding_names(c.child_by_field_name("value"))
            elif c.type == "object_assignment_pattern":
                left = c.child_by_field_name("left")
                key = ja.text(left) if left is not None else ""
                targets = ja.binding_names(left)
            else:
                continue
            st = self.source_taint("member", key, c, sf, obj_name="req",
                                   path="req." + key)
            if st is not None:
                for name in targets:
                    env[name] = st
        return env

    def user_call_taint(self, callee, recv_root, args, node, sf, env, ctx):
        if ctx.depth >= MAX_DEPTH or not callee:
            return None
        fsym = None
        if recv_root and ctx.current_class and recv_root == "this":
            fsym = self.symbols.lookup_method(ctx.current_class, callee)
        if fsym is None and not recv_root:
            # The same module's own function first: names like `verify` or
            # `handler` are defined in many files, and the global table keeps
            # only one of them.
            fsym = (self._function_in(os.path.normpath(sf.path), callee)
                    or self.symbols.lookup_function(callee))
        if fsym is None and recv_root and recv_root != "this":
            fsym = self._module_function(sf, recv_root, callee, node)
        if fsym is None:
            return None

        new_env = {}
        sig = []
        for i, p in enumerate(fsym.params):
            if i < len(args):
                t = self.taint_of(args[i], sf, env, ctx)
                if t is not None:
                    new_env[p] = t.with_step(TaintStep(
                        location=_loc(sf, node),
                        description=f"argument flows into parameter {p} of {fsym.name}()",
                        code=sf.node_line(node),
                    ))
                    sig.append((i, _taint_key(t)))
        key = (id(fsym.node), ctx.depth, tuple(sig))
        if key in self._call_memo:
            return self._call_memo[key]
        body = ja.body_of(fsym.node)
        if body is None:
            result = None
        else:
            self._call_memo[key] = None  # guard against recursion
            result = self.process_any(body, fsym.source, new_env,
                                      Ctx(depth=ctx.depth + 1,
                                          current_class=fsym.class_name))
        self._call_memo[key] = result
        return result

    def _apply_exit_guard(self, cond: str, env: dict) -> None:
        """Code after `if (<reject x>) return;` runs only for an accepted x.

        Narrowly: a redirect target that must start with "/" and must not
        start with "//" is a same-origin relative path, so it can no longer
        send the browser off-site. Checking only the first lets `//evil.com`
        through, so both are required.
        """
        for name in _relative_path_guarded(cond):
            t = env.get(name)
            if t is None or "redirect" not in t.tags:
                continue
            remaining = t.tags - {"redirect"}
            env[name] = Taint(tags=remaining, origins=list(t.origins),
                              steps=list(t.steps),
                              confidence=t.confidence) if remaining else None
            if env[name] is None:
                del env[name]

    def _check_computed_assign(self, left, vt, node, sf, env, ctx):
        """`target[key] = value` with both key and value attacker-controlled.

        This is what every hand-written deep merge does, and why it pollutes
        Object.prototype: a `__proto__` key in the input names the prototype.
        Library merges are matched by name; a merge the application wrote
        itself — vulnerable-node's `deepMerge` — has no name to match.
        """
        idx = left.child_by_field_name("index")
        if idx is None or ja.strip(idx).type in ("string", "number",
                                                 "template_string"):
            return
        kt = self.taint_of(idx, sf, env, ctx)
        if kt is None or "proto" not in kt.tags or "proto" not in vt.tags:
            return
        for sink in self.rules.sinks:
            if sink.kind == "computed_assign":
                self.report(sink, kt, node, sf)
                return

    def _module_function(self, sf, recv_root: str, callee: str, node: Node):
        """`db.login(...)` where `db = require("../model/db")`.

        Only bare calls were resolved, so a route reaching its data layer
        through a module object — the usual Express layout — was never
        followed, and the SQL built in model/db.js went unreported. The
        receiver must be bound to a relative require or import in this file
        and the function defined in that file; a package is not followed.
        """
        callee_node = node.child_by_field_name("function")
        obj = callee_node.child_by_field_name("object") \
            if callee_node is not None else None
        if obj is None or obj.type != "identifier":
            return None
        target = self._imports(sf).get(recv_root)
        if not target:
            return None
        return self._function_in(target, callee)

    def _function_in(self, path: str, name: str):
        """The function `name` declared in the file at normalised `path`."""
        if self._by_file is None:
            self._by_file = {}
            for fsym in self.symbols.all_functions:
                self._by_file.setdefault(
                    (os.path.normpath(fsym.source.path), fsym.name), fsym)
        return self._by_file.get((path, name))

    def _imports(self, sf) -> dict:
        """Local names bound to a relative module in one file, resolved."""
        cached = self._modules.get(sf.path)
        if cached is not None:
            return cached
        known = {os.path.normpath(f.source.path)
                 for f in self.symbols.all_functions}
        here = os.path.dirname(sf.path)
        out: dict = {}

        def resolve(spec: str) -> str:
            if not spec.startswith("."):
                return ""
            base = os.path.normpath(os.path.join(here, spec))
            for cand in (base, *(base + e for e in _JS_EXTS),
                         *(os.path.join(base, "index" + e) for e in _JS_EXTS)):
                if cand in known:
                    return cand
            return ""

        stack = [sf.root]
        while stack:
            n = stack.pop()
            if n.type == "variable_declarator":
                name, value = n.child_by_field_name("name"), \
                    n.child_by_field_name("value")
                value = ja.strip(value) if value is not None else None
                if (name is not None and name.type == "identifier"
                        and value is not None and value.type == "call_expression"):
                    fn = value.child_by_field_name("function")
                    if fn is not None and ja.text(fn) == "require":
                        spec = _first_string_arg(value)
                        target = resolve(spec) if spec else ""
                        if target:
                            out[ja.text(name)] = target
            elif n.type == "import_statement":
                src = n.child_by_field_name("source")
                target = resolve(_string_text(src)) if src is not None else ""
                if target:
                    for clause in n.named_children:
                        if clause.type != "import_clause":
                            continue
                        for c in clause.named_children:
                            if c.type == "identifier":
                                out[ja.text(c)] = target  # default import
                            elif c.type == "namespace_import":
                                for i in c.named_children:
                                    if i.type == "identifier":
                                        out[ja.text(i)] = target
            stack.extend(n.named_children)
        self._modules[sf.path] = out
        return out

    # ------------------------------------------------------------------
    # Rule matching
    # ------------------------------------------------------------------
    def source_taint(self, kind, name, node, sf, obj_name="", path="", args=None):
        for src in self.rules.sources:
            if src.kind != kind:
                continue
            if not match_callee(name, src.match):
                continue
            if src.obj_hint and not _hint_matches(src.obj_hint, obj_name, path):
                continue
            if src.arg_literal:
                idx, lit = src.arg_literal
                if not (args and len(args) > idx
                        and ja.literal_string(args[idx]) == lit):
                    continue
            return Taint(
                tags=set(src.tags),
                origins=[_loc(sf, node)],
                steps=[TaintStep(location=_loc(sf, node),
                                 description=src.description,
                                 code=sf.node_line(node))],
                confidence=src.confidence,
            )
        return None

    def match_sanitizer(self, callee, obj_name, arg_texts):
        for san in self.rules.sanitizers:
            if san.kind != "call":
                continue
            if not match_callee(callee, san.match):
                continue
            if san.cls and not _hint_matches(san.cls, obj_name, ""):
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
                    location=_loc(sf, node),
                    description=san.note or f"weak sanitizer {san.match}() applied",
                    code=sf.node_line(node))],
                confidence=weakest_confidence(t.confidence, "medium"),
            )
        if "*" in san.neutralize:
            return None
        remaining = t.tags - set(san.neutralize)
        if not remaining:
            return None
        return Taint(tags=remaining, origins=list(t.origins), steps=list(t.steps),
                     confidence=t.confidence)

    def check_call_sink(self, callee, recv_root, recv_path, args, node, sf, env,
                        ctx, recv_taint=None):
        for sink in self.rules.sinks:
            if sink.kind != "call":
                continue
            if not match_callee(callee, sink.match):
                continue
            if sink.obj_hint and not _hint_matches(sink.obj_hint, recv_root, recv_path):
                continue
            if sink.receivers and recv_root not in sink.receivers:
                continue
            if sink.receiver_tainted:
                # Dangerous for what it is called on: `zip.extractAllTo(dir)`
                # writes wherever the archive's own entry names point.
                if recv_taint is not None and set(sink.tags) & recv_taint.tags:
                    self.report(sink, recv_taint, node, sf)
                continue
            indices = range(len(args)) if sink.arg_index < 0 else [sink.arg_index]
            for i in indices:
                if i >= len(args):
                    continue
                shape = ja.strip(args[i])
                if not sink.shape_allows(shape.type if shape else ""):
                    continue
                t = self.taint_of(args[i], sf, env, ctx)
                if t is None:
                    continue
                if set(sink.tags) & t.tags:
                    self.report(sink, t, node, sf)
                    break

    def check_property_sink(self, left, right, vt, node, sf, env, ctx):
        """`el.innerHTML = tainted`, `location.href = tainted`, ..."""
        if vt is None:
            return
        left = ja.strip(left)
        if left is not None and left.type == "subscript_expression":
            self._check_computed_assign(left, vt, node, sf, env, ctx)
        if left is None or left.type not in ("member_expression", "subscript_expression"):
            return
        _, prop = ja.member_parts(left)
        root = ja.root_object(left)
        path = ja.member_path(left)
        for sink in self.rules.sinks:
            if sink.kind != "property_assign":
                continue
            if not match_callee(prop, sink.match):
                continue
            if sink.obj_hint and not _hint_matches(sink.obj_hint, root, path):
                continue
            if set(sink.tags) & vt.tags:
                self.report(sink, vt, node, sf)
                return

    def report(self, sink, taint: Taint, node: Node, sf: SourceFile) -> None:
        loc = _loc(sf, node)
        # One finding per rule and location. The source used to be part of
        # this key, so a sink reached from several sources was reported once
        # per source — the same line appearing eight times in OpenDoor's
        # report. A reviewer fixes the sink once, and the trace still shows a
        # representative path, so the extra copies were pure noise.
        key = (sink.rule_id, loc.file, loc.line, loc.column)
        if key in self._seen:
            return
        self._seen.add(key)
        trace = list(taint.steps[-MAX_STEPS:])
        trace.append(TaintStep(location=loc, description=sink.title,
                               code=sf.node_line(node)))
        source = taint.origins[0] if taint.origins else None
        self.findings.append(Finding(
            rule_id=sink.rule_id,
            title=sink.title,
            severity=Severity(sink.severity),
            cwe=sink.cwe,
            owasp=sink.owasp,
            category=sink.category,
            description=sink.description,
            remediation=sink.remediation,
            confidence=weakest_confidence(sink.confidence, taint.confidence),
            framework=self.framework,
            language=self.language,
            location=loc,
            source=source,
            trace=trace,
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
            cache[key] = _re.search(rule.absent, _code_text(sf)) is None
        return cache[key]

    def run_patterns(self, sf: SourceFile) -> None:
        if not self.rules.patterns:
            return
        # A text rule matching `node_type="*"` matches at every level of
        # nesting — the statement, its class, and the whole program all
        # contain the text — so collect matches first and report only the
        # innermost node, otherwise one occurrence becomes a dozen findings.
        matches: dict = {}
        for node in sf.walk():
            # Commented-out code is not code; see the generic engine.
            if node.type == "comment":
                continue
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
                    continue  # a nested node also matched; prefer that one
                self.emit_pattern(rule, node, sf)

    def _pattern_value(self, node: Node, field: str):
        if field == "text":
            return ja.text(node)
        if field == "callee":
            if ja.is_call(node):
                callee, receiver, _ = ja.call_parts(node)
                if receiver is not None:
                    return f"{ja.member_path(receiver)}.{callee}"
                return callee
            return None
        if field == "name":
            name = node.child_by_field_name("name")
            return ja.text(name) if name is not None else None
        return None

    def emit_pattern(self, rule, node: Node, sf: SourceFile) -> None:
        loc = _loc(sf, node)
        key = (rule.rule_id, loc.file, loc.line, loc.column)
        if key in self._seen:
            return
        if getattr(rule, "taint_backstop", False) and any(
                f.category == rule.category and f.location.file == loc.file
                and f.location.line == loc.line for f in self.findings):
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
            trace=[TaintStep(location=loc, description=rule.title,
                             code=sf.node_line(node))],
            tags=[rule.category],
        ))


def _code_text(sf: SourceFile) -> str:
    """The file's text with comments blanked: commented-out middleware such
    as `// app.use(helmet())` must not count as present."""
    content = bytearray(sf.content)
    stack = [sf.root]
    while stack:
        n = stack.pop()
        if n.type == "comment":
            content[n.start_byte:n.end_byte] = b" " * (n.end_byte - n.start_byte)
            continue
        stack.extend(n.children)
    return content.decode("utf-8", "replace")


def _always_exits(node) -> bool:
    """True when a branch ends by leaving the function."""
    if node is None:
        return False
    node = ja.strip(node) if node.type != "statement_block" else node
    if node.type in ("return_statement", "throw_statement"):
        return True
    if node.type == "statement_block":
        stmts = [c for c in node.named_children if c.type != "comment"]
        return bool(stmts) and stmts[-1].type in ("return_statement",
                                                  "throw_statement")
    return False


def _relative_path_guarded(cond: str) -> list:
    """Names the condition rejects unless they start with '/' but not '//'."""
    import re
    out = []
    for m in re.finditer(r"!\s*([A-Za-z_$][\w$]*)\.startsWith\(\s*([\"'`])/\2\s*\)",
                         cond):
        name = m.group(1)
        if re.search(re.escape(name) + r"\.startsWith\(\s*([\"'`])//\1\s*\)", cond):
            out.append(name)
    return out


_JS_EXTS = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts")


def _string_text(node) -> str:
    if node is None or node.type not in ("string", "template_string"):
        return ""
    return "".join(ja.text(c) for c in node.named_children
                   if c.type == "string_fragment")


def _first_string_arg(call) -> str:
    args = call.child_by_field_name("arguments")
    if args is None:
        return ""
    for a in args.named_children:
        if a.type == "string":
            return _string_text(a)
    return ""


def _hint_matches(hint: str, obj_name: str, path: str) -> bool:
    """Receiver hints match the root identifier or anywhere in the chain.

    `req`/`request` style hints are matched case-insensitively against the
    root object and the full dotted path, so `req.query`, `request.query` and
    `this.req.query` all resolve. `a|b` accepts either fragment.
    """
    alternatives = hint.lower().split("|")
    obj_name, path = (obj_name or "").lower(), (path or "").lower()
    return any(h in obj_name or h in path for h in alternatives)


def _merge_env(env: dict, other: dict) -> None:
    for k, t in other.items():
        if k not in env:
            env[k] = t
        else:
            env[k] = env[k].merge(t)
