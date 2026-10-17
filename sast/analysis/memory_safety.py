"""Use-after-free and double-free detection for C and C++.

The taint engines answer "where does attacker data reach a dangerous call".
That is the whole question in a managed language, but in C the dominant
vulnerability class does not involve attacker data reaching anything: a
pointer is freed and then used, or freed twice, and the bug exists regardless
of where the values came from. No amount of source-to-sink tracking finds it,
which is why a C scanner without this has a visible hole.

The analysis is deliberately small and intra-procedural. Per function it walks
the statements in order, holding a state for each local pointer:

* ``ALLOCATED`` — it came from malloc and friends
* ``FREED``     — free() was called on it on every path to here
* ``MAYBE``     — free() was called on some path but not all

A use while ``FREED`` is reported with high confidence and one while ``MAYBE``
with medium, because the second depends on which branch ran. Assigning the
pointer again, or setting it to NULL, clears the state — which is why
``free(p); p = NULL;`` is the recommended idiom and must not be reported.

What it deliberately does not do: reason across function boundaries (a pointer
handed to another function may be freed or stored there, so a parameter is
never tracked), reason about loop iterations, or follow a pointer into a
struct field or an array element. Each of those needs an alias analysis to
stay sound, and guessing without one produces false reports on correct code.
Simple must-aliasing from a direct assignment *is* tracked, since
``q = p; free(p); use(q);`` is a common shape and unambiguous.
"""
from __future__ import annotations

from tree_sitter import Node

from ..models import Finding, Location, Severity, TaintStep
from ..parsing.source import SourceFile

A06 = "A06:2021 — Vulnerable and Outdated Components"

# Calls that hand back owned memory.
ALLOCATORS = frozenset({
    "malloc", "calloc", "realloc", "strdup", "strndup", "aligned_alloc",
    "valloc", "memalign", "posix_memalign", "reallocarray",
})
# Calls that release it. `realloc` both frees and allocates, so it is handled
# on its own rather than appearing here.
DEALLOCATORS = frozenset({"free", "cfree"})

ALLOCATED, FREED, MAYBE = "allocated", "freed", "maybe-freed"

# Node types whose appearance means the pointer's value is being read.
_DEREF = ("pointer_expression", "field_expression", "subscript_expression")


class _State:
    """Per-variable allocation state, plus where the free happened."""

    __slots__ = ("status", "free_node", "aliases")

    def __init__(self, status: str, free_node: Node = None, aliases=None):
        self.status = status
        self.free_node = free_node
        self.aliases = set(aliases or ())

    def copy(self) -> "_State":
        return _State(self.status, self.free_node, self.aliases)


def _text(node: Node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _merge(into: dict, branch: dict) -> None:
    """Join a conditional branch's states into the outer ones.

    A free on a branch that may not have run leaves the pointer MAYBE freed,
    not FREED: reporting it as certain would put a high-confidence finding on
    code that is correct whenever the other path is taken. Certainty is
    restored only by `_join_certain`, when every arm of an if/else frees.
    """
    for name, state in branch.items():
        weakened = MAYBE if state.status == FREED else state.status
        outer = into.get(name)
        if outer is None:
            into[name] = _State(weakened, state.free_node, state.aliases)
        elif outer.status == state.status:
            outer.free_node = outer.free_node or state.free_node
        elif FREED in (outer.status, state.status) or \
                MAYBE in (outer.status, state.status):
            outer.status = MAYBE
            outer.free_node = state.free_node or outer.free_node
        else:
            outer.status = state.status


class MemorySafetyChecker:
    """Finds use-after-free and double-free in one C or C++ translation unit."""

    def __init__(self, language: str = "c") -> None:
        self.language = language
        self.findings: list[Finding] = []
        self._seen: set = set()

    # ------------------------------------------------------------------
    def analyze(self, files: list[SourceFile]) -> list[Finding]:
        for sf in files:
            for fn in self._functions(sf.root):
                body = fn.child_by_field_name("body")
                if body is None:
                    continue
                if _has_goto(body):
                    # A goto can jump past a free or into the middle of a
                    # cleanup block, so the order statements appear in is no
                    # longer the order they run in. This walk assumes it is,
                    # so skip the function rather than report on a path that
                    # may not exist — which is what cJSON's `goto cleanup`
                    # error handling turned into a false use-after-free.
                    continue
                self._walk_block(body, sf, {})
        return self.findings

    def _functions(self, root: Node):
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "function_definition":
                yield node
                continue  # a nested definition is its own scope
            stack.extend(node.named_children)

    # ------------------------------------------------------------------
    def _walk_block(self, block: Node, sf: SourceFile, states: dict) -> None:
        for stmt in block.named_children:
            self._walk_stmt(stmt, sf, states)

    def _walk_stmt(self, node: Node, sf: SourceFile, states: dict) -> None:
        t = node.type
        if t in ("comment", "line_comment", "block_comment"):
            return

        if t == "compound_statement":
            self._walk_block(node, sf, states)
            return

        if t in ("labeled_statement", "case_statement"):
            # The inner statements are statements, not expressions. Letting
            # them fall through to the expression walk below meant an
            # assignment inside a labelled block was read as a *use* of its
            # left-hand side, so the `free(p); p = NULL;` idiom under a
            # `cleanup:` label reported a use-after-free on the NULL store.
            for child in node.named_children:
                if child.type not in ("statement_identifier",):
                    self._walk_stmt(child, sf, states)
            return

        if t in ("break_statement", "continue_statement", "goto_statement"):
            return

        if t == "if_statement":
            self._check_expression(node.child_by_field_name("condition"),
                                   sf, states)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            branches = []
            for child in (consequence, alternative):
                if child is None:
                    continue
                branch = {k: v.copy() for k, v in states.items()}
                self._walk_stmt(child, sf, branch)
                branches.append(branch)
            # With no else, one path skips the branch entirely, so nothing a
            # branch did is certain — each merge can only weaken a free to
            # MAYBE. When both arms are present and both free, the join below
            # restores certainty.
            for branch in branches:
                _merge(states, branch)
            if alternative is not None and len(branches) == 2:
                self._join_certain(states, branches)
            return

        if t in ("while_statement", "for_statement", "do_statement",
                 "switch_statement"):
            # A loop body may run zero, one or many times, and a switch picks
            # one arm, so nothing either does is certain on every path.
            branch = {k: v.copy() for k, v in states.items()}
            for child in node.named_children:
                self._walk_stmt(child, sf, branch)
            _merge(states, branch)
            return

        if t == "declaration":
            for child in node.named_children:
                if child.type == "init_declarator":
                    self._handle_assign(
                        child.child_by_field_name("declarator"),
                        child.child_by_field_name("value"), sf, states)
                else:
                    self._check_expression(child, sf, states)
            return

        if t == "expression_statement":
            inner = [c for c in node.named_children
                     if c.type not in ("comment",)]
            if inner and inner[0].type == "assignment_expression":
                self._handle_assign(inner[0].child_by_field_name("left"),
                                    inner[0].child_by_field_name("right"),
                                    sf, states)
                return
            for c in inner:
                self._check_expression(c, sf, states)
            return

        if t == "return_statement":
            for c in node.named_children:
                self._check_expression(c, sf, states)
            # Whatever is returned leaves this function's ownership.
            for c in node.named_children:
                name = self._base_name(c)
                if name:
                    states.pop(name, None)
            return

        if t == "assignment_expression":
            # Reached bare in a for-initialiser or a comma expression.
            self._handle_assign(node.child_by_field_name("left"),
                                node.child_by_field_name("right"), sf, states)
            return

        # Anything else: look through it for uses and calls.
        self._check_expression(node, sf, states)

    @staticmethod
    def _join_certain(states: dict, branches: list) -> None:
        """Both arms present: a free in every arm is certain, not maybe."""
        names = set(branches[0]) & set(branches[1])
        for name in names:
            if all(b[name].status == FREED for b in branches):
                state = states.get(name)
                if state is not None:
                    state.status = FREED
                    state.free_node = (branches[0][name].free_node
                                       or branches[1][name].free_node)

    # ------------------------------------------------------------------
    def _handle_assign(self, left: Node, right: Node, sf: SourceFile,
                       states: dict) -> None:
        if right is not None:
            self._check_expression(right, sf, states)
        # `q[0] = 'x'`, `*q = 'x'` and `q->f = 0` all *use* q — a write
        # through a freed pointer is a use-after-free, and the worse kind.
        # Only a bare name rebinds, so treating every assignment as a rebind
        # dropped the state and reported nothing.
        if left is not None and left.type in _DEREF:
            self._check_expression(left, sf, states)
            return

        name = self._base_name(left)
        if not name:
            return

        allocated_from = self._allocation_call(right)
        if allocated_from is not None:
            states[name] = _State(ALLOCATED)
            return
        # `q = p` makes q another name for the same memory, so freeing either
        # invalidates both. Only a bare identifier counts: anything computed
        # needs an alias analysis this does not have.
        if right is not None and right.type == "identifier":
            other = _text(right)
            source = states.get(other)
            if source is not None:
                source.aliases.add(name)
                shared = _State(source.status, source.free_node,
                                source.aliases | {other})
                states[name] = shared
                return
        # Any other assignment — including `p = NULL`, the correct idiom after
        # a free — replaces the pointer, so the old state no longer applies.
        states.pop(name, None)

    @staticmethod
    def _allocation_call(node: Node):
        """The allocator call in `node`, looking through a cast."""
        seen = 0
        while node is not None and seen < 6:
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and _text(fn).rsplit("::", 1)[-1] in ALLOCATORS:
                    return node
                return None
            if node.type in ("cast_expression", "parenthesized_expression"):
                node = node.child_by_field_name("value") or (
                    node.named_children[-1] if node.named_children else None)
                seen += 1
                continue
            return None
        return None

    @staticmethod
    def _base_name(node: Node) -> str:
        """The variable a declarator or lvalue ultimately names."""
        seen = 0
        while node is not None and seen < 8:
            if node.type == "identifier":
                return _text(node)
            kids = [c for c in node.named_children if c.type != "comment"]
            if not kids:
                return ""
            node = kids[0]
            seen += 1
        return ""

    # ------------------------------------------------------------------
    def _check_expression(self, node: Node, sf: SourceFile,
                          states: dict) -> None:
        """Walk an expression, reporting uses of freed memory and double frees."""
        if node is None:
            return
        if node.type == "call_expression":
            self._check_call(node, sf, states)
            return
        if node.type == "identifier":
            self._report_use(node, _text(node), sf, states)
            return
        if node.type in _DEREF:
            name = self._base_name(node)
            if name:
                self._report_use(node, name, sf, states)
            # Still walk the index expression, which is its own use.
            for child in node.named_children[1:]:
                self._check_expression(child, sf, states)
            return
        for child in node.named_children:
            self._check_expression(child, sf, states)

    def _check_call(self, node: Node, sf: SourceFile, states: dict) -> None:
        fn = node.child_by_field_name("function")
        name = _text(fn).rsplit("::", 1)[-1] if fn is not None else ""
        args_node = node.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node is not None else []

        if name in DEALLOCATORS and args:
            target = self._base_name(args[0])
            state = states.get(target) if target else None
            if state is not None and state.status in (FREED, MAYBE):
                self._report(
                    "c-double-free" if state.status == FREED
                    else "c-double-free-conditional",
                    "Double free" if state.status == FREED
                    else "Possible double free",
                    "critical" if state.status == FREED else "high",
                    "CWE-415",
                    f"'{target}' was already freed"
                    + (" on this path" if state.status == FREED
                       else " on some path to here")
                    + ". Freeing it again corrupts the allocator's metadata, "
                    "which is reliably exploitable.",
                    "Free once, and set the pointer to NULL immediately after "
                    "so a later free is a no-op.",
                    node, sf, state.free_node,
                    confidence="high" if state.status == FREED else "medium")
            if target:
                freed = _State(FREED, node, state.aliases if state else ())
                states[target] = freed
                for alias in freed.aliases:
                    if alias != target:
                        states[alias] = _State(FREED, node, freed.aliases)
            return

        if name == "realloc" and args:
            # realloc frees the old block; using the old pointer afterwards is
            # a use-after-free, so the argument's state ends here.
            target = self._base_name(args[0])
            for arg in args:
                self._check_expression(arg, sf, states)
            if target:
                # The old block is gone whether or not realloc moved it, so
                # the old pointer is freed rather than merely unknown.
                states[target] = _State(FREED, node)
            return

        for arg in args:
            self._check_expression(arg, sf, states)

    def _report_use(self, node: Node, name: str, sf: SourceFile,
                    states: dict) -> None:
        state = states.get(name)
        if state is None or state.status not in (FREED, MAYBE):
            return
        certain = state.status == FREED
        self._report(
            "c-use-after-free" if certain else "c-use-after-free-conditional",
            "Use after free" if certain else "Possible use after free",
            "critical" if certain else "high",
            "CWE-416",
            f"'{name}' is used after it was freed"
            + ("" if certain else " on some path to here")
            + ". The allocator may have handed the block to another "
            "allocation, so this reads or writes memory that now belongs "
            "elsewhere.",
            "Set the pointer to NULL after freeing it, and re-check before "
            "every use; or restructure so the lifetime is obvious.",
            node, sf, state.free_node,
            confidence="high" if certain else "medium")

    def _report(self, rule_id, title, severity, cwe, description, remediation,
                node, sf, free_node, confidence) -> None:
        loc = _loc(sf, node)
        key = (rule_id, loc.file, loc.line, loc.column)
        if key in self._seen:
            return
        self._seen.add(key)
        trace = []
        if free_node is not None:
            freed_at = _loc(sf, free_node)
            trace.append(TaintStep(location=freed_at,
                                   description="freed here",
                                   code=freed_at.code))
        trace.append(TaintStep(location=loc, description=title, code=loc.code))
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=Severity(severity),
            cwe=cwe, owasp=A06, category="memory-safety",
            description=description, remediation=remediation,
            confidence=confidence, framework="raw", language=self.language,
            location=loc, source=None, trace=trace, tags=["memory-safety"],
        ))


def _has_goto(body: Node) -> bool:
    stack = [body]
    while stack:
        node = stack.pop()
        if node.type == "goto_statement":
            return True
        stack.extend(node.named_children)
    return False


def _loc(sf: SourceFile, node: Node) -> Location:
    return Location(
        file=sf.path,
        line=node.start_point.row + 1,
        column=node.start_point.column + 1,
        end_line=node.end_point.row + 1,
        end_column=node.end_point.column + 1,
        code=sf.node_line(node),
    )


def scan_memory_safety(files: list[SourceFile], language: str) -> list[Finding]:
    """Entry point: findings for one C or C++ language pass."""
    return MemorySafetyChecker(language).analyze(files)
