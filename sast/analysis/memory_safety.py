"""Use-after-free, double-free and memory-leak detection for C and C++.

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

Leaks (CWE-401) are answered with a second, deliberately different question.
The states above are path-sensitive, which is what makes a use-after-free
claim precise; a leak claim needs the opposite, because "freed on one path"
still means "not leaked on that path" and reporting it would be noise. So a
leak is decided on function-wide facts instead: a local that was allocated
here, never freed on *any* path, and never *escaped* this function. Escaping
covers being returned, stored through a pointer or into a field, assigned to
anything not declared here, having its address taken, or being handed to a
function that is not on the borrowing list below. Anything unknown is assumed
to take ownership, so the default on an unrecognised callee is silence.
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

# Standard-library calls that read or write through a pointer without keeping
# it. Passing a pointer to anything *not* on this list is treated as handing
# over ownership, because a function that stores it somewhere is
# indistinguishable from one that does not without looking inside it — and
# guessing the other way would report a leak every time memory is passed to a
# helper. The cost of that choice is a missed leak; the cost of the reverse is
# a false one on correct code, which is worse.
BORROWING = frozenset({
    # Copies and comparisons.
    "strcpy", "strncpy", "strlcpy", "strcat", "strncat", "strlcat",
    "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strcoll", "strxfrm",
    "strlen", "strnlen", "strchr", "strrchr", "strstr", "strcasestr",
    "strspn", "strcspn", "strpbrk", "strtok", "strtok_r",
    "memcpy", "memmove", "memset", "memcmp", "memchr", "memrchr", "bzero",
    # Formatted and unformatted I/O.
    "printf", "fprintf", "sprintf", "snprintf", "dprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "puts", "fputs", "fwrite", "fread", "perror", "write", "read",
    "send", "recv", "sendto", "recvfrom", "fflush",
    "scanf", "sscanf", "fscanf", "vsscanf",
    # Conversions and character classification.
    "atoi", "atol", "atoll", "atof",
    "strtol", "strtoul", "strtoll", "strtoull", "strtod", "strtof",
    "isalpha", "isdigit", "isalnum", "isspace", "isupper", "islower",
    "toupper", "tolower",
    # Deallocation is handled on its own, but naming it here keeps a
    # `free(p)` from being read as an ownership transfer if the order of the
    # checks below ever changes.
    "free", "cfree",
})

# Reported once per function at its end: an allocation that never came back.
LEAK_RULE = "c-memory-leak"

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
        # Function-wide leak bookkeeping, reset per function. These are
        # deliberately *not* path-sensitive: see the module docstring.
        self._declared: set = set()
        self._alloc_sites: dict = {}
        self._escaped: set = set()
        self._freed_any: set = set()
        self._groups: dict = {}
        self._leaks: dict = {}
        self._guarded: list = []

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
                self._begin_function(body)
                self._walk_block(body, sf, {})
                self._report_leaks(sf)
        return self.findings

    # ------------------------------------------------------------------
    # Leak bookkeeping
    def _begin_function(self, body: Node) -> None:
        self._declared = _declared_locals(body)
        self._alloc_sites = {}
        self._escaped = set()
        self._freed_any = set()
        self._groups = {}
        self._leaks = {}
        self._guarded = []

    def _group(self, name: str) -> set:
        """The must-alias group `name` belongs to, created on first use."""
        group = self._groups.get(name)
        if group is None:
            group = {name}
            self._groups[name] = group
        return group

    def _alias(self, a: str, b: str) -> None:
        """Record that `a` and `b` name the same block from here on."""
        merged = self._group(a) | self._group(b)
        for name in merged:
            self._groups[name] = merged

    def _mark_escaped(self, node: Node) -> None:
        """Every name appearing in `node` leaves this function's control."""
        for name in _names_in(node):
            self._escaped |= self._group(name)

    def _mark_freed(self, name: str) -> None:
        self._freed_any |= self._group(name)

    def _note_return(self, node: Node, states: dict) -> None:
        """Record an allocation still held when this `return` is taken.

        This is the error-path leak, and it is the common one: allocate,
        notice something else went wrong, return early, and the block is
        gone. It has to be judged where the return is rather than at the end
        of the function, because a `free` further down does run on the normal
        path and so says nothing about this one.

        Escapes are read as they stand *at this point* in the walk, which is
        exactly right: a `store(p)` written below this return did not run on
        the path that took it.
        """
        for name, state in states.items():
            if state.status != ALLOCATED or name not in self._alloc_sites:
                continue
            if self._group(name) & self._escaped:
                continue
            if any(name in names for names in self._guarded):
                # The branch that returns is itself conditional on this
                # pointer, so this is `if (!p) return -1;` — the allocation
                # failed and there is nothing to leak. Reporting it would put
                # a finding on the check that makes the code correct.
                continue
            self._leaks.setdefault(name, (
                self._alloc_sites[name],
                f"'{name}' is allocated here, and the function returns at "
                f"line {node.start_point.row + 1} without freeing it. A "
                "`free` on the normal path does not cover this one, so every "
                "call that takes the early return loses the block.",
            ))

    def _report_leaks(self, sf: SourceFile) -> None:
        # Path-specific leaks first: their message names the return that
        # loses the block, which is more use to a reviewer than the general
        # case, and recording one suppresses the general report below.
        for site, detail in self._leaks.values():
            self._emit_leak(detail, site, sf)
        for name, site in self._alloc_sites.items():
            if name in self._leaks:
                continue
            group = self._group(name)
            if group & self._escaped or group & self._freed_any:
                continue
            self._emit_leak(
                f"'{name}' is allocated here and the block is never freed, "
                "returned, stored anywhere outside this function, or passed "
                "to a function that could take ownership of it. Every call "
                "to this function loses the allocation, so a caller that "
                "runs it per request grows without bound until the process "
                "is killed.",
                site, sf)

    def _emit_leak(self, description: str, site: Node,
                   sf: SourceFile) -> None:
        self._report(
            LEAK_RULE, "Memory leak", "low", "CWE-401", description,
            "Free the block on every path out of the function, including "
            "the error paths; or return it and document that the caller "
            "owns it.",
            site, sf, None, confidence="medium")

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
            condition = node.child_by_field_name("condition")
            self._check_expression(condition, sf, states)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            branches = []
            # Names the condition mentions are off-limits to the leak check
            # inside either arm: a branch taken because of the pointer's own
            # value says nothing about whether a block was lost.
            self._guarded.append(set(_names_in(condition)))
            for child in (consequence, alternative):
                if child is None:
                    continue
                branch = {k: v.copy() for k, v in states.items()}
                self._walk_stmt(child, sf, branch)
                branches.append(branch)
            self._guarded.pop()
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
            # `malloc(n);` on its own throws the only reference away as the
            # statement ends. Nothing needs to be tracked to know that is a
            # leak, and there is no variable to name in the report.
            if inner and self._allocation_call(inner[0]) is not None:
                self._report(
                    LEAK_RULE, "Memory leak", "low", "CWE-401",
                    "The allocated block's address is discarded as this "
                    "statement ends, so the memory can never be freed.",
                    "Keep the returned pointer and free it, or drop the "
                    "allocation.",
                    inner[0], sf, None, confidence="high")
                return
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
                self._mark_escaped(c)
                name = self._base_name(c)
                if name:
                    states.pop(name, None)
            self._note_return(node, states)
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
            # `*out = p` and `s->buf = p` hand the block to whatever owns the
            # left side, which outlives this function.
            self._mark_escaped(right)
            return

        name = self._base_name(left)
        if not name:
            return
        # Assigning to anything this function did not declare — a global, a
        # parameter, a static — publishes the block somewhere another function
        # can free it, so it is not this function's to leak.
        if name not in self._declared:
            self._mark_escaped(right)

        allocated_from = self._allocation_call(right)
        if allocated_from is not None:
            states[name] = _State(ALLOCATED)
            if name in self._declared:
                self._alloc_sites[name] = allocated_from
            return
        # `q = p` makes q another name for the same memory, so freeing either
        # invalidates both. Only a bare identifier counts: anything computed
        # needs an alias analysis this does not have.
        if right is not None and right.type == "identifier":
            other = _text(right)
            self._alias(name, other)
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
        return _base_name_of(node)

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
                self._mark_freed(target)
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
                self._mark_freed(target)
                states[target] = _State(FREED, node)
            return

        for arg in args:
            self._check_expression(arg, sf, states)
        # A callee that is not known to merely borrow may store the pointer,
        # free it, or both, so the block stops being this function's to leak.
        # Taking the address of a local does the same thing: the callee can
        # reassign it out from under us.
        if name not in BORROWING:
            for arg in args:
                self._mark_escaped(arg)
        else:
            for arg in args:
                for addressed in _address_taken(arg):
                    self._mark_escaped(addressed)

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


def _names_in(node: Node):
    """Every identifier appearing anywhere in an expression."""
    if node is None:
        return
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier":
            yield _text(current)
            continue
        stack.extend(current.named_children)


def _address_taken(node: Node):
    """The operands of every `&x` inside an expression.

    `scanf("%s", &p)` and `get_buffer(&p)` both let the callee replace `p`,
    which means the block it pointed at is no longer this function's to
    account for even when the callee only borrows what it is given.
    """
    if node is None:
        return
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in ("pointer_expression", "unary_expression"):
            op = current.child_by_field_name("operator")
            if op is not None and _text(op) == "&":
                argument = current.child_by_field_name("argument")
                if argument is not None:
                    yield argument
                    continue
        stack.extend(current.named_children)


def _declared_locals(body: Node) -> set:
    """Names this function declares, excluding `static` ones.

    A `static` local outlives the call, so its allocation is not lost when
    the function returns and reporting it would be wrong. Scoping within the
    function is ignored on purpose: the question a leak asks is whether the
    block survived the whole call, so an inner block's name is still this
    function's responsibility.
    """
    names: set = set()
    stack = [body]
    while stack:
        node = stack.pop()
        if node.type == "declaration":
            if any(c.type == "storage_class_specifier" and _text(c) == "static"
                   for c in node.named_children):
                continue
            for child in node.named_children:
                target = child
                if child.type == "init_declarator":
                    target = child.child_by_field_name("declarator")
                name = _base_name_of(target)
                if name:
                    names.add(name)
            continue
        stack.extend(node.named_children)
    return names


def _base_name_of(node: Node) -> str:
    """The variable a declarator ultimately names."""
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
