"""Rule model: taint sources, sinks, sanitizers, and pattern rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

ALL = ("*",)  # applies to every framework


def _framework_applies(rule_frameworks, detected):
    """True if a rule (with given frameworks tuple) applies to `detected`."""
    if not rule_frameworks or rule_frameworks == ALL or "*" in rule_frameworks:
        return True
    return detected in rule_frameworks


@dataclass
class TaintSource:
    """An expression that introduces attacker-controlled data."""
    kind: str                 # 'superglobal' | 'function' | 'method' | 'static'
    match: str                # name to match (superglobal name, function/method name)
    tags: list[str]           # vulnerability classes this source can reach
    description: str
    frameworks: tuple = ALL
    cls: Optional[str] = None  # class name, for 'static'/'method' matching
    arg_literal: Optional[tuple] = None  # (arg_index, literal) — only a source when arg matches
    obj_hint: Optional[str] = None  # substring the receiver must contain (Java)
    # Subscript keys this source applies to, e.g. $_SERVER['HTTP_HOST']. An
    # entry ending in '*' matches by prefix. None = any key (whole container).
    keys: Optional[tuple] = None
    # How certain we are the data is attacker-controlled. Propagated into the
    # finding so second-order sources ($_SESSION, $_ENV) report below direct
    # request input. One of 'high' | 'medium' | 'low'.
    confidence: str = "high"
    # Argument positions this call *writes into*, for the C-style convention of
    # filling a caller-supplied buffer and returning only a count or status:
    # `fread(&img, ...)`, `recv(fd, buf, ...)`, `scanf("%d", &n)`. Modelling
    # those as return-value sources taints the wrong expression, so the data
    # read from the network or a file looked clean to every later sink.
    # Indices past the end of the argument list are ignored, which is how a
    # varargs family like scanf covers its whole tail.
    out_args: Optional[tuple] = None
    # True when the return value is *not* itself attacker data — fread returns
    # an item count, read a byte count. Without this they would taint an
    # integer, and a size check on it would look like a tainted allocation.
    out_only: bool = False
    # Regex that must appear somewhere in the file for this source to apply.
    # Some attacker-controlled values are reached through an attribute name
    # too common to claim unconditionally: `self.path` is the request line in
    # an http.server handler and a filename in everything else. Gating on the
    # base class the file actually names keeps the source without the noise.
    file_requires: Optional[str] = None

    def file_allows(self, text: str) -> bool:
        if not self.file_requires:
            return True
        cached = getattr(self, "_file_re", None)
        if cached is None:
            import re
            cached = re.compile(self.file_requires)
            object.__setattr__(self, "_file_re", cached)
        return bool(cached.search(text))

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)

    def key_matches(self, key: Optional[str]) -> bool:
        """True if a subscript key selects this source.

        A source restricted to specific keys never matches an unknown key
        (``None``, i.e. a dynamic subscript or whole-container access), so a
        broader fallback rule can handle those instead.
        """
        if self.keys is None:
            return True
        if key is None:
            return False
        for want in self.keys:
            if want.endswith("*"):
                if key.startswith(want[:-1]):
                    return True
            elif key == want:
                return True
        return False


@dataclass
class SinkRule:
    """A dangerous operation that becomes a finding when reached by taint."""
    rule_id: str
    kind: str                 # 'function' | 'method' | 'static' | 'echo' | 'include' | 'object_create' | 'print'
    match: str                # function/method/class name
    title: str
    severity: str
    cwe: str
    owasp: str
    category: str
    description: str
    remediation: str
    tags: list[str]           # taint tags that trigger this sink
    arg_index: int = -1       # -1 = any argument; else 0-based argument position
    frameworks: tuple = ALL
    cls: Optional[str] = None
    obj_hint: Optional[str] = None  # substring the receiver must contain (Java)
    confidence: str = "high"
    # Fire on taint in the *receiver* rather than an argument. A handful of
    # sinks are dangerous because of what they are called on, not what they
    # are passed: `untrusted.format(x)` can walk attributes out of x, whereas
    # `"literal {}".format(untrusted)` is ordinary formatting. Checking the
    # arguments for these would invert the rule.
    receiver_tainted: bool = False

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)


@dataclass
class SanitizerRule:
    """A call that neutralizes specific taint tags in its arguments.

    Escaping is only sound for the context it was designed for, and several
    widely-used functions are conditional on their arguments. A rule that
    clears taint unconditionally turns those cases into silent false
    negatives, so a rule can instead be marked `weak` (lowers confidence but
    keeps the finding) or be gated on `required_arg`.
    """
    kind: str                 # 'function' | 'method' | 'static'
    match: str
    neutralize: list[str]     # tags to remove, or ['*'] for all
    frameworks: tuple = ALL
    cls: Optional[str] = None
    arg_index: int = 0        # which argument is sanitized
    # Escapes, but with a documented bypass or a context caveat. The finding
    # survives at reduced confidence instead of disappearing.
    weak: bool = False
    # Minimum argument count for the call to sanitize at all. filter_var($x)
    # with no filter is a no-op, for example.
    min_args: int = 0
    # (index, (substring, ...)) — one of the substrings must appear in that
    # argument, e.g. ENT_QUOTES for htmlspecialchars to escape single quotes.
    required_arg: Optional[tuple] = None
    # Explains the caveat; surfaced in the trace of a weak-sanitizer finding.
    note: str = ""

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)

    def args_satisfied(self, arg_texts: list) -> bool:
        """True if the call's arguments meet this rule's preconditions."""
        if len(arg_texts) < self.min_args:
            return False
        if self.required_arg:
            idx, wanted = self.required_arg
            if idx >= len(arg_texts):
                return False
            text = arg_texts[idx] or ""
            if not any(w in text for w in wanted):
                return False
        return True


@dataclass
class PatternRule:
    """A non-taint syntactic/semantic check (weak crypto, dangerous config...)."""
    rule_id: str
    node_type: str            # node type to match, or '*' for any
    match: str                # literal or regex
    match_field: str = "text"  # 'text' | 'callee' | 'name'
    title: str = ""
    severity: str = "medium"
    cwe: str = ""
    owasp: str = ""
    category: str = ""
    description: str = ""
    remediation: str = ""
    frameworks: tuple = ALL
    regex: bool = False
    confidence: str = "high"
    # Match case-insensitively. Needed wherever identifiers are matched by
    # name, since `$apiKey` and `api_key` are the same thing to a reader.
    ignore_case: bool = False
    # Only fire when this regex does NOT appear anywhere in the file. Lets a
    # rule express "this was created but never hardened" — a cookie built
    # without setSecure, for instance — which a per-node match cannot say.
    absent: Optional[str] = None

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)

    def compiled(self):
        """Cached compiled regex for this rule (None when not a regex rule)."""
        if not self.regex:
            return None
        cached = getattr(self, "_compiled", None)
        if cached is None:
            import re
            cached = re.compile(self.match, re.IGNORECASE if self.ignore_case else 0)
            object.__setattr__(self, "_compiled", cached)
        return cached


@dataclass
class RuleSet:
    sources: list = field(default_factory=list)
    sinks: list = field(default_factory=list)
    sanitizers: list = field(default_factory=list)
    patterns: list = field(default_factory=list)

    def for_framework(self, framework: str) -> "RuleSet":
        return RuleSet(
            sources=[r for r in self.sources if r.applies(framework)],
            sinks=[r for r in self.sinks if r.applies(framework)],
            sanitizers=[r for r in self.sanitizers if r.applies(framework)],
            patterns=[r for r in self.patterns if r.applies(framework)],
        )
