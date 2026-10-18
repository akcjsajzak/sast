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
    # (arg_index, (literal, ...)) — *not* a source when that argument is one of
    # these. `System.getProperty` is a plausible source in general, but the
    # JVM's own properties ("os.name", "user.dir") are configuration the
    # attacker does not set, and treating them as request data put a finding on
    # every servlet that asked the platform where it was running.
    arg_not_literal: Optional[tuple] = None

    def arg_allows(self, arg_texts: list) -> bool:
        """False when an argument rules this source out."""
        if self.arg_not_literal:
            idx, blocked = self.arg_not_literal
            if idx < len(arg_texts):
                text = (arg_texts[idx] or "").strip().strip('"\'')
                if text in blocked:
                    return False
        return True
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
    # Receiver names the call must be made on, matched exactly against the
    # last segment of the receiver (`request` in `self.request.json()`).
    # obj_hint is a substring test, which is right for a hint like "Statement"
    # but makes "request" match `requests.post(url)` — the HTTP client, whose
    # return value is a response, not attacker input. Generic engine only.
    receivers: Optional[tuple] = None

    def file_allows(self, text: str) -> bool:
        return _file_gate_allows(self, text)

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
    # Node types the matched argument must have for the sink to apply.
    # `res.send(x)` is XSS only when x is a string: Express sends an object or
    # an array as JSON, which a browser never renders as HTML, so reporting
    # those put 18 false findings on one application. Empty means any shape.
    arg_shape: tuple = ()

    def shape_allows(self, node_type: str) -> bool:
        return not self.arg_shape or node_type in self.arg_shape

    # Fire on taint in the *receiver* rather than an argument. A handful of
    # sinks are dangerous because of what they are called on, not what they
    # are passed: `untrusted.format(x)` can walk attributes out of x, whereas
    # `"literal {}".format(untrusted)` is ordinary formatting. Checking the
    # arguments for these would invert the rule.
    receiver_tainted: bool = False
    # Regex that must appear somewhere in the file for this sink to apply,
    # for a library function whose name is too common to claim on its own:
    # SQLAlchemy's `text()` is one import away from any project's own
    # `text()` helper. Honoured by the generic engine, like the same field
    # on TaintSource.
    file_requires: Optional[str] = None
    # Regex over the call's argument text that makes it safe: an explicit
    # `Loader=yaml.SafeLoader` turns yaml.load() into safe_load(). Matched
    # against every argument, keyword arguments included. Generic engine.
    safe_args: Optional[str] = None

    def file_allows(self, text: str) -> bool:
        return _file_gate_allows(self, text)

    def args_safe(self, arg_texts: list) -> bool:
        if not self.safe_args:
            return False
        cached = getattr(self, "_safe_re", None)
        if cached is None:
            import re
            cached = re.compile(self.safe_args)
            object.__setattr__(self, "_safe_re", cached)
        return any(cached.search(t or "") for t in arg_texts)

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)


def _file_gate_allows(rule, text: str) -> bool:
    """Whether `rule.file_requires` matches the file, compiling it once."""
    if not rule.file_requires:
        return True
    cached = getattr(rule, "_file_re", None)
    if cached is None:
        import re
        cached = re.compile(rule.file_requires)
        object.__setattr__(rule, "_file_re", cached)
    return bool(cached.search(text))


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
