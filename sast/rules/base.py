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

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)


@dataclass
class SanitizerRule:
    """A call that neutralizes specific taint tags in its arguments."""
    kind: str                 # 'function' | 'method' | 'static'
    match: str
    neutralize: list[str]     # tags to remove, or ['*'] for all
    frameworks: tuple = ALL
    cls: Optional[str] = None
    arg_index: int = 0        # which argument is sanitized

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)


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

    def applies(self, framework) -> bool:
        return _framework_applies(self.frameworks, framework)


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
