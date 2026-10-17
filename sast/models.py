"""Core data model for the SAST engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# OWASP Top 10 (2021)
OWASP_2021 = {
    "A01": "A01:2021 — Broken Access Control",
    "A02": "A02:2021 — Cryptographic Failures",
    "A03": "A03:2021 — Injection",
    "A04": "A04:2021 — Insecure Design",
    "A05": "A05:2021 — Security Misconfiguration",
    "A06": "A06:2021 — Vulnerable and Outdated Components",
    "A07": "A07:2021 — Identification and Authentication Failures",
    "A08": "A08:2021 — Software and Data Integrity Failures",
    "A09": "A09:2021 — Security Logging and Monitoring Failures",
    "A10": "A10:2021 — Server-Side Request Forgery (SSRF)",
}


@dataclass
class Location:
    """A position in a source file."""
    file: str
    line: int
    column: int
    end_line: int = 0
    end_column: int = 0
    code: str = ""

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "code": self.code,
        }


@dataclass
class TaintStep:
    """One hop in a validated source-to-sink taint trace."""
    location: Location
    description: str
    code: str = ""

    def to_dict(self) -> dict:
        return {
            "location": self.location.to_dict(),
            "description": self.description,
            "code": self.code,
        }


@dataclass
class EntryPoint:
    """The HTTP route that reaches a finding.

    A finding without this says what is wrong. With it, it says what to
    send: `POST /api/user/update` with a tainted `name` parameter is a test
    case, where `SQL injection at Foo.java:42` is a reading exercise.
    """
    method: str
    path: str
    handler: str = ""
    guards: list = field(default_factory=list)
    file: str = ""
    line: int = 0

    @property
    def guarded(self) -> bool:
        """True when an authorisation guard was found at the declaration.

        The negative is weaker than it looks: authorisation can live in a
        filter, a security config or a gateway, none of which is visible
        here. False means nothing was found, not that nothing exists.
        """
        return bool(self.guards)

    @property
    def signature(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "handler": self.handler,
            "guards": self.guards,
            "guarded": self.guarded,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class Finding:
    """A single validated security finding."""
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    owasp: str
    category: str
    description: str
    remediation: str
    confidence: str
    framework: str
    language: str
    location: Location                 # the sink location
    source: Optional[Location] = None  # the taint source location
    trace: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    # The route that reaches this finding, when one could be established.
    entry_point: Optional[EntryPoint] = None
    # A ready-to-send request reproducing the entry point, when one applies.
    request: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "framework": self.framework,
            "language": self.language,
            "location": self.location.to_dict(),
            "source": self.source.to_dict() if self.source else None,
            "trace": [s.to_dict() for s in self.trace],
            "tags": self.tags,
            "entry_point": self.entry_point.to_dict() if self.entry_point else None,
            "request": self.request,
        }


@dataclass
class DependencyIssue:
    """A vulnerable dependency, matched against the offline advisory DB."""
    package: str
    version: str
    cve: str
    severity: Severity
    title: str
    description: str
    fixed_in: str
    cwe: str = ""
    references: list = field(default_factory=list)
    # Whether first-party code actually reaches this package: 'called',
    # 'imported', 'unused', or '' when the question does not apply (a base
    # image). This is import/call-site evidence, not an exploitability claim.
    reachability: str = ""
    reachability_note: str = ""

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "cve": self.cve,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "fixed_in": self.fixed_in,
            "cwe": self.cwe,
            "references": self.references,
            "reachability": self.reachability,
            "reachability_note": self.reachability_note,
        }


@dataclass
class ScanResult:
    """Aggregate result of a scan."""
    root: str
    language: str                      # primary language (most prevalent)
    framework: str                     # framework of the primary language
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    dependency_issues: list = field(default_factory=list)
    duration_seconds: float = 0.0
    # Every language found, most prevalent first, and the framework detected
    # for each. A polyglot repo scans them all; `language`/`framework` stay as
    # the primary pair so existing consumers keep working.
    languages: list = field(default_factory=list)
    frameworks: dict = field(default_factory=dict)
    # Files left out of the scan, keyed by reason ('tests', 'too_large', ...).
    files_skipped: dict = field(default_factory=dict)
    # Every HTTP entry point found, so a report can state the attack
    # surface and tie findings to the request that reaches them.
    routes: list = field(default_factory=list)
    # Offline advisory database provenance.
    advisory_count: int = 0
    advisory_db_date: str = ""

    def stats(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.severity.value in counts:
                counts[f.severity.value] += 1
        return counts

    def count_at_or_above(self, severity: Severity) -> int:
        """How many findings AND dependency issues are at least `severity`.

        Used by `--fail-on` so a vulnerable dependency can break a build just
        as a code finding does.
        """
        threshold = SEVERITY_ORDER.get(severity, 99)
        return sum(
            1 for item in (*self.findings, *self.dependency_issues)
            if SEVERITY_ORDER.get(item.severity, 99) <= threshold
        )

    def total_skipped(self) -> int:
        return sum(self.files_skipped.values())
