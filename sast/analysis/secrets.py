"""Secrets detection across every file in a repository.

Two complementary strategies:

1. **Provider patterns** — a credential with a recognisable shape (an AWS key
   id, a GitHub token, a PEM block) is matched directly and reported with high
   confidence. These have essentially no false positives because the prefix and
   length are fixed by the issuer.
2. **Entropy** — an assignment to a secret-shaped name whose value looks random
   is reported at lower confidence. This catches credentials with no
   distinctive format, at the cost of needing suppression heuristics.

Secret *values* are never written into a finding: everything is redacted
before it reaches a report.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field

from ..models import Finding, Location, Severity, TaintStep

A07 = "A07:2021 — Identification and Authentication Failures"

# Files worth reading for secrets: source, config, scripts, CI, notebooks,
# env files, infrastructure. Binary and lock files are skipped.
_TEXT_EXTENSIONS = {
    ".php", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py",
    ".go", ".cs", ".c", ".h", ".cpp", ".hpp", ".cc", ".rb", ".sh", ".bash",
    ".zsh", ".ps1", ".pl", ".sql", ".yml", ".yaml", ".json", ".xml", ".toml",
    ".ini", ".cfg", ".conf", ".properties", ".env", ".tf", ".tfvars", ".hcl",
    ".tpl", ".txt", ".md", ".gradle", ".kt", ".swift", ".scala", ".r",
    ".ipynb", ".dockerfile", ".service", ".plist",
}
_TEXT_FILENAMES = {
    ".env", "dockerfile", "makefile", "jenkinsfile", "procfile", "vagrantfile",
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".dockercfg", "credentials",
    "config", "secrets",
}

# Files that are allowed to contain example credentials.
_EXAMPLE_FILE_RE = re.compile(
    r"(^|[./_-])(example|examples|sample|samples|template|templates|fixture|"
    r"fixtures|mock|mocks|dummy|demo|doc|docs|test|tests|spec)([./_-]|$)",
    re.IGNORECASE,
)

# Values that are obviously not real credentials.
_PLACEHOLDER_RE = re.compile(
    r"^(?:x+|y+|z+|a+|0+|1+|\*+|\.+|-+|_+|changeme|change_me|placeholder|"
    r"your[-_a-z]*|my[-_a-z]*|some[-_a-z]*|example[-_a-z]*|sample[-_a-z]*|"
    r"dummy[-_a-z]*|test[-_a-z]*|fake[-_a-z]*|insert[-_a-z]*|todo|tbd|none|"
    r"null|nil|undefined|empty|redacted|removed|secret|password|token|"
    r"api[-_]?key|xxxxx+|<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|%[a-z_]+%|"
    r"\$[a-z_][a-z0-9_]*|process\.env\..*|os\.environ.*)$",
    re.IGNORECASE,
)

# A value made only of these is structural, not random.
_LOW_VARIETY_RE = re.compile(r"^[^a-zA-Z0-9]*$")


@dataclass
class SecretPattern:
    """A credential with a recognisable, issuer-defined shape."""
    rule_id: str
    name: str
    regex: str
    severity: str = "critical"
    # Group holding the secret itself (for redaction); 0 = the whole match.
    group: int = 0
    confidence: str = "high"
    _compiled: object = field(default=None, repr=False, compare=False)

    def compiled(self):
        if self._compiled is None:
            object.__setattr__(self, "_compiled", re.compile(self.regex))
        return self._compiled


# Prefix-anchored, fixed-length credentials. Each of these is issued by a
# provider in a documented format, so a match is near-certainly a real key.
PROVIDER_PATTERNS = [
    SecretPattern("secret-aws-access-key-id", "AWS access key ID",
                  r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b", group=1),
    SecretPattern("secret-aws-secret-access-key", "AWS secret access key",
                  r"(?i)aws[-_ ]?(?:secret|sec)[-_ ]?(?:access)?[-_ ]?key[\"' ]*[:=][\"' ]*"
                  r"([A-Za-z0-9/+=]{40})", group=1),
    SecretPattern("secret-github-token", "GitHub token",
                  r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255})\b", group=1),
    SecretPattern("secret-gitlab-token", "GitLab token",
                  r"\b(glpat-[A-Za-z0-9_\-]{20,})\b", group=1),
    SecretPattern("secret-slack-token", "Slack token",
                  r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", group=1),
    SecretPattern("secret-slack-webhook", "Slack webhook URL",
                  r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)",
                  group=1, severity="high"),
    SecretPattern("secret-stripe-key", "Stripe API key",
                  r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,})\b", group=1),
    SecretPattern("secret-google-api-key", "Google API key",
                  r"\b(AIza[0-9A-Za-z_\-]{35})\b", group=1),
    SecretPattern("secret-gcp-service-account", "GCP service-account key",
                  r"(\"type\"\s*:\s*\"service_account\")", group=1, severity="critical"),
    SecretPattern("secret-openai-key", "OpenAI API key",
                  r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b", group=1),
    SecretPattern("secret-anthropic-key", "Anthropic API key",
                  r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b", group=1),
    SecretPattern("secret-npm-token", "npm access token",
                  r"\b(npm_[A-Za-z0-9]{36})\b", group=1),
    SecretPattern("secret-pypi-token", "PyPI upload token",
                  r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b", group=1),
    SecretPattern("secret-sendgrid-key", "SendGrid API key",
                  r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", group=1),
    SecretPattern("secret-twilio-key", "Twilio account SID / key",
                  r"\b((?:AC|SK)[0-9a-fA-F]{32})\b", group=1, severity="high"),
    SecretPattern("secret-mailgun-key", "Mailgun API key",
                  r"\b(key-[0-9a-f]{32})\b", group=1, severity="high"),
    SecretPattern("secret-private-key", "Private key block",
                  r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
                  group=1),
    SecretPattern("secret-jwt", "JSON Web Token",
                  r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
                  group=1, severity="medium", confidence="medium"),
    SecretPattern("secret-db-connection-uri", "Database connection string with password",
                  r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
                  r"[^\s:/@]+:[^\s:/@]{3,}@[^\s/]+)", group=1, severity="high"),
    SecretPattern("secret-azure-storage-key", "Azure storage account key",
                  r"(?i)(AccountKey\s*=\s*[A-Za-z0-9+/=]{60,})", group=1),
    SecretPattern("secret-heroku-key", "Heroku API key",
                  r"(?i)heroku[a-z0-9_ .\-,]{0,25}[\"' ]*[:=][\"' ]*"
                  r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                  group=1, severity="high"),
    SecretPattern("secret-basic-auth-header", "Hardcoded HTTP Basic credentials",
                  r"(?i)(Authorization\s*[:=]\s*[\"']?(?:Basic|Bearer)\s+[A-Za-z0-9+/=_\-.]{16,})",
                  group=1, severity="high", confidence="medium"),
]

# Generic "name = value" assignment, used for the entropy strategy.
_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\-]{0,48}
        (?:password|passwd|pwd|secret|token|api[_.\-]?key|apikey|auth|
           credential|private[_.\-]?key|access[_.\-]?key|client[_.\-]?secret|
           encryption[_.\-]?key|signing[_.\-]?key|session[_.\-]?key))
    \s*[:=]\s*
    (?P<quote>["'`]?)(?P<value>[^\s"'`,;)\]}]{8,120})(?P=quote)
    """
)

# Minimum Shannon entropy (bits/char) for a value to look random.
_MIN_ENTROPY_B64 = 3.6
_MIN_ENTROPY_HEX = 3.0


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    """Show enough of a secret to find it, never enough to use it."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 8, 24)}{value[-4:]}"


def _redact_line(line: str, secret: str) -> str:
    return line.replace(secret, redact(secret)) if secret else line


def _looks_like_placeholder(value: str) -> bool:
    if _PLACEHOLDER_RE.match(value.strip()):
        return True
    if _LOW_VARIETY_RE.match(value):
        return True
    # A value made of a single repeated character carries no entropy.
    return len(set(value)) <= 2


def _is_hex(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", value))


def is_scannable(path: str) -> bool:
    """True if the file is plain text worth searching for credentials."""
    name = os.path.basename(path).lower()
    if name in _TEXT_FILENAMES or name.startswith(".env"):
        return True
    ext = os.path.splitext(name)[1].lower()
    if ext in _TEXT_EXTENSIONS:
        return True
    return "." not in name and name in _TEXT_FILENAMES


def collect_scannable_files(root: str, max_bytes: int = 1024 * 1024) -> list[str]:
    from ..detection.language import IGNORED_DIRS

    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            path = os.path.join(dirpath, fname)
            if not is_scannable(path):
                continue
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
            except OSError:
                continue
            out.append(path)
    out.sort()
    return out


def scan_secrets(paths: list[str], root: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        rel = os.path.relpath(path, root) if root else path
        in_example = bool(_EXAMPLE_FILE_RE.search(rel))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue  # binary
        lines = text.splitlines()
        seen_values: set = set()

        # 1. Provider patterns.
        for pattern in PROVIDER_PATTERNS:
            for m in pattern.compiled().finditer(text):
                secret = m.group(pattern.group) if pattern.group else m.group(0)
                if not secret or _looks_like_placeholder(secret):
                    continue
                if secret in seen_values:
                    continue
                seen_values.add(secret)
                line_no = text.count("\n", 0, m.start()) + 1
                raw = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                findings.append(_finding(
                    rule_id=pattern.rule_id,
                    title=f"{pattern.name} committed to source",
                    severity=pattern.severity if not in_example else "medium",
                    confidence=pattern.confidence if not in_example else "low",
                    description=(
                        f"A {pattern.name} appears in {os.path.basename(path)}. "
                        "Anything committed to version control must be treated as "
                        "disclosed, including to anyone with historical access."
                    ),
                    remediation=(
                        "Revoke and rotate this credential, then load it from a "
                        "secrets manager or the environment. Removing the line is "
                        "not enough — it remains in git history."
                    ),
                    path=path, line=line_no,
                    code=_redact_line(raw.strip(), secret),
                ))

        # 2. Entropy on secret-shaped assignments.
        for m in _ASSIGNMENT_RE.finditer(text):
            value = m.group("value")
            name = m.group("name")
            if value in seen_values or _looks_like_placeholder(value):
                continue
            threshold = _MIN_ENTROPY_HEX if _is_hex(value) else _MIN_ENTROPY_B64
            if len(value) < 12 or shannon_entropy(value) < threshold:
                continue
            seen_values.add(value)
            line_no = text.count("\n", 0, m.start()) + 1
            raw = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
            findings.append(_finding(
                rule_id="secret-high-entropy-assignment",
                title="High-entropy value assigned to a credential-shaped name",
                severity="high" if not in_example else "low",
                confidence="medium" if not in_example else "low",
                description=(
                    f"`{name}` is assigned a high-entropy literal, which usually "
                    "means a real credential is hardcoded here."
                ),
                remediation=(
                    "If this is a live credential, rotate it and load it from the "
                    "environment or a secrets manager."
                ),
                path=path, line=line_no,
                code=_redact_line(raw.strip(), value),
            ))
    return findings


def _finding(rule_id, title, severity, confidence, description, remediation,
             path, line, code) -> Finding:
    loc = Location(file=path, line=line, column=1, end_line=line,
                   end_column=len(code) + 1, code=code)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity(severity),
        cwe="CWE-798",
        owasp=A07,
        category="hardcoded-secret",
        description=description,
        remediation=remediation,
        confidence=confidence,
        framework="",
        language="secrets",
        location=loc,
        source=None,
        trace=[TaintStep(location=loc, description=title, code=code)],
        tags=["secret"],
    )
