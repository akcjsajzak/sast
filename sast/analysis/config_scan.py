"""Scanner for configuration files.

Security posture often lives in configuration rather than code: a debug flag
left on, a secret committed to .env, an actuator endpoint exposed. None of
these files are PHP or Java source, so the taint engines never see them.
"""
from __future__ import annotations

import os
import re

from ..models import Finding, Location, Severity, TaintStep

_A05 = "A05:2021 — Security Misconfiguration"
_A02 = "A02:2021 — Cryptographic Failures"
_A07 = "A07:2021 — Identification and Authentication Failures"

# Files worth reading, by exact name or suffix.
CONFIG_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.prod", ".env.staging",
    "application.properties", "application.yml", "application.yaml",
    "bootstrap.yml", "bootstrap.yaml", "web.xml", "php.ini", ".htaccess",
}
_CONFIG_PREFIXES = ("application-",)   # application-prod.properties, ...


class _CRule:
    def __init__(self, rule_id, pattern, title, description, remediation,
                 severity=Severity.MEDIUM, cwe="CWE-16", owasp=_A05,
                 category="security-misconfiguration", confidence="high",
                 files=None):
        self.rule_id = rule_id
        self.regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.cwe = cwe
        self.owasp = owasp
        self.category = category
        self.confidence = confidence
        self.files = files  # restrict to filenames containing one of these


_RULES = [
    # --- Debug / error exposure ---
    _CRule(
        "config-debug-enabled",
        r"^[ \t]*(?:APP_DEBUG|DEBUG|APP_ENV)[ \t]*=[ \t]*(?:true|1|dev|develop(?:ment)?|local)\s*$",
        "Debug mode enabled in configuration",
        "Debug mode renders stack traces, environment variables and query logs "
        "to anyone who triggers an error.",
        "Set APP_DEBUG=false and APP_ENV=production for deployed environments.",
        severity=Severity.HIGH, cwe="CWE-489",
    ),
    _CRule(
        "config-spring-actuator-exposed",
        r"^[ \t]*management\.endpoints\.web\.exposure\.include[ \t]*[=:][ \t]*.*(?:\*|env|heapdump|threaddump|shutdown)",
        "Spring Actuator endpoints broadly exposed",
        "Exposing all (or env/heapdump/shutdown) actuator endpoints leaks "
        "configuration and credentials, and can allow remote shutdown.",
        "Expose only health and info, and put actuators behind authentication.",
        severity=Severity.HIGH, cwe="CWE-200", category="information-disclosure",
    ),
    _CRule(
        "config-stacktrace-exposed",
        r"^[ \t]*server\.error\.include-(?:stacktrace|message)[ \t]*[=:][ \t]*(?:always)",
        "Error responses include stack traces",
        "Returning stack traces to clients leaks internal paths, class names "
        "and dependency versions.",
        "Use 'never' (or 'on-param' in non-production only).",
        severity=Severity.LOW, cwe="CWE-209", category="information-disclosure",
    ),
    # --- Secrets ---
    _CRule(
        "config-hardcoded-secret",
        r"^[ \t]*(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_?KEY|TOKEN|PRIVATE_KEY|"
        r"ACCESS_KEY|CLIENT_SECRET)[A-Z0-9_]*)[ \t]*=[ \t]*(?!\s*$)(?!['\"]?(?:null|changeme|"
        r"your[-_]|xxx|placeholder|<|\$\{))['\"]?[^\s'\"]{8,}",
        "Secret committed in a configuration file",
        "A credential is stored in a configuration file, so it is in version "
        "control and in every deployed copy of the repository.",
        "Move it to a secrets manager or inject it at deploy time, and rotate "
        "the exposed value.",
        severity=Severity.HIGH, cwe="CWE-798", owasp=_A07, category="hardcoded-secret",
        confidence="medium",
    ),
    _CRule(
        "config-spring-datasource-password",
        r"^[ \t]*spring\.datasource\.password[ \t]*[=:][ \t]*(?!\s*$)(?!\$\{)\S+",
        "Database password hardcoded in Spring configuration",
        "spring.datasource.password is set to a literal value rather than a "
        "placeholder resolved at runtime.",
        "Use ${DB_PASSWORD} and supply it from the environment or a vault.",
        severity=Severity.HIGH, cwe="CWE-798", owasp=_A07, category="hardcoded-secret",
    ),
    # --- Transport / crypto ---
    _CRule(
        "config-tls-disabled",
        r"^[ \t]*(?:server\.ssl\.enabled[ \t]*[=:][ \t]*false"
        r"|.*ssl[._-]?verify(?:peer)?[ \t]*[=:][ \t]*(?:false|0|off)"
        r"|FORCE_HTTPS[ \t]*=[ \t]*(?:false|0))\s*$",
        "TLS disabled or certificate verification turned off",
        "Traffic is sent in plaintext, or certificates are not verified, "
        "leaving the connection open to interception.",
        "Enable TLS and leave certificate verification on.",
        severity=Severity.HIGH, cwe="CWE-319", owasp=_A02,
        category="insecure-transport",
    ),
    _CRule(
        "config-session-insecure",
        r"^[ \t]*(?:session\.cookie_secure[ \t]*=[ \t]*(?:0|off|false)"
        r"|session\.cookie_httponly[ \t]*=[ \t]*(?:0|off|false)"
        r"|SESSION_SECURE_COOKIE[ \t]*=[ \t]*false)\s*$",
        "Session cookie missing Secure/HttpOnly",
        "The session cookie is sent over plaintext HTTP or is readable from "
        "JavaScript, making session hijacking easier.",
        "Set cookie_secure and cookie_httponly on, and add SameSite.",
        cwe="CWE-1004",
    ),
    # --- PHP runtime ---
    _CRule(
        "config-php-display-errors",
        r"^[ \t]*display_errors[ \t]*=[ \t]*(?:on|1|true)\s*$",
        "PHP display_errors enabled",
        "PHP will render error messages, including file paths and SQL, to the "
        "browser.",
        "Set display_errors = Off and log errors instead.",
        cwe="CWE-209", category="information-disclosure",
    ),
    _CRule(
        "config-php-dangerous-functions",
        r"^[ \t]*disable_functions[ \t]*=[ \t]*$",
        "PHP disable_functions is empty",
        "No dangerous functions are disabled, so exec/system/passthru are all "
        "reachable if an injection flaw exists.",
        "Disable the functions the application does not need.",
        severity=Severity.LOW, confidence="medium",
    ),
    _CRule(
        "config-php-allow-url-include",
        r"^[ \t]*allow_url_(?:include|fopen)[ \t]*=[ \t]*(?:on|1|true)\s*$",
        "PHP allow_url_include/fopen enabled",
        "Remote URLs may be opened or included, turning a file-inclusion flaw "
        "into remote code execution.",
        "Set allow_url_include = Off.",
        severity=Severity.HIGH, cwe="CWE-98", category="file-inclusion",
    ),
    # --- Servlet container ---
    _CRule(
        "config-webxml-missing-httponly",
        r"<cookie-config>(?:(?!</cookie-config>).)*?<http-only>\s*false\s*</http-only>",
        "Servlet session cookie HttpOnly disabled",
        "web.xml explicitly turns off HttpOnly for the session cookie, so it "
        "is readable from JavaScript.",
        "Set <http-only>true</http-only> and <secure>true</secure>.",
        cwe="CWE-1004", files=("web.xml",),
    ),
    _CRule(
        "config-webxml-listings",
        r"<param-name>\s*listings\s*</param-name>\s*<param-value>\s*true\s*</param-value>",
        "Servlet directory listings enabled",
        "Directory listings expose the application's file layout.",
        "Set the listings parameter to false.",
        severity=Severity.LOW, cwe="CWE-548", category="information-disclosure",
        files=("web.xml",),
    ),

    # --- Crypto chosen in configuration ---
    # `MessageDigest.getInstance(props.getProperty("hashAlg"))` is a call the
    # taint engines see but cannot judge: the algorithm is a string decided at
    # runtime. The value is right here in the repository, so read it.
    _CRule(
        "config-weak-hash-algorithm",
        r"^[ \t]*[\w.\-]*(?:hash|digest|checksum|mac|signature|sign)[\w.\-]*"
        r"[ \t]*[=:][ \t]*\"?(MD2|MD4|MD5|SHA-?1|SHA1withRSA|MD5withRSA)\b",
        "Weak hash algorithm selected in configuration",
        "MD2, MD4, MD5 and SHA-1 are collision-prone and unfit for signatures, "
        "integrity checks or password storage. Code that reads this key will "
        "use the weak algorithm no matter how the call site is written.",
        "Set the value to SHA-256 or better; use bcrypt, scrypt or argon2 for "
        "passwords.",
        severity=Severity.MEDIUM, cwe="CWE-328", owasp=_A02,
        category="weak-crypto",
    ),
    _CRule(
        "config-weak-cipher-algorithm",
        r"^[ \t]*[\w.\-]*(?:crypt|cipher|algo|encryption|transformation)[\w.\-]*"
        r"[ \t]*[=:][ \t]*\"?"
        r"(DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish|IDEA"
        r"|[A-Za-z0-9]+/ECB[\w/]*)\b",
        "Weak or broken cipher selected in configuration",
        "DES, 3DES, RC2, RC4, Blowfish and IDEA are broken or too weak for "
        "current use, and ECB mode leaks plaintext structure by mapping equal "
        "blocks to equal ciphertext. Code that reads this key will use it "
        "whatever the call site looks like.",
        "Set the value to AES/GCM/NoPadding with a 256-bit key.",
        severity=Severity.HIGH, cwe="CWE-327", owasp=_A02,
        category="weak-crypto",
    ),
]


def _is_config_file(fname: str) -> bool:
    low = fname.lower()
    if low in CONFIG_FILENAMES:
        return True
    if low.startswith(".env."):
        return True
    # Any .properties file, not just Spring's. A Java application puts its
    # configuration in whatever name it likes, and the choice of hash or
    # cipher often lives there rather than in the source — which is exactly
    # the case the source scanners cannot see.
    if low.endswith(".properties"):
        return True
    return any(low.startswith(p) for p in _CONFIG_PREFIXES) and low.endswith(
        (".yml", ".yaml")
    )


def load_properties(root: str) -> dict:
    """Return {key: value} for every `.properties` file under `root`.

    A value only survives when every file that defines the key agrees on it.
    Code reading an ambiguous key could get either value, so claiming one
    would let the taint engines fold a constant that is not constant. The
    result feeds `MessageDigest.getInstance(props.getProperty("hashAlg"))`,
    where the algorithm is a string the source alone cannot judge.
    """
    from ..detection.language import IGNORED_DIRS

    seen: dict = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in IGNORED_DIRS and not d.startswith(".")]
        for fname in filenames:
            if not fname.lower().endswith(".properties"):
                continue
            try:
                with open(os.path.join(dirpath, fname), "r",
                          encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line[0] in "#!":
                    continue
                for sep in ("=", ":"):
                    if sep in line:
                        key, value = line.split(sep, 1)
                        key, value = key.strip(), value.strip()
                        if key:
                            seen.setdefault(key, set()).add(value)
                        break
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


def collect_config_files(root: str) -> list[str]:
    """Return every configuration file under `root` worth scanning."""
    from ..detection.language import IGNORED_DIRS

    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            if _is_config_file(fname):
                out.append(os.path.join(dirpath, fname))
    out.sort()
    return out


def scan_configs(paths: list[str], language: str = "", framework: str = "raw") -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        base = os.path.basename(path).lower()
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = text.splitlines()
        for rule in _RULES:
            if rule.files and not any(f in base for f in rule.files):
                continue
            for m in rule.regex.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                # Never echo a secret into the report.
                if rule.category == "hardcoded-secret":
                    code = _redact(code)
                loc = Location(file=path, line=line, column=1, end_line=line,
                               end_column=len(code) + 1, code=code)
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    category=rule.category,
                    description=rule.description,
                    remediation=rule.remediation,
                    confidence=rule.confidence,
                    framework=framework,
                    language=language or "config",
                    location=loc,
                    source=None,
                    trace=[TaintStep(location=loc, description=rule.title, code=code)],
                    tags=["config"],
                ))
    return findings


def _redact(line: str) -> str:
    """Replace the value half of a key=value line so reports never leak it."""
    for sep in ("=", ":"):
        if sep in line:
            key, _, value = line.partition(sep)
            value = value.strip()
            if not value:
                return line
            return f"{key}{sep} {'*' * min(len(value), 12)} (redacted)"
    return line
