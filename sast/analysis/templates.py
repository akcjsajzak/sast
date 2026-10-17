"""Scanners for template languages the taint engines never parse.

Twig, JSP and Thymeleaf templates hold the final HTML-rendering step of a
request, so an unescaped expression there is reflected XSS regardless of how
clean the controller is. They are not PHP or Java source, so tree-sitter never
sees them; these are deliberately shallow regex scanners over the raw text.
"""
from __future__ import annotations

import os
import re

from ..models import Finding, Location, Severity, TaintStep

TEMPLATE_EXTENSIONS = {
    ".twig": "twig",
    ".jsp": "jsp",
    ".jspx": "jsp",
    ".jspf": "jsp",
    ".tag": "jsp",
    ".ftl": "freemarker",
}

# Thymeleaf lives in .html, so it is only scanned when the markers appear.
_THYMELEAF_HINT = re.compile(r"th:(?:utext|text|href|src|attr)|xmlns:th=")

_A03 = "A03:2021 — Injection"
_A05 = "A05:2021 — Security Misconfiguration"


class _Rule:
    def __init__(self, rule_id, pattern, title, description, remediation,
                 severity=Severity.MEDIUM, cwe="CWE-79", owasp=_A03,
                 category="xss", confidence="medium", tags=("xss",)):
        self.rule_id = rule_id
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.title = title
        self.description = description
        self.remediation = remediation
        self.severity = severity
        self.cwe = cwe
        self.owasp = owasp
        self.category = category
        self.confidence = confidence
        self.tags = list(tags)


_TWIG_RULES = [
    _Rule(
        "twig-xss-raw-filter",
        r"\{\{.*?\|\s*raw\b.*?\}\}",
        "Unescaped Twig output (|raw)",
        "The |raw filter disables Twig's auto-escaping. If the expression "
        "carries user-controlled data this renders as HTML and is XSS.",
        "Drop |raw, or sanitize the value first (e.g. with an HTML purifier).",
    ),
    _Rule(
        "twig-xss-autoescape-off",
        r"\{%\s*autoescape\s+(?:false|'none'|\"none\")\s*%\}",
        "Twig auto-escaping disabled",
        "An autoescape block turns Twig's escaping off for everything inside it.",
        "Remove the block, or scope it as tightly as possible and escape by hand.",
        severity=Severity.HIGH,
    ),
    _Rule(
        "twig-ssti-template-from-string",
        r"template_from_string\s*\(",
        "Twig template compiled from a string",
        "template_from_string() compiles its argument as a Twig template. With "
        "user-controlled input this is server-side template injection.",
        "Render a fixed template and pass data as variables.",
        severity=Severity.HIGH, cwe="CWE-1336", category="ssti", tags=("ssti",),
    ),
]

_JSP_RULES = [
    _Rule(
        "jsp-xss-scriptlet-expression",
        r"<%=\s*(?!\s*//)[^%]*?(?:request\.|param\.|\bgetParameter\b)[^%]*?%>",
        "Unescaped JSP expression writing request data",
        "A <%= %> expression writes directly to the response without escaping. "
        "With request data in the expression this is reflected XSS.",
        "Use <c:out value=\"...\"/> or an encoder such as OWASP Java Encoder.",
        severity=Severity.HIGH,
    ),
    _Rule(
        "jsp-xss-cout-escaping-off",
        r"<c:out\b[^>]*escapeXml\s*=\s*[\"']false[\"']",
        "JSTL <c:out> with escaping disabled",
        "escapeXml=\"false\" turns off the escaping that makes <c:out> safe.",
        "Remove escapeXml=\"false\".",
        severity=Severity.HIGH,
    ),
    _Rule(
        "jsp-xss-el-request-param",
        r"\$\{\s*(?:param|paramValues|header|cookie)\b[^}]*\}",
        "JSP EL writes a request value without escaping",
        "${param...} interpolates a request value straight into the page. EL "
        "does not escape, so this is reflected XSS.",
        "Wrap the value in <c:out> or encode it explicitly.",
    ),
    _Rule(
        "jsp-config-errors-exposed",
        r"isErrorPage\s*=\s*[\"']true[\"']",
        "JSP error page may expose stack traces",
        "An error page with isErrorPage=\"true\" can render exception details, "
        "leaking internal paths and framework versions.",
        "Render a generic message and log the exception server-side.",
        severity=Severity.LOW, cwe="CWE-209", owasp=_A05,
        category="information-disclosure", tags=("log",),
    ),
]

_THYMELEAF_RULES = [
    _Rule(
        "thymeleaf-xss-utext",
        r"th:utext\s*=",
        "Unescaped Thymeleaf output (th:utext)",
        "th:utext writes its expression as raw markup. th:text escapes; "
        "th:utext does not, so user data here is XSS.",
        "Use th:text unless the value is trusted HTML you have sanitized.",
    ),
    _Rule(
        "thymeleaf-ssti-expression",
        r"th:[a-z]+\s*=\s*[\"']\s*\$\{\s*__\$\{",
        "Thymeleaf preprocessing expression",
        "__${...}__ preprocessing evaluates before the main expression and is a "
        "known server-side template injection vector when it contains user input.",
        "Avoid preprocessing expressions with request-derived data.",
        severity=Severity.HIGH, cwe="CWE-1336", category="ssti", tags=("ssti",),
    ),
]

_FREEMARKER_RULES = [
    _Rule(
        "freemarker-xss-noesc",
        r"<#noescape>|\?no_esc\b",
        "FreeMarker auto-escaping disabled",
        "#noescape / ?no_esc render the value as raw markup.",
        "Remove it, or sanitize the value before rendering.",
    ),
    _Rule(
        "freemarker-ssti-new",
        r"\?\s*new\s*\(",
        "FreeMarker ?new() builtin",
        "The ?new() builtin instantiates arbitrary classes and is the standard "
        "FreeMarker sandbox-escape primitive.",
        "Disable ?new() via the FreeMarker sandbox / TemplateClassResolver.",
        severity=Severity.HIGH, cwe="CWE-1336", category="ssti", tags=("ssti",),
    ),
]

_RULES_BY_KIND = {
    "twig": _TWIG_RULES,
    "jsp": _JSP_RULES,
    "thymeleaf": _THYMELEAF_RULES,
    "freemarker": _FREEMARKER_RULES,
}

_FRAMEWORK_BY_KIND = {
    "twig": ("Symfony", "php"),
    "jsp": ("Jakarta EE", "java"),
    "thymeleaf": ("Spring", "java"),
    "freemarker": ("Spring", "java"),
}


def collect_template_files(root: str) -> list[tuple[str, str]]:
    """Return [(path, kind)] for every template file under `root`."""
    from ..detection.language import IGNORED_DIRS

    out: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            kind = TEMPLATE_EXTENSIONS.get(ext)
            path = os.path.join(dirpath, fname)
            if kind:
                out.append((path, kind))
            elif ext in (".html", ".xhtml"):
                # Only a Thymeleaf template if it actually uses th: attributes.
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        head = fh.read(8192)
                except OSError:
                    continue
                if _THYMELEAF_HINT.search(head):
                    out.append((path, "thymeleaf"))
    out.sort()
    return out


def scan_templates(files: list[tuple[str, str]]) -> list[Finding]:
    """Run the template rules over the given [(path, kind)] pairs."""
    findings: list[Finding] = []
    for path, kind in files:
        rules = _RULES_BY_KIND.get(kind)
        if not rules:
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = text.splitlines()
        framework, language = _FRAMEWORK_BY_KIND.get(kind, ("raw", "php"))
        for rule in rules:
            for m in rule.regex.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
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
                    language=language,
                    location=loc,
                    source=None,
                    trace=[TaintStep(location=loc, description=rule.title, code=code)],
                    tags=list(rule.tags),
                ))
    return findings
