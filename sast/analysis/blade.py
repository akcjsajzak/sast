"""Lightweight Blade template scanner (Laravel) for unescaped output."""
from __future__ import annotations

import os
import re

from ..models import Finding, Location, Severity, TaintStep

# Blade `{!! !!}` does NOT escape; `{{ }}` does. Also @ directives with raw.
_UNESCAPED_RE = re.compile(r"\{\{?\s*!!\s*(.*?)\s*!!\s*\}\}?", re.DOTALL)
_VAR_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")


def scan_blade(blade_files: list[str]) -> list[Finding]:
    findings = []
    for path in blade_files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = text.splitlines()
        for m in _UNESCAPED_RE.finditer(text):
            body = m.group(1)
            has_var = bool(_VAR_RE.search(body)) or bool(re.search(r"->|\(", body))
            if not has_var:
                continue
            line = text.count("\n", 0, m.start()) + 1
            code = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            loc = Location(
                file=path, line=line, column=1,
                end_line=line, end_column=len(code) + 1, code=code,
            )
            findings.append(Finding(
                rule_id="laravel-xss-blade-raw",
                title="Unescaped Blade output ({!! !!})",
                severity=Severity.MEDIUM,
                cwe="CWE-79",
                owasp="A03:2021 — Injection",
                category="xss",
                description="Blade {!! !!} output is not HTML-escaped. If the expression contains user-controlled data this is reflected XSS.",
                remediation="Use {{ }} (auto-escaped) or escape explicitly with e().",
                confidence="medium",
                framework="Laravel",
                language="php",
                location=loc,
                source=None,
                trace=[TaintStep(location=loc, description="Unescaped Blade output", code=code)],
                tags=["xss"],
            ))
    return findings
