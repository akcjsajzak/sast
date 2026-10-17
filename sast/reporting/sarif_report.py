"""SARIF 2.1.0 report rendering (interop with GitHub, VS Code, SonarQube, ...)."""
from __future__ import annotations

import json

from .. import __version__
from ..models import ScanResult

_SEV_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _region(loc) -> dict:
    if not loc:
        return {}
    return {
        "startLine": loc.line,
        "startColumn": loc.column,
        "endLine": loc.end_line or loc.line,
        "endColumn": loc.end_column or (loc.column + 1),
    }


def _phys(loc) -> dict:
    r = {"artifactLocation": {"uri": loc.file.replace("\\", "/")}}
    region = _region(loc)
    if region:
        r["region"] = region
    return r


def _thread_flow(f) -> dict:
    locs = []
    for step in f.trace:
        entry = {"location": {"physicalLocation": _phys(step.location)}}
        locs.append(entry)
    return {"threadFlows": [{"locations": locs}]}


def _result(f) -> dict:
    r = {
        "ruleId": f.rule_id,
        "level": _SEV_LEVEL.get(f.severity.value, "warning"),
        "message": {"text": f.title},
        "locations": [{"physicalLocation": _phys(f.location)}],
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence,
            "cwe": f.cwe,
            "owasp": f.owasp,
            "category": f.category,
            "framework": f.framework,
        },
    }
    if f.source:
        r["properties"]["source"] = {"file": f.source.file, "line": f.source.line}
    if f.trace:
        r["codeFlows"] = [_thread_flow(f)]
    return r


def render_sarif(result: ScanResult) -> str:
    rules = []
    seen = {}
    for f in result.findings:
        if f.rule_id not in seen:
            seen[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "properties": {
                    "cwe": [f.cwe] if f.cwe else [],
                    "owasp": f.owasp,
                    "category": f.category,
                    "security-severity": _sev_to_score(f.severity.value),
                },
                "help": {"text": f.remediation},
            }
            rules.append(seen[f.rule_id])

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sast",
                    "version": __version__,
                    "informationUri": "https://github.com/Twigpine/openclaude",
                    "rules": rules,
                }
            },
            "results": [_result(f) for f in result.findings],
        }],
    }
    return json.dumps(doc, indent=2)


def _sev_to_score(sev: str) -> str:
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }.get(sev, "5.5")
