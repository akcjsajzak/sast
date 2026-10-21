"""SARIF 2.1.0 report rendering (interop with GitHub, VS Code, SonarQube, ...)."""
from __future__ import annotations

import json
import os

from .. import __version__
from ..models import ScanResult

_SEV_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Paths are emitted relative to this, which the consumer resolves to wherever
# the repository sits for it. Absolute scan-machine paths meant GitHub code
# scanning could not match a result to a file in the repository, so it
# accepted the upload and annotated nothing.
_SRCROOT = "%SRCROOT%"


def _rel(path: str, root: str) -> str:
    """A repository-relative, forward-slash URI for a scanned file."""
    if not path:
        return ""
    if root:
        try:
            rel = os.path.relpath(path, root)
        except ValueError:                       # different drive on Windows
            rel = path
        if not rel.startswith(".."):
            path = rel
    return path.replace("\\", "/")


def _region(loc) -> dict:
    if not loc:
        return {}
    return {
        "startLine": loc.line,
        "startColumn": loc.column,
        "endLine": loc.end_line or loc.line,
        "endColumn": loc.end_column or (loc.column + 1),
    }


def _phys(loc, root: str) -> dict:
    r = {"artifactLocation": {"uri": _rel(loc.file, root), "uriBaseId": _SRCROOT}}
    region = _region(loc)
    if region:
        r["region"] = region
    return r


def _thread_flow(f, root: str) -> dict:
    locs = []
    for step in f.trace:
        locs.append({
            "location": {
                "physicalLocation": _phys(step.location, root),
                "message": {"text": step.description},
            }
        })
    return {"threadFlows": [{"locations": locs}]}


def _result(f, root: str) -> dict:
    r = {
        "ruleId": f.rule_id,
        "level": _SEV_LEVEL.get(f.severity.value, "warning"),
        "message": {"text": f.title},
        "locations": [{"physicalLocation": _phys(f.location, root)}],
        # Keyed on the rule, the relative path and the offending line's text,
        # never the line number, so a result keeps its identity when code
        # shifts: that is what lets a dismissal in GitHub survive an edit
        # above it.
        "partialFingerprints": {"sastFingerprint/v1": f.fingerprint(root)},
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
        r["properties"]["source"] = {
            "file": _rel(f.source.file, root), "line": f.source.line,
        }
    if f.trace:
        r["codeFlows"] = [_thread_flow(f, root)]
    if getattr(f, "suppression", None):
        # SARIF's own suppression model: the result stays in the file and the
        # consumer hides it, rather than disappearing with no trace of why.
        kind = "inSource" if f.suppression.kind == "inline" else "external"
        entry = {"kind": kind}
        if f.suppression.reason:
            entry["justification"] = f.suppression.reason
        r["suppressions"] = [entry]
    return r


def _dependency_result(issue, root: str, index: int) -> dict:
    """A vulnerable dependency as a SARIF result.

    These were left out entirely, so a SARIF consumer saw a repository's code
    findings and none of its vulnerable packages. The manifest is the
    location, because that is the file a fix edits.
    """
    uri = _rel(issue.manifest, root) if issue.manifest else ""
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri or "<dependencies>",
                                 "uriBaseId": _SRCROOT},
            "region": {"startLine": 1},
        }
    }
    reach = f" ({issue.reachability})" if issue.reachability else ""
    return {
        "ruleId": _dep_rule_id(issue),
        "level": _SEV_LEVEL.get(issue.severity.value, "warning"),
        "message": {"text": f"{issue.package} {issue.version}: {issue.title}{reach}"},
        "locations": [location],
        "partialFingerprints": {
            "sastFingerprint/v1": f"dep:{issue.package}:{issue.cve}",
        },
        "properties": {
            "severity": issue.severity.value,
            "package": issue.package,
            "version": issue.version,
            "cve": issue.cve,
            "fixed_in": issue.fixed_in,
            "reachability": issue.reachability,
        },
    }


def _dep_rule_id(issue) -> str:
    return issue.cve or f"dependency-{issue.package}"


def _sev_to_score(sev: str) -> str:
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }.get(sev, "5.5")


def render_sarif(result: ScanResult) -> str:
    root = result.root or ""
    rules: list = []
    seen: dict = {}
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
    for issue in result.dependency_issues:
        rule_id = _dep_rule_id(issue)
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": issue.title},
                "fullDescription": {"text": issue.description},
                "properties": {
                    "cwe": [issue.cwe] if issue.cwe else [],
                    "category": "vulnerable-dependency",
                    "security-severity": _sev_to_score(issue.severity.value),
                },
                "help": {"text": f"Upgrade to {issue.fixed_in}" if issue.fixed_in
                                 else "Upgrade to a fixed version."},
            }
            rules.append(seen[rule_id])

    results = [_result(f, root) for f in result.findings]
    results += [_dependency_result(d, root, i)
                for i, d in enumerate(result.dependency_issues)]

    run = {
        "tool": {
            "driver": {
                "name": "sast",
                "version": __version__,
                "informationUri": "https://github.com/akcjsajzak/sast",
                "rules": rules,
            }
        },
        "originalUriBaseIds": {_SRCROOT: {"uri": _root_uri(root)}},
        "results": results,
    }
    if result.errors:
        # A stage that crashed is reported as a tool execution notification,
        # so a consumer reading only the SARIF can still tell this run is
        # incomplete rather than clean.
        run["invocations"] = [{
            "executionSuccessful": False,
            "toolExecutionNotifications": [
                {
                    "level": "error",
                    "message": {"text": f"{e.stage}: {e.error}"},
                    "descriptor": {"id": f"stage-failed/{e.stage}"},
                }
                for e in result.errors
            ],
        }]

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(doc, indent=2)


def _root_uri(root: str) -> str:
    """file:// URI for the scan root, as originalUriBaseIds expects."""
    if not root:
        return "file:///"
    path = os.path.abspath(root).replace("\\", "/")
    if not path.startswith("/"):
        path = "/" + path                        # C:/x -> /C:/x
    return "file://" + path + ("" if path.endswith("/") else "/")
