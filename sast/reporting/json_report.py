"""JSON report rendering."""
from __future__ import annotations

import json

from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    payload = {
        "root": result.root,
        "language": result.language,
        "framework": result.framework,
        "files_scanned": result.files_scanned,
        "duration_seconds": result.duration_seconds,
        "summary": result.stats(),
        "findings": [f.to_dict() for f in result.findings],
        "dependency_issues": [d.to_dict() for d in result.dependency_issues],
    }
    return json.dumps(payload, indent=2)
