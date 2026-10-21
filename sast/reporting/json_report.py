"""JSON report rendering."""
from __future__ import annotations

import json

from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    payload = {
        "root": result.root,
        "language": result.language,
        "framework": result.framework,
        "languages": result.languages or [result.language],
        "frameworks": result.frameworks or {result.language: result.framework},
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "duration_seconds": result.duration_seconds,
        "advisory_db": {
            "advisories": result.advisory_count,
            "generated_at": result.advisory_db_date,
        },
        "summary": result.stats(),
        # Findings and dependency issues accepted by a marker or a baseline.
        # They stay in the lists below, each carrying why.
        **({"suppressed": result.suppressed_counts()}
           if result.suppressed_counts() else {}),
        # Stages that failed. Present only when something went wrong, so a
        # consumer can tell an incomplete scan from a clean one.
        **({"errors": [e.to_dict() for e in result.errors]} if result.errors else {}),
        "attack_surface": {
            "total": len(result.routes),
            "open": sum(1 for r in result.routes if r.open),
            "guarded": sum(1 for r in result.routes if not r.open),
            "routes": [r.to_dict() for r in result.routes],
        },
        "findings": [f.to_dict() for f in result.findings],
        "dependency_issues": [d.to_dict() for d in result.dependency_issues],
    }
    return json.dumps(payload, indent=2)
