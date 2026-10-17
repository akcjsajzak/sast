"""Parse composer.lock / composer.json for installed package versions."""
from __future__ import annotations

import json
import os


def parse_composer_lock(root: str) -> list[tuple[str, str]]:
    """Return [(package, version)] from composer.lock, or [] if absent."""
    path = os.path.join(root, "composer.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    result = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                result.append((name, version))
    return result


def parse_composer_json(root: str) -> list[tuple[str, str]]:
    """Return [(package, constraint)] from composer.json (constraints, not exact)."""
    path = os.path.join(root, "composer.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    result = []
    deps = {}
    deps.update(data.get("require", {}) or {})
    deps.update(data.get("require-dev", {}) or {})
    for name, constraint in deps.items():
        if isinstance(constraint, str):
            result.append((name, constraint))
    return result
