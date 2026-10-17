"""Parse npm manifests and lockfiles for installed package versions.

package.json carries only direct dependencies, and as version *ranges* rather
than resolved versions. The lockfiles (package-lock.json, yarn.lock,
pnpm-lock.yaml) carry the full resolved tree, so they are preferred wherever
one exists — a vulnerable transitive package is invisible from package.json.
"""
from __future__ import annotations

import json
import os
import re

_YARN_ENTRY_RE = re.compile(
    r'^"?((?:@[^/\s"]+/)?[^@\s"][^@\s"]*)@[^\n]*?:\n(?:\s+[^\n]*\n)*?\s+version '
    r'"?([^"\n]+)"?',
    re.MULTILINE,
)
_PNPM_ENTRY_RE = re.compile(
    r"^\s{2,}/((?:@[^/]+/)?[^/@\s]+)(?:@|/)([0-9][^:\s(]*)", re.MULTILINE
)


def _clean_version(version: str) -> str:
    """Strip range operators so a constraint can be matched approximately."""
    if not version:
        return ""
    v = version.strip()
    for prefix in ("^", "~", ">=", "<=", ">", "<", "=", "v"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v.strip()


def parse_package_json(root: str) -> list[tuple[str, str]]:
    """[(package, version-constraint)] from package.json — direct deps only."""
    path = os.path.join(root, "package.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    result: list[tuple[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, constraint in (data.get(section, {}) or {}).items():
            if not isinstance(constraint, str):
                continue
            version = _clean_version(constraint)
            # Skip non-registry specs: file:, link:, git URLs, workspace:, *.
            if not version or not version[0].isdigit():
                continue
            result.append((name, version))
    return result


def parse_package_lock(root: str) -> list[tuple[str, str]]:
    """[(package, version)] from package-lock.json, including transitive deps."""
    path = os.path.join(root, "package-lock.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []

    out: list[tuple[str, str]] = []
    seen: set = set()

    def add(name, version):
        if not name or not version or not isinstance(version, str):
            return
        if (name, version) in seen:
            return
        seen.add((name, version))
        out.append((name, version))

    # lockfileVersion 2/3: a "packages" map keyed by install path.
    for key, meta in (data.get("packages", {}) or {}).items():
        if not isinstance(meta, dict):
            continue
        name = meta.get("name")
        if not name:
            # "node_modules/foo" / "node_modules/@scope/foo"
            marker = "node_modules/"
            idx = key.rfind(marker)
            if idx == -1:
                continue
            name = key[idx + len(marker):]
        add(name, meta.get("version"))

    # lockfileVersion 1: a nested "dependencies" tree.
    def walk(deps):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            add(name, meta.get("version"))
            walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return out


def parse_yarn_lock(root: str) -> list[tuple[str, str]]:
    path = os.path.join(root, "yarn.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    out, seen = [], set()
    for m in _YARN_ENTRY_RE.finditer(text):
        entry = (m.group(1), m.group(2))
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def parse_pnpm_lock(root: str) -> list[tuple[str, str]]:
    path = os.path.join(root, "pnpm-lock.yaml")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    out, seen = [], set()
    for m in _PNPM_ENTRY_RE.finditer(text):
        entry = (m.group(1), m.group(2))
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def parse_npm_dependencies(root: str) -> list[tuple[str, str]]:
    """Resolved dependencies when a lockfile exists, else package.json."""
    for parser in (parse_package_lock, parse_yarn_lock, parse_pnpm_lock):
        deps = parser(root)
        if deps:
            return deps
    return parse_package_json(root)
