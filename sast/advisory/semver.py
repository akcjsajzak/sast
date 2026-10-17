"""Minimal semantic-version parsing and range matching (enough for composer/maven)."""
from __future__ import annotations

import re

_VERSION_RE = re.compile(r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$")
_CONSTRAINT_RE = re.compile(r"^(>=|<=|>|<|==|=|!=)?\s*[vV]?([0-9][0-9A-Za-z.\-]*)$")


def parse_version(v: str):
    """Return a comparable tuple (major, minor, patch) for a version string."""
    m = _VERSION_RE.match(str(v).strip())
    if not m:
        return None
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return (major, minor, patch)


def _cmp(a, b) -> int:
    if a is None or b is None:
        return 0
    return (a > b) - (a < b)


def _check(version, op: str, target) -> bool:
    v = parse_version(version)
    t = parse_version(target)
    if v is None or t is None:
        return False
    c = _cmp(v, t)
    if op in ("=", "==", ""):
        return c == 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op == "!=":
        return c != 0
    return False


def satisfies(version: str, constraint: str) -> bool:
    """True if `version` satisfies a comma/space separated constraint string.

    Supports: '>=1.0.0,<2.0.0', '>=1.0.0 <2.0.0', '<1.2.3', '=1.0.0', '1.0.0', '*'.
    """
    constraint = (constraint or "").strip()
    if constraint in ("", "*"):
        return True
    for part in re.split(r"[,\s]+", constraint):
        if not part:
            continue
        m = _CONSTRAINT_RE.match(part)
        if not m:
            return False
        op, target = m.group(1) or "=", m.group(2)
        if not _check(version, op, target):
            return False
    return True


def version_in_ranges(version: str, ranges: list[str]) -> bool:
    """True if version satisfies ANY of the given range strings."""
    return any(satisfies(version, r) for r in ranges)
