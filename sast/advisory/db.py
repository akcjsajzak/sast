"""Offline advisory database: load bundled seed + user files, match versions."""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .semver import version_in_ranges


@dataclass
class Advisory:
    package: str
    ranges: list[str]                  # affected version ranges (any-match)
    cve: str = ""
    severity: str = "high"             # critical|high|medium|low
    title: str = ""
    description: str = ""
    fixed_in: str = ""                 # human-readable fixed version
    cwe: str = ""
    references: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "ranges": self.ranges,
            "cve": self.cve,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "fixed_in": self.fixed_in,
            "cwe": self.cwe,
            "references": self.references,
        }


class AdvisoryDB:
    def __init__(self, seed_path: str = None) -> None:
        self.advisories: list[Advisory] = []
        self._by_package: dict = {}
        self._seen: set = set()
        # Newest 'generated_at' across every loaded file (ISO-8601 date), so
        # reports can state how stale the offline database is.
        self.generated_at: str = ""
        if seed_path and os.path.isfile(seed_path):
            self.load_file(seed_path)

    def load_file(self, path: str) -> int:
        """Load an advisory JSON file (our internal format). Returns count added."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0
        if isinstance(data, list):
            entries = data
            # A bare list carries no metadata; fall back to the file's mtime.
            stamp = _mtime_date(path)
        else:
            entries = data.get("advisories", [])
            stamp = data.get("generated_at") or _mtime_date(path)
        if stamp and stamp > self.generated_at:
            self.generated_at = stamp
        count = 0
        for e in entries:
            adv = self._from_dict(e)
            if adv:
                self.add(adv)
                count += 1
        return count

    def _from_dict(self, e: dict) -> Advisory:
        pkg = e.get("package") or e.get("name")
        if not pkg:
            return None
        ranges = e.get("ranges") or e.get("affected_versions") or e.get("affected")
        if isinstance(ranges, str):
            ranges = [ranges]
        ranges = ranges or ["*"]
        return Advisory(
            package=pkg,
            ranges=ranges,
            cve=e.get("cve", ""),
            severity=(e.get("severity") or "high").lower(),
            title=e.get("title", ""),
            description=e.get("description", ""),
            fixed_in=e.get("fixed_in") or e.get("patched_versions", ""),
            cwe=e.get("cwe", ""),
            references=e.get("references", []),
        )

    def add(self, adv: Advisory) -> None:
        # Deduplicate on (package, cve, ranges) — title as fallback when CVE absent.
        key = (adv.package.lower(), adv.cve or adv.title or adv.description,
               tuple(sorted(adv.ranges)))
        if key in self._seen:
            return
        self._seen.add(key)
        self.advisories.append(adv)
        self._by_package.setdefault(adv.package.lower(), []).append(adv)

    def match(self, package: str, version: str) -> list[Advisory]:
        """Return advisories whose range contains the given package version."""
        results = []
        for adv in self._by_package.get(package.lower(), []):
            if version_in_ranges(version, adv.ranges):
                results.append(adv)
        return results

    def packages(self) -> list[str]:
        return sorted(self._by_package.keys())

    def to_dicts(self) -> list[dict]:
        return [a.to_dict() for a in self.advisories]

    def export(self, path: str) -> int:
        """Write the DB with a generation stamp so staleness is visible later."""
        payload = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "advisories": self.to_dicts(),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return len(self.advisories)

    def clone(self) -> "AdvisoryDB":
        """Return a mutable shallow copy sharing the immutable Advisory objects.

        The list and the two indices are copied so the clone can accept further
        ``load_file``/``add`` calls (user-supplied extra databases) without
        mutating the cached source.
        """
        copy = AdvisoryDB()
        copy.advisories = list(self.advisories)
        copy._by_package = {k: list(v) for k, v in self._by_package.items()}
        copy._seen = set(self._seen)
        copy.generated_at = self.generated_at
        return copy


def _mtime_date(path: str) -> str:
    """The file's modification date (YYYY-MM-DD), or '' if unavailable."""
    try:
        ts = os.path.getmtime(path)
    except OSError:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


# A full OSV export is hundreds of megabytes, and parsing it dominates a scan.
# The bundled files are read-only at scan time, so the parsed database is
# cached (keyed on each file's size and mtime) and callers receive a cheap
# mutable clone. This is shared across scans and threads, hence the lock.
_seed_cache: dict = {"key": None, "db": None}
_seed_cache_lock = threading.Lock()


def load_seed_db(paths: list) -> AdvisoryDB:
    """Load the bundled advisory files once, then return clones of the result."""
    key = tuple((p, _stat_key(p)) for p in paths)
    with _seed_cache_lock:
        if _seed_cache["key"] != key:
            db = AdvisoryDB()
            for p in paths:
                db.load_file(p)
            _seed_cache["key"] = key
            _seed_cache["db"] = db
        return _seed_cache["db"].clone()


def _stat_key(path: str) -> tuple:
    try:
        st = os.stat(path)
        return (st.st_size, st.st_mtime_ns)
    except OSError:
        return (-1, -1)
