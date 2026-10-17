"""Offline advisory database: load bundled seed + user files, match versions."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

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
        if seed_path and os.path.isfile(seed_path):
            self.load_file(seed_path)

    def load_file(self, path: str) -> int:
        """Load an advisory JSON file (our internal format). Returns count added."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return 0
        count = 0
        entries = data if isinstance(data, list) else data.get("advisories", [])
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
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dicts(), fh, indent=2)
        return len(self.advisories)
