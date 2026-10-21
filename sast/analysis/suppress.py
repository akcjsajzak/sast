"""Accepting a finding: inline `sast:ignore` markers and a baseline file.

Without a way to accept a finding, `--fail-on` gates on everything the
scanner has ever reported, triaged or not, which on an existing codebase
makes the gate impossible to adopt: the first run is red and stays red.

Two mechanisms, deliberately different in scope:

* An inline marker accepts one finding where it lives, in the diff, reviewed
  by whoever reads that line. It names the rule and says why.
* A baseline accepts everything that exists today, so a gate can be turned
  on for *new* findings only, without pretending the old ones are fixed.

Neither deletes anything. A suppressed finding stays in the result, carrying
why it was suppressed, and the reports say how many there are — an accepted
finding that disappears from the report is indistinguishable from one that
was never found.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field

# `sast:ignore`, optionally naming rules and giving a reason:
#   // sast:ignore -- the path is a constant
#   # sast:ignore py-cmdi-os-system: fixed argument list
#   /* sast:ignore js-xss-innerhtml, js-code-eval */
#   // sast:ignore-next-line
#
# The marker only counts inside a comment: something has to introduce one
# before it on the line, so the string "sast:ignore" sitting in data cannot
# silence a rule. The introducers cover every language scanned; `;` is only
# one at the start of a line (ini, assembly), because mid-line it is a
# statement terminator in most of them.
_IGNORE = re.compile(r"\bsast:ignore(-next-line)?\b", re.IGNORECASE)
_COMMENT_INTRODUCER = re.compile(r"//|\#|/\*|<!--|--|\*")
_LINE_COMMENT_ONLY = re.compile(r"^\s*;")
# A rule id, or `*` for every rule. The list ends at a reason separator
# (`--` or `:`) or at a comment terminator.
_RULE = re.compile(r"[A-Za-z0-9_.*][A-Za-z0-9_.*-]*")
_REASON_SEPARATOR = re.compile(r"\s*(?:--|:)\s*")
_COMMENT_END = re.compile(r"\*/|-->")


def _parse_marker(text: str, start: int, end: int):
    """Rules and reason following a marker, or None if it is not in a comment.

    `start`/`end` bound the `sast:ignore` token itself. Rule ids contain
    hyphens, and so does the `--` that introduces a reason, so the list is
    read token by token rather than by splitting on a character class.
    """
    before = text[:start]
    if not _COMMENT_INTRODUCER.search(before) and not _LINE_COMMENT_ONLY.match(before):
        return None
    rest = text[end:]
    terminator = _COMMENT_END.search(rest)
    if terminator:
        rest = rest[:terminator.start()]
    rules: list = []
    while True:
        separator = _REASON_SEPARATOR.match(rest)
        if separator:
            rest = rest[separator.end():]
            break
        stripped = rest.lstrip(" \t,")
        match = _RULE.match(stripped)
        if not match:
            break
        rules.append(match.group(0))
        rest = stripped[match.end():]
    return tuple(r for r in rules if r != "*"), rest.strip()


@dataclass
class Suppression:
    """Why a finding is not being counted."""
    kind: str                 # 'inline' | 'baseline'
    reason: str = ""
    rule_id: str = ""         # the rule the marker named ('' = every rule)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "reason": self.reason, "rule_id": self.rule_id}


@dataclass
class _Marker:
    rules: tuple
    reason: str

    def covers(self, rule_id: str) -> bool:
        return not self.rules or rule_id in self.rules


class InlineSuppressions:
    """The `sast:ignore` markers of the files a scan touched, read once."""

    def __init__(self) -> None:
        self._by_file: dict = {}

    def _markers(self, path: str) -> dict:
        """line number -> marker, for the file at `path`."""
        cached = self._by_file.get(path)
        if cached is not None:
            return cached
        found: dict = {}
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        for number, text in enumerate(lines, 1):
            match = _IGNORE.search(text)
            if not match:
                continue
            parsed = _parse_marker(text, match.start(), match.end())
            if parsed is None:
                continue
            rules, reason = parsed
            # `-next-line` applies to the line below, everything else to its own.
            target = number + 1 if match.group(1) else number
            found[target] = _Marker(rules=rules, reason=reason)
        self._by_file[path] = found
        return found

    def match(self, path: str, line: int, rule_id: str):
        """The marker accepting `rule_id` at that line, if there is one."""
        marker = self._markers(path).get(line)
        if marker is not None and marker.covers(rule_id):
            return Suppression(kind="inline", reason=marker.reason, rule_id=rule_id)
        return None


@dataclass
class Baseline:
    """Fingerprints accepted as pre-existing."""
    fingerprints: dict = field(default_factory=dict)
    generated_at: str = ""
    root: str = ""

    @classmethod
    def load(cls, path: str) -> "Baseline":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "fingerprints" not in data:
            raise ValueError(f"{path} is not a sast baseline")
        return cls(
            fingerprints=dict(data.get("fingerprints") or {}),
            generated_at=str(data.get("generated_at") or ""),
            root=str(data.get("root") or ""),
        )

    def covers(self, fingerprint: str) -> bool:
        return fingerprint in self.fingerprints

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "generated_at": self.generated_at,
            "root": self.root,
            "fingerprints": self.fingerprints,
        }


def dependency_fingerprint(issue) -> str:
    """Identity of a vulnerable dependency, stable across versions bumps of
    unrelated packages. Mirrors what the SARIF report emits."""
    return f"dep:{issue.package}:{issue.cve}"


def build_baseline(result) -> Baseline:
    """Every finding and dependency issue in `result`, as a baseline."""
    entries: dict = {}
    for f in result.findings:
        entries[f.fingerprint(result.root)] = {
            "rule_id": f.rule_id,
            "file": _rel(f.location.file, result.root),
            "title": f.title,
            "severity": f.severity.value,
        }
    for d in result.dependency_issues:
        entries[dependency_fingerprint(d)] = {
            "rule_id": d.cve or d.package,
            "file": _rel(d.manifest, result.root),
            "title": d.title,
            "severity": d.severity.value,
        }
    return Baseline(
        fingerprints=entries,
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        root=result.root,
    )


def apply_suppressions(result, baseline: "Baseline" = None,
                       inline: bool = True) -> dict:
    """Mark accepted findings on `result`; returns counts by kind.

    Nothing is removed: each suppressed item carries a `suppression` saying
    which mechanism accepted it and why.
    """
    counts = {"inline": 0, "baseline": 0}
    markers = InlineSuppressions() if inline else None
    for f in result.findings:
        f.suppression = None
        if markers is not None and f.location.file:
            hit = markers.match(f.location.file, f.location.line, f.rule_id)
            if hit is not None:
                f.suppression = hit
                counts["inline"] += 1
                continue
        if baseline is not None and baseline.covers(f.fingerprint(result.root)):
            f.suppression = Suppression(kind="baseline", reason="in baseline")
            counts["baseline"] += 1
    for d in result.dependency_issues:
        d.suppression = None
        if baseline is not None and baseline.covers(dependency_fingerprint(d)):
            d.suppression = Suppression(kind="baseline", reason="in baseline")
            counts["baseline"] += 1
    return counts


def _rel(path: str, root: str) -> str:
    if not path:
        return ""
    if root:
        try:
            rel = os.path.relpath(path, root)
        except ValueError:
            return path.replace(os.sep, "/")
        if not rel.startswith(".."):
            path = rel
    return path.replace(os.sep, "/")
