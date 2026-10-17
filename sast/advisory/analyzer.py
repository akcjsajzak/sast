"""Dependency vulnerability analysis: match installed packages against the DB."""
from __future__ import annotations

from ..models import DependencyIssue, Severity
from .composer import parse_composer_json, parse_composer_lock
from .db import AdvisoryDB
from .maven import parse_java_dependencies


def analyze_dependencies(root: str, language: str, db: AdvisoryDB) -> list[DependencyIssue]:
    issues: list[DependencyIssue] = []
    if language == "php":
        packages = parse_composer_lock(root)
        if not packages:
            # Fall back to constraints (approximate; note in fixed_in).
            packages = [(n, v) for (n, v) in parse_composer_json(root)]
    elif language == "java":
        packages = parse_java_dependencies(root)
    else:
        packages = []

    for pkg, version in packages:
        for adv in db.match(pkg, version):
            issues.append(DependencyIssue(
                package=pkg,
                version=version,
                cve=adv.cve,
                severity=Severity(adv.severity),
                title=adv.title or f"Known vulnerability in {pkg}",
                description=adv.description,
                fixed_in=adv.fixed_in,
                cwe=adv.cwe,
                references=adv.references,
            ))
    return issues
