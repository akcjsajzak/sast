"""Dependency vulnerability analysis: match installed packages against the DB."""
from __future__ import annotations

from ..models import DependencyIssue, Severity
from .composer import parse_composer_json, parse_composer_lock
from .db import AdvisoryDB
from .maven import parse_java_dependencies
from .npm import parse_npm_dependencies


def _packages_for(module: str, language: str) -> list[tuple[str, str]]:
    if language == "php":
        packages = parse_composer_lock(module)
        if not packages:
            # Fall back to constraints (approximate; note in fixed_in).
            packages = [(n, v) for (n, v) in parse_composer_json(module)]
        return packages
    if language == "java":
        return parse_java_dependencies(module)
    if language == "javascript":
        return parse_npm_dependencies(module)
    return []


def analyze_dependencies(root: str, language: str, db: AdvisoryDB,
                         module_dirs: list = None) -> list[DependencyIssue]:
    """Match declared dependencies against the advisory DB.

    `module_dirs` lets a monorepo report every module's manifest; it defaults
    to the scan root alone. Identical (package, version) pairs declared by
    several modules are collapsed.
    """
    modules = module_dirs or [root]
    packages: list[tuple[str, str]] = []
    seen_pkgs: set = set()
    for module in modules:
        for pkg, version in _packages_for(module, language):
            if (pkg, version) in seen_pkgs:
                continue
            seen_pkgs.add((pkg, version))
            packages.append((pkg, version))

    issues: list[DependencyIssue] = []
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
