"""Dependency vulnerability analysis: match installed packages against the DB."""
from __future__ import annotations

import os

from ..models import DependencyIssue, Severity
from .composer import parse_composer_json, parse_composer_lock
from .db import AdvisoryDB
from .maven import parse_java_dependencies
from .misc_ecosystems import (
    parse_dotnet_dependencies,
    parse_go_dependencies,
    parse_native_dependencies,
    parse_python_dependencies,
)
from .npm import parse_npm_dependencies


# Manifest filenames per language, most authoritative first. Used only to
# give a dependency finding a file to point at: SARIF consumers (GitHub code
# scanning among them) drop a result that has no location.
_MANIFESTS = {
    "php": ("composer.lock", "composer.json"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"),
    "javascript": ("package-lock.json", "yarn.lock", "package.json"),
    "python": ("poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt",
               "pyproject.toml"),
    "go": ("go.sum", "go.mod"),
    "csharp": ("packages.lock.json", "packages.config"),
    "c": ("conan.lock", "conanfile.txt", "vcpkg.json"),
    "cpp": ("conan.lock", "conanfile.txt", "vcpkg.json"),
}


def manifest_for(module: str, language: str) -> str:
    """The manifest a module's dependencies were read from, if one is there."""
    for name in _MANIFESTS.get(language, ()):
        candidate = os.path.join(module, name)
        if os.path.isfile(candidate):
            return candidate
    return ""


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
    if language == "python":
        return parse_python_dependencies(module)
    if language == "go":
        return parse_go_dependencies(module)
    if language == "csharp":
        return parse_dotnet_dependencies(module)
    if language in ("c", "cpp"):
        return parse_native_dependencies(module)
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
    manifests: dict = {}
    for module in modules:
        manifest = manifest_for(module, language)
        for pkg, version in _packages_for(module, language):
            if (pkg, version) in seen_pkgs:
                continue
            seen_pkgs.add((pkg, version))
            packages.append((pkg, version))
            manifests[(pkg, version)] = manifest

    issues: list[DependencyIssue] = []
    for pkg, version in packages:
        for adv in db.match(pkg, version):
            issues.append(DependencyIssue(
                package=pkg,
                version=version,
                manifest=manifests.get((pkg, version), ""),
                cve=adv.cve,
                severity=Severity(adv.severity),
                title=adv.title or f"Known vulnerability in {pkg}",
                description=adv.description,
                fixed_in=adv.fixed_in,
                cwe=adv.cwe,
                references=adv.references,
            ))
    return issues
