"""Dependency manifests for Python, Go, .NET and C/C++.

Where a lockfile exists it is preferred, because it carries the resolved
transitive tree; a plain manifest lists only direct dependencies and often as
version ranges.
"""
from __future__ import annotations

import json
import os
import re

# --------------------------------------------------------------------------
# Python (PyPI)
# --------------------------------------------------------------------------
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#]*)",
    re.MULTILINE,
)
_POETRY_RE = re.compile(
    r'^\s*name\s*=\s*"([^"]+)"\s*\n\s*version\s*=\s*"([^"]+)"', re.MULTILINE
)


def parse_python_dependencies(root: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set = set()

    def add(name, version):
        key = (name.lower(), version)
        if name and version and key not in seen:
            seen.add(key)
            out.append((name, version))

    # Pipfile.lock / poetry.lock carry the resolved tree.
    lock = os.path.join(root, "Pipfile.lock")
    if os.path.isfile(lock):
        try:
            with open(lock, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for section in ("default", "develop"):
                for name, meta in (data.get(section, {}) or {}).items():
                    version = (meta or {}).get("version", "")
                    add(name, version.lstrip("="))
        except (OSError, json.JSONDecodeError):
            pass

    poetry = os.path.join(root, "poetry.lock")
    if os.path.isfile(poetry):
        try:
            with open(poetry, "r", encoding="utf-8", errors="replace") as fh:
                for m in _POETRY_RE.finditer(fh.read()):
                    add(m.group(1), m.group(2))
        except OSError:
            pass

    for name in ("requirements.txt", "requirements-dev.txt", "constraints.txt"):
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for m in _REQ_RE.finditer(fh.read()):
                    add(m.group(1), m.group(2))
        except OSError:
            continue
    return out


# --------------------------------------------------------------------------
# Go modules
# --------------------------------------------------------------------------
_GOSUM_RE = re.compile(r"^(\S+)\s+v([0-9][^\s/]*)(?:/go\.mod)?\s+h1:", re.MULTILINE)
_GOMOD_REQUIRE_RE = re.compile(r"^\s*(\S+)\s+v([0-9]\S*)", re.MULTILINE)


def parse_go_dependencies(root: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set = set()

    def add(name, version):
        key = (name, version)
        if name and version and key not in seen:
            seen.add(key)
            out.append((name, version))

    # go.sum lists every module in the build graph, including transitive ones.
    gosum = os.path.join(root, "go.sum")
    if os.path.isfile(gosum):
        try:
            with open(gosum, "r", encoding="utf-8", errors="replace") as fh:
                for m in _GOSUM_RE.finditer(fh.read()):
                    add(m.group(1), m.group(2))
        except OSError:
            pass
    if out:
        return out

    gomod = os.path.join(root, "go.mod")
    if os.path.isfile(gomod):
        try:
            with open(gomod, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for m in _GOMOD_REQUIRE_RE.finditer(text):
                name = m.group(1)
                if name in ("module", "go", "require", "replace", "exclude"):
                    continue
                add(name, m.group(2))
        except OSError:
            pass
    return out


# --------------------------------------------------------------------------
# .NET (NuGet)
# --------------------------------------------------------------------------
_PKGREF_RE = re.compile(
    r'<PackageReference\s+Include\s*=\s*"([^"]+)"\s+Version\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)
_PKGCONFIG_RE = re.compile(
    r'<package\s+id\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"', re.IGNORECASE
)


def parse_dotnet_dependencies(root: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set = set()

    def add(name, version):
        key = (name.lower(), version)
        if name and version and key not in seen:
            seen.add(key)
            out.append((name, version))

    # packages.lock.json carries the resolved transitive graph.
    lock = os.path.join(root, "packages.lock.json")
    if os.path.isfile(lock):
        try:
            with open(lock, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for _framework, deps in (data.get("dependencies", {}) or {}).items():
                for name, meta in (deps or {}).items():
                    add(name, (meta or {}).get("resolved", ""))
        except (OSError, json.JSONDecodeError):
            pass
        if out:
            return out

    try:
        entries = os.listdir(root)
    except OSError:
        entries = []
    for fname in entries:
        path = os.path.join(root, fname)
        low = fname.lower()
        if not (low.endswith(".csproj") or low.endswith(".fsproj")
                or low.endswith(".vbproj") or low == "packages.config"
                or low == "directory.packages.props"):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _PKGREF_RE.finditer(text):
            add(m.group(1), m.group(2))
        for m in _PKGCONFIG_RE.finditer(text):
            add(m.group(1), m.group(2))
    return out


# --------------------------------------------------------------------------
# C / C++ (Conan, vcpkg)
# --------------------------------------------------------------------------
_CONAN_RE = re.compile(r"^\s*([A-Za-z0-9._\-]+)/([0-9][^@\s#]*)", re.MULTILINE)


def parse_native_dependencies(root: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set = set()

    def add(name, version):
        key = (name.lower(), version)
        if name and version and key not in seen:
            seen.add(key)
            out.append((name, version))

    for fname in ("conanfile.txt", "conanfile.py", "conan.lock"):
        path = os.path.join(root, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _CONAN_RE.finditer(text):
            add(m.group(1), m.group(2))

    vcpkg = os.path.join(root, "vcpkg.json")
    if os.path.isfile(vcpkg):
        try:
            with open(vcpkg, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for dep in data.get("dependencies", []) or []:
                if isinstance(dep, str):
                    add(dep, data.get("version", "") or "")
                elif isinstance(dep, dict):
                    add(dep.get("name", ""), dep.get("version>=", "") or "")
        except (OSError, json.JSONDecodeError):
            pass
    return out
