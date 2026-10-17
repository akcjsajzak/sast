"""Parse Maven (pom.xml) and Gradle (build.gradle) dependency declarations."""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _find(child, name):
    for c in child:
        if _local(c.tag) == name:
            return c
    return None


def parse_pom(root: str) -> list[tuple[str, str]]:
    """Return [(groupId:artifactId, version)] from pom.xml."""
    path = os.path.join(root, "pom.xml")
    if not os.path.isfile(path):
        return []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    proj = tree.getroot()

    props = {}
    props_el = _find(proj, "properties")
    if props_el is not None:
        for c in props_el:
            if _local(c.tag) not in ("",):
                props[_local(c.tag)] = (c.text or "").strip()

    project_version = ""
    ver_el = _find(proj, "version")
    if ver_el is not None:
        project_version = (ver_el.text or "").strip()

    def resolve(v):
        if not v:
            return ""
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), project_version), v)

    # dependencyManagement versions (for deps without an explicit version).
    managed = {}
    dm = _find(proj, "dependencyManagement")
    if dm is not None:
        deps_el = _find(dm, "dependencies")
        if deps_el is not None:
            for d in deps_el:
                if _local(d.tag) != "dependency":
                    continue
                g = (a.text or "").strip() if (a := _find(d, "groupId")) is not None else ""
                art = (a.text or "").strip() if (a := _find(d, "artifactId")) is not None else ""
                v = (a.text or "").strip() if (a := _find(d, "version")) is not None else ""
                managed[f"{g}:{art}"] = resolve(v)

    result = []
    # parent
    parent = _find(proj, "parent")
    if parent is not None:
        g = (a.text or "").strip() if (a := _find(parent, "groupId")) is not None else ""
        art = (a.text or "").strip() if (a := _find(parent, "artifactId")) is not None else ""
        v = (a.text or "").strip() if (a := _find(parent, "version")) is not None else ""
        if g and art and v:
            result.append((f"{g}:{art}", resolve(v)))

    deps_el = _find(proj, "dependencies")
    if deps_el is not None:
        for d in deps_el:
            if _local(d.tag) != "dependency":
                continue
            g = (a.text or "").strip() if (a := _find(d, "groupId")) is not None else ""
            art = (a.text or "").strip() if (a := _find(d, "artifactId")) is not None else ""
            v = (a.text or "").strip() if (a := _find(d, "version")) is not None else ""
            if not v:
                v = managed.get(f"{g}:{art}", "")
            if not v:
                continue
            # skip test-scope deps only if marked test (keeps them by default)
            result.append((f"{g}:{art}", resolve(v)))
    return result


_GRADLE_SHORT = re.compile(
    r"\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|"
    r"annotationProcessor|kapt)\s+['\"]([^:'\"]+):([^:'\"]+):([^'\"\s]+)['\"]"
)
_GRADLE_MAP = re.compile(
    r"\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile)\s+"
    r"group\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*"
    r"version\s*:\s*['\"]([^'\"]+)['\"]",
    re.DOTALL,
)


def parse_gradle(root: str) -> list[tuple[str, str]]:
    """Return [(groupId:artifactId, version)] from build.gradle."""
    path = os.path.join(root, "build.gradle")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    result = []
    for m in _GRADLE_SHORT.finditer(text):
        result.append((f"{m.group(2)}:{m.group(3)}", m.group(4)))
    for m in _GRADLE_MAP.finditer(text):
        result.append((f"{m.group(2)}:{m.group(3)}", m.group(4)))
    return result


# Gradle dependency locking: "group:artifact:version=conf1,conf2". These are
# fully resolved, so they include transitive dependencies.
_GRADLE_LOCK_RE = re.compile(
    r"^([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([^=\s]+)=", re.MULTILINE
)

# `mvn dependency:tree` text output, e.g.
#   [INFO] +- org.apache.logging.log4j:log4j-core:jar:2.14.0:compile
#   [INFO] |  \- com.example:lib:jar:1.0:runtime
_MVN_TREE_RE = re.compile(
    r"[|+\\\- ]*\b([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):(?:[a-z-]+:)?"
    r"(?:[A-Za-z0-9_.\-]+:)?([0-9][A-Za-z0-9_.\-]*):(?:compile|provided|runtime|test|system)",
    re.MULTILINE,
)

# Files that, when present, give a fully resolved dependency set.
RESOLVED_FILES = (
    "gradle.lockfile",
    "dependency-tree.txt",
    "dependencies.txt",
    "deps.txt",
    "maven-dependency-tree.txt",
)


def parse_resolved(root: str) -> list[tuple[str, str]]:
    """Parse a resolved dependency listing, including transitive entries.

    `pom.xml` and `build.gradle` only declare *direct* dependencies, so a
    library pulled in transitively — the shape of the Log4Shell exposure, where
    log4j-core arrived via spring-boot-starter — is invisible from them alone.
    Resolving that properly needs the Maven/Gradle resolver and a network, so
    instead we read a resolved listing when the project has committed or
    generated one.
    """
    result: list[tuple[str, str]] = []
    seen: set = set()
    for name in RESOLVED_FILES:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        regex = _GRADLE_LOCK_RE if name == "gradle.lockfile" else _MVN_TREE_RE
        for m in regex.finditer(text):
            pkg, version = f"{m.group(1)}:{m.group(2)}", m.group(3)
            if (pkg, version) not in seen:
                seen.add((pkg, version))
                result.append((pkg, version))
    return result


def parse_java_dependencies(root: str) -> list[tuple[str, str]]:
    """Declared dependencies, plus transitive ones when a resolved file exists."""
    deps = parse_pom(root)
    if not deps:
        deps = parse_gradle(root)

    resolved = parse_resolved(root)
    if not resolved:
        return deps

    seen = {(p, v) for p, v in deps}
    for pkg, version in resolved:
        if (pkg, version) not in seen:
            seen.add((pkg, version))
            deps.append((pkg, version))
    return deps
