"""Language detection and source file collection."""
from __future__ import annotations

import os
from typing import Optional

LANGUAGE_EXTENSIONS = {
    "php": {".php", ".php3", ".php4", ".php5", ".phtml", ".inc"},
    "java": {".java"},
}

# Directories that should never be scanned (vendor dirs, build output, caches).
IGNORED_DIRS = {
    "vendor", "node_modules", ".git", ".svn", ".hg",
    "target", "build", "dist", "out", ".idea", ".gradle",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    "storage", "bootstrap/cache", "var/cache", "var/log",
}

IGNORED_FILES = {"composer.lock", "composer.json", "package-lock.json"}


def collect_source_files(root: str, language: Optional[str] = None) -> list[str]:
    """Walk `root` and return source files for the given (or auto-detected) language."""
    if language is None:
        language = detect_language(root)

    if language is None:
        return []

    exts = LANGUAGE_EXTENSIONS.get(language, set())
    results: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place.
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORED_DIRS and not d.startswith(".")
        ]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in exts:
                results.append(os.path.join(dirpath, fname))
    results.sort()
    return results


def detect_language(root: str) -> Optional[str]:
    """Detect the primary language of a project directory.

    Heuristic: count files by extension, weighted by the presence of a
    manifest file (composer.json / pom.xml / build.gradle).
    """
    counts = {"php": 0, "java": 0}

    if os.path.isfile(os.path.join(root, "composer.json")):
        counts["php"] += 100
    if os.path.isfile(os.path.join(root, "pom.xml")):
        counts["java"] += 100
    if os.path.isfile(os.path.join(root, "build.gradle")):
        counts["java"] += 80

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in LANGUAGE_EXTENSIONS["php"]:
                counts["php"] += 1
            elif ext in LANGUAGE_EXTENSIONS["java"]:
                counts["java"] += 1

    if counts["php"] == 0 and counts["java"] == 0:
        return None
    return "php" if counts["php"] >= counts["java"] else "java"
