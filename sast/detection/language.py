"""Language detection and source file collection."""
from __future__ import annotations

import os
import re
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

# Default cap on a single source file. Generated/minified sources well past
# this size cost far more to parse and taint than they are worth.
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB

# Path segments and filename shapes that mark a file as test code. Matched
# against the path *relative to the scan root*, so a project that merely lives
# under e.g. /home/me/testing/ is not wholly excluded.
_TEST_DIR_SEGMENTS = {
    "test", "tests", "testing", "spec", "specs",
    "__tests__", "fixtures", "testdata",
}
# "test" as a separator-delimited word: test_foo.php, foo-spec.php, Foo.test.js.
# Case-insensitive, but the separators stop it matching inside a longer word.
_TEST_WORD_RE = re.compile(
    r"(^|[._-])(test|tests|spec|specs)([._-]|$)", re.IGNORECASE,
)
# CamelCase suffix conventions: UserTest.java, FooIT.java, AdminSpec.php. Kept
# case-SENSITIVE and anchored to a preceding lowercase letter or digit, so an
# ordinary word that merely ends in "test" (Contest.php) is not a test file.
_TEST_SUFFIX_RE = re.compile(
    r"[a-z0-9](Test|Tests|TestCase|IT|ITCase|Spec)\.(java|php|phtml|inc)$",
)


def is_test_path(rel_path: str) -> bool:
    """True if a repo-relative path looks like test code rather than app code."""
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    # Directory conventions, including Maven/Gradle's src/test/java/...
    for seg in parts[:-1]:
        if seg.lower() in _TEST_DIR_SEGMENTS:
            return True
    name = parts[-1]
    return bool(_TEST_WORD_RE.search(name) or _TEST_SUFFIX_RE.search(name))


def collect_source_files(
    root: str,
    language: Optional[str] = None,
    include_tests: bool = True,
    max_file_bytes: Optional[int] = None,
    max_files: Optional[int] = None,
) -> list[str]:
    """Walk `root` and return source files for the given (or detected) language.

    `include_tests` defaults to True so existing callers keep their behaviour;
    the scan engine passes the user's choice explicitly. Use
    `collect_source_files_detailed` when the caller needs the skip counts.
    """
    files, _ = collect_source_files_detailed(
        root, language, include_tests=include_tests,
        max_file_bytes=max_file_bytes, max_files=max_files,
    )
    return files


def collect_source_files_detailed(
    root: str,
    language: Optional[str] = None,
    include_tests: bool = True,
    max_file_bytes: Optional[int] = None,
    max_files: Optional[int] = None,
) -> tuple[list[str], dict]:
    """Like `collect_source_files`, but also reports what was skipped.

    Returns `(files, skipped)` where `skipped` counts files left out, keyed by
    reason: 'tests', 'too_large', 'truncated'.
    """
    if language is None:
        language = detect_language(root)

    skipped = {"tests": 0, "too_large": 0, "truncated": 0}
    if language is None:
        return [], skipped

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
            if ext not in exts:
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, root)
            if not include_tests and is_test_path(rel):
                skipped["tests"] += 1
                continue
            if max_file_bytes:
                try:
                    if os.path.getsize(path) > max_file_bytes:
                        skipped["too_large"] += 1
                        continue
                except OSError:
                    continue
            results.append(path)
    results.sort()
    if max_files and len(results) > max_files:
        skipped["truncated"] = len(results) - max_files
        results = results[:max_files]
    return results, skipped


def _language_counts(root: str) -> dict:
    """Weighted file counts per language (manifests count heavily)."""
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
    return counts


def detect_languages(root: str) -> list[str]:
    """Detect every language present, most prevalent first.

    A polyglot repository (say a Spring service alongside a PHP admin panel)
    returns both, so the engine can scan each instead of silently analysing
    only the larger half.
    """
    counts = _language_counts(root)
    present = [lang for lang, n in counts.items() if n > 0]
    present.sort(key=lambda lang: counts[lang], reverse=True)
    return present


def detect_language(root: str) -> Optional[str]:
    """Detect the primary (most prevalent) language of a project directory."""
    languages = detect_languages(root)
    return languages[0] if languages else None
