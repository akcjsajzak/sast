"""Language detection and source file collection."""
from __future__ import annotations

import os
import re
from typing import Optional

LANGUAGE_EXTENSIONS = {
    "php": {".php", ".php3", ".php4", ".php5", ".phtml", ".inc"},
    "java": {".java"},
    # TypeScript is included under "javascript": Angular is .ts and React is
    # frequently .tsx, so excluding it would miss both frameworks entirely.
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"},
    "python": {".py", ".pyi"},
    "go": {".go"},
    "csharp": {".cs"},
    "c": {".c"},
    # .h is claimed by C++ so a header using C++ constructs still parses; a
    # C-only project's headers parse fine under the C++ grammar too.
    "cpp": {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h"},
}

# Build output and vendored bundles: minified, not first-party, and a rich
# source of false positives.
_JS_SKIP_SUFFIXES = (".min.js", ".bundle.js", ".chunk.js", ".min.mjs",
                     ".d.ts", ".map")

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
# CamelCase suffix conventions: UserTest.java, AdminSpec.php, ParserTests.cs.
# Kept case-SENSITIVE and anchored to a preceding lowercase letter or digit, so
# an ordinary word that merely ends in "test" (Contest.php) is not a test file.
# The extension is open: the convention is not Java's alone, and limiting it to
# java/php meant FooTest.cs, parser_test.cc and HandlerSpec.ts were all scanned
# as application code.
_TEST_SUFFIX_RE = re.compile(
    r"[a-z0-9](Test|Tests|TestCase|TestCases|Spec|Specs)\.[A-Za-z0-9]+$",
)
# `FooIT.java` is a Maven failsafe integration test. Two letters are too short
# to claim anywhere else, so this one stays tied to Java.
_TEST_SUFFIX_JAVA_RE = re.compile(r"[a-z0-9](IT|ITCase)\.java$")
# Directory conventions that are not a bare word: .NET's `Project.Tests`, and
# CamelCase `UnitTests` / `MyProjectTests`. Checked on each path segment.
# The dotted form is case-insensitive (`Newtonsoft.Json.Tests`, `foo.test`);
# the CamelCase form stays case-sensitive so `latest` is not a test directory.
_TEST_DIR_SUFFIX_RE = re.compile(
    r"(?:(?i:\.(?:tests?|specs?))$)|(?:[a-z0-9](?:Tests?|Specs?|TestCases?)$)",
)


def is_test_path(rel_path: str) -> bool:
    """True if a repo-relative path looks like test code rather than app code."""
    norm = rel_path.replace("\\", "/")
    parts = norm.split("/")
    # Directory conventions, including Maven/Gradle's src/test/java/...
    for seg in parts[:-1]:
        if seg.lower() in _TEST_DIR_SEGMENTS or _TEST_DIR_SUFFIX_RE.search(seg):
            return True
    name = parts[-1]
    return bool(_TEST_WORD_RE.search(name)
                or _TEST_SUFFIX_RE.search(name)
                or _TEST_SUFFIX_JAVA_RE.search(name))


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
            if language == "javascript" and fname.lower().endswith(_JS_SKIP_SUFFIXES):
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


# A manifest is strong evidence the language is present even when few source
# files are. Mapped to the weight it contributes.
_MANIFEST_WEIGHTS = {
    "composer.json": ("php", 100),
    "pom.xml": ("java", 100),
    "build.gradle": ("java", 80),
    "build.gradle.kts": ("java", 80),
    "package.json": ("javascript", 100),
    "requirements.txt": ("python", 100),
    "pyproject.toml": ("python", 100),
    "Pipfile": ("python", 80),
    "setup.py": ("python", 80),
    "go.mod": ("go", 100),
    "CMakeLists.txt": ("cpp", 60),
    "conanfile.txt": ("cpp", 60),
    "vcpkg.json": ("cpp", 60),
}

# Extension -> language, built once from LANGUAGE_EXTENSIONS. Later entries
# win on conflict, which is why .h resolves to cpp.
_EXT_LANGUAGE: dict = {}
for _lang, _exts in LANGUAGE_EXTENSIONS.items():
    for _ext in _exts:
        _EXT_LANGUAGE[_ext] = _lang


def _language_counts(root: str) -> dict:
    """Weighted file counts per language (manifests count heavily)."""
    counts = {lang: 0 for lang in LANGUAGE_EXTENSIONS}

    for manifest, (lang, weight) in _MANIFEST_WEIGHTS.items():
        if os.path.isfile(os.path.join(root, manifest)):
            counts[lang] += weight

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            low = fname.lower()
            ext = os.path.splitext(low)[1]
            lang = _EXT_LANGUAGE.get(ext)
            if lang is None:
                continue
            if lang == "javascript" and low.endswith(_JS_SKIP_SUFFIXES):
                continue
            # A .csproj next to .cs files is the C# signal.
            counts[lang] += 1
            if low.endswith(".csproj") or low.endswith(".sln"):
                counts["csharp"] += 50
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
