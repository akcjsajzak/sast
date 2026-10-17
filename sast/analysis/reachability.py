"""Reachability analysis for dependency findings.

A vulnerable package in a lockfile is not the same thing as a vulnerable
application. Most dependency alerts are for packages that are installed but
never used, or used in a way that never touches the vulnerable code. Reporting
them all at equal weight is what makes dependency scanning so noisy that teams
stop reading it.

This module answers a narrower, answerable question: **does first-party code
import this package at all, and does it call anything the advisory names?**
That yields three states:

- ``imported`` — the package is imported, so the vulnerable version is loaded.
- ``called``   — a symbol the advisory names is also invoked. Strongest signal.
- ``unused``   — nothing in first-party code imports it. Almost always
  deprioritisable, though it may still be loaded by another dependency.

This is deliberately *not* a claim about exploitability: it is import and
call-site evidence, which is what can be established without resolving the
dependency's own source. The states are named to reflect that.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Import syntax per language. Each regex must capture the imported module path
# in group 1 so it can be matched against a package name.
_IMPORT_PATTERNS = {
    "python": [
        re.compile(r"^\s*import\s+([A-Za-z0-9_.]+)", re.MULTILINE),
        re.compile(r"^\s*from\s+([A-Za-z0-9_.]+)\s+import", re.MULTILINE),
    ],
    "javascript": [
        re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),
        re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]"""),
        re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]"""),
        re.compile(r"""^\s*import\s+['"]([^'"]+)['"]""", re.MULTILINE),
    ],
    "java": [
        re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z0-9_.]+)", re.MULTILINE),
    ],
    "go": [
        re.compile(r"""^\s*(?:[A-Za-z0-9_.]+\s+)?["`]([^"`]+)["`]""", re.MULTILINE),
    ],
    "csharp": [
        re.compile(r"^\s*using\s+(?:static\s+)?([A-Za-z0-9_.]+)", re.MULTILINE),
    ],
    "php": [
        re.compile(r"^\s*use\s+([A-Za-z0-9_\\]+)", re.MULTILINE),
        re.compile(r"""\brequire(?:_once)?\s*\(?\s*['"]([^'"]+)['"]"""),
    ],
    "c": [re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)],
    "cpp": [re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)],
}

# Extension -> language, for deciding which import syntax applies.
_EXT_LANGUAGE = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".php": "php", ".phtml": "php", ".inc": "php",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".cxx": "cpp",
}

UNUSED = "unused"
IMPORTED = "imported"
CALLED = "called"

# Ordered weakest to strongest, for sorting and comparison.
STATES = (UNUSED, IMPORTED, CALLED)


@dataclass
class ImportIndex:
    """Every module path imported by first-party code, and every called name."""
    modules: set = field(default_factory=set)
    calls: set = field(default_factory=set)

    def merge(self, other: "ImportIndex") -> None:
        self.modules |= other.modules
        self.calls |= other.calls


# A call or attribute access: `foo.bar(` or `bar(`. Used to collect the set of
# names first-party code actually invokes.
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def build_import_index(paths: list[str], max_bytes: int = 2 * 1024 * 1024) -> ImportIndex:
    """Collect imported module paths and called names from first-party source.

    Text-level rather than AST-level on purpose: this needs to run across every
    language at once, including ones whose grammar the taint engines never
    load, and import statements are unambiguous enough to read directly.
    """
    index = ImportIndex()
    for path in paths:
        language = _EXT_LANGUAGE.get(os.path.splitext(path)[1].lower())
        if language is None:
            continue
        try:
            if os.path.getsize(path) > max_bytes:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for pattern in _IMPORT_PATTERNS.get(language, []):
            for m in pattern.finditer(text):
                module = m.group(1).strip()
                if module:
                    index.modules.add(module)
                    index.modules.add(module.lower())
        for m in _CALL_RE.finditer(text):
            index.calls.add(m.group(1))
    return index


def _candidate_module_names(package: str, language: str) -> set:
    """Module paths that importing `package` would plausibly produce.

    Package names and import names differ by ecosystem: `@scope/pkg` is
    imported as `@scope/pkg`, `org.group:artifact` as `org.group.artifact`,
    and PyPI's `PyYAML` as `yaml`. This covers the mechanical transforms;
    irreducibly arbitrary mappings are listed in _IMPORT_ALIASES.
    """
    names = set()
    pkg = package.strip()
    if not pkg:
        return names
    names.add(pkg)
    names.add(pkg.lower())

    if language == "java" or ":" in pkg:
        group, _, artifact = pkg.partition(":")
        if group:
            names.add(group)
            names.add(group.lower())
        if artifact:
            # org.apache.logging.log4j:log4j-core -> org.apache.logging.log4j
            names.add(f"{group}.{artifact.replace('-', '.')}".lower())
    if "/" in pkg and not pkg.startswith("@"):
        # Composer vendor/name, or a Go module path.
        names.add(pkg.split("/")[-1].lower())
        names.add(pkg.lower())
    # PyPI and NuGet names commonly differ from the import name by separators.
    names.add(pkg.replace("-", "_").lower())
    names.add(pkg.replace(".", "_").lower())
    names.add(pkg.replace("-", "").lower())
    return {n for n in names if n}


# Package name -> import name, where the two are unrelated.
_IMPORT_ALIASES = {
    "pyyaml": {"yaml"},
    "beautifulsoup4": {"bs4"},
    "pillow": {"pil"},
    "python-dateutil": {"dateutil"},
    "scikit-learn": {"sklearn"},
    "msgpack-python": {"msgpack"},
    "attrs": {"attr"},
    "protobuf": {"google.protobuf", "google"},
    "setuptools": {"pkg_resources", "setuptools"},
}


def _matches(module: str, candidates: set) -> bool:
    """True if an imported module path refers to one of these names."""
    low = module.lower()
    if low in candidates:
        return True
    # An import of a submodule still loads the package: `yaml.loader` -> yaml.
    for candidate in candidates:
        if not candidate:
            continue
        if low.startswith(candidate + ".") or low.startswith(candidate + "/"):
            return True
        # Java's org.apache.x.Class, Go's github.com/a/b/sub
        if candidate.startswith(low + ".") or candidate.startswith(low + "/"):
            return True
    return False


# Symbols an advisory names. Advisories write APIs both as `defaultsDeep()`
# and as bare `defaultsDeep`, so both forms are collected; the intersection
# with names the code actually calls is what filters out ordinary prose.
_SYMBOL_CALL_RE = re.compile(r"\b([a-zA-Z_][A-Za-z0-9_]{2,})\s*\(\)")
_SYMBOL_IDENT_RE = re.compile(r"\b([a-z][A-Za-z0-9_]*[A-Z_][A-Za-z0-9_]*)\b")
_SYMBOL_DOTTED_RE = re.compile(r"\b[a-z][A-Za-z0-9_]*\.([a-zA-Z_][A-Za-z0-9_]{2,})\b")

# Words that look like identifiers but are prose, and are also plausible
# function names — without this, "the template function" would match a call to
# an unrelated `template()`.
_PROSE_WORDS = frozenset({
    "the", "this", "that", "with", "from", "when", "where", "which", "while",
    "allows", "allowing", "enables", "causes", "results", "leads", "attacker",
    "attackers", "remote", "arbitrary", "malicious", "crafted", "untrusted",
    "vulnerable", "vulnerability", "version", "versions", "before", "after",
    "prior", "through", "using", "used", "uses", "via", "into", "code",
    "execution", "injection", "denial", "service", "request", "requests",
    "response", "header", "headers", "input", "output", "data", "value",
    "values", "string", "strings", "object", "objects", "function",
    "functions", "method", "methods", "module", "modules", "package",
    "packages", "library", "server", "client", "user", "users", "file",
    "files", "path", "paths", "name", "names", "type", "types", "error",
    "errors", "handling", "parsing", "processing", "validation", "sanitize",
    "escape", "bypass", "disclosure", "pollution", "prototype", "overflow",
    "traversal", "forgery", "scripting", "cross", "site", "and", "for", "not",
    "may", "can", "could", "would", "should", "has", "have", "been", "its",
})


def affected_symbols(advisory_text: str) -> set:
    """Function names an advisory calls out, e.g. `defaultsDeep` or `load()`."""
    text = advisory_text or ""
    found: set = set()
    # `foo()` — unambiguous.
    found |= {m.group(1) for m in _SYMBOL_CALL_RE.finditer(text)}
    # `lodash.merge` / `yaml.load` — the dotted half is an API name.
    found |= {m.group(1) for m in _SYMBOL_DOTTED_RE.finditer(text)}
    # Bare camelCase/snake_case identifiers: prose is rarely written that way.
    found |= {m.group(1) for m in _SYMBOL_IDENT_RE.finditer(text)}
    return {s for s in found if s.lower() not in _PROSE_WORDS}


def assess(package: str, language: str, index: ImportIndex,
           advisory_text: str = "") -> tuple:
    """Return (state, evidence) for one vulnerable package.

    `evidence` is a short human-readable reason, shown in reports so the
    verdict can be checked rather than taken on trust.
    """
    candidates = _candidate_module_names(package, language)
    candidates |= _IMPORT_ALIASES.get(package.lower(), set())

    matched = next((m for m in index.modules if _matches(m, candidates)), None)
    if matched is None:
        return UNUSED, "no first-party import of this package was found"

    symbols = affected_symbols(advisory_text)
    called = sorted(symbols & index.calls)
    if called:
        return CALLED, (f"imported as '{matched}' and the advisory's "
                        f"{', '.join(called[:3])}() is called in first-party code")
    return IMPORTED, f"imported as '{matched}' by first-party code"


def annotate(dependency_issues: list, index: ImportIndex,
             language_by_package: dict = None) -> None:
    """Set reachability on every dependency issue, in place."""
    language_by_package = language_by_package or {}
    for issue in dependency_issues:
        # Base images are not imported by source code; the question does not apply.
        if "(base image)" in issue.package:
            issue.reachability = ""
            issue.reachability_note = ""
            continue
        language = language_by_package.get(issue.package, "")
        text = f"{issue.title} {issue.description}"
        state, note = assess(issue.package, language, index, text)
        issue.reachability = state
        issue.reachability_note = note


def rank(state: str) -> int:
    """Higher means more strongly reached: called > imported > unused.

    An unknown state (a base image, where the question does not apply) sorts
    with 'imported' rather than at either extreme, so it is neither buried nor
    promoted above evidence of an actual call.
    """
    if not state:
        return STATES.index(IMPORTED)
    try:
        return STATES.index(state)
    except ValueError:
        return STATES.index(IMPORTED)
