"""Top-level scan orchestration."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .advisory.analyzer import analyze_dependencies
from .advisory.db import AdvisoryDB
from .analysis.blade import scan_blade
from .analysis.dataflow import TaintEngine
from .analysis.java_dataflow import JavaTaintEngine
from .analysis.java_symbols import build_java_symbols
from .analysis.symbols import build_symbol_table
from .detection import collect_source_files, detect_framework, detect_language
from .models import Finding, ScanResult, SEVERITY_ORDER
from .parsing.java import JavaParser
from .parsing.php import PhpParser
from .rules.registry import Registry


@dataclass
class ScanOptions:
    advisory_db: str = None
    extra_db_files: list = None
    min_severity: str = "info"
    include_tests: bool = False
    scan_tests: bool = False


class ScanEngine:
    def __init__(self, options: ScanOptions = None) -> None:
        self.options = options or ScanOptions()
        self.registry = Registry()

    def scan(self, root: str) -> ScanResult:
        start = time.time()
        root = os.path.abspath(root)

        language = detect_language(root)
        if language is None:
            return ScanResult(root=root, language="unknown", framework="raw")

        source_files = collect_source_files(root, language)
        profile = detect_framework(root, language, source_files)

        rules = self.registry.rules_for(language, profile.framework)
        findings: list = []

        if language == "php":
            php_files = [f for f in source_files if not f.endswith(".blade.php")]
            blade_files = [f for f in source_files if f.endswith(".blade.php")]
            parser = PhpParser()
            parsed = []
            for path in php_files:
                try:
                    with open(path, "rb") as fh:
                        content = fh.read()
                except OSError:
                    continue
                parsed.append(parser.parse(path, content))
            symbols = build_symbol_table(parsed)
            engine = TaintEngine(symbols, rules, profile.framework, language)
            findings = engine.analyze(parsed)
            if profile.framework == "Laravel":
                findings.extend(scan_blade(blade_files))
            files_scanned = len(parsed)
        elif language == "java":
            parser = JavaParser()
            parsed = []
            for path in source_files:
                try:
                    with open(path, "rb") as fh:
                        content = fh.read()
                except OSError:
                    continue
                parsed.append(parser.parse(path, content))
            symbols = build_java_symbols(parsed)
            engine = JavaTaintEngine(symbols, rules, profile.framework, language)
            findings = engine.analyze(parsed)
            files_scanned = len(parsed)
        else:
            files_scanned = 0

        # Dependency analysis.
        db = AdvisoryDB()
        for seed in self._seed_paths():
            db.load_file(seed)
        if self.options.advisory_db and os.path.isfile(self.options.advisory_db):
            db.load_file(self.options.advisory_db)
        for extra in (self.options.extra_db_files or []):
            if os.path.isfile(extra):
                db.load_file(extra)
        dep_issues = analyze_dependencies(root, language, db)

        # Filter + sort.
        min_sev = self.options.min_severity or "info"
        min_order = SEVERITY_ORDER.get(_sev_enum(min_sev), 99)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99),
                                     f.location.file, f.location.line))
        dep_issues.sort(key=lambda d: (SEVERITY_ORDER.get(d.severity, 99), d.package))

        return ScanResult(
            root=root,
            language=language,
            framework=profile.framework,
            files_scanned=files_scanned,
            findings=findings,
            dependency_issues=dep_issues,
            duration_seconds=round(time.time() - start, 3),
        )

    def _seed_paths(self):
        here = os.path.dirname(os.path.abspath(__file__))
        base = os.path.join(here, "data", "advisories")
        if not os.path.isdir(base):
            return []
        import glob
        paths = sorted(glob.glob(os.path.join(base, "*.json")))
        return [p for p in paths if os.path.isfile(p)]


def _sev_enum(s: str):
    from .models import Severity
    try:
        return Severity(s)
    except ValueError:
        return Severity.INFO
