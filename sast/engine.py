"""Top-level scan orchestration."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .advisory.analyzer import analyze_dependencies
from .advisory.db import AdvisoryDB
from .analysis.blade import scan_blade
from .analysis.config_scan import collect_config_files, scan_configs
from .analysis.dataflow import TaintEngine
from .analysis.templates import collect_template_files, scan_templates
from .analysis.java_dataflow import JavaTaintEngine
from .analysis.java_symbols import build_java_symbols
from .analysis.symbols import build_symbol_table
from .detection import (
    collect_source_files_detailed,
    detect_framework,
    detect_languages,
    is_test_path,
)
from .detection.language import DEFAULT_MAX_FILE_BYTES
from .models import ScanResult, SEVERITY_ORDER
from .parsing.java import JavaParser
from .parsing.php import PhpParser
from .rules.registry import Registry


@dataclass
class ScanOptions:
    advisory_dbs: list = field(default_factory=list)
    min_severity: str = "info"
    # Test code is excluded by default: fixtures deliberately contain unsafe
    # patterns and are not reachable by an attacker in production.
    include_tests: bool = False
    # Resource guards. A single generated or minified file past this size is
    # skipped rather than allowed to stall the whole scan.
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_files: int = 0  # 0 = unlimited
    # Templates and configuration files are scanned alongside source; these
    # exist so a noisy repo can turn either off.
    scan_templates: bool = True
    scan_configs: bool = True


class ScanEngine:
    def __init__(self, options: ScanOptions = None) -> None:
        self.options = options or ScanOptions()
        self.registry = Registry()

    def scan(self, root: str) -> ScanResult:
        start = time.time()
        root = os.path.abspath(root)

        languages = detect_languages(root)
        if not languages:
            return ScanResult(root=root, language="unknown", framework="raw")

        findings: list = []
        frameworks: dict = {}
        module_dirs: dict = {}
        files_scanned = 0
        skipped: dict = {}

        for language in languages:
            source_files, lang_skipped = collect_source_files_detailed(
                root, language,
                include_tests=self.options.include_tests,
                max_file_bytes=self.options.max_file_bytes,
                max_files=self.options.max_files or None,
            )
            for reason, n in lang_skipped.items():
                if n:
                    skipped[reason] = skipped.get(reason, 0) + n

            profile = detect_framework(root, language, source_files)
            frameworks[language] = profile.framework
            module_dirs[language] = profile.module_dirs

            rules = self.registry.rules_for(language, profile.framework)
            lang_findings, parsed_count, unreadable = self._analyze(
                language, profile.framework, rules, source_files,
            )
            findings.extend(lang_findings)
            files_scanned += parsed_count
            if unreadable:
                skipped["unreadable"] = skipped.get("unreadable", 0) + unreadable

        # Templates and configuration are scanned independently of the
        # detected source languages: they are where rendering and deployment
        # posture actually live, and neither is PHP or Java source.
        primary = languages[0]
        if self.options.scan_templates:
            tpl_files = collect_template_files(root)
            if not self.options.include_tests:
                tpl_files = [(p, k) for (p, k) in tpl_files
                             if not is_test_path(os.path.relpath(p, root))]
            findings.extend(scan_templates(tpl_files))
            files_scanned += len(tpl_files)
        if self.options.scan_configs:
            cfg_files = collect_config_files(root)
            findings.extend(scan_configs(
                cfg_files, language=primary, framework=frameworks.get(primary, "raw"),
            ))
            files_scanned += len(cfg_files)

        # Dependency analysis, per language and per module.
        db = AdvisoryDB()
        for seed in self._seed_paths():
            db.load_file(seed)
        for extra in (self.options.advisory_dbs or []):
            if os.path.isfile(extra):
                db.load_file(extra)

        dep_issues: list = []
        for language in languages:
            dep_issues.extend(analyze_dependencies(
                root, language, db, module_dirs.get(language),
            ))

        # Filter + sort.
        min_order = SEVERITY_ORDER.get(_sev_enum(self.options.min_severity or "info"), 99)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99),
                                     f.location.file, f.location.line))
        dep_issues.sort(key=lambda d: (SEVERITY_ORDER.get(d.severity, 99), d.package))

        return ScanResult(
            root=root,
            language=languages[0],
            framework=frameworks.get(languages[0], "raw"),
            languages=languages,
            frameworks=frameworks,
            files_scanned=files_scanned,
            files_skipped=skipped,
            findings=findings,
            dependency_issues=dep_issues,
            advisory_count=len(db.advisories),
            advisory_db_date=db.generated_at,
            duration_seconds=round(time.time() - start, 3),
        )

    # ------------------------------------------------------------------
    def _analyze(self, language, framework, rules, source_files):
        """Parse and taint-analyse one language. Returns (findings, parsed, unreadable)."""
        if language == "php":
            php_files = [f for f in source_files if not f.endswith(".blade.php")]
            blade_files = [f for f in source_files if f.endswith(".blade.php")]
            parsed, unreadable = self._parse_all(PhpParser(), php_files)
            symbols = build_symbol_table(parsed)
            engine = TaintEngine(symbols, rules, framework, language)
            findings = engine.analyze(parsed)
            if framework == "Laravel":
                findings.extend(scan_blade(blade_files))
            return findings, len(parsed), unreadable

        if language == "java":
            parsed, unreadable = self._parse_all(JavaParser(), source_files)
            symbols = build_java_symbols(parsed)
            engine = JavaTaintEngine(symbols, rules, framework, language)
            return engine.analyze(parsed), len(parsed), unreadable

        return [], 0, 0

    @staticmethod
    def _parse_all(parser, paths):
        """Read and parse every path, counting the ones that could not be read.

        Parsing is deliberately serial: tree-sitter's Python binding holds the
        GIL for the duration of a parse, so a thread pool measurably slows this
        down rather than speeding it up.
        """
        parsed = []
        unreadable = 0
        for path in paths:
            try:
                with open(path, "rb") as fh:
                    content = fh.read()
            except OSError:
                unreadable += 1
                continue
            parsed.append(parser.parse(path, content))
        return parsed, unreadable

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
