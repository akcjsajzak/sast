"""Top-level scan orchestration."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from .advisory.analyzer import analyze_dependencies
from .advisory.db import AdvisoryDB
from .analysis.blade import scan_blade
from .analysis.config_scan import collect_config_files, scan_configs
from .analysis.containers import (
    collect_dockerfiles, scan_base_images, scan_dockerfiles,
)
from .analysis.dataflow import TaintEngine
from .analysis.templates import collect_template_files, scan_templates
from .analysis.java_dataflow import JavaTaintEngine
from .analysis.java_symbols import build_java_symbols
from .analysis.generic_dataflow import GenericTaintEngine, build_symbols
from .analysis.iac import collect_iac_files, scan_iac
from .analysis.js_dataflow import JsTaintEngine
from .analysis.js_symbols import build_js_symbols
from .analysis.lang_profile import PROFILES
from .analysis.reachability import annotate as annotate_reachability
from .analysis.reachability import build_import_index, rank as reach_rank
from .analysis.secrets import collect_scannable_files, scan_secrets
from .analysis.symbols import build_symbol_table
from .detection import (
    collect_source_files_detailed,
    detect_framework,
    detect_languages,
    is_test_path,
)
from .detection.language import DEFAULT_MAX_FILE_BYTES
from .models import ScanResult, SEVERITY_ORDER
from .parsing.generic import GenericParser
from .parsing.java import JavaParser
from .parsing.javascript import JsParser
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
    # Each scanner can be turned off independently, so a repo can be scanned
    # for one concern at a time.
    scan_code: bool = True
    scan_templates: bool = True
    scan_configs: bool = True
    scan_iac: bool = True
    scan_containers: bool = True
    scan_secrets: bool = True
    scan_dependencies: bool = True
    # Establish whether first-party code actually imports and calls each
    # vulnerable dependency, and rank findings by that.
    reachability: bool = True


class ScanEngine:
    def __init__(self, options: ScanOptions = None) -> None:
        self.options = options or ScanOptions()
        self.registry = Registry()

    def scan(self, root: str) -> ScanResult:
        start = time.time()
        root = os.path.abspath(root)

        # A repository with no application source at all is still worth
        # scanning: it may be nothing but Terraform, Kubernetes manifests or a
        # Dockerfile, which is exactly where cloud exposure lives.
        languages = detect_languages(root)
        findings: list = []
        frameworks: dict = {}
        module_dirs: dict = {}
        files_scanned = 0
        skipped: dict = {}
        # Every first-party source file, kept for reachability analysis.
        all_source_files: list = []
        package_language: dict = {}

        for language in (languages if self.options.scan_code else []):
            source_files, lang_skipped = collect_source_files_detailed(
                root, language,
                include_tests=self.options.include_tests,
                max_file_bytes=self.options.max_file_bytes,
                max_files=self.options.max_files or None,
            )
            for reason, n in lang_skipped.items():
                if n:
                    skipped[reason] = skipped.get(reason, 0) + n
            all_source_files.extend(source_files)

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

        # Templates, configuration, IaC, containers and secrets are scanned
        # independently of the detected source languages: they are where
        # rendering and deployment posture live, and none of them is
        # application source.
        primary = languages[0] if languages else ""
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

        # Infrastructure as code: where a bucket becomes public or a container
        # becomes privileged. Not reachable from any application taint path.
        if self.options.scan_iac:
            iac_files = collect_iac_files(root)
            findings.extend(scan_iac(iac_files))
            files_scanned += len(iac_files)

        dockerfiles: list = []
        if self.options.scan_containers:
            dockerfiles = collect_dockerfiles(root)
            findings.extend(scan_dockerfiles(dockerfiles))
            files_scanned += len(dockerfiles)

        # Secrets are searched across every text file, not only source: a
        # credential is as dangerous in a README or a CI config.
        if self.options.scan_secrets:
            secret_files = collect_scannable_files(root)
            findings.extend(scan_secrets(secret_files, root))

        # Dependency analysis, per language and per module.
        db = AdvisoryDB()
        for seed in self._seed_paths():
            db.load_file(seed)
        for extra in (self.options.advisory_dbs or []):
            if os.path.isfile(extra):
                db.load_file(extra)

        dep_issues: list = []
        if self.options.scan_dependencies:
            for language in languages:
                found = analyze_dependencies(
                    root, language, db, module_dirs.get(language) or [root],
                )
                for issue in found:
                    package_language.setdefault(issue.package, language)
                dep_issues.extend(found)
            # A base image is a dependency like any other.
            if dockerfiles:
                dep_issues.extend(scan_base_images(dockerfiles, db))

        # Reachability: a vulnerable package that first-party code never
        # imports is rarely the same risk as one it calls into.
        if dep_issues and self.options.reachability:
            if not all_source_files:
                for language in languages:
                    all_source_files.extend(collect_source_files_detailed(
                        root, language,
                        include_tests=self.options.include_tests,
                        max_file_bytes=self.options.max_file_bytes,
                    )[0])
            index = build_import_index(all_source_files)
            annotate_reachability(dep_issues, index, package_language)

        # Filter + sort.
        min_order = SEVERITY_ORDER.get(_sev_enum(self.options.min_severity or "info"), 99)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99),
                                     f.location.file, f.location.line))
        # Reachable issues first, then by severity: a called vulnerability in a
        # medium-severity package usually matters more than a critical one in a
        # package nothing imports.
        dep_issues.sort(key=lambda d: (-reach_rank(d.reachability),
                                       SEVERITY_ORDER.get(d.severity, 99),
                                       d.package))

        return ScanResult(
            root=root,
            language=primary or "none",
            framework=frameworks.get(primary, "raw"),
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

        if language == "javascript":
            parsed, unreadable = self._parse_all(JsParser(), source_files)
            symbols = build_js_symbols(parsed)
            engine = JsTaintEngine(symbols, rules, framework, language)
            return engine.analyze(parsed), len(parsed), unreadable

        # Python, Go, C#, C and C++ share one engine, configured by profile.
        profile = PROFILES.get(language)
        if profile is not None:
            parser = GenericParser(language)
            if not parser.available:
                return [], 0, 0
            parsed, unreadable = self._parse_all(parser, source_files)
            symbols = build_symbols(parsed, profile)
            engine = GenericTaintEngine(profile, rules, framework, language,
                                        symbols)
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
