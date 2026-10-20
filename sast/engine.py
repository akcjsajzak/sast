"""Top-level scan orchestration."""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .advisory.analyzer import analyze_dependencies
from .advisory.db import load_seed_db
from .analysis.authz import scan_authz
from .analysis.blade import scan_blade
from .analysis.config_scan import (collect_config_files, load_properties,
                                   scan_configs)
from .analysis.containers import (
    collect_dockerfiles, scan_base_images, scan_dockerfiles,
)
from .analysis.dataflow import TaintEngine
from .analysis.templates import collect_template_files, scan_templates
from .analysis.java_dataflow import JavaTaintEngine
from .analysis.java_symbols import build_java_symbols
from .analysis.memory_safety import scan_memory_safety
from .analysis.generic_dataflow import GenericTaintEngine, build_symbols
from .analysis.iac import collect_iac_files, scan_iac
from .analysis.js_dataflow import JsTaintEngine
from .analysis.js_symbols import build_js_symbols
from .analysis.lang_profile import PROFILES
from .analysis.reachability import annotate as annotate_reachability
from .analysis.reachability import build_import_index, rank as reach_rank
from .analysis.routes import (bind_entry_points, exposure_rank,
                              scan_routes)
from .analysis.requests import build_requests
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
    # Called with a human-readable phase message as the scan progresses, so a
    # CLI can print it and a server can store or stream it. None silences it.
    progress: Optional[Callable[[str], None]] = None
    # Broken-access-control candidates (IDOR, missing authorisation). Off by
    # default and deliberately so: they trade precision for recall, which is
    # what an auditor wants reading a report once and what nobody wants
    # failing a build. See sast/analysis/authz.py.
    audit: bool = False


class ScanEngine:
    def __init__(self, options: ScanOptions = None) -> None:
        self.options = options or ScanOptions()
        self.registry = Registry()

    def _progress(self, message: str) -> None:
        if self.options.progress is not None:
            self.options.progress(message)

    _properties: dict = {}

    def scan(self, root: str) -> ScanResult:
        start = time.time()
        # The walkers recurse once per level of AST nesting and spend several
        # frames doing it, so the default limit is reached well before
        # MAX_NODE_DEPTH, which is the bound that should decide where analysis
        # stops. Raised, never lowered: scans share the interpreter with each
        # other (the web server runs them in worker threads) and with whatever
        # embeds this.
        if sys.getrecursionlimit() < _RECURSION_LIMIT:
            sys.setrecursionlimit(_RECURSION_LIMIT)
        root = os.path.abspath(root)
        # Loaded first, so a database the user named but that cannot be read
        # fails the scan before the code analysis rather than after it.
        db = load_seed_db(self._seed_paths())
        for extra in (self.options.advisory_dbs or []):
            db.load_file(extra, strict=True)

        # A repository with no application source at all is still worth
        # scanning: it may be nothing but Terraform, Kubernetes manifests or a
        # Dockerfile, which is exactly where cloud exposure lives.
        languages = detect_languages(root)
        findings: list = []
        routes: list = []
        # Values from the repository's .properties files, read once and handed
        # to the engines that can resolve a configured constant at a call
        # site: a hash or cipher chosen in configuration is invisible to both
        # pattern matching and taint tracking without them.
        self._properties = load_properties(root)
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
            self._progress(
                f"Scanning {language}: {len(source_files)} file(s), "
                f"framework {profile.framework}",
            )
            lang_findings, parsed_count, unreadable, lang_routes = self._analyze(
                language, profile.framework, rules, source_files, root,
            )
            self._progress(
                f"{language}: {len(lang_findings)} finding(s), "
                f"{len(lang_routes)} route(s)")
            findings.extend(lang_findings)
            routes.extend(lang_routes)
            files_scanned += parsed_count
            if unreadable:
                skipped["unreadable"] = skipped.get("unreadable", 0) + unreadable

        # Templates, configuration, IaC, containers and secrets are scanned
        # independently of the detected source languages: they are where
        # rendering and deployment posture live, and none of them is
        # application source.
        primary = languages[0] if languages else ""
        if self.options.scan_templates:
            self._progress("Scanning templates")
            tpl_files = collect_template_files(root)
            if not self.options.include_tests:
                tpl_files = [(p, k) for (p, k) in tpl_files
                             if not is_test_path(os.path.relpath(p, root))]
            findings.extend(scan_templates(tpl_files))
            files_scanned += len(tpl_files)
        if self.options.scan_configs:
            self._progress("Scanning configuration")
            cfg_files = collect_config_files(root)
            findings.extend(scan_configs(
                cfg_files, language=primary, framework=frameworks.get(primary, "raw"),
            ))
            files_scanned += len(cfg_files)

        # Infrastructure as code: where a bucket becomes public or a container
        # becomes privileged. Not reachable from any application taint path.
        if self.options.scan_iac:
            self._progress("Scanning infrastructure-as-code")
            iac_files = collect_iac_files(root)
            findings.extend(scan_iac(iac_files))
            files_scanned += len(iac_files)

        dockerfiles: list = []
        if self.options.scan_containers:
            self._progress("Scanning containers")
            dockerfiles = collect_dockerfiles(root)
            findings.extend(scan_dockerfiles(dockerfiles))
            files_scanned += len(dockerfiles)

        # Secrets are searched across every text file, not only source: a
        # credential is as dangerous in a README or a CI config.
        if self.options.scan_secrets:
            self._progress("Scanning secrets")
            secret_files = collect_scannable_files(root)
            findings.extend(scan_secrets(secret_files, root))

        # Dependency analysis, per language and per module.
        dep_issues: list = []
        if self.options.scan_dependencies:
            self._progress("Checking dependencies")
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
            self._progress("Resolving dependency reachability")
            if not all_source_files:
                for language in languages:
                    all_source_files.extend(collect_source_files_detailed(
                        root, language,
                        include_tests=self.options.include_tests,
                        max_file_bytes=self.options.max_file_bytes,
                    )[0])
            index = build_import_index(all_source_files)
            annotate_reachability(dep_issues, index, package_language)

        # Tie each finding to the request that reaches it, then rank by how
        # exposed that request is. A finding on a route with no guard found
        # is where an audit starts; one behind an authorisation check needs
        # credentials before it can even be tried.
        if routes and findings:
            self._progress("Resolving entry points")
            bound = bind_entry_points(findings, routes)
            self._progress(f"{bound} finding(s) tied to an entry point")
            build_requests(findings)

        # Filter + sort.
        min_order = SEVERITY_ORDER.get(_sev_enum(self.options.min_severity or "info"), 99)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]
        dep_issues = [d for d in dep_issues
                      if SEVERITY_ORDER.get(d.severity, 99) <= min_order]
        findings.sort(key=lambda f: (exposure_rank(f),
                                     SEVERITY_ORDER.get(f.severity, 99),
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
            routes=routes,
            dependency_issues=dep_issues,
            advisory_count=len(db.advisories),
            advisory_db_date=db.generated_at,
            duration_seconds=round(time.time() - start, 3),
        )

    # ------------------------------------------------------------------
    def _analyze(self, language, framework, rules, source_files, root):
        """Parse, taint-analyse and map the routes of one language.

        Returns (findings, parsed, unreadable, routes). Route extraction
        reuses the trees the taint engine just parsed, so the attack surface
        costs one extra walk rather than a second parse.
        """
        if language == "php":
            php_files = [f for f in source_files if not f.endswith(".blade.php")]
            blade_files = [f for f in source_files if f.endswith(".blade.php")]
            parsed, unreadable = self._parse_all(PhpParser(), php_files)
            symbols = build_symbol_table(parsed)
            engine = TaintEngine(symbols, rules, framework, language)
            findings = engine.analyze(parsed)
            if framework == "Laravel":
                findings.extend(scan_blade(blade_files))
            routes, extra = self._surface(parsed, language, framework, root)
            return findings + extra, len(parsed), unreadable, routes

        if language == "java":
            parsed, unreadable = self._parse_all(JavaParser(), source_files)
            symbols = build_java_symbols(parsed)
            engine = JavaTaintEngine(symbols, rules, framework, language,
                                     properties=self._properties)
            found = engine.analyze(parsed)
            routes, extra = self._surface(parsed, language, framework, root)
            return found + extra, len(parsed), unreadable, routes

        if language == "javascript":
            parsed, unreadable = self._parse_all(JsParser(), source_files)
            symbols = build_js_symbols(parsed)
            engine = JsTaintEngine(symbols, rules, framework, language)
            found = engine.analyze(parsed)
            routes, extra = self._surface(parsed, language, framework, root)
            return found + extra, len(parsed), unreadable, routes

        # Python, Go, C#, C and C++ share one engine, configured by profile.
        profile = PROFILES.get(language)
        if profile is not None:
            parser = GenericParser(language)
            if not parser.available:
                return [], 0, 0, []
            parsed, unreadable = self._parse_all(parser, source_files)
            symbols = build_symbols(parsed, profile)
            # Routes first: their handlers' parameters are request data.
            routes = scan_routes(parsed, language, framework, root)
            engine = GenericTaintEngine(profile, rules, framework, language,
                                        symbols,
                                        entry_points=_entry_params(
                                            routes, language, framework))
            findings = engine.analyze(parsed)
            # C and C++ carry a vulnerability class the taint engines cannot
            # express: a pointer freed and then used, or freed twice, is a bug
            # wherever its value came from.
            if language in ("c", "cpp"):
                findings.extend(scan_memory_safety(parsed, language))
            routes, extra = self._surface(parsed, language, framework, root,
                                          routes=routes)
            return findings + extra, len(parsed), unreadable, routes

        return [], 0, 0, []

    def _surface(self, parsed, language, framework, root, routes=None):
        """Routes for one language, plus the access-control candidates.

        Both read the same trees the taint engine just built. The authz pass
        needs the routes as well as the files, because deciding that an
        unguarded route is anomalous means knowing whether its neighbours
        are guarded.
        """
        if routes is None:
            routes = scan_routes(parsed, language, framework, root)
        extra: list = []
        if self.options.audit:
            extra = scan_authz(parsed, routes, language, framework)
        return routes, extra

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


# Frameworks that bind request data into every handler parameter (model
# binding), as opposed to only the parameters named in the URL pattern.
_BINDS_ALL_PARAMS = {("python", "FastAPI"), ("csharp", "ASP.NET Core"),
                     ("csharp", "ASP.NET")}


# Frames to allow the analysis, sized from MAX_NODE_DEPTH: a few frames per
# level of nesting, plus the scan's own stack, with room to spare.
_RECURSION_LIMIT = 20_000


def _entry_params(routes: list, language: str, framework: str) -> dict:
    """(file, handler start line) -> (mode, names) for the generic engine.

    "all": every parameter the framework does not inject itself (FastAPI,
    ASP.NET model binding). "named": only the URL's named segments (Flask
    view args, Django URL kwargs). A route without a resolved handler body
    contributes nothing.
    """
    binds_all = (language, framework) in _BINDS_ALL_PARAMS
    out: dict = {}
    for r in routes:
        if not r.body or len(r.body) < 2:
            continue
        key = (r.body[0], r.body[1])
        if binds_all:
            out[key] = ("all", ())
        elif r.params:
            prev = out.get(key)
            names = set(prev[1]) if prev else set()
            out[key] = ("named", tuple(names | set(r.params)))
    return out


def _sev_enum(s: str):
    from .models import Severity
    try:
        return Severity(s)
    except ValueError:
        return Severity.INFO
