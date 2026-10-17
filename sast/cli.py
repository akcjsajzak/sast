"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .advisory.db import AdvisoryDB
from .advisory.importers import import_feed
from .engine import ScanEngine, ScanOptions
from .fetch_feeds import fetch
from .models import SEVERITY_ORDER, Severity
from .reporting import render_html, render_json, render_sarif


def _severity_choices() -> str:
    return ", ".join(s.value for s in Severity)


def _stderr_progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def cmd_scan(args) -> int:
    # --advisory-db is repeatable; --advisory-dbs is a deprecated alias.
    advisory_dbs = list(args.advisory_db or []) + list(args.advisory_dbs or [])
    if args.advisory_dbs:
        print("warning: --advisory-dbs is deprecated; use repeated --advisory-db",
              file=sys.stderr)

    only = set(args.only or [])
    def enabled(kind: str, disabled: bool = False) -> bool:
        return (kind in only) if only else not disabled

    options = ScanOptions(
        advisory_dbs=advisory_dbs,
        min_severity=args.min_severity,
        include_tests=args.include_tests,
        max_file_bytes=int(args.max_file_size * 1024 * 1024),
        max_files=args.max_files,
        scan_code=enabled("code"),
        scan_secrets=enabled("secrets", args.no_secrets),
        scan_iac=enabled("iac", args.no_iac),
        scan_containers=enabled("containers", args.no_containers),
        scan_templates=enabled("templates"),
        scan_configs=enabled("config"),
        scan_dependencies=enabled("deps"),
        reachability=not args.no_reachability,
        progress=None if args.quiet else _stderr_progress,
        audit=args.audit,
    )
    engine = ScanEngine(options)
    result = engine.scan(args.path)

    if args.ignore_unreachable:
        result.dependency_issues = [
            d for d in result.dependency_issues if d.reachability != "unused"
        ]

    if args.format in ("json", "sarif"):
        print_summary(result, stream=sys.stderr)
        out = render_json(result) if args.format == "json" else render_sarif(result)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
            print(f"\n{args.format.upper()} report written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(out)
            sys.stdout.write("\n")
        return _exit_code(result, args.fail_on, stream=sys.stderr)

    print_summary(result)

    html_out = render_html(result)
    output = args.output or "sast-report.html"
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    print(f"\nHTML report written to {output}")
    return _exit_code(result, args.fail_on)


def _exit_code(result, fail_on: str, stream=None) -> int:
    """Exit 1 when the scan meets the configured failure threshold."""
    if not fail_on or fail_on == "none":
        return 0
    try:
        threshold = Severity(fail_on)
    except ValueError:
        return 0
    n = result.count_at_or_above(threshold)
    if n:
        print(f"\nFAILED: {n} issue(s) at or above '{fail_on}' severity.",
              file=stream or sys.stdout)
        return 1
    return 0


def print_summary(result, stream=None) -> None:
    stats = result.stats()
    p = print if stream is None else lambda *a, **k: print(*a, file=stream, **k)
    languages = result.languages or [result.language]
    p("=" * 60)
    p("SAST scan complete")
    p(f"  Root:        {result.root}")
    if len(languages) > 1:
        p(f"  Languages:   {', '.join(languages)}")
        for lang in languages:
            p(f"    {lang:<8} framework: {result.frameworks.get(lang, 'raw')}")
    else:
        p(f"  Language:    {result.language}")
        p(f"  Framework:   {result.framework}")
    p(f"  Files:       {result.files_scanned}")
    if result.files_skipped:
        detail = ", ".join(f"{n} {reason}" for reason, n in sorted(result.files_skipped.items()))
        p(f"  Skipped:     {result.total_skipped()} ({detail})")
    p(f"  Duration:    {result.duration_seconds}s")
    p("  Findings:")
    for sev in ("critical", "high", "medium", "low", "info"):
        if stats.get(sev):
            p(f"    {sev:<10} {stats[sev]}")
    if result.routes:
        openc = sum(1 for r in result.routes if r.open)
        p(f"  Attack surface: {len(result.routes)} route(s), "
          f"{openc} with no guard found")
    p(f"  Dependencies with known vulns: {len(result.dependency_issues)}")
    reach: dict = {}
    for d in result.dependency_issues:
        if d.reachability:
            reach[d.reachability] = reach.get(d.reachability, 0) + 1
    if reach:
        parts = [f"{reach[k]} {k}" for k in ("called", "imported", "unused")
                 if reach.get(k)]
        p(f"    reachability: {', '.join(parts)}")
    if result.advisory_count:
        stamp = result.advisory_db_date or "unknown date"
        p(f"  Advisory DB: {result.advisory_count} advisories, as of {stamp}")
    p("=" * 60)


def cmd_import_feed(args) -> int:
    db = AdvisoryDB()
    if args.db and os.path.isfile(args.db):
        db.load_file(args.db)
    total = 0
    for feed in args.feeds:
        try:
            kind, count = import_feed(feed, db, args.package_map)
            print(f"Imported {count} advisories from {feed} (format: {kind})")
            total += count
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
    out = args.output or args.db or "advisories.json"
    db.export(out)
    print(f"\nWrote {len(db.advisories)} total advisories to {out}")
    return 0


def cmd_package_map(args) -> int:
    # Helper: inspect a package map file.
    if not args.map or not os.path.isfile(args.map):
        print("No package map file provided.", file=sys.stderr)
        return 1
    import json
    with open(args.map, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    print(json.dumps(data, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast",
        description="Offline application security scanning: code, dependencies, IaC, containers and secrets.",
    )
    parser.add_argument("--version", action="version", version=f"sast {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Scan a project directory")
    p_scan.add_argument("path", help="Path to the project to scan")
    p_scan.add_argument("-o", "--output", help="Output report file")
    p_scan.add_argument("--format", choices=["html", "json", "sarif"], default="html")
    p_scan.add_argument("--min-severity", default="info",
                        help=f"Minimum severity to report ({_severity_choices()})")
    p_scan.add_argument("--fail-on", default="none",
                        choices=[*(s.value for s in Severity), "none"],
                        help="Exit with status 1 if any finding or vulnerable "
                             "dependency is at or above this severity "
                             "(default: none — always exit 0)")
    p_scan.add_argument("--advisory-db", action="append", default=[], metavar="FILE",
                        help="Additional advisory JSON file (repeatable)")
    # Deprecated alias kept so existing invocations keep working.
    p_scan.add_argument("--advisory-dbs", nargs="*", default=[],
                        help=argparse.SUPPRESS)
    p_scan.add_argument("--include-tests", action="store_true",
                        help="Also scan test code (excluded by default)")
    p_scan.add_argument("--max-file-size", type=float, default=2.0, metavar="MB",
                        help="Skip source files larger than this many MB (default: 2)")
    p_scan.add_argument("--max-files", type=int, default=0, metavar="N",
                        help="Scan at most N files per language (0 = unlimited)")
    p_scan.add_argument("--no-reachability", action="store_true",
                        help="Skip reachability analysis for dependencies")
    p_scan.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress progress output")
    p_scan.add_argument("--audit", action="store_true",
                        help="Also report broken-access-control candidates "
                             "(IDOR, missing authorization). These trade "
                             "precision for recall and need manual triage, "
                             "so they are off by default and unsuitable for "
                             "a build gate")
    p_scan.add_argument("--ignore-unreachable", action="store_true",
                        help="Omit vulnerable dependencies that no first-party "
                             "code imports")
    p_scan.add_argument("--no-secrets", action="store_true",
                        help="Skip secrets detection")
    p_scan.add_argument("--no-iac", action="store_true",
                        help="Skip infrastructure-as-code scanning")
    p_scan.add_argument("--no-containers", action="store_true",
                        help="Skip Dockerfile and base-image scanning")
    p_scan.add_argument("--only", metavar="KIND", action="append", default=[],
                        choices=["code", "secrets", "iac", "containers",
                                 "templates", "config", "deps"],
                        help="Run only these scanners (repeatable)")
    p_scan.set_defaults(func=cmd_scan)

    p_import = sub.add_parser("import-feed", help="Import an OSV/NVD/generic feed")
    p_import.add_argument("feeds", nargs="+", help="Feed JSON file(s)")
    p_import.add_argument("--db", help="Existing advisory DB to merge into")
    p_import.add_argument("-o", "--output", help="Output advisory DB file")
    p_import.add_argument("--package-map", help="JSON map of cpe vendor:product -> package")
    p_import.set_defaults(func=cmd_import_feed)

    p_server = sub.add_parser(
        "server", help="Serve the web interface (scan from a browser)")
    p_server.add_argument("--host", default="127.0.0.1",
                          help="Bind address (default: 127.0.0.1). The interface "
                               "has no authentication, so binding to a routable "
                               "address exposes this machine.")
    p_server.add_argument("--port", type=int, default=8000,
                          help="Port to listen on (default: 8000; 0 picks a free one)")
    p_server.add_argument("--data-dir", default=None, metavar="DIR",
                          help="Where scan history and reports are kept "
                               "(default: ~/.sast)")
    p_server.add_argument("--include-tests", action="store_true",
                          help="Also scan test code (excluded by default)")
    p_server.add_argument("--no-reachability", action="store_true",
                          help="Skip reachability analysis for dependencies")
    p_server.set_defaults(func=cmd_server)

    p_fetch = sub.add_parser("fetch-feeds", help="Download OSV feeds into the internal advisory format")
    p_fetch.add_argument("--ecosystems", nargs="*", default=None,
                         choices=["Packagist", "Maven", "npm", "PyPI", "Go", "NuGet",
                                  "Alpine", "Debian", "Ubuntu", "crates.io"],
                         help="OSV ecosystems to fetch (default: every language ecosystem; "
                              "distro feeds are opt-in)")
    p_fetch.add_argument("-o", "--output", default="sast/data/advisories/downloaded.json")
    p_fetch.set_defaults(func=cmd_fetch_feeds)

    return parser


def cmd_server(args) -> int:
    from .web import DEFAULT_DATA_DIR, serve
    options = ScanOptions(
        include_tests=args.include_tests,
        reachability=not args.no_reachability,
    )
    return serve(host=args.host, port=args.port,
                 data_dir=args.data_dir or DEFAULT_DATA_DIR,
                 options=options)


def cmd_fetch_feeds(args) -> int:
    from .fetch_feeds import ECOSYSTEMS
    ecosystems = args.ecosystems or list(ECOSYSTEMS)
    fetch(ecosystems, args.output)
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
