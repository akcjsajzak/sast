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


def cmd_scan(args) -> int:
    # --advisory-db is repeatable; --advisory-dbs is a deprecated alias.
    advisory_dbs = list(args.advisory_db or []) + list(args.advisory_dbs or [])
    if args.advisory_dbs:
        print("warning: --advisory-dbs is deprecated; use repeated --advisory-db",
              file=sys.stderr)

    options = ScanOptions(
        advisory_dbs=advisory_dbs,
        min_severity=args.min_severity,
        include_tests=args.include_tests,
        max_file_bytes=int(args.max_file_size * 1024 * 1024),
        max_files=args.max_files,
    )
    engine = ScanEngine(options)
    result = engine.scan(args.path)

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
    p(f"  Dependencies with known vulns: {len(result.dependency_issues)}")
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
        description="Offline framework-aware SAST for PHP and Java.",
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
    p_scan.set_defaults(func=cmd_scan)

    p_import = sub.add_parser("import-feed", help="Import an OSV/NVD/generic feed")
    p_import.add_argument("feeds", nargs="+", help="Feed JSON file(s)")
    p_import.add_argument("--db", help="Existing advisory DB to merge into")
    p_import.add_argument("-o", "--output", help="Output advisory DB file")
    p_import.add_argument("--package-map", help="JSON map of cpe vendor:product -> package")
    p_import.set_defaults(func=cmd_import_feed)

    p_fetch = sub.add_parser("fetch-feeds", help="Download OSV feeds into the internal advisory format")
    p_fetch.add_argument("--ecosystems", nargs="*", default=None,
                         choices=["Packagist", "Maven"],
                         help="OSV ecosystems to fetch (default: both)")
    p_fetch.add_argument("-o", "--output", default="sast/data/advisories/downloaded.json")
    p_fetch.set_defaults(func=cmd_fetch_feeds)

    return parser


def cmd_fetch_feeds(args) -> int:
    ecosystems = args.ecosystems or ["Packagist", "Maven"]
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
