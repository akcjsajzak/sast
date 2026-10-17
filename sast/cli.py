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
    options = ScanOptions(
        advisory_db=args.advisory_db,
        extra_db_files=args.advisory_dbs or [],
        min_severity=args.min_severity,
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
        return 0

    print_summary(result)

    html_out = render_html(result)
    output = args.output or "sast-report.html"
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    print(f"\nHTML report written to {output}")
    return 0


def print_summary(result, stream=None) -> None:
    stats = result.stats()
    p = print if stream is None else lambda *a, **k: print(*a, file=stream, **k)
    p("=" * 60)
    p("SAST scan complete")
    p(f"  Root:        {result.root}")
    p(f"  Language:    {result.language}")
    p(f"  Framework:   {result.framework}")
    p(f"  Files:       {result.files_scanned}")
    p(f"  Duration:    {result.duration_seconds}s")
    p("  Findings:")
    for sev in ("critical", "high", "medium", "low", "info"):
        if stats.get(sev):
            p(f"    {sev:<10} {stats[sev]}")
    p(f"  Dependencies with known vulns: {len(result.dependency_issues)}")
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
    p_scan.add_argument("--advisory-db", help="Additional advisory JSON file")
    p_scan.add_argument("--advisory-dbs", nargs="*", default=[],
                        help="Additional advisory JSON files")
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
