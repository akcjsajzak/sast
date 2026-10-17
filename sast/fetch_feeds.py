"""Download OSV vulnerability feeds and convert them into the internal format.

Used by the Makefile to embed a real, up-to-date advisory database into the
offline binary.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import urllib.request
import zipfile

from .advisory.db import AdvisoryDB
from .advisory.importers import osv_entry_to_advisories

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

# OSV ecosystem export name -> language (informational only).
# OSV ecosystems backing each language this tool analyses. Every one of these
# is fetched by default: a dependency parser without a matching feed silently
# reports zero vulnerabilities, which is worse than not supporting it.
#
# C and C++ have no entry because OSV publishes no ecosystem for them
# (ConanCenter returns 404). Native-library CVEs live in NVD instead — see
# `sast import-feed` and the README.
ECOSYSTEMS = {
    "Packagist": "php",       # PHP / Composer
    "Maven": "java",          # Java / Maven
    "npm": "javascript",      # JavaScript / npm
    "PyPI": "python",         # Python / pip
    "Go": "go",               # Go modules
    "NuGet": "csharp",        # .NET / NuGet
}

# Fetchable but not downloaded by default. The OS distribution feeds back
# base-image scanning, and Ubuntu's export alone is ~740 MB, which would
# dominate the size of an otherwise self-contained binary.
OPTIONAL_ECOSYSTEMS = {
    "Alpine": "container",
    "Debian": "container",
    "Ubuntu": "container",
    "crates.io": "rust",
}

ALL_ECOSYSTEMS = {**ECOSYSTEMS, **OPTIONAL_ECOSYSTEMS}

_USER_AGENT = "sast-feed-fetch/1.0"


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def fetch_ecosystem(db: AdvisoryDB, ecosystem: str) -> int:
    url = f"{OSV_BASE}/{ecosystem}/all.zip"
    data = _download(url)
    before = len(db.advisories)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                entry = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError, OSError):
                continue
            if not isinstance(entry, dict):
                continue
            for adv in osv_entry_to_advisories(entry):
                db.add(adv)
    return len(db.advisories) - before


def fetch(ecosystems, out_path: str) -> int:
    db = AdvisoryDB()
    for eco in ecosystems:
        print(f"[fetch] downloading OSV {eco} feed ...", file=sys.stderr)
        try:
            added = fetch_ecosystem(db, eco)
            print(f"[fetch] {eco}: {added} advisories", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — a single failed feed must not abort
            print(f"[fetch] {eco}: FAILED ({e})", file=sys.stderr)
    db.export(out_path)
    print(f"[fetch] wrote {len(db.advisories)} advisories to {out_path}", file=sys.stderr)
    return len(db.advisories)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Download OSV feeds into the internal advisory format")
    parser.add_argument("--ecosystems", nargs="*", default=list(ECOSYSTEMS),
                        choices=list(ALL_ECOSYSTEMS),
                        help="OSV ecosystems to fetch (default: every language "
                             "ecosystem; the OS distribution feeds are "
                             "available but opt-in because of their size)")
    parser.add_argument("-o", "--output", default="sast/data/advisories/downloaded.json")
    args = parser.parse_args(argv)
    fetch(args.ecosystems, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
