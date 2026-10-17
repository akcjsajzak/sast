"""Import offline vulnerability feeds (OSV, NVD, generic JSON) into the DB."""
from __future__ import annotations

import json
import os
import re

from .db import Advisory, AdvisoryDB

_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "MODERATE": "medium", "LOW": "low"}


def _numeric_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _cvss_from_vector(vector: str) -> str:
    """Best-effort severity estimate from a CVSS v3.x vector string."""
    if not vector or ":" not in vector:
        return "high"
    parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
    av = parts.get("AV", "N")
    ac = parts.get("AC", "L")
    pr = parts.get("PR", "N")
    ui = parts.get("UI", "N")
    s = parts.get("S", "U")
    c = parts.get("C", "H")
    i = parts.get("I", "H")
    a = parts.get("A", "H")
    # Simplified (not a full CVSS calculator, but monotone with impact/exposure).
    score = 6.0
    if ac == "L":
        score += 1.0
    if pr == "N":
        score += 0.8
    elif pr == "L":
        score += 0.4
    if ui == "N":
        score += 0.3
    if s == "C":
        score += 0.5
    if c == "H":
        score += 0.8
    if i == "H":
        score += 0.4
    if a == "H":
        score += 0.2
    if av == "P":
        score += 0.2
    if av == "L":
        score -= 0.3
    return _numeric_severity(min(score, 10.0))


def osv_entry_to_advisories(e: dict) -> list[Advisory]:
    """Convert one OSV vulnerability entry into one Advisory per affected package."""
    vuln_id = e.get("id", "")
    aliases = e.get("aliases", [])
    cve = next((x for x in aliases if x.upper().startswith("CVE-")), "")
    summary = e.get("summary") or e.get("details", "")
    details = e.get("details", "")
    # Severity.
    severity = "high"
    for sev in e.get("severity", []):
        score = sev.get("score", "")
        if isinstance(score, (int, float)):
            severity = _numeric_severity(float(score))
        elif isinstance(score, str) and score.startswith("CVSS:"):
            severity = _cvss_from_vector(score)
    ds = e.get("database_specific", {})
    if isinstance(ds, dict) and ds.get("severity") in _SEV:
        severity = _SEV[ds["severity"]]
    cwes = []
    if isinstance(ds, dict):
        cwes = ds.get("cwe_ids", []) or []
    refs = [r.get("url") for r in e.get("references", []) if r.get("url")]

    advisories = []
    for affected in e.get("affected", []):
        pkg_obj = affected.get("package", {})
        pkg = pkg_obj.get("name")
        if not pkg:
            continue
        ranges = []
        fixed_in = ""
        for r in affected.get("ranges", []):
            events = r.get("events", [])
            introduced = None
            fixed = None
            for ev in events:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
                    fixed_in = fixed
            if introduced and fixed:
                ranges.append(f">={introduced},<{fixed}")
            elif introduced:
                ranges.append(f">={introduced}")
        if not ranges:
            ranges = ["*"]
        advisories.append(Advisory(
            package=pkg,
            ranges=ranges,
            cve=cve or vuln_id,
            severity=severity,
            title=summary or f"{vuln_id}: vulnerability in {pkg}",
            description=details or summary,
            fixed_in=fixed_in,
            cwe=cwes[0] if cwes else "",
            references=list(refs),
        ))
    return advisories


def import_osv(path: str, db: AdvisoryDB) -> int:
    """Import an OSV JSON feed (osv.dev / GHSA). Returns count added."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return 0
    entries = data if isinstance(data, list) else data.get("results", [])
    before = len(db.advisories)
    for e in entries:
        for adv in osv_entry_to_advisories(e):
            db.add(adv)
    return len(db.advisories) - before


def import_osv_zip(path: str, db: AdvisoryDB) -> int:
    """Import an OSV bulk export (a zip of per-vulnerability JSON files)."""
    try:
        import zipfile
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            before = len(db.advisories)
            for name in names:
                try:
                    entry = json.loads(zf.read(name))
                except (json.JSONDecodeError, KeyError, OSError):
                    continue
                if not isinstance(entry, dict):
                    continue
                for adv in osv_entry_to_advisories(entry):
                    db.add(adv)
    except (OSError, zipfile.BadZipFile):
        return 0
    return len(db.advisories) - before


def import_nvd(path: str, db: AdvisoryDB, package_map: dict = None) -> int:
    """Import an NVD CVE JSON feed (best effort CPE -> package mapping).

    Supports both the legacy 1.1 API schema (CVE_Items) and the 2.0 schema
    (vulnerabilities). Detection is based on the shape of each item's "cve"
    object, since both formats carry a top-level "cve" key.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return 0
    package_map = package_map or {}
    items = data.get("CVE_Items") or data.get("vulnerabilities") or []
    before = len(db.advisories)
    for item in items:
        cve_obj = item.get("cve", {})
        if not isinstance(cve_obj, dict):
            continue
        if "CVE_data_meta" in cve_obj:
            # --- NVD 1.1 ---
            cve = cve_obj.get("CVE_data_meta", {}).get("ID", "")
            descs = cve_obj.get("description", {}).get("description_data", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            impact = item.get("impact", {})
            base = None
            for k in ("baseMetricV3", "baseMetricV2"):
                if k in impact:
                    metric = impact[k]
                    cvss = metric.get("cvssV3") or metric.get("cvssV2") or {}
                    base = cvss.get("baseScore")
                    break
            sev = _numeric_severity(float(base)) if base is not None else "high"
            nodes = item.get("configurations", {}).get("nodes", [])
        elif "id" in cve_obj:
            # --- NVD 2.0 ---
            cve = cve_obj.get("id", "")
            descs = cve_obj.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            sev = "high"
            for m in item.get("metrics", {}).values():
                for mm in m:
                    cvss = mm.get("cvssData", {})
                    base = cvss.get("baseScore")
                    if base is not None:
                        sev = _numeric_severity(float(base))
            nodes = item.get("configurations", [])
        else:
            continue

        if not cve:
            continue
        for pkg, ranges in _cpe_to_packages(nodes, package_map):
            db.add(Advisory(
                package=pkg, ranges=ranges, cve=cve, severity=sev,
                title=f"{cve}: vulnerability in {pkg}", description=desc,
            ))
    return len(db.advisories) - before


def _cpe_to_packages(nodes, package_map: dict):
    results = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        matches = node.get("cpe_match") or node.get("cpeMatch") or []
        for match in matches:
            if not isinstance(match, dict):
                continue
            cpe = match.get("cpe23Uri") or match.get("criteria") or ""
            if not cpe.startswith("cpe:2.3:"):
                continue
            parts = cpe.split(":")
            if len(parts) < 6:
                continue
            vendor, product, version = parts[3], parts[4], parts[5]
            pkg = package_map.get(f"{vendor}:{product}", f"{vendor}/{product}")
            ranges = []
            if version and version not in ("*", "-"):
                if match.get("versionEndExcluding"):
                    ranges.append(f">={version},<{match['versionEndExcluding']}")
                elif match.get("versionEndIncluding"):
                    ranges.append(f">={version},<={match['versionEndIncluding']}")
                else:
                    ranges.append(f"={version}")
            else:
                ranges.append("*")
            results.append((pkg, ranges))
    return results


def import_generic(path: str, db: AdvisoryDB) -> int:
    """Import our internal advisory JSON format (see data/advisories/seed.json)."""
    return db.load_file(path)


def import_feed(path: str, db: AdvisoryDB, package_map: dict = None) -> tuple[str, int]:
    """Auto-detect feed type and import. Returns (kind, count)."""
    if path.endswith(".zip"):
        return "osv", import_osv_zip(path, db)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read feed {path}: {e}") from e
    if isinstance(data, list):
        first = data[0] if data else {}
        if isinstance(first, dict) and "affected" in first:
            return "osv", import_osv(path, db)
        return "generic", import_generic(path, db)
    if isinstance(data, dict):
        if "CVE_Items" in data or "vulnerabilities" in data:
            return "nvd", import_nvd(path, db, package_map)
        if "advisories" in data:
            return "generic", import_generic(path, db)
    return "unknown", 0
