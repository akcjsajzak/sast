"""Persistent scan history.

SQLite from the standard library, so the web interface adds no runtime
dependency — the whole point of this tool is that the binary runs with nothing
installed. Scan metadata lives in the database; the rendered HTML report is
written beside it, because reports are large and are only ever read whole.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

RUNNING = "running"
DONE = "done"
FAILED = "failed"
INTERRUPTED = "interrupted"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    source_type   TEXT NOT NULL,
    source_label  TEXT NOT NULL,
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    finished_at   TEXT,
    duration      REAL DEFAULT 0,
    root          TEXT DEFAULT '',
    languages     TEXT DEFAULT '[]',
    frameworks    TEXT DEFAULT '{}',
    counts        TEXT DEFAULT '{}',
    findings      INTEGER DEFAULT 0,
    dependencies  INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    progress      TEXT DEFAULT '',
    error         TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS scans_created ON scans (created_at DESC);
-- One triage verdict per finding per scan. Keyed on the finding's
-- fingerprint rather than its position, so a verdict survives a re-scan
-- that shifts line numbers.
CREATE TABLE IF NOT EXISTS triage (
    scan_id    TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanRecord:
    id: str
    source_type: str
    source_label: str
    status: str
    created_at: str
    finished_at: str = ""
    duration: float = 0.0
    root: str = ""
    languages: list = field(default_factory=list)
    frameworks: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    findings: int = 0
    dependencies: int = 0
    files_scanned: int = 0
    progress: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_type": self.source_type,
            "source_label": self.source_label,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "root": self.root,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "counts": self.counts,
            "findings": self.findings,
            "dependencies": self.dependencies,
            "files_scanned": self.files_scanned,
            "progress": self.progress,
            "error": self.error,
        }


class ScanStore:
    """Scan history that survives a restart."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = os.path.abspath(os.path.expanduser(data_dir))
        self.reports_dir = os.path.join(self.data_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "history.db")
        # One connection guarded by a lock: scans run on worker threads, and
        # SQLite objects are not safe to share across threads otherwise.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._ensure_column("progress", "TEXT DEFAULT ''")
            self._conn.commit()
        self._recover()

    def _ensure_column(self, name: str, decl: str) -> None:
        """Add a column to a store created before the column existed."""
        cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(scans)")}
        if name not in cols:
            self._conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {decl}")

    def _recover(self) -> None:
        """Mark scans that a restart cut short.

        Without this a crash leaves rows reading 'running' forever, and the UI
        would poll them indefinitely.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status = ?, finished_at = ?, "
                "error = 'interrupted by a restart' WHERE status = ?",
                (INTERRUPTED, _now(), RUNNING),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    def create(self, source_type: str, source_label: str) -> ScanRecord:
        record = ScanRecord(
            id=uuid.uuid4().hex[:16],
            source_type=source_type,
            source_label=source_label,
            status=RUNNING,
            created_at=_now(),
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans (id, source_type, source_label, status, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (record.id, record.source_type, record.source_label,
                 record.status, record.created_at),
            )
            self._conn.commit()
        return record

    def finish(self, scan_id: str, result, duration: float) -> None:
        counts = result.stats()
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status=?, finished_at=?, duration=?, root=?,"
                " languages=?, frameworks=?, counts=?, findings=?,"
                " dependencies=?, files_scanned=? WHERE id=?",
                (DONE, _now(), round(duration, 3), result.root,
                 json.dumps(result.languages or []),
                 json.dumps(result.frameworks or {}),
                 json.dumps(counts), len(result.findings),
                 len(result.dependency_issues), result.files_scanned, scan_id),
            )
            self._conn.commit()

    def progress(self, scan_id: str, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET progress=? WHERE id=?", (message, scan_id))
            self._conn.commit()

    # ------------------------------------------------------------------
    # Triage verdicts
    VERDICTS = ("real", "investigate", "false")

    def triage(self, scan_id: str) -> dict:
        """Every verdict recorded against one scan's findings."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT finding_id, verdict FROM triage WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        return {row["finding_id"]: row["verdict"] for row in rows}

    def set_triage(self, scan_id: str, verdicts: dict) -> int:
        """Record or clear verdicts. An empty verdict removes the row.

        Unknown verdict values are dropped rather than stored: the column
        feeds a UI that only understands three states, and a request is not
        a reason to put a fourth one in the database.
        """
        written = 0
        with self._lock:
            for finding_id, verdict in (verdicts or {}).items():
                if not isinstance(finding_id, str) or not finding_id:
                    continue
                if len(finding_id) > 128:
                    continue
                if verdict in (None, ""):
                    self._conn.execute(
                        "DELETE FROM triage WHERE scan_id=? AND finding_id=?",
                        (scan_id, finding_id))
                    written += 1
                    continue
                if verdict not in self.VERDICTS:
                    continue
                self._conn.execute(
                    "INSERT INTO triage (scan_id, finding_id, verdict, updated_at)"
                    " VALUES (?,?,?,?) ON CONFLICT(scan_id, finding_id)"
                    " DO UPDATE SET verdict=excluded.verdict,"
                    " updated_at=excluded.updated_at",
                    (scan_id, finding_id, verdict, _now()))
                written += 1
            self._conn.commit()
        return written

    def fail(self, scan_id: str, error: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                (FAILED, _now(), error[:2000], scan_id),
            )
            self._conn.commit()

    def get(self, scan_id: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_record(row) if row else None

    def list(self, limit: int = 100) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,)).fetchall()
        return [_row_to_record(r) for r in rows]

    def delete(self, scan_id: str) -> bool:
        """Remove a scan, its verdicts and its reports.

        The rows go first, under the lock, so a scan still running cannot
        write its report back afterwards: write_report checks for the row
        under the same lock.
        """
        try:
            paths = (self.report_path(scan_id), self.json_path(scan_id),
                     self.sources_path(scan_id))
        except ValueError:
            return False  # not an id this store could have issued
        with self._lock:
            cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            if cur.rowcount == 0:
                self._conn.commit()
                return False
            self._conn.execute("DELETE FROM triage WHERE scan_id = ?", (scan_id,))
            self._conn.commit()
        for path in paths:
            try:
                os.remove(path)
            except OSError:
                pass
        return True

    # ------------------------------------------------------------------
    def report_path(self, scan_id: str) -> str:
        return os.path.join(self.reports_dir, f"{_safe_id(scan_id)}.html")

    def json_path(self, scan_id: str) -> str:
        return os.path.join(self.reports_dir, f"{_safe_id(scan_id)}.json")

    def write_report(self, scan_id: str, html: str, payload: str = "") -> bool:
        """Write a scan's reports. False if the scan was deleted meanwhile."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return False
            with open(self.report_path(scan_id), "w", encoding="utf-8") as fh:
                fh.write(html)
            if payload:
                with open(self.json_path(scan_id), "w", encoding="utf-8") as fh:
                    fh.write(payload)
        return True

    # ------------------------------------------------------------------
    # Source snapshot for the code browser (see web/codeview.py)
    def sources_path(self, scan_id: str) -> str:
        return os.path.join(self.reports_dir, f"{_safe_id(scan_id)}.src.zip")

    def write_sources(self, scan_id: str, root: str, paths: list,
                      max_file: int, max_total: int, max_files: int) -> int:
        """Snapshot `paths` (absolute, under `root`) for one scan.

        Returns how many files were kept. Nothing is written for a scan
        deleted meanwhile, for the same reason as write_report.
        """
        from .codeview import rel_path
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return 0
            kept, total = 0, 0
            tmp = self.sources_path(scan_id) + ".tmp"
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in paths:
                    rel = rel_path(root, path)
                    if not rel or kept >= max_files:
                        continue
                    try:
                        if not os.path.isfile(path) or os.path.islink(path):
                            continue
                        size = os.path.getsize(path)
                        if size > max_file or total + size > max_total:
                            continue
                        with open(path, "rb") as fh:
                            data = fh.read(max_file + 1)
                    except OSError:
                        continue
                    zf.writestr(rel, data)
                    kept += 1
                    total += len(data)
            os.replace(tmp, self.sources_path(scan_id))
        return kept

    def source_files(self, scan_id: str) -> list:
        """Relative paths kept in a scan's snapshot (empty if it has none)."""
        try:
            with zipfile.ZipFile(self.sources_path(scan_id)) as zf:
                return sorted(zf.namelist())
        except (OSError, ValueError, zipfile.BadZipFile):
            return []

    def read_source(self, scan_id: str, rel: str):
        """One snapshot file's bytes, or None.

        Only a name listed in the archive is read, so no request can reach
        anything the scan did not store, whatever the path contains.
        """
        try:
            with zipfile.ZipFile(self.sources_path(scan_id)) as zf:
                if rel not in set(zf.namelist()):
                    return None
                return zf.read(rel)
        except (OSError, ValueError, KeyError, zipfile.BadZipFile):
            return None

    def read_json_report(self, scan_id: str) -> str:
        try:
            with open(self.json_path(scan_id), "r", encoding="utf-8") as fh:
                return fh.read()
        except (OSError, ValueError):
            return ""

    def read_report(self, scan_id: str) -> str:
        try:
            with open(self.report_path(scan_id), "r", encoding="utf-8") as fh:
                return fh.read()
        except (OSError, ValueError):
            return ""

    def close(self) -> None:
        with self._lock:
            self._conn.close()


_HEX = frozenset("0123456789abcdef")


def _safe_id(scan_id: str) -> str:
    """Validate a scan id before it is used as a filename.

    Ids are generated as hex, so anything else is invalid input and is
    rejected rather than filtered: stripping the offending characters would
    silently map two different ids onto the same file.
    """
    if not scan_id or len(scan_id) > 32:
        raise ValueError("invalid scan id")
    if not all(c in _HEX for c in scan_id):
        raise ValueError("invalid scan id")
    return scan_id


def _row_to_record(row) -> ScanRecord:
    return ScanRecord(
        id=row["id"],
        source_type=row["source_type"],
        source_label=row["source_label"],
        status=row["status"],
        created_at=row["created_at"],
        finished_at=row["finished_at"] or "",
        duration=row["duration"] or 0.0,
        root=row["root"] or "",
        languages=json.loads(row["languages"] or "[]"),
        frameworks=json.loads(row["frameworks"] or "{}"),
        counts=json.loads(row["counts"] or "{}"),
        findings=row["findings"] or 0,
        dependencies=row["dependencies"] or 0,
        files_scanned=row["files_scanned"] or 0,
        progress=row["progress"] or "",
        error=row["error"] or "",
    )
