"""The `sast server` web interface.

Built on `http.server` rather than a framework, because the tool's defining
property is that it runs offline with nothing installed, and the binary must
keep working the same way.

The interface has no authentication, by request. That makes the bind address
the security boundary, so it listens on loopback by default and warns loudly
when told to do otherwise. Two browser-facing protections apply regardless:
the `Host` header is checked (a page on another site cannot drive this server
through DNS rebinding) and state-changing requests must be same-origin.
"""
from __future__ import annotations

import html
import json
import os
import socket
import sys
import threading
import time
import traceback
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..engine import ScanEngine, ScanOptions
from ..reporting import render_html, render_json
from . import multipart
from .sources import SourceError, resolve
from .store import ScanStore
from .ui import render_page

MAX_UPLOAD_BYTES = 256 * 1024 * 1024
# Triage verdicts are a handful of 16-character ids and one word each, so
# anything large is either a mistake or someone probing. 1 MB covers a report
# with tens of thousands of findings.
MAX_TRIAGE_BYTES = 1024 * 1024
DEFAULT_DATA_DIR = os.path.join(os.path.expanduser("~"), ".sast")

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}

_WARNING_BANNER = (
    '<div class="warn-banner">This server is reachable from the network and '
    'has no authentication. Anyone who can reach it can scan paths on this '
    'machine and read the results.</div>'
)


class ScanService:
    """Runs scans on worker threads and records them in the store."""

    def __init__(self, store: ScanStore, options: ScanOptions = None) -> None:
        self.store = store
        self.options = options or ScanOptions()
        self._threads: list = []

    def start(self, source_type: str, value: str, upload: bytes = b"",
              filename: str = "", branch: str = "") -> str:
        label = {"path": value, "git": value, "zip": filename or "upload.zip"}.get(
            source_type, value)
        record = self.store.create(source_type, label or "(unnamed)")
        thread = threading.Thread(
            target=self._run,
            args=(record.id, source_type, value, upload, filename, branch),
            daemon=True,
        )
        self._threads.append(thread)
        thread.start()
        self._log(record.id, f"started: {label}")
        return record.id

    def _log(self, scan_id: str, message: str) -> None:
        # Progress goes to stderr so it is visible whether stdout is a terminal
        # or redirected to a log file, and flushed so it appears promptly.
        print(f"[scan {scan_id[:8]}] {message}", file=sys.stderr, flush=True)

    def _on_progress(self, scan_id: str, message: str) -> None:
        self.store.progress(scan_id, message)
        self._log(scan_id, message)

    def _run(self, scan_id, source_type, value, upload, filename, branch) -> None:
        cleanup = None
        started = time.time()
        try:
            directory, label, cleanup = resolve(
                source_type, value, upload, filename, branch)
            options = replace(
                self.options,
                progress=lambda msg: self._on_progress(scan_id, msg),
            )
            result = ScanEngine(options).scan(directory)
            self.store.write_report(
                scan_id, render_html(result), render_json(result))
            self.store.finish(scan_id, result, time.time() - started)
            self._log(scan_id, "done: "
                      f"{len(result.findings)} finding(s), "
                      f"{len(result.dependency_issues)} dependency "
                      f"issue(s) in {result.duration_seconds}s")
        except SourceError as exc:
            self._log(scan_id, f"failed: {exc}")
            self.store.fail(scan_id, str(exc))
        except Exception as exc:  # noqa: BLE001 — a scan must never kill the server
            self._log(scan_id, f"failed: {type(exc).__name__}: {exc}")
            self.store.fail(scan_id, f"{type(exc).__name__}: {exc}\n\n"
                                     f"{traceback.format_exc(limit=5)}")
        finally:
            if cleanup is not None:
                cleanup()

    def wait(self, timeout: float = 120) -> None:
        """Block until in-flight scans finish. Used by the tests."""
        deadline = time.time() + timeout
        for thread in list(self._threads):
            remaining = max(0.0, deadline - time.time())
            thread.join(remaining)


class Handler(BaseHTTPRequestHandler):
    server_version = "sast"
    sys_version = ""

    # Injected by make_server.
    service: ScanService = None
    store: ScanStore = None
    banner: str = ""
    allowed_hosts: set = frozenset()

    # ------------------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: A003 — stdlib signature
        # The default logs to stderr on every request, which buries the
        # startup message. Errors still surface through log_error.
        return

    def _send(self, code: int, body: bytes, content_type: str,
              extra: dict = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # The report is rendered in an iframe from this same origin; deny
        # everything else from framing it.
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, code: int, message: str) -> None:
        self._json(code, {"error": message})

    # ------------------------------------------------------------------
    def _host_allowed(self) -> bool:
        """Reject requests whose Host header we do not recognise.

        Without this, a page on an attacker's domain could point DNS at
        127.0.0.1 and drive this server from the victim's browser.
        """
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        if not host:
            return False
        return host in self.allowed_hosts

    def _same_origin(self) -> bool:
        """State-changing requests must come from this server's own page."""
        origin = self.headers.get("Origin")
        if origin is None:
            # No Origin on a same-origin form post from some clients; the Host
            # check above still applies.
            return True
        expected_host = (self.headers.get("Host") or "").lower()
        return origin.lower().endswith("//" + expected_host)

    # ------------------------------------------------------------------
    def do_GET(self):  # noqa: N802 — stdlib signature
        if not self._host_allowed():
            self._error(421, "Unrecognised Host header.")
            return
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/":
            self._send(200, render_page(self.banner).encode("utf-8"),
                       "text/html; charset=utf-8")
            return

        if path == "/api/scans":
            self._json(200, {"scans": [s.to_dict() for s in self.store.list()]})
            return

        if path.startswith("/api/scan/"):
            record = self.store.get(path.rsplit("/", 1)[-1])
            if record is None:
                self._error(404, "No such scan.")
                return
            self._json(200, record.to_dict())
            return

        if path.startswith("/report/"):
            name = path.rsplit("/", 1)[-1]
            wants_json = name.endswith(".json")
            scan_id = name[:-5] if wants_json else name
            record = self.store.get(scan_id)
            if record is None:
                self._error(404, "No such scan.")
                return
            if wants_json:
                try:
                    with open(self.store.json_path(scan_id), "rb") as fh:
                        payload = fh.read()
                except (OSError, ValueError):
                    self._error(404, "No JSON report stored for that scan.")
                    return
                self._send(200, payload, "application/json; charset=utf-8")
                return
            report = self.store.read_report(scan_id)
            if not report:
                self._error(404, "No report stored for that scan.")
                return
            self._send(200, report.encode("utf-8"), "text/html; charset=utf-8")
            return

        if path.startswith("/api/triage/"):
            scan_id = path.rsplit("/", 1)[-1]
            if self.store.get(scan_id) is None:
                self._error(404, "No such scan.")
                return
            self._json(200, {"verdicts": self.store.triage(scan_id)})
            return

        if path == "/healthz":
            self._json(200, {"status": "ok"})
            return

        self._error(404, "Not found.")

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        if not self._host_allowed():
            self._error(421, "Unrecognised Host header.")
            return
        if not self._same_origin():
            self._error(403, "Cross-origin requests are refused.")
            return
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/start":
            self._handle_start()
            return
        if path.startswith("/delete/"):
            scan_id = path.rsplit("/", 1)[-1]
            self._json(200, {"deleted": self.store.delete(scan_id)})
            return
        if path.startswith("/api/triage/"):
            self._handle_triage(path.rsplit("/", 1)[-1])
            return
        self._error(404, "Not found.")

    def _handle_triage(self, scan_id: str) -> None:
        """Record triage verdicts sent by a report page.

        Bounded well below the upload limit: this carries a handful of
        16-character ids and a word each, never a file.
        """
        if self.store.get(scan_id) is None:
            self._error(404, "No such scan.")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "Invalid Content-Length.")
            return
        if length <= 0 or length > MAX_TRIAGE_BYTES:
            self._error(400, "Expected a small JSON body of verdicts.")
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._error(400, "Body is not valid JSON.")
            return
        verdicts = payload.get("verdicts") if isinstance(payload, dict) else None
        if not isinstance(verdicts, dict):
            self._error(400, "Expected a 'verdicts' object.")
            return
        written = self.store.set_triage(scan_id, verdicts)
        self._json(200, {"saved": written,
                         "verdicts": self.store.triage(scan_id)})

    # ------------------------------------------------------------------
    def _handle_start(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "Invalid Content-Length.")
            return
        if length <= 0:
            self._error(400, "Empty request.")
            return
        if length > MAX_UPLOAD_BYTES:
            self._error(413, "Upload is larger than the 256 MB limit.")
            return

        body = self.rfile.read(length)
        parts = multipart.parse(body, self.headers.get("Content-Type", ""))
        if not parts:
            self._error(400, "Could not read the form data.")
            return

        source_type = parts["source_type"].text.strip() if "source_type" in parts else ""
        if source_type not in ("path", "zip", "git"):
            self._error(400, "Choose a local path, a ZIP upload, or a git URL.")
            return

        value, upload, filename, branch = "", b"", "", ""
        if source_type == "path":
            value = parts["path"].text.strip() if "path" in parts else ""
            if not value:
                self._error(400, "No path given.")
                return
        elif source_type == "git":
            value = parts["git"].text.strip() if "git" in parts else ""
            branch = parts["branch"].text.strip() if "branch" in parts else ""
            if not value:
                self._error(400, "No repository URL given.")
                return
        else:
            part = parts.get("archive")
            if part is None or not part.data:
                self._error(400, "No archive uploaded.")
                return
            upload, filename = part.data, os.path.basename(part.filename or "upload.zip")

        scan_id = self.service.start(source_type, value, upload, filename, branch)
        self._json(202, {"id": scan_id})


def make_server(host: str, port: int, data_dir: str,
                options: ScanOptions = None) -> tuple:
    """Build the HTTP server. Returns (httpd, store, service)."""
    store = ScanStore(data_dir)
    service = ScanService(store, options)

    is_loopback = host in _LOOPBACK
    allowed = set(_LOOPBACK)
    allowed.add(host.lower())
    if not is_loopback:
        # Binding to a real interface means the Host header will carry
        # whatever name was used to reach it.
        try:
            allowed.add(socket.gethostname().lower())
        except OSError:
            pass
        if host == "0.0.0.0":  # noqa: S104 — explicit operator choice
            allowed.add("0.0.0.0")

    class Bound(Handler):
        pass

    Bound.service = service
    Bound.store = store
    Bound.banner = "" if is_loopback else _WARNING_BANNER
    Bound.allowed_hosts = allowed

    httpd = ThreadingHTTPServer((host, port), Bound)
    httpd.daemon_threads = True
    return httpd, store, service


def serve(host: str = "127.0.0.1", port: int = 8000,
          data_dir: str = DEFAULT_DATA_DIR, options: ScanOptions = None) -> int:
    httpd, store, _service = make_server(host, port, data_dir, options)
    shown = host if host not in ("0.0.0.0", "::") else "127.0.0.1"
    actual_port = httpd.server_address[1]

    lines = [
        "=" * 60,
        "SAST server",
        f"  URL:       http://{shown}:{actual_port}/",
        f"  Data dir:  {store.data_dir}",
        f"  History:   {store.db_path}",
    ]
    if host not in _LOOPBACK:
        lines += [
            "",
            "  WARNING: bound to a non-loopback address with no",
            "  authentication. Anyone who can reach this port can scan",
            "  paths on this machine and read the results.",
        ]
    lines += ["=" * 60, "Press Ctrl+C to stop."]
    # Flushed explicitly: stdout is block-buffered when redirected, so
    # `sast server > log &` would otherwise show nothing at all.
    print("\n".join(lines), flush=True)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()
    return 0


def _escape(value: str) -> str:
    return html.escape(value or "")
