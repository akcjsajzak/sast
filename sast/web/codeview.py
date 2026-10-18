"""The code browser served by `sast server`: snapshot selection and pages.

A finding is only useful to a reviewer next to the code it points at, and
the code does not outlive the scan: an uploaded archive or a git checkout is
deleted the moment the scan finishes, and a local path can change under the
report. So when a scan completes, every file the report refers to — sinks,
trace steps, route declarations — is copied into a per-scan snapshot, and
the browser serves only from that snapshot. That keeps line numbers true to
what was scanned, and it means the browser can never be used to read a file
the scan did not report on: the server has no authentication, so serving
from the live filesystem would make it a general file reader.
"""
from __future__ import annotations

import html
import json
import os
from collections import Counter, defaultdict
from urllib.parse import quote

# Caps on what a scan's snapshot may hold. A file over the per-file cap is
# left out (its references stay plain text); past the totals, the files
# referenced least are dropped first.
MAX_SNAPSHOT_FILE_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES = 2000


def rel_path(root: str, path: str) -> str:
    """`path` relative to the scan root with / separators, or "" if outside.

    The same relation the HTML report displays, so a reference rendered
    there names exactly the key the snapshot stores.
    """
    if not path or not root:
        return ""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return ""
    if rel.startswith("..") or os.path.isabs(rel):
        return ""
    return rel.replace(os.sep, "/")


def referenced_files(result) -> list:
    """Absolute paths the report refers to, most-referenced first."""
    counts: Counter = Counter()
    root = result.root
    for f in result.findings:
        locs = [f.location, f.source] + [s.location for s in f.trace]
        if f.entry_point is not None and f.entry_point.file:
            counts[f.entry_point.file] += 1
        for loc in locs:
            if loc is not None and loc.file:
                counts[loc.file] += 1
    for r in result.routes:
        if r.file:
            counts[r.file] += 1
    return [p for p, _n in counts.most_common() if rel_path(root, p)]


# ---------------------------------------------------------------------------
# Annotations from the stored JSON report
# ---------------------------------------------------------------------------
def annotations(report_json: str) -> dict:
    """rel path -> line -> [annotation] for every finding touching a file.

    A finding's sink is marked with its severity; the other trace steps are
    marked as passing through, so a reviewer reading a helper can see that a
    flow crosses it.
    """
    try:
        report = json.loads(report_json)
    except (ValueError, TypeError):
        return {}
    root = report.get("root", "")
    out: dict = defaultdict(lambda: defaultdict(list))
    for idx, f in enumerate(report.get("findings", [])):
        loc = f.get("location") or {}
        sink_rel = rel_path(root, loc.get("file", ""))
        base = {"index": idx, "title": f.get("title", ""),
                "rule_id": f.get("rule_id", ""),
                "severity": f.get("severity", "info"),
                "sink_rel": sink_rel, "sink_line": loc.get("line", 0)}
        if sink_rel:
            out[sink_rel][loc.get("line", 0)].append(dict(base, kind="sink"))
        steps = f.get("trace") or []
        for n, step in enumerate(steps):
            sloc = step.get("location") or {}
            srel = rel_path(root, sloc.get("file", ""))
            if not srel:
                continue
            line = sloc.get("line", 0)
            if srel == sink_rel and line == loc.get("line", 0):
                continue  # the sink itself
            kind = "source" if n == 0 else "step"
            out[srel][line].append(dict(base, kind=kind,
                                        step=step.get("description", "")))
    return out


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def code_url(scan_id: str, rel: str, line: int = 0) -> str:
    """The browser URL for a file, relative to the server root."""
    url = f"code/{scan_id}/{quote(rel)}"
    return url + (f"#L{int(line)}" if line else "")


def _file_list(scan_id: str, files: list, notes: dict, current: str = "") -> str:
    """The sidebar: every snapshot file, grouped by directory."""
    groups: dict = defaultdict(list)
    for rel in sorted(files):
        directory, _, name = rel.rpartition("/")
        groups[directory].append((rel, name))
    parts = []
    depth = "../" * (current.count("/") + 2) if current else "../"
    for directory in sorted(groups):
        parts.append(f'<div class="dir">{_esc(directory or "/")}</div>')
        for rel, name in groups[directory]:
            lines = notes.get(rel, {})
            sinks = sum(1 for anns in lines.values()
                        for a in anns if a["kind"] == "sink")
            badge = f'<span class="n">{sinks}</span>' if sinks else ""
            cls = ' class="on"' if rel == current else ""
            parts.append(
                f'<a{cls} href="{depth}{_esc(code_url(scan_id, rel))}">'
                f'{_esc(name)}{badge}</a>')
    return "".join(parts)


def render_index(scan_id: str, label: str, files: list, notes: dict) -> str:
    """The browser's landing page: the file list and nothing open."""
    body = ('<div class="empty">Pick a file on the left, or follow a code '
            'reference from the report.</div>') if files else (
        '<div class="empty">No source was kept for this scan. Scans run '
        'before the code browser existed have no snapshot.</div>')
    return _page(scan_id, label, "", _file_list(scan_id, files, notes), body,
                 back="../")


def render_file(scan_id: str, label: str, rel: str, content: bytes,
                files: list, notes: dict) -> str:
    """One file with line numbers, finding markers and inline notes.

    A source or step note links to its finding's sink, which is often in
    another file: following a trace is a matter of clicking through it.
    """
    from .highlight import highlight_lines
    text = content.decode("utf-8", "replace")
    # Rows split on newline alone, as tree-sitter counts them, so a
    # finding's line number lands on the row it names.
    lines = text.split("\n")
    if len(lines) > 1 and lines[-1] == "":
        lines.pop()
    lines = [line.rstrip("\r") for line in lines] or [""]
    highlighted = highlight_lines(rel, content)
    if highlighted is not None and len(highlighted) != len(lines):
        highlighted = None  # never let colouring shift a line number
    file_notes = notes.get(rel, {})
    rows = []
    for n, line in enumerate(lines, 1):
        anns = file_notes.get(n, [])
        mark = ""
        cls = ""
        if anns:
            sink = [a for a in anns if a["kind"] == "sink"]
            if sink:
                worst = min(sink, key=lambda a: _SEV_ORDER.get(a["severity"], 9))
                cls = ' class="has-sink"'
                mark = f'<span class="mk sev-{_esc(worst["severity"])}">●</span>'
            else:
                cls = ' class="has-step"'
                mark = '<span class="mk step">○</span>'
        rows.append(
            f'<tr id="L{n}"{cls}><td class="ln"><a href="#L{n}">{n}</a></td>'
            f'<td class="gm">{mark}</td>'
            f'<td class="src"><code>'
            f'{(highlighted[n - 1] if highlighted is not None else _esc(line)) or " "}'
            f'</code></td></tr>')
        if anns:
            rows.append('<tr class="note"><td></td><td></td><td>'
                        + "".join(_note(a, scan_id, rel, set(files)) for a in anns)
                        + "</td></tr>")
    depth = "../" * (rel.count("/") + 2)
    sinks = sum(1 for anns in file_notes.values() for a in anns if a["kind"] == "sink")
    summary = (f'{len(lines)} lines · {sinks} finding'
               f'{"" if sinks == 1 else "s"} with a sink here')
    body = (f'<div class="file-bar"><span class="path">{_esc(rel)}</span>'
            f'<span class="meta">{summary}</span></div>'
            f'<div class="code-wrap"><table class="code">{"".join(rows)}</table></div>')
    return _page(scan_id, label, rel, _file_list(scan_id, files, notes, rel),
                 body, back=depth)


def _note(a: dict, scan_id: str, here: str, files: set) -> str:
    sev = _esc(a["severity"])
    if a["kind"] == "sink":
        what = f'<span class="tag sev-{sev}">{sev.upper()}</span> {_esc(a["title"])}'
    else:
        tag = ('<span class="tag src">SOURCE</span>' if a["kind"] == "source"
               else '<span class="tag step">STEP</span>')
        target = _esc(a["title"])
        sink_rel, sink_line = a.get("sink_rel"), a.get("sink_line", 0)
        if sink_rel and sink_rel in files:
            href = ("../" * (here.count("/") + 2)
                    + code_url(scan_id, sink_rel, sink_line))
            where = (f"{sink_rel}:{sink_line}" if sink_rel != here
                     else f"line {sink_line}")
            target = (f'<a href="{_esc(href)}">{target} · {_esc(where)}</a>')
        what = (f'{tag} {_esc(a["step"])} '
                f'<span class="dim">→ {target}</span>')
    return f'<div class="n-{_esc(a["kind"])}">{what} <span class="rule">{_esc(a["rule_id"])}</span></div>'


def _page(scan_id: str, label: str, rel: str, sidebar: str, body: str,
          back: str) -> str:
    title = f"{rel} · " if rel else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}Code · {_esc(label)}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="bar">
  <a class="back" href="{back}report/{_esc(scan_id)}">← Report</a>
  <span class="label">{_esc(label)}</span>
  <input id="filter" type="search" placeholder="Filter files" aria-label="Filter files">
</header>
<div class="layout">
  <nav class="files" id="files">{sidebar}</nav>
  <main>{body}</main>
</div>
<script>
(function(){{
  var f = document.getElementById('filter');
  f.addEventListener('input', function(){{
    var q = f.value.toLowerCase();
    Array.prototype.forEach.call(document.querySelectorAll('#files a'), function(a){{
      a.style.display = a.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
    }});
  }});
  var on = document.querySelector('#files a.on');
  if (on && on.scrollIntoView) on.scrollIntoView({{block: 'center'}});
}})();
</script>
</body>
</html>"""


_CSS = """
:root {
  --bg:#f1f5f9; --panel:#fff; --panel-2:#f8fafc; --border:#e2e8f0;
  --text:#0f172a; --muted:#64748b; --accent:#0ea5e9; --hl:#fef9c3;
  --sink:rgba(220,38,38,.07); --step:rgba(14,165,233,.07);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg:#0b1120; --panel:#111827; --panel-2:#0f172a; --border:#1f2937;
    --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; --hl:#3f3a12;
    --sink:rgba(248,113,113,.10); --step:rgba(56,189,248,.08);
  }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px; }
header.bar { position:sticky; top:0; z-index:2; display:flex; align-items:center; gap:14px;
  padding:10px 16px; background:linear-gradient(135deg,#0f172a,#1e293b); color:#e2e8f0; }
header.bar .back { color:#7dd3fc; text-decoration:none; font-weight:600; font-size:13px; }
header.bar .label { flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; font-size:13px; color:#cbd5e1; }
#filter { width:220px; max-width:40vw; padding:6px 10px; border-radius:7px;
  border:1px solid #334155; background:#0f172a; color:#e2e8f0; font:inherit; font-size:12.5px; }
.layout { display:grid; grid-template-columns:280px minmax(0,1fr); min-height:calc(100vh - 46px); }
@media (max-width:800px) { .layout { grid-template-columns:1fr; } nav.files { max-height:30vh; } }
nav.files { border-right:1px solid var(--border); background:var(--panel); overflow-y:auto;
  max-height:calc(100vh - 46px); position:sticky; top:46px; padding:8px 0 40px; }
nav.files .dir { padding:10px 14px 3px; font-size:11px; font-weight:700; color:var(--muted);
  text-transform:uppercase; letter-spacing:.04em; word-break:break-all; }
nav.files a { display:flex; align-items:center; gap:6px; padding:4px 14px 4px 22px;
  color:var(--text); text-decoration:none; font-size:12.5px; word-break:break-all; }
nav.files a:hover { background:var(--panel-2); }
nav.files a.on { background:var(--panel-2); box-shadow:inset 3px 0 0 var(--accent); font-weight:600; }
nav.files .n { margin-left:auto; font-size:10.5px; font-weight:700; padding:0 6px;
  border-radius:8px; background:#dc2626; color:#fff; }
main { min-width:0; background:var(--panel); }
.file-bar { position:sticky; top:46px; z-index:1; display:flex; gap:12px; align-items:baseline;
  flex-wrap:wrap; padding:9px 16px; background:var(--panel-2); border-bottom:1px solid var(--border); }
.file-bar .path { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:13px; font-weight:600; word-break:break-all; }
.file-bar .meta { font-size:12px; color:var(--muted); }
.code-wrap { overflow-x:auto; }
table.code { border-collapse:collapse; width:100%;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; line-height:1.55; }
table.code td { padding:0; vertical-align:top; }
td.ln { width:1%; text-align:right; padding:0 8px 0 12px !important; user-select:none; }
td.ln a { color:var(--muted); text-decoration:none; }
td.gm { width:16px; text-align:center; user-select:none; }
td.src code { white-space:pre; padding-right:24px; }
tr[id] { scroll-margin-top:110px; }
tr.has-sink td { background:var(--sink); }
tr.has-step td { background:var(--step); }
tr:target td { background:var(--hl) !important; }
tr:target td.ln a { color:var(--text); font-weight:700; }
tr.note td:last-child { padding:4px 16px 8px 0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  font-size:12px; white-space:normal; }
tr.note div { margin:2px 0; }
.mk { font-size:11px; }
.mk.step { color:var(--accent); }
.tag { font-size:10px; font-weight:750; padding:1px 6px; border-radius:4px; color:#fff; background:var(--muted); }
.tag.src { background:#0d9488; } .tag.step { background:var(--accent); }
.sev-critical { color:#dc2626; } .sev-high { color:#ea580c; }
.sev-medium { color:#d97706; } .sev-low { color:#2563eb; } .sev-info { color:var(--muted); }
.tag.sev-critical { background:#dc2626; color:#fff; } .tag.sev-high { background:#ea580c; color:#fff; }
.tag.sev-medium { background:#d97706; color:#fff; } .tag.sev-low { background:#2563eb; color:#fff; }
.tag.sev-info { background:var(--muted); color:#fff; }
.rule { color:var(--muted); font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px; }
.dim { color:var(--muted); }
.dim a { color:var(--accent); text-decoration:none; }
.dim a:hover { text-decoration:underline; }
.empty { padding:80px 20px; text-align:center; color:var(--muted); }
/* Syntax colours (GitHub-like), light then dark. */
.hl-k { color:#cf222e; } .hl-s { color:#0a3069; } .hl-c { color:#6e7781; font-style:italic; }
.hl-n { color:#0550ae; } .hl-t { color:#953800; } .hl-f { color:#8250df; }
.hl-o { color:#0550ae; } .hl-a { color:#116329; } .hl-v { color:#953800; }
.hl-g { color:#116329; }
@media (prefers-color-scheme: dark) {
  .hl-k { color:#ff7b72; } .hl-s { color:#a5d6ff; } .hl-c { color:#8b949e; }
  .hl-n { color:#79c0ff; } .hl-t { color:#ffa657; } .hl-f { color:#d2a8ff; }
  .hl-o { color:#79c0ff; } .hl-a { color:#7ee787; } .hl-v { color:#ffa657; }
  .hl-g { color:#7ee787; }
}
"""
