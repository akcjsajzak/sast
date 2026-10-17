"""Self-contained HTML report rendering.

The report is a single static HTML file with inline CSS/JS (no external
resources — the tool runs fully offline). It supports light and dark colour
schemes, severity filtering, full-text search, and renders each finding's
source-to-sink trace as a readable vertical timeline.
"""
from __future__ import annotations

import html
import os
from datetime import datetime

from ..models import ScanResult

_SEV_ORDER = ("critical", "high", "medium", "low", "info")

# Accent colour per severity (used for badges, card accents, stat cards).
_SEV_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def _badge(severity: str) -> str:
    sev = (severity or "info").lower()
    return f'<span class="sev sev-{_esc(sev)}">{_esc(sev.upper())}</span>'


def _rel(root: str, path: str) -> str:
    """Shorten an absolute file path relative to the scan root for display."""
    if not path:
        return ""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return path
    # Don't climb out of the root with ../../ noise — fall back to the full path.
    return rel if not rel.startswith("..") else path


def _chip(label: str, value) -> str:
    value = _esc(value)
    if not value:
        return ""
    return (
        f'<span class="chip"><span class="chip-k">{_esc(label)}</span>'
        f'<span class="chip-v">{value}</span></span>'
    )


def _code(text: str) -> str:
    return f'<pre class="code">{_esc(text)}</pre>'


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------
def render_html(result: ScanResult) -> str:
    root = result.root
    findings = result.findings
    deps = result.dependency_issues
    stats = result.stats()

    # Combined severity counts (findings + dependency issues) drive the filter
    # chips and the "showing N of M" counter.
    combined: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        combined[f.severity.value] = combined.get(f.severity.value, 0) + 1
    for d in deps:
        combined[d.severity.value] = combined.get(d.severity.value, 0) + 1
    total_cards = len(findings) + len(deps)

    finding_rows = "\n".join(_finding_card(i, f, root) for i, f in enumerate(findings))
    if not findings:
        finding_rows = '<div class="empty">No code findings. 🎉</div>'

    dep_rows = "\n".join(_dep_card(i, d) for i, d in enumerate(deps))
    if not deps:
        dep_rows = '<div class="empty">No known vulnerable dependencies.</div>'

    # Summary / filter chips. Each is clickable and filters the list.
    summary_cards = [_stat_card("all", "All", total_cards, active=True)]
    for sev in _SEV_ORDER:
        summary_cards.append(_stat_card(sev, sev, combined[sev]))
    summary = "".join(summary_cards)

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    languages = result.languages or [result.language]
    lang_label = ", ".join(l.upper() for l in languages)
    if result.frameworks:
        fw_label = ", ".join(
            f"{result.frameworks.get(l, 'raw')} ({l})" if len(languages) > 1
            else result.frameworks.get(l, "raw")
            for l in languages
        )
    else:
        fw_label = result.framework

    files_label = str(result.files_scanned)
    if result.files_skipped:
        detail = ", ".join(f"{n} {reason}" for reason, n in sorted(result.files_skipped.items()))
        files_label += f" ({detail} skipped)"

    meta = [
        ("Project", root),
        ("Language", lang_label),
        ("Framework", fw_label),
        ("Files scanned", files_label),
        ("Duration", f"{result.duration_seconds}s"),
        ("Generated", generated),
    ]
    if result.advisory_count:
        meta.append((
            "Advisory DB",
            f"{result.advisory_count} advisories · "
            f"as of {result.advisory_db_date or 'unknown date'}",
        ))

    meta_items = "".join(
        f'<div class="hmeta"><span class="hk">{_esc(k)}</span>'
        f'<span class="hv">{_esc(v)}</span></div>'
        for k, v in meta
    )

    return _PAGE.format(
        title=f"SAST Report — {_esc(os.path.basename(root.rstrip('/')) or root)}",
        meta_items=meta_items,
        summary=summary,
        surface=_surface_section(result.routes, root),
        categories=_category_section(findings),
        total=total_cards,
        finding_count=len(findings),
        dep_count=len(deps),
        rows=finding_rows,
        dep_rows=dep_rows,
    )


def _category_section(findings: list) -> str:
    """A toggle per rule category, every one of them on to begin with.

    A report mixes concerns that different people act on — injection,
    memory safety, access control, misconfiguration — and an auditor
    usually wants one of them at a time. These are independent toggles
    rather than a single-choice filter, because narrowing to two related
    categories is the common move and a radio button cannot express it.
    """
    counts: dict = {}
    for f in findings:
        key = f.category or "uncategorised"
        counts[key] = counts.get(key, 0) + 1
    if len(counts) < 2:
        # One category is not a choice, and an empty row is just clutter.
        return ""
    chips = "".join(
        f'<button type="button" class="tbtn catchip on" '
        f'data-cat-filter="{_esc(name)}">{_esc(name)} '
        f'<span class="catn">{n}</span></button>'
        for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return (
        '<div id="cat-bar">'
        '<span class="lbl">Category</span>'
        f'{chips}'
        '<button type="button" class="tbtn" id="cat-all">All</button>'
        '<button type="button" class="tbtn" id="cat-none">None</button>'
        '</div>'
    )


def _surface_section(routes: list, root: str) -> str:
    """The attack-surface inventory: the target list, with findings aside.

    Collapsed by default so it never buries the findings, but present on
    every scan that found routes because on an unfamiliar app it is the first
    thing an auditor builds by hand.
    """
    if not routes:
        return ""
    openc = sum(1 for r in routes if r.open)
    rows = []
    for r in sorted(routes, key=lambda r: (r.open is False, r.path, r.method)):
        guard = (f'<span class="ep-guard ep-guarded">'
                 f'{_esc(", ".join(r.guards))}</span>' if r.guards
                 else '<span class="ep-guard ep-open">no guard found</span>')
        handler = _esc(r.handler) if r.handler else ""
        rows.append(
            f'<tr><td class="mono"><span class="ep-method">{_esc(r.method)}</span></td>'
            f'<td class="mono">{_esc(r.path)}</td>'
            f'<td class="mono rt-h">{handler}</td>'
            f'<td>{guard}</td>'
            f'<td class="mono rt-f">{_rel(root, r.file)}:{_esc(r.line)}</td></tr>'
        )
    return (
        '<details class="surface"><summary>Attack surface '
        f'<span class="n">{len(routes)}</span> '
        f'<span class="surface-sub">{openc} with no guard found</span></summary>'
        '<table class="rt"><thead><tr><th>Method</th><th>Path</th>'
        '<th>Handler</th><th>Guard</th><th>Declared</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></details>'
    )


def _stat_card(key: str, label: str, count: int, active: bool = False) -> str:
    color = _SEV_COLOR.get(key, "#64748b") if key != "all" else "#0ea5e9"
    cls = "stat" + (" on" if active else "")
    return (
        f'<button class="{cls}" data-filter="{_esc(key)}" '
        f'style="--accent:{color}">'
        f'<span class="stat-n">{count}</span>'
        f'<span class="stat-l">{_esc(label)}</span></button>'
    )


# ---------------------------------------------------------------------------
# Finding card
# ---------------------------------------------------------------------------
# The three verdicts a reviewer can record against a finding. Kept to three
# on purpose: a triage pass answers "is this real", and a longer list turns
# a decision into a taxonomy exercise.
TRIAGE_STATES = (
    ("real", "Real", "A confirmed issue"),
    ("investigate", "To investigate", "Needs more work before a verdict"),
    ("false", "False positive", "Not an issue here"),
)

_TRIAGE_CONTROL = (
    '<div class="triage" role="group" aria-label="Triage">'
    '<span class="lbl">Triage</span>'
    + "".join(
        f'<button type="button" class="tbtn tb-{key}" data-triage-set="{key}" '
        f'title="{desc}">{label}</button>'
        for key, label, desc in TRIAGE_STATES)
    + '<button type="button" class="tbtn tb-clear" data-triage-set="" '
      'title="Clear the verdict">Clear</button>'
      '</div>'
)


def _finding_card(i: int, f, root: str) -> str:
    sink_loc = f"{_rel(root, f.location.file)}:{_esc(f.location.line)}"

    chips = "".join(
        c for c in (
            _chip("Rule", f.rule_id),
            _chip("CWE", f.cwe),
            _chip("OWASP", f.owasp),
            _chip("Confidence", f.confidence),
            _chip("Framework", f.framework),
        ) if c
    )

    tags = ""
    if f.tags:
        tags = (
            '<div class="tags"><span class="lbl">Tags</span>'
            + "".join(f'<span class="tag">{_esc(t)}</span>' for t in f.tags)
            + "</div>"
        )

    remediation = ""
    if f.remediation:
        remediation = (
            '<div class="rem"><span class="lbl">Remediation</span>'
            f'<div class="rem-b">{_esc(f.remediation)}</div></div>'
        )

    entry = _entry_point_line(f)
    request = _request_block(f)
    trace = _trace_timeline(f, root)

    return f"""
    <article class="finding" data-sev="{_esc(f.severity.value)}"
             data-cat="{_esc(f.category)}"
             data-fid="{_esc(f.fingerprint(root))}" data-triage="">
      <div class="accent sev-bar-{_esc(f.severity.value)}"></div>
      <div class="finding-main">
        <header class="fh">
          <div class="fh-top">
            {_badge(f.severity.value)}
            <span class="cat">{_esc(f.category)}</span>
          </div>
          <h3 class="title">{_esc(f.title)}</h3>
          <div class="sink mono"><span class="lbl">Sink</span>{sink_loc}</div>
          {entry}
          <div class="chips">{chips}</div>
          {_TRIAGE_CONTROL}
        </header>
        <div class="fb">
          <p class="desc">{_esc(f.description)}</p>
          {request}
          {remediation}
          {tags}
          {trace}
        </div>
      </div>
    </article>"""


def _entry_point_line(f) -> str:
    """The route reaching a finding, and whether a guard was found on it."""
    entry = getattr(f, "entry_point", None)
    if entry is None:
        return ""
    if entry.guards:
        badge = (f'<span class="ep-guard ep-guarded">guarded · '
                 f'{_esc(", ".join(entry.guards))}</span>')
    else:
        badge = '<span class="ep-guard ep-open">no guard found</span>'
    handler = f' → {_esc(entry.handler)}' if entry.handler else ""
    return (
        '<div class="entry mono"><span class="lbl">Entry</span>'
        f'<span class="ep-method">{_esc(entry.method)}</span> '
        f'{_esc(entry.path)}{handler} {badge}</div>'
    )


def _request_block(f) -> str:
    """The reproduction request skeleton, when one applies."""
    request = getattr(f, "request", "")
    if not request:
        return ""
    return (
        '<div class="req"><span class="lbl">Reproduce</span>'
        f'<pre class="req-b mono">{_esc(request)}</pre></div>'
    )


def _trace_timeline(f, root: str) -> str:
    steps = f.trace
    if not steps:
        return ""
    items = []
    n = len(steps)
    for idx, step in enumerate(steps):
        loc = step.location
        if idx == 0:
            kind, tag = "src", '<span class="step-tag st-src">SOURCE</span>'
        elif idx == n - 1:
            kind, tag = "sink", '<span class="step-tag st-sink">SINK</span>'
        else:
            kind, tag = "hop", ""
        loc_str = f"{_rel(root, loc.file)}:{_esc(loc.line)}" if loc and loc.file else ""
        code = _code(step.code) if step.code else ""
        items.append(
            f'<li class="step step-{kind}">'
            f'<span class="dot">{idx + 1}</span>'
            f'<div class="step-body">'
            f'<div class="step-desc">{tag}{_esc(step.description)}</div>'
            f'{f"<div class=\'step-loc mono\'>{loc_str}</div>" if loc_str else ""}'
            f'{code}'
            f'</div></li>'
        )
    return (
        '<details class="trace" open>'
        f'<summary>Data-flow trace · {n} step{"s" if n != 1 else ""} '
        '<span class="hint">(source → sink)</span></summary>'
        f'<ol class="timeline">{"".join(items)}</ol>'
        '</details>'
    )


# ---------------------------------------------------------------------------
# Dependency card
# ---------------------------------------------------------------------------
_REACH_LABEL = {
    "called": ("Called", "reach-called"),
    "imported": ("Imported", "reach-imported"),
    "unused": ("Not imported", "reach-unused"),
}


def _dep_card(i: int, d) -> str:
    chips = "".join(
        c for c in (
            _chip("Package", f"{d.package} @ {d.version}"),
            _chip("CVE", d.cve),
            _chip("CWE", d.cwe),
            _chip("Fixed in", d.fixed_in),
        ) if c
    )
    reach = ""
    label = _REACH_LABEL.get(getattr(d, "reachability", "") or "")
    if label:
        text, cls = label
        note = getattr(d, "reachability_note", "") or ""
        reach = (f'<div class="reach {cls}"><span class="reach-tag">{_esc(text)}</span>'
                 f'<span class="reach-note">{_esc(note)}</span></div>')
    refs = ""
    if d.references:
        items = "".join(
            f'<li><a href="{_esc(r)}" rel="noreferrer noopener" target="_blank">{_esc(r)}</a></li>'
            for r in d.references
        )
        refs = f'<div class="refs"><span class="lbl">References</span><ul>{items}</ul></div>'

    return f"""
    <article class="finding" data-sev="{_esc(d.severity.value)}">
      <div class="accent sev-bar-{_esc(d.severity.value)}"></div>
      <div class="finding-main">
        <header class="fh">
          <div class="fh-top">
            {_badge(d.severity.value)}
            <span class="cat">dependency</span>
          </div>
          <h3 class="title">{_esc(d.title or d.package)}</h3>
          <div class="chips">{chips}</div>
        </header>
        <div class="fb">
          {reach}
          <p class="desc">{_esc(d.description)}</p>
          {refs}
        </div>
      </div>
    </article>"""


# ---------------------------------------------------------------------------
# Page shell
# ---------------------------------------------------------------------------
_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg:#f1f5f9; --panel:#ffffff; --panel-2:#f8fafc; --border:#e2e8f0;
  --text:#0f172a; --muted:#64748b; --muted-2:#475569;
  --code-bg:#0f172a; --code-fg:#e2e8f0; --code-border:#1e293b;
  --link:#2563eb; --accent:#0ea5e9;
  --rem-bg:#f0fdfa; --rem-fg:#0f766e; --rem-bar:#14b8a6;
  --chip-bg:#f1f5f9; --chip-k:#64748b; --chip-v:#334155;
  --shadow:0 1px 2px rgba(15,23,42,.06), 0 1px 3px rgba(15,23,42,.08);
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg:#0b1120; --panel:#111827; --panel-2:#0f172a; --border:#1f2937;
    --text:#e5e7eb; --muted:#94a3b8; --muted-2:#cbd5e1;
    --code-bg:#020617; --code-fg:#e2e8f0; --code-border:#1e293b;
    --link:#60a5fa; --accent:#38bdf8;
    --rem-bg:#042f2e; --rem-fg:#5eead4; --rem-bar:#14b8a6;
    --chip-bg:#1e293b; --chip-k:#94a3b8; --chip-v:#cbd5e1;
    --shadow:0 1px 2px rgba(0,0,0,.4);
  }}
}}
:root[data-theme="dark"] {{
  --bg:#0b1120; --panel:#111827; --panel-2:#0f172a; --border:#1f2937;
  --text:#e5e7eb; --muted:#94a3b8; --muted-2:#cbd5e1;
  --code-bg:#020617; --code-fg:#e2e8f0; --code-border:#1e293b;
  --link:#60a5fa; --accent:#38bdf8;
  --rem-bg:#042f2e; --rem-fg:#5eead4; --rem-bar:#14b8a6;
  --chip-bg:#1e293b; --chip-k:#94a3b8; --chip-v:#cbd5e1;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}}

/* Severity accents — shared by badges and card bars. */
.sev-critical,.sev-bar-critical {{ --sv:#dc2626; }}
.sev-high,.sev-bar-high         {{ --sv:#ea580c; }}
.sev-medium,.sev-bar-medium     {{ --sv:#d97706; }}
.sev-low,.sev-bar-low           {{ --sv:#2563eb; }}
.sev-info,.sev-bar-info         {{ --sv:#64748b; }}

* {{ box-sizing:border-box; }}
html {{ scroll-behavior:smooth; }}
body {{
  margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px; line-height:1.5;
}}
a {{ color:var(--link); }}
.mono {{ font-family:"SFMono-Regular",ui-monospace,Menlo,Consolas,"Liberation Mono",monospace; }}
.lbl {{
  display:inline-block; font-size:10.5px; font-weight:700; text-transform:uppercase;
  letter-spacing:.05em; color:var(--muted); margin-right:8px;
}}

/* Header */
header.page {{
  background:linear-gradient(135deg,#0f172a,#1e293b); color:#e2e8f0;
  padding:22px 16px;
}}
header.page .wrap {{ max-width:1100px; margin:0 auto; }}
header.page h1 {{ margin:0 0 14px; font-size:20px; font-weight:650; color:#fff; letter-spacing:-.01em; }}
.hmeta-grid {{ display:flex; flex-wrap:wrap; gap:10px 26px; }}
.hmeta {{ display:flex; flex-direction:column; gap:2px; min-width:0; }}
.hmeta .hk {{ font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:#94a3b8; }}
.hmeta .hv {{ font-size:13px; color:#e2e8f0; font-weight:550; word-break:break-word; }}

/* Toolbar */
.toolbar {{
  position:sticky; top:0; z-index:20; background:var(--panel);
  border-bottom:1px solid var(--border); box-shadow:var(--shadow);
  padding:12px 16px;
}}
.toolbar .wrap {{
  max-width:1100px; margin:0 auto; display:flex; gap:10px; align-items:center; flex-wrap:wrap;
}}
#q {{
  flex:1 1 240px; min-width:0; padding:9px 13px; border:1px solid var(--border);
  border-radius:9px; font-size:13.5px; background:var(--panel-2); color:var(--text);
}}
#q:focus {{ outline:2px solid var(--accent); outline-offset:-1px; }}
#count {{ font-size:12.5px; color:var(--muted); white-space:nowrap; }}
#theme {{
  padding:9px 12px; border:1px solid var(--border); border-radius:9px; cursor:pointer;
  background:var(--panel-2); color:var(--text); font-size:13px;
}}

/* Summary / filter chips */
.summary {{ max-width:1100px; margin:0 auto; padding:18px 16px 4px; display:flex; gap:10px; flex-wrap:wrap; }}
.stat {{
  flex:1 1 120px; min-width:104px; text-align:left; cursor:pointer;
  background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--accent);
  border-radius:11px; padding:11px 14px; box-shadow:var(--shadow); color:var(--text);
  display:flex; flex-direction:column; gap:1px; transition:transform .08s ease, box-shadow .12s ease;
  font:inherit;
}}
.stat:hover {{ transform:translateY(-1px); }}
.stat.on {{ outline:2px solid var(--accent); outline-offset:0; }}
.stat .stat-n {{ font-size:25px; font-weight:750; color:var(--accent); line-height:1.1; }}
.stat .stat-l {{ font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }}

/* Layout */
main {{ max-width:1100px; margin:0 auto; padding:10px 16px 72px; }}
h2.sec {{
  font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:.06em;
  color:var(--muted); margin:28px 0 10px; display:flex; align-items:center; gap:8px;
}}
h2.sec .n {{
  background:var(--chip-bg); color:var(--chip-v); border-radius:999px;
  padding:1px 9px; font-size:12px; font-weight:650; letter-spacing:0;
}}

/* Finding card */
.finding {{
  display:flex; background:var(--panel); border:1px solid var(--border);
  border-radius:12px; margin:12px 0; overflow:hidden; box-shadow:var(--shadow);
}}
.accent {{ flex:0 0 5px; background:var(--sv,#64748b); }}
.finding-main {{ flex:1; min-width:0; }}
.fh {{ padding:15px 18px 10px; }}
.fh-top {{ display:flex; align-items:center; gap:8px; margin-bottom:8px; }}
.sev {{
  font-size:10.5px; font-weight:750; letter-spacing:.03em; padding:3px 10px; border-radius:999px;
  color:#fff; background:var(--sv,#64748b);
}}
.cat {{
  font-size:11.5px; color:var(--chip-v); background:var(--chip-bg);
  padding:3px 10px; border-radius:999px;
}}
.title {{ margin:0 0 7px; font-size:16px; font-weight:650; line-height:1.3; letter-spacing:-.01em; }}
.sink {{ font-size:12.5px; color:var(--muted-2); margin-bottom:9px; word-break:break-all; }}
.chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
.chip {{
  display:inline-flex; align-items:center; font-size:11.5px;
  border:1px solid var(--border); border-radius:7px; overflow:hidden;
}}
.chip-k {{ background:var(--chip-bg); color:var(--chip-k); padding:2px 7px; font-weight:650;
  text-transform:uppercase; letter-spacing:.03em; font-size:10px; }}
.chip-v {{ padding:2px 8px; color:var(--chip-v); font-family:"SFMono-Regular",ui-monospace,Menlo,Consolas,monospace; }}

.fb {{ padding:4px 18px 16px; }}
.desc {{ margin:4px 0 12px; color:var(--muted-2); font-size:13.5px; }}

.rem {{
  background:var(--rem-bg); border-left:3px solid var(--rem-bar); border-radius:7px;
  padding:9px 13px; margin:10px 0;
}}
.rem .lbl {{ color:var(--rem-fg); }}
.rem-b {{ color:var(--rem-fg); font-size:13px; margin-top:3px; }}

.entry {{ font-size:12.5px; color:var(--muted-2); margin-bottom:9px;
  word-break:break-all; display:flex; align-items:center; flex-wrap:wrap; gap:6px; }}
.ep-method {{ font-weight:700; color:var(--chip-v); }}
.ep-guard {{ font-size:10.5px; font-weight:650; padding:1px 7px; border-radius:6px;
  text-transform:uppercase; letter-spacing:.03em; }}
.ep-open {{ background:rgba(239,68,68,.14); color:#ef4444; }}
.ep-guarded {{ background:rgba(100,116,139,.16); color:var(--muted-2); }}
.req {{ background:var(--chip-bg); border:1px solid var(--border); border-radius:7px;
  padding:9px 13px; margin:10px 0; }}
.req-b {{ margin:4px 0 0; font-size:12px; color:var(--chip-v); white-space:pre-wrap;
  word-break:break-all; }}

.surface {{ background:var(--card); border:1px solid var(--border); border-radius:10px;
  margin:0 0 18px; padding:4px 6px; }}
.surface > summary {{ cursor:pointer; padding:10px 12px; font-weight:650;
  font-size:14px; color:var(--fg); }}
.surface-sub {{ font-weight:500; font-size:12px; color:var(--muted-2); margin-left:6px; }}
.rt {{ width:100%; border-collapse:collapse; font-size:12px; margin:4px 0 8px; }}
.rt th {{ text-align:left; padding:6px 10px; color:var(--muted-2); font-size:10.5px;
  text-transform:uppercase; letter-spacing:.03em; border-bottom:1px solid var(--border); }}
.rt td {{ padding:5px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
.rt-h {{ color:var(--muted-2); }}
.rt-f {{ color:var(--muted-2); font-size:11px; word-break:break-all; }}

/* Triage */
.triage {{ display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-top:9px; }}
.tbtn {{
  font:inherit; font-size:11px; font-weight:600; cursor:pointer;
  padding:3px 9px; border-radius:7px; border:1px solid var(--border);
  background:var(--chip-bg); color:var(--muted-2); transition:all .12s;
}}
.tbtn:hover {{ border-color:var(--muted-2); color:var(--fg); }}
.tb-clear {{ opacity:.55; }}
.finding[data-triage="real"] .tb-real {{
  background:rgba(239,68,68,.16); border-color:#ef4444; color:#ef4444; }}
.finding[data-triage="investigate"] .tb-investigate {{
  background:rgba(245,158,11,.16); border-color:#f59e0b; color:#f59e0b; }}
.finding[data-triage="false"] .tb-false {{
  background:rgba(100,116,139,.18); border-color:#64748b; color:#64748b; }}
/* A dismissed finding stays readable but stops competing for attention. */
.finding[data-triage="false"] .finding-main {{ opacity:.55; }}
.finding[data-triage="false"] .title {{ text-decoration:line-through; }}
.tnote {{ font-size:11.5px; color:var(--muted-2); margin-left:2px; }}
#triage-bar {{
  display:flex; align-items:center; gap:8px; flex-wrap:wrap;
  margin:0 0 14px; font-size:12px; color:var(--muted-2);
}}
#triage-bar .tbtn.on {{ border-color:var(--muted-2); color:var(--fg); }}
#cat-bar {{
  display:flex; align-items:center; gap:6px; flex-wrap:wrap;
  margin:0 0 10px; font-size:12px; color:var(--muted-2);
}}
.catchip {{ opacity:.45; }}
.catchip.on {{ opacity:1; border-color:var(--muted-2); color:var(--fg); }}
.catn {{ opacity:.65; font-weight:500; }}

.reach {{
  display:flex; align-items:baseline; gap:9px; flex-wrap:wrap;
  margin:2px 0 11px; font-size:12.5px;
}}
.reach-tag {{
  font-size:10.5px; font-weight:750; letter-spacing:.03em; padding:2px 9px;
  border-radius:999px; color:#fff; white-space:nowrap;
}}
.reach-called .reach-tag   {{ background:#dc2626; }}
.reach-imported .reach-tag {{ background:#d97706; }}
.reach-unused .reach-tag   {{ background:#64748b; }}
.reach-note {{ color:var(--muted); }}
.tags {{ margin:10px 0; }}
.tag {{
  display:inline-block; font-size:11px; background:var(--chip-bg); color:var(--chip-v);
  padding:2px 9px; border-radius:999px; margin:0 5px 4px 0;
}}

/* Code blocks */
.code {{
  margin:7px 0 0; background:var(--code-bg); color:var(--code-fg);
  border:1px solid var(--code-border); border-radius:7px; padding:9px 11px;
  font-family:"SFMono-Regular",ui-monospace,Menlo,Consolas,"Liberation Mono",monospace;
  font-size:12.5px; line-height:1.45; white-space:pre-wrap; word-break:break-word; overflow-x:auto;
}}

/* Trace timeline */
details.trace {{ margin-top:14px; border-top:1px solid var(--border); padding-top:10px; }}
details.trace summary {{
  cursor:pointer; font-size:12.5px; font-weight:650; color:var(--muted-2);
  list-style:none; user-select:none;
}}
details.trace summary::-webkit-details-marker {{ display:none; }}
details.trace summary::before {{ content:"▸ "; color:var(--muted); }}
details.trace[open] summary::before {{ content:"▾ "; }}
details.trace summary .hint {{ color:var(--muted); font-weight:450; }}
.timeline {{ list-style:none; margin:12px 0 2px; padding:0 0 0 6px; }}
.step {{ position:relative; padding:0 0 16px 28px; }}
.step::before {{
  content:""; position:absolute; left:10px; top:19px; bottom:-3px; width:2px; background:var(--border);
}}
.step:last-child::before {{ display:none; }}
.step .dot {{
  position:absolute; left:0; top:0; width:22px; height:22px; border-radius:999px;
  background:var(--panel-2); border:2px solid var(--border); color:var(--muted);
  font-size:10px; font-weight:700; display:flex; align-items:center; justify-content:center;
}}
.step-src .dot {{ background:#dc2626; border-color:#dc2626; color:#fff; }}
.step-sink .dot {{ background:var(--sv,#0f172a); border-color:var(--sv,#0f172a); color:#fff; }}
.step-desc {{ font-size:13px; color:var(--text); font-weight:500; }}
.step-tag {{
  display:inline-block; font-size:9.5px; font-weight:750; letter-spacing:.04em;
  padding:1px 6px; border-radius:5px; margin-right:7px; vertical-align:1px; color:#fff;
}}
.step-tag.st-src {{ background:#dc2626; }}
.step-tag.st-sink {{ background:#334155; }}
.step-loc {{ font-size:11.5px; color:var(--muted); margin-top:2px; word-break:break-all; }}

.refs {{ margin:10px 0 0; }}
.refs ul {{ margin:5px 0 0; padding-left:20px; font-size:12.5px; }}
.refs a {{ word-break:break-all; }}

.empty {{
  text-align:center; color:var(--muted); padding:36px; background:var(--panel);
  border:1px dashed var(--border); border-radius:12px;
}}
.no-results {{ display:none; }}

@media (max-width:640px) {{
  .stat {{ flex:1 1 84px; min-width:84px; }}
  .stat .stat-n {{ font-size:21px; }}
}}
@media print {{
  .toolbar, #theme {{ display:none !important; }}
  .finding {{ break-inside:avoid; box-shadow:none; }}
  details.trace {{ }}
}}
</style>
</head>
<body>
<header class="page">
  <div class="wrap">
    <h1>SAST Security Report</h1>
    <div class="hmeta-grid">{meta_items}</div>
  </div>
</header>

<div class="toolbar">
  <div class="wrap">
    <input id="q" type="search" placeholder="Filter by title, file, CWE, rule, package…" autocomplete="off">
    <span id="count"></span>
    <button id="theme" type="button" title="Toggle light / dark">◐ Theme</button>
  </div>
</div>

<div class="summary">{summary}</div>

<main>
  {surface}
  {categories}
  <div id="triage-bar">
    <span class="lbl">Triage</span>
    <button type="button" class="tbtn on" data-triage-filter="all">All</button>
    <button type="button" class="tbtn" data-triage-filter="real">Real <span data-tc="real">0</span></button>
    <button type="button" class="tbtn" data-triage-filter="investigate">To investigate <span data-tc="investigate">0</span></button>
    <button type="button" class="tbtn" data-triage-filter="false">False positive <span data-tc="false">0</span></button>
    <button type="button" class="tbtn" data-triage-filter="untriaged">Unreviewed <span data-tc="untriaged">0</span></button>
    <span class="tnote" id="triage-where"></span>
    <button type="button" class="tbtn" id="triage-export">Export JSON</button>
  </div>
  <h2 class="sec">Code Findings <span class="n">{finding_count}</span></h2>
  <div id="list">{rows}</div>

  <h2 class="sec">Dependency Vulnerabilities <span class="n">{dep_count}</span></h2>
  <div id="deps">{dep_rows}</div>

  <div id="noresults" class="empty no-results">No findings match the current filter.</div>
</main>

<script>
(function(){{
  var q = document.getElementById('q');
  var stats = Array.prototype.slice.call(document.querySelectorAll('.stat'));
  var countEl = document.getElementById('count');
  var noResults = document.getElementById('noresults');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var total = cards.length;
  var active = 'all';

  // ---- Triage -----------------------------------------------------------
  // Verdicts live on the server when this page is served by `sast server`,
  // so a second reviewer on another machine sees the same state. Opened as
  // a file there is no server to ask, and they fall back to this browser's
  // localStorage. Either way the page works; only the sharing differs.
  var triage = {{}};
  var tFilter = 'all';
  // Every category starts enabled, so the default view is the whole report.
  var catChips = Array.prototype.slice.call(
    document.querySelectorAll('[data-cat-filter]'));
  var activeCats = null;  // null means "no category filtering at all"
  if (catChips.length) {{
    activeCats = {{}};
    catChips.forEach(function(c){{
      activeCats[c.getAttribute('data-cat-filter')] = true;
    }});
  }}
  var scanId = (function(){{
    var m = location.pathname.match(new RegExp('/report/([A-Za-z0-9_-]+)'));
    return m ? m[1] : '';
  }})();
  var remote = !!scanId && location.protocol.indexOf('http') === 0;
  var storeKey = 'sast-triage:' + (scanId || location.pathname);
  var whereEl = document.getElementById('triage-where');

  function loadLocal(){{
    try {{ return JSON.parse(localStorage.getItem(storeKey) || '{{}}') || {{}}; }}
    catch (e) {{ return {{}}; }}
  }}
  function saveLocal(){{
    try {{ localStorage.setItem(storeKey, JSON.stringify(triage)); }}
    catch (e) {{ /* private mode, quota, blocked storage: keep going */ }}
  }}
  function persist(fid, state){{
    if (!remote) {{ saveLocal(); return; }}
    var payload = {{ verdicts: {{}} }};
    payload.verdicts[fid] = state;
    fetch('/api/triage/' + scanId, {{
      method: 'POST', headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload)
    }}).catch(function(){{
      // The server went away mid-review; keep the verdict locally so the
      // reviewer does not silently lose their work.
      remote = false; saveLocal(); setWhere();
    }});
  }}
  function setWhere(){{
    whereEl.textContent = remote ? 'saved on the server'
                                 : 'saved in this browser';
  }}

  function paint(){{
    var counts = {{ real:0, investigate:0, 'false':0, untriaged:0 }};
    cards.forEach(function(c){{
      var fid = c.getAttribute('data-fid');
      var state = triage[fid] || '';
      c.setAttribute('data-triage', state);
      counts[state || 'untriaged'] = (counts[state || 'untriaged'] || 0) + 1;
    }});
    Object.keys(counts).forEach(function(k){{
      var el = document.querySelector('[data-tc="' + k + '"]');
      if (el) el.textContent = counts[k];
    }});
  }}

  function apply(){{
    var term = q.value.trim().toLowerCase();
    var shown = 0;
    cards.forEach(function(c){{
      var state = triage[c.getAttribute('data-fid')] || '';
      var okSev = (active === 'all') || (c.getAttribute('data-sev') === active);
      var okTerm = !term || c.textContent.toLowerCase().indexOf(term) !== -1;
      var okTriage = (tFilter === 'all')
        || (tFilter === 'untriaged' ? !state : state === tFilter);
      var cat = c.getAttribute('data-cat') || 'uncategorised';
      var okCat = !activeCats || activeCats[cat] === true;
      var show = okSev && okTerm && okTriage && okCat;
      c.style.display = show ? '' : 'none';
      if (show) shown++;
    }});
    countEl.textContent = 'Showing ' + shown + ' of ' + total;
    noResults.style.display = (shown === 0 && total > 0) ? 'block' : 'none';
  }}

  document.addEventListener('click', function(ev){{
    var btn = ev.target.closest ? ev.target.closest('[data-triage-set]') : null;
    if (btn) {{
      var card = btn.closest('.finding');
      if (!card) return;
      var fid = card.getAttribute('data-fid');
      var state = btn.getAttribute('data-triage-set');
      if (state) {{ triage[fid] = state; }} else {{ delete triage[fid]; }}
      persist(fid, state);
      paint(); apply();
      return;
    }}
    var cbtn = ev.target.closest ? ev.target.closest('[data-cat-filter]') : null;
    if (cbtn && activeCats) {{
      var name = cbtn.getAttribute('data-cat-filter');
      activeCats[name] = !activeCats[name];
      cbtn.classList.toggle('on', activeCats[name]);
      apply();
      return;
    }}
    if (ev.target.id === 'cat-all' || ev.target.id === 'cat-none') {{
      var want = ev.target.id === 'cat-all';
      catChips.forEach(function(c){{
        activeCats[c.getAttribute('data-cat-filter')] = want;
        c.classList.toggle('on', want);
      }});
      apply();
      return;
    }}
    var fbtn = ev.target.closest ? ev.target.closest('[data-triage-filter]') : null;
    if (fbtn) {{
      Array.prototype.slice.call(
        document.querySelectorAll('[data-triage-filter]')).forEach(
          function(x){{ x.classList.remove('on'); }});
      fbtn.classList.add('on');
      tFilter = fbtn.getAttribute('data-triage-filter');
      apply();
    }}
  }});

  var exportBtn = document.getElementById('triage-export');
  if (exportBtn) exportBtn.addEventListener('click', function(){{
    var rows = cards.map(function(c){{
      return {{
        id: c.getAttribute('data-fid'),
        verdict: triage[c.getAttribute('data-fid')] || 'untriaged',
        severity: c.getAttribute('data-sev'),
        title: (c.querySelector('.title') || {{}}).textContent || '',
        location: (c.querySelector('.sink') || {{}}).textContent || ''
      }};
    }});
    var blob = new Blob([JSON.stringify(rows, null, 2)],
                        {{ type: 'application/json' }});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'sast-triage.json';
    a.click();
    setTimeout(function(){{ URL.revokeObjectURL(a.href); }}, 1000);
  }});

  function startTriage(){{
    setWhere();
    if (!remote) {{ triage = loadLocal(); paint(); apply(); return; }}
    fetch('/api/triage/' + scanId)
      .then(function(r){{ return r.ok ? r.json() : null; }})
      .then(function(d){{
        triage = (d && d.verdicts) || {{}};
        paint(); apply();
      }})
      .catch(function(){{
        remote = false; triage = loadLocal(); setWhere(); paint(); apply();
      }});
  }}

  stats.forEach(function(s){{
    s.addEventListener('click', function(){{
      stats.forEach(function(x){{ x.classList.remove('on'); }});
      s.classList.add('on');
      active = s.getAttribute('data-filter');
      apply();
    }});
  }});
  q.addEventListener('input', apply);

  // Theme toggle (persists for the session only; file is static).
  var themeBtn = document.getElementById('theme');
  var root = document.documentElement;
  themeBtn.addEventListener('click', function(){{
    var cur = root.getAttribute('data-theme');
    var isDark = cur ? cur === 'dark'
      : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    root.setAttribute('data-theme', isDark ? 'light' : 'dark');
  }});

  apply();
  startTriage();
}})();
</script>
</body>
</html>
"""
