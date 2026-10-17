"""Self-contained HTML report rendering."""
from __future__ import annotations

import html
from datetime import datetime

from ..models import OWASP_2021, ScanResult

_SEV_COLOR = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
}
_SEV_BG = {
    "critical": "#fee2e2",
    "high": "#fef2f2",
    "medium": "#fef3c7",
    "low": "#dbeafe",
    "info": "#f1f5f9",
}


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def _badge(severity: str) -> str:
    sev = severity.lower()
    return (
        f'<span class="sev" style="background:{_SEV_BG.get(sev, "#f1f5f9")};'
        f'color:{_SEV_COLOR.get(sev, "#64748b")}">{_esc(severity.upper())}</span>'
    )


def render_html(result: ScanResult) -> str:
    stats = result.stats()
    findings = result.findings
    deps = result.dependency_issues

    total = len(findings)
    rows = []
    for i, f in enumerate(findings):
        rows.append(_finding_card(i, f))

    dep_rows = []
    for d in deps:
        dep_rows.append(_dep_card(d))

    rows_html = "\n".join(rows) if rows else '<div class="empty">No findings.</div>'
    dep_rows_html = "\n".join(dep_rows) if dep_rows else '<div class="empty">No known vulnerable dependencies.</div>'

    summary = "".join(
        f'<div class="stat" style="border-left-color:{_SEV_COLOR.get(k, "#64748b")}">'
        f'<div class="n" style="color:{_SEV_COLOR.get(k, "#64748b")}">{v}</div>'
        f'<div class="l">{_esc(k)}</div></div>'
        for k, v in stats.items()
    )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return _PAGE.format(
        title=f"SAST Report — {_esc(result.root)}",
        generated=generated,
        root=_esc(result.root),
        language=_esc(result.language.upper()),
        framework=_esc(result.framework),
        files=_esc(result.files_scanned),
        duration=_esc(result.duration_seconds),
        total=total,
        summary=summary,
        rows=rows_html,
        dep_rows=dep_rows_html,
        dep_count=len(deps),
    )


def _finding_card(i: int, f) -> str:
    trace_rows = []
    for step in f.trace:
        loc = step.location
        trace_rows.append(
            "<tr>"
            f'<td class="mono loc"><a href="#f{i}">{_esc(loc.file)}:{_esc(loc.line)}</a></td>'
            f"<td>{_esc(step.description)}</td>"
            f'<td class="code">{_esc(step.code)}</td>'
            "</tr>"
        )

    source_ln = f.source.line if f.source else ""
    source_file = f.source.file if f.source else ""
    source_html = ""
    if f.source:
        source_html = (
            '<div class="src">'
            f'<span class="lbl">Source</span> '
            f'<span class="mono">{_esc(source_file)}:{_esc(source_ln)}</span>'
            f'<div class="code">{_esc(f.source.code)}</div></div>'
        )

    tags = " ".join(f'<span class="tag">{_esc(t)}</span>' for t in f.tags)

    return f"""
    <div class="finding" id="f{i}" data-sev="{_esc(f.severity.value)}" data-cat="{_esc(f.category)}">
      <div class="fh">
        {_badge(f.severity.value)}
        <div class="ft">
          <div class="title">{_esc(f.title)}</div>
          <div class="meta mono">
            {_esc(f.rule_id)} ·
            {_esc(f.location.file)}:{_esc(f.location.line)} ·
            {_esc(f.cwe)} · {_esc(f.owasp)} ·
            confidence: {_esc(f.confidence)} · framework: {_esc(f.framework)}
          </div>
        </div>
        <div class="cat">{_esc(f.category)}</div>
      </div>
      <div class="fb">
        <div class="desc">{_esc(f.description)}</div>
        {source_html}
        <div class="rem"><span class="lbl">Remediation</span> {_esc(f.remediation)}</div>
        {tags}
        <details class="trace">
          <summary>Source-to-sink trace ({len(f.trace)} steps)</summary>
          <table class="tt">
            <thead><tr><th>Location</th><th>Step</th><th>Code</th></tr></thead>
            <tbody>{''.join(trace_rows)}</tbody>
          </table>
        </details>
      </div>
    </div>"""


def _dep_card(d) -> str:
    refs = "".join(
        f'<li><a href="{_esc(r)}" rel="noreferrer">{_esc(r)}</a></li>' for r in d.references
    )
    return f"""
    <div class="finding dep" data-sev="{_esc(d.severity.value)}" data-cat="dependency">
      <div class="fh">
        {_badge(d.severity.value)}
        <div class="ft">
          <div class="title">{_esc(d.title)}</div>
          <div class="meta mono">
            {_esc(d.package)} @ {_esc(d.version)} · {_esc(d.cve)} · {_esc(d.cwe)}
            · fixed in {_esc(d.fixed_in)}
          </div>
        </div>
        <div class="cat">dependency</div>
      </div>
      <div class="fb">
        <div class="desc">{_esc(d.description)}</div>
        {f'<ul class="refs">{refs}</ul>' if refs else ''}
      </div>
    </div>"""


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background:#f8fafc; color:#0f172a; }}
header {{ background:#0f172a; color:#e2e8f0; padding:20px 28px; }}
header h1 {{ margin:0 0 6px; font-size:20px; font-weight:600; color:#fff; }}
header .sub {{ color:#94a3b8; font-size:13px; }}
header .sub b {{ color:#cbd5e1; font-weight:600; }}
.toolbar {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; padding:14px 28px; background:#fff; border-bottom:1px solid #e2e8f0; position:sticky; top:0; }}
.toolbar input {{ padding:8px 12px; border:1px solid #cbd5e1; border-radius:8px; font-size:13px; min-width:220px; }}
.btn {{ padding:8px 12px; border:1px solid #cbd5e1; border-radius:8px; background:#fff; cursor:pointer; font-size:13px; }}
.btn.on {{ background:#0f172a; color:#fff; border-color:#0f172a; }}
.summary {{ display:flex; gap:14px; flex-wrap:wrap; padding:16px 28px; }}
.stat {{ background:#fff; border:1px solid #e2e8f0; border-left:4px solid #64748b; border-radius:10px; padding:10px 18px; min-width:90px; }}
.stat .n {{ font-size:26px; font-weight:700; }}
.stat .l {{ font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:.03em; }}
.container {{ padding:0 28px 60px; max-width:1180px; }}
.finding {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; margin:14px 0; overflow:hidden; }}
.fh {{ display:flex; align-items:flex-start; gap:12px; padding:14px 18px; }}
.sev {{ font-size:11px; font-weight:700; padding:3px 9px; border-radius:999px; white-space:nowrap; }}
.ft {{ flex:1; }}
.title {{ font-size:15px; font-weight:600; line-height:1.3; }}
.meta {{ font-size:12px; color:#64748b; margin-top:3px; }}
.cat {{ font-size:12px; color:#475569; background:#f1f5f9; padding:4px 10px; border-radius:999px; white-space:nowrap; }}
.fb {{ padding:0 18px 16px; }}
.desc {{ font-size:13.5px; color:#334155; margin:4px 0 10px; }}
.src {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:10px 12px; margin:8px 0; }}
.lbl {{ font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; color:#64748b; }}
.rem {{ font-size:13px; color:#0f766e; background:#f0fdfa; border-left:3px solid #14b8a6; padding:8px 12px; border-radius:6px; margin:8px 0; }}
.tag {{ display:inline-block; font-size:11px; background:#eef2ff; color:#4338ca; padding:2px 8px; border-radius:999px; margin:2px 4px 0 0; }}
.mono, .code {{ font-family: "SFMono-Regular", ui-monospace, Menlo, Consolas, monospace; }}
.code {{ font-size:12px; color:#1e293b; background:#0f172a; color:#e2e8f0; padding:6px 9px; border-radius:6px; overflow-x:auto; white-space:pre; }}
details.trace {{ margin-top:10px; }}
details.trace summary {{ cursor:pointer; font-size:13px; font-weight:600; color:#334155; }}
table.tt {{ width:100%; border-collapse:collapse; margin-top:8px; font-size:12.5px; }}
table.tt th {{ text-align:left; background:#f1f5f9; padding:7px 9px; border:1px solid #e2e8f0; color:#475569; }}
table.tt td {{ padding:7px 9px; border:1px solid #e2e8f0; vertical-align:top; }}
table.tt td.loc {{ white-space:nowrap; }}
table.tt td.code {{ color:#e2e8f0; }}
.refs {{ margin:8px 0 0; padding-left:18px; font-size:12.5px; }}
.refs a {{ color:#2563eb; }}
.empty {{ text-align:center; color:#64748b; padding:40px; }}
h2.sec {{ font-size:16px; font-weight:600; margin:28px 0 4px; }}
</style>
</head>
<body>
<header>
  <h1>SAST Security Report</h1>
  <div class="sub">Root: <b>{root}</b> &nbsp;·&nbsp; Language: <b>{language}</b> &nbsp;·&nbsp; Framework: <b>{framework}</b> &nbsp;·&nbsp; Files scanned: <b>{files}</b> &nbsp;·&nbsp; Duration: <b>{duration}s</b> &nbsp;·&nbsp; Generated: <b>{generated}</b></div>
</header>
<div class="toolbar">
  <input id="q" type="text" placeholder="Filter by title, file, CWE, rule…">
  <button class="btn" data-sev="all">All ({total})</button>
  <button class="btn" data-sev="critical">Critical</button>
  <button class="btn" data-sev="high">High</button>
  <button class="btn" data-sev="medium">Medium</button>
  <button class="btn" data-sev="low">Low</button>
  <button class="btn" data-sev="info">Info</button>
</div>
<div class="summary">{summary}</div>
<div class="container">
  <h2 class="sec">Findings ({total})</h2>
  <div id="list">{rows}</div>
  <h2 class="sec">Dependency Vulnerabilities ({dep_count})</h2>
  <div id="deps">{dep_rows}</div>
</div>
<script>
(function(){{
  var q = document.getElementById('q');
  var active = 'all';
  var btns = document.querySelectorAll('.btn');
  function apply(){{
    var term = q.value.toLowerCase();
    var cards = document.querySelectorAll('.finding');
    cards.forEach(function(c){{
      var sev = c.getAttribute('data-sev');
      var showSev = (active === 'all' || active === sev);
      var showTerm = !term || c.textContent.toLowerCase().indexOf(term) !== -1;
      c.style.display = (showSev && showTerm) ? '' : 'none';
    }});
  }}
  btns.forEach(function(b){{
    b.addEventListener('click', function(){{
      btns.forEach(function(x){{ x.classList.remove('on'); }});
      b.classList.add('on');
      active = b.getAttribute('data-sev');
      apply();
    }});
  }});
  q.addEventListener('input', apply);
  btns[0].classList.add('on');
}})();
</script>
</body>
</html>
"""
