"""The single-page interface served by `sast server`."""
from __future__ import annotations

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAST Scanner</title>
<style>
:root {
  --bg:#f1f5f9; --panel:#fff; --panel-2:#f8fafc; --border:#e2e8f0;
  --text:#0f172a; --muted:#64748b; --muted-2:#475569; --accent:#0ea5e9;
  --shadow:0 1px 2px rgba(15,23,42,.06), 0 1px 3px rgba(15,23,42,.08);
  --danger:#dc2626; --ok:#16a34a; --warn:#d97706;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg:#0b1120; --panel:#111827; --panel-2:#0f172a; --border:#1f2937;
    --text:#e5e7eb; --muted:#94a3b8; --muted-2:#cbd5e1; --accent:#38bdf8;
    --shadow:0 1px 2px rgba(0,0,0,.4);
  }
}
:root[data-theme="dark"] {
  --bg:#0b1120; --panel:#111827; --panel-2:#0f172a; --border:#1f2937;
  --text:#e5e7eb; --muted:#94a3b8; --muted-2:#cbd5e1; --accent:#38bdf8;
  --shadow:0 1px 2px rgba(0,0,0,.4);
}
* { box-sizing:border-box; }
body {
  margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px; line-height:1.5;
}
header.page { background:linear-gradient(135deg,#0f172a,#1e293b); color:#e2e8f0; padding:18px 16px; }
header.page .wrap { max-width:1180px; margin:0 auto; display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
header.page h1 { margin:0; font-size:18px; font-weight:650; color:#fff; }
header.page .sub { font-size:12.5px; color:#94a3b8; }
header.page .spacer { flex:1; }
main { max-width:1180px; margin:0 auto; padding:18px 16px 60px; }

.card { background:var(--panel); border:1px solid var(--border); border-radius:12px; box-shadow:var(--shadow); }
.scan-card { padding:16px 18px; margin-bottom:18px; }
h2 { font-size:12.5px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:0 0 12px; }

.tabs { display:flex; gap:6px; margin-bottom:14px; flex-wrap:wrap; }
.tab {
  padding:7px 14px; border:1px solid var(--border); border-radius:9px;
  background:var(--panel-2); color:var(--text); cursor:pointer; font:inherit; font-size:13px;
}
.tab.on { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
.pane { display:none; }
.pane.on { display:block; }

label.fl { display:block; font-size:12px; font-weight:600; color:var(--muted-2); margin:0 0 5px; }
input[type=text], input[type=file] {
  width:100%; padding:9px 12px; border:1px solid var(--border); border-radius:9px;
  background:var(--panel-2); color:var(--text); font-size:13.5px; font-family:inherit;
}
input[type=text]:focus { outline:2px solid var(--accent); outline-offset:-1px; }
.row { display:flex; gap:10px; flex-wrap:wrap; }
.row > * { flex:1; min-width:180px; }
.hint { font-size:12px; color:var(--muted); margin-top:6px; }
.actions { display:flex; align-items:center; gap:12px; margin-top:14px; flex-wrap:wrap; }
button.go {
  padding:10px 20px; border:0; border-radius:9px; background:var(--accent);
  color:#fff; font:inherit; font-size:14px; font-weight:650; cursor:pointer;
}
button.go:disabled { opacity:.55; cursor:not-allowed; }
.btn-sm {
  padding:5px 11px; border:1px solid var(--border); border-radius:7px;
  background:var(--panel-2); color:var(--text); font:inherit; font-size:12px; cursor:pointer;
}
#msg { font-size:13px; }
#msg.err { color:var(--danger); }
#msg.ok { color:var(--ok); }

.layout { display:grid; grid-template-columns:330px 1fr; gap:18px; align-items:start; }
@media (max-width:900px) { .layout { grid-template-columns:1fr; } }

.hist { max-height:70vh; overflow-y:auto; }
.hist-item {
  display:block; width:100%; text-align:left; padding:11px 13px; border:0;
  border-bottom:1px solid var(--border); background:none; color:var(--text);
  cursor:pointer; font:inherit;
}
.hist-item:hover { background:var(--panel-2); }
.hist-item.on { background:var(--panel-2); box-shadow:inset 3px 0 0 var(--accent); }
.hist-top { display:flex; align-items:center; gap:7px; margin-bottom:3px; }
.src-tag {
  font-size:9.5px; font-weight:750; letter-spacing:.04em; padding:1px 6px;
  border-radius:4px; background:var(--border); color:var(--muted-2); text-transform:uppercase;
}
.hist-label {
  font-size:12.5px; font-weight:600; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; flex:1; min-width:0;
}
.hist-meta { font-size:11.5px; color:var(--muted); display:flex; gap:8px; flex-wrap:wrap; }
.dot { width:7px; height:7px; border-radius:50%; flex:0 0 auto; }
.st-running { background:var(--accent); animation:pulse 1.2s infinite; }
.st-done { background:var(--ok); }
.st-failed { background:var(--danger); }
.st-interrupted { background:var(--warn); }
@keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.3; } }
.sev { font-weight:650; }
.sev-critical { color:#dc2626; } .sev-high { color:#ea580c; }
.sev-medium { color:#d97706; } .sev-low { color:#2563eb; }

.viewer { min-height:70vh; display:flex; flex-direction:column; overflow:hidden; }
.viewer-bar {
  display:flex; align-items:center; gap:10px; padding:10px 14px;
  border-bottom:1px solid var(--border); flex-wrap:wrap;
}
.viewer-title { font-size:13px; font-weight:600; flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
iframe { width:100%; flex:1; min-height:70vh; border:0; background:var(--panel); }
.empty { padding:60px 20px; text-align:center; color:var(--muted); }
.err-box {
  margin:14px; padding:12px 14px; border-radius:9px; border:1px solid var(--danger);
  background:rgba(220,38,38,.08); color:var(--danger); font-size:13px; white-space:pre-wrap;
}
.spin { display:inline-block; width:13px; height:13px; border:2px solid var(--border);
  border-top-color:var(--accent); border-radius:50%; animation:spin .7s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }
.warn-banner {
  background:#fef3c7; color:#92400e; padding:9px 16px; font-size:12.5px; text-align:center;
}
:root[data-theme="dark"] .warn-banner,
@media (prefers-color-scheme: dark) { .warn-banner { background:#422006; color:#fbbf24; } }
</style>
</head>
<body>
__BANNER__
<header class="page">
  <div class="wrap">
    <h1>SAST Scanner</h1>
    <span class="sub">offline · code, dependencies, IaC, containers, secrets</span>
    <span class="spacer"></span>
    <button class="btn-sm" id="theme" type="button">◐ Theme</button>
  </div>
</header>

<main>
  <section class="card scan-card">
    <h2>New scan</h2>
    <div class="tabs" role="tablist">
      <button class="tab on" data-pane="path" type="button">Local path</button>
      <button class="tab" data-pane="zip" type="button">ZIP upload</button>
      <button class="tab" data-pane="git" type="button">Git repository</button>
    </div>

    <form id="form">
      <div class="pane on" data-pane="path">
        <label class="fl" for="f-path">Directory on this machine</label>
        <input type="text" id="f-path" name="path" placeholder="/srv/myapp" autocomplete="off">
        <div class="hint">Scanned in place; nothing is copied.</div>
      </div>

      <div class="pane" data-pane="zip">
        <label class="fl" for="f-zip">Archive to upload</label>
        <input type="file" id="f-zip" name="archive" accept=".zip,application/zip">
        <div class="hint">Extracted to a temporary directory, scanned, then deleted.
          Entries that escape the archive root are refused.</div>
      </div>

      <div class="pane" data-pane="git">
        <div class="row">
          <div>
            <label class="fl" for="f-git">Repository URL</label>
            <input type="text" id="f-git" name="git" placeholder="https://github.com/owner/repo.git" autocomplete="off">
          </div>
          <div style="max-width:200px">
            <label class="fl" for="f-branch">Branch (optional)</label>
            <input type="text" id="f-branch" name="branch" placeholder="main" autocomplete="off">
          </div>
        </div>
        <div class="hint">https, ssh or git@host:owner/repo. Shallow clone, then deleted.
          SSH uses this machine's keys.</div>
      </div>

      <div class="actions">
        <button class="go" id="go" type="submit">Scan</button>
        <span id="msg"></span>
      </div>
    </form>
  </section>

  <div class="layout">
    <section class="card">
      <h2 style="padding:14px 14px 0; margin-bottom:8px;">History</h2>
      <div class="hist" id="hist"><div class="empty">No scans yet.</div></div>
    </section>

    <section class="card viewer">
      <div class="viewer-bar">
        <span class="viewer-title" id="v-title">No report selected</span>
        <a class="btn-sm" id="v-open" href="#" target="_blank" style="display:none;text-decoration:none">Open ↗</a>
        <a class="btn-sm" id="v-code" href="#" target="_blank" style="display:none;text-decoration:none">Code</a>
        <a class="btn-sm" id="v-json" href="#" target="_blank" style="display:none;text-decoration:none">JSON</a>
        <button class="btn-sm" id="v-del" type="button" style="display:none">Delete</button>
      </div>
      <div id="v-body"><div class="empty">Run a scan, or pick one from the history.</div></div>
    </section>
  </div>
</main>

<script>
(function(){
  var current = null, polling = null, lastSignature = "";

  function $(id){ return document.getElementById(id); }

  // Tabs
  var activePane = "path";
  document.querySelectorAll(".tab").forEach(function(tab){
    tab.addEventListener("click", function(){
      activePane = tab.dataset.pane;
      document.querySelectorAll(".tab").forEach(function(t){ t.classList.toggle("on", t === tab); });
      document.querySelectorAll(".pane").forEach(function(p){
        p.classList.toggle("on", p.dataset.pane === activePane);
      });
    });
  });

  $("theme").addEventListener("click", function(){
    var root = document.documentElement, cur = root.getAttribute("data-theme");
    var dark = cur ? cur === "dark"
      : window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.setAttribute("data-theme", dark ? "light" : "dark");
  });

  function setMsg(text, kind){
    var el = $("msg");
    el.className = kind || "";
    el.innerHTML = kind === "busy" ? '<span class="spin"></span> ' + text : text;
  }

  // Submit
  $("form").addEventListener("submit", function(ev){
    ev.preventDefault();
    var body = new FormData();
    body.append("source_type", activePane);
    if (activePane === "path") {
      if (!$("f-path").value.trim()) { setMsg("Enter a directory path.", "err"); return; }
      body.append("path", $("f-path").value.trim());
    } else if (activePane === "git") {
      if (!$("f-git").value.trim()) { setMsg("Enter a repository URL.", "err"); return; }
      body.append("git", $("f-git").value.trim());
      body.append("branch", $("f-branch").value.trim());
    } else {
      var f = $("f-zip").files[0];
      if (!f) { setMsg("Choose a .zip file.", "err"); return; }
      body.append("archive", f, f.name);
    }
    $("go").disabled = true;
    setMsg("Starting…", "busy");
    fetch("start", { method:"POST", body:body })
      .then(function(r){ return r.json().then(function(j){ return {ok:r.ok, j:j}; }); })
      .then(function(res){
        $("go").disabled = false;
        if (!res.ok || res.j.error) { setMsg(res.j.error || "Scan failed to start.", "err"); return; }
        setMsg("", "");
        current = res.j.id;
        refresh(true);
      })
      .catch(function(e){ $("go").disabled = false; setMsg(String(e), "err"); });
  });

  function fmtWhen(iso){
    if (!iso) return "";
    var d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }

  function counts(rec){
    var c = rec.counts || {}, out = [];
    ["critical","high","medium","low"].forEach(function(k){
      if (c[k]) out.push('<span class="sev sev-' + k + '">' + c[k] + " " + k.charAt(0).toUpperCase() + "</span>");
    });
    if (!out.length && rec.status === "done") out.push("clean");
    return out.join(" ");
  }

  function render(scans){
    var hist = $("hist");
    if (!scans.length) { hist.innerHTML = '<div class="empty">No scans yet.</div>'; return; }
    hist.innerHTML = scans.map(function(s){
      var label = s.source_label || s.root || "(unknown)";
      var meta = s.status === "running" ? (s.progress || "scanning…")
        : s.status === "failed" ? "failed"
        : s.status === "interrupted" ? "interrupted"
        : (s.findings + " findings · " + s.dependencies + " deps · " + s.duration + "s");
      return '<button class="hist-item' + (s.id === current ? " on" : "") + '" data-id="' + s.id + '">'
        + '<div class="hist-top"><span class="dot st-' + s.status + '"></span>'
        + '<span class="src-tag">' + s.source_type + '</span>'
        + '<span class="hist-label" title="' + esc(label) + '">' + esc(label) + '</span></div>'
        + '<div class="hist-meta"><span>' + fmtWhen(s.created_at) + '</span><span>' + meta + '</span>'
        + '<span>' + counts(s) + '</span></div></button>';
    }).join("");
    hist.querySelectorAll(".hist-item").forEach(function(b){
      b.addEventListener("click", function(){ current = b.dataset.id; show(); refresh(false); });
    });
  }

  function esc(s){
    return String(s).replace(/[&<>"']/g, function(c){
      return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c];
    });
  }

  var records = {};
  function show(){
    var rec = records[current];
    var body = $("v-body"), title = $("v-title");
    ["v-open","v-code","v-json","v-del"].forEach(function(id){ $(id).style.display = "none"; });
    if (!rec) {
      title.textContent = "No report selected";
      body.innerHTML = '<div class="empty">Run a scan, or pick one from the history.</div>';
      return;
    }
    title.textContent = rec.source_label || rec.root;
    $("v-del").style.display = "";
    if (rec.status === "running") {
      body.innerHTML = '<div class="empty"><span class="spin"></span> '
        + esc(rec.progress || "Scanning…") + '</div>';
    } else if (rec.status === "done") {
      $("v-open").style.display = ""; $("v-open").href = "report/" + rec.id;
      $("v-json").style.display = ""; $("v-json").href = "report/" + rec.id + ".json";
      $("v-code").style.display = ""; $("v-code").href = "code/" + rec.id;
      if (body.dataset.shown !== rec.id) {
        body.innerHTML = '<iframe src="report/' + rec.id + '" title="Scan report"></iframe>';
        body.dataset.shown = rec.id;
      }
    } else {
      body.dataset.shown = "";
      body.innerHTML = '<div class="err-box">' + esc(rec.error || rec.status) + "</div>";
    }
  }

  $("v-del").addEventListener("click", function(){
    if (!current) return;
    fetch("delete/" + current, { method:"POST" }).then(function(){
      delete records[current]; current = null;
      $("v-body").dataset.shown = ""; show(); refresh(false);
    });
  });

  function refresh(force){
    fetch("api/scans").then(function(r){ return r.json(); }).then(function(data){
      var scans = data.scans || [];
      records = {}; scans.forEach(function(s){ records[s.id] = s; });
      var signature = JSON.stringify(scans.map(function(s){
        return [s.id, s.status, s.findings, s.progress];
      }));
      if (force || signature !== lastSignature) {
        lastSignature = signature;
        render(scans);
        show();
      }
      var busy = scans.some(function(s){ return s.status === "running"; });
      if (busy && !polling) polling = setInterval(function(){ refresh(false); }, 1500);
      if (!busy && polling) { clearInterval(polling); polling = null; }
    }).catch(function(){});
  }

  refresh(true);
})();
</script>
</body>
</html>
"""


def render_page(banner: str = "") -> str:
    return PAGE.replace("__BANNER__", banner)
