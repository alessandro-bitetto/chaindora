package server

import (
	"net/http"
	"strings"
)

// handleDashboard serves a single static HTML page that talks
// to the JSON API via plain fetch(). No frameworks, no build
// step — vendored into the binary as a string literal.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := strings.ReplaceAll(dashboardHTML, "${VERSION}", s.ChdoraVersion)
	_, _ = w.Write([]byte(page))
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>chaindora — fleet</title>
<style>
:root {
  --bg: #0e1116;
  --fg: #c9d1d9;
  --muted: #8b949e;
  --accent: #58a6ff;
  --critical: #f85149;
  --high: #f0883e;
  --medium: #d29922;
  --low: #3fb950;
  --row: #161b22;
  --border: #30363d;
}
* { box-sizing: border-box; }
body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", monospace; background: var(--bg); color: var(--fg); margin: 0; padding: 24px; }
h1 { margin: 0 0 8px; font-size: 20px; font-weight: 600; }
.sub { color: var(--muted); margin-bottom: 24px; font-size: 12px; }
.cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
.card { background: var(--row); border: 1px solid var(--border); border-radius: 6px; padding: 16px 20px; min-width: 140px; }
.card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; }
.card .value { font-size: 28px; font-weight: 600; margin-top: 4px; }
.card.critical .value { color: var(--critical); }
.card.high .value { color: var(--high); }
.card.medium .value { color: var(--medium); }
.card.low .value { color: var(--low); }
table { width: 100%; border-collapse: collapse; background: var(--row); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
th, td { padding: 8px 12px; border-bottom: 1px solid var(--border); text-align: left; }
th { background: #0d1117; color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: none; }
.sev { display: inline-block; min-width: 70px; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-align: center; font-weight: 600; }
.sev.CRITICAL { background: var(--critical); color: #000; }
.sev.HIGH { background: var(--high); color: #000; }
.sev.MEDIUM { background: var(--medium); color: #000; }
.sev.LOW { background: var(--low); color: #000; }
.sev.UNKNOWN { background: var(--border); color: var(--fg); }
code { font-family: "SF Mono", Consolas, monospace; background: #0d1117; padding: 2px 6px; border-radius: 3px; }
section { margin-bottom: 32px; }
.muted { color: var(--muted); }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.empty { padding: 24px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
<h1>chaindora · fleet</h1>
<div class="sub">server ${VERSION} · <span id="updated"></span></div>

<div class="cards" id="cards">
  <div class="card"><div class="label">Agents</div><div class="value" id="agent-count">—</div></div>
  <div class="card critical"><div class="label">Critical</div><div class="value" id="sev-CRITICAL">—</div></div>
  <div class="card high"><div class="label">High</div><div class="value" id="sev-HIGH">—</div></div>
  <div class="card medium"><div class="label">Medium</div><div class="value" id="sev-MEDIUM">—</div></div>
  <div class="card low"><div class="label">Low</div><div class="value" id="sev-LOW">—</div></div>
</div>

<section>
<h2>Agents</h2>
<table>
<thead><tr><th>Name</th><th>Hostname</th><th>Chdora</th><th>Enrolled</th><th>Last seen</th><th>Findings</th></tr></thead>
<tbody id="agents"></tbody>
</table>
</section>

<section>
<h2>Recent findings</h2>
<table>
<thead><tr><th>Severity</th><th>Detector</th><th>Vuln</th><th>Package</th><th>Agent</th><th>When</th></tr></thead>
<tbody id="findings"></tbody>
</table>
</section>

<script>
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"})[c]); }
function fmt(ts) { if (!ts) return ""; try { return new Date(ts).toLocaleString(); } catch(e) { return ts; } }
async function load() {
  const summary = await fetch("/api/v1/summary").then(r => r.json());
  const findings = await fetch("/api/v1/findings?latest=1&limit=200").then(r => r.json());
  document.getElementById("updated").textContent = "updated " + new Date().toLocaleString();
  document.getElementById("agent-count").textContent = summary.agent_count;
  for (const sev of ["CRITICAL","HIGH","MEDIUM","LOW"]) {
    document.getElementById("sev-" + sev).textContent = (summary.by_severity || {})[sev] || 0;
  }
  const agentsBody = document.getElementById("agents");
  agentsBody.innerHTML = "";
  if (!summary.by_agent || summary.by_agent.length === 0) {
    agentsBody.innerHTML = "<tr><td colspan=\"6\" class=\"empty\">No agents enrolled yet. Run <code>chdora agent enroll --server &lt;url&gt;</code> on a host.</td></tr>";
  } else {
    for (const a of summary.by_agent) {
      const sevSpans = ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"].map(s =>
        (a.by_severity||{})[s] ? '<span class="sev '+s+'">'+s+': '+a.by_severity[s]+'</span>' : ''
      ).filter(Boolean).join(" ");
      agentsBody.innerHTML += "<tr>" +
        "<td>" + esc(a.agent.name) + "</td>" +
        "<td>" + esc(a.agent.hostname || "—") + "</td>" +
        "<td><code>" + esc(a.agent.chdora_version || "—") + "</code></td>" +
        "<td>" + fmt(a.agent.enrolled_at) + "</td>" +
        "<td>" + (a.agent.last_seen ? fmt(a.agent.last_seen) : '<span class="muted">never</span>') + "</td>" +
        "<td>" + sevSpans + "</td>" +
      "</tr>";
    }
  }
  const fBody = document.getElementById("findings");
  fBody.innerHTML = "";
  if (!findings || findings.length === 0) {
    fBody.innerHTML = "<tr><td colspan=\"6\" class=\"empty\">No findings yet.</td></tr>";
  } else {
    const agentName = {};
    for (const a of summary.by_agent || []) agentName[a.agent.id] = a.agent.name;
    for (const fr of findings) {
      const f = fr.finding;
      const sev = f.severity || "UNKNOWN";
      fBody.innerHTML += "<tr>" +
        '<td><span class="sev '+esc(sev)+'">'+esc(sev)+'</span></td>' +
        "<td><code>" + esc(f.detector || "") + "</code></td>" +
        "<td><code>" + esc(f.vuln_id || "—") + "</code></td>" +
        "<td><code>" + esc((f.name||"") + (f.version ? "@" + f.version : "")) + "</code></td>" +
        "<td>" + esc(agentName[fr.agent_id] || fr.agent_id) + "</td>" +
        "<td>" + fmt(fr.received_at) + "</td>" +
      "</tr>";
    }
  }
}
load();
setInterval(load, 30000);
</script>
</body>
</html>
`
