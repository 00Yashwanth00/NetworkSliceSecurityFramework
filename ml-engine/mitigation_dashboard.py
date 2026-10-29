#!/usr/bin/env python3
"""
mitigation_dashboard.py

Standalone, read-only dashboard for the mitigation pipeline. Shows:

  1. Live verdicts        -- tail of the 'verdicts' Redis stream
  2. Mitigation actions   -- tail of the 'mitigation:events' Redis stream
                              (written by mitigation.py), with a clear
                              APPLIED vs RECOMMENDED badge per action. This
                              is the fallback view: even if sacore-web was
                              completely unreachable all session, every
                              strategy mitigation.py decided to take still
                              shows up here as "RECOMMENDED".
  3. mmt-core live state  -- pulled fresh from sacore-web's own REST API
                              (blocked IPs, IDS hit counters, audit
                              summary) each poll. Degrades to a banner
                              instead of crashing if sacore-web is down.

This process touches ONLY Redis (read-only) and sacore-web's read-only
GET endpoints. It never writes to mmt-core.

Run:
    pip install fastapi uvicorn httpx redis
    python mitigation_dashboard.py
    # then open http://localhost:8787
"""

import asyncio
import os
import time

import httpx
import redis.asyncio as redis
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
SACORE_URL = os.environ.get("SACORE_URL", "http://localhost:5000")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8787"))

# Written by tester/run_tracked.py right before it launches a test case,
# and deleted when that test finishes (pass, fail, or crash). Absent means
# "nothing is running right now" -- not an error.
CURRENT_TEST_KEY = "pipeline:current_test"

app = FastAPI(title="Mitigation Dashboard")
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


async def _tail_stream(name: str, count: int = 30):
    try:
        entries = await r.xrevrange(name, count=count)
        return [{"id": eid, **fields} for eid, fields in entries]
    except Exception as e:
        return [{"error": str(e)}]


async def _current_test():
    """Returns None when no test is running (the normal, common case) --
    not an error, so the frontend should treat None/missing the same as
    'nothing running', not as a fetch failure."""
    try:
        data = await r.hgetall(CURRENT_TEST_KEY)
        if not data:
            return None
        return {
            "tc_id": data.get("tc_id", ""),
            "cli_name": data.get("cli_name", ""),
            "started_at": float(data.get("started_at", 0) or 0),
        }
    except Exception as e:
        return {"error": str(e)}


async def _core_snapshot():
    out = {"reachable": False, "url": SACORE_URL}
    try:
        async with httpx.AsyncClient(base_url=SACORE_URL, timeout=3.0) as client:
            blocked, ids_hits, status = await asyncio.gather(
                client.get("/api/security/blocked-ips"),
                client.get("/api/security/ids/hits"),
                client.get("/api/security/status"),
            )
        out.update({
            "reachable": True,
            "blocked_ips": blocked.json().get("blocked", []),
            "ids_hits": ids_hits.json(),
            "status": status.json(),
        })
    except Exception as e:
        out["error"] = str(e)
    return out


@app.get("/api/dashboard-data")
async def dashboard_data():
    verdicts, mitigations, core, current_test = await asyncio.gather(
        _tail_stream("verdicts", 30),
        _tail_stream("mitigation:events", 60),
        _core_snapshot(),
        _current_test(),
    )
    return JSONResponse({
        "generated_at": time.time(),
        "verdicts": verdicts,
        "mitigations": mitigations,
        "core": core,
        "current_test": current_test,
    })


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_PAGE


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Mitigation Dashboard</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #12181f; --border: #232c36; --text: #e6edf3;
    --muted: #8b98a5; --accent: #4fa8ff; --good: #3fb950; --warn: #d29922;
    --bad: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
    font-size: 13px; padding: 20px;
  }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .sub { color: var(--muted); margin-bottom: 18px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 1000px) { .grid { grid-template-columns: 1fr; } }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px; overflow-x: auto;
  }
  .panel h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: .05em;
    color: var(--muted); margin: 0 0 10px;
  }
  table { width: 100%; border-collapse: collapse; }
  th, td {
    text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--border);
    white-space: nowrap; font-size: 12px;
  }
  th { color: var(--muted); font-weight: 500; }
  .badge {
    display: inline-block; padding: 1px 7px; border-radius: 10px;
    font-size: 11px; font-weight: 600;
  }
  .badge.attack, .badge.bad, .badge.recommended { background: #3a1114; color: var(--bad); }
  .badge.normal, .badge.good, .badge.applied { background: #0f2a17; color: var(--good); }
  .banner {
    background: #3a1114; color: var(--bad); border: 1px solid var(--bad);
    border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; display: none;
  }
  .score { color: var(--accent); }
  .muted { color: var(--muted); }
  .wrap { white-space: normal; max-width: 420px; }
</style>
</head>
<body>
  <h1>Mitigation Dashboard</h1>
  <div class="sub" id="meta">loading…</div>
  <div class="sub" id="current-test"></div>
  <div class="banner" id="core-banner"></div>

  <div class="grid">
    <div class="panel">
      <h2>Mitigation Actions (applied / recommended)</h2>
      <table><thead><tr>
        <th>Time</th><th>Action</th><th>Status</th><th>Src IP</th><th>Score</th><th>Detail</th>
      </tr></thead><tbody id="mitigations"></tbody></table>
    </div>

    <div class="panel">
      <h2>Live Verdicts</h2>
      <table><thead><tr>
        <th>Time</th><th>Verdict</th><th>Score</th><th>Session</th><th>Src IP</th><th>Line1 Net/Pkt</th>
      </tr></thead><tbody id="verdicts"></tbody></table>
    </div>

    <div class="panel">
      <h2>mmt-core: Blocked IPs (live)</h2>
      <table><thead><tr>
        <th>IP</th><th>Reason</th><th>Added</th><th>Expires</th>
      </tr></thead><tbody id="blocked"></tbody></table>
    </div>

    <div class="panel">
      <h2>mmt-core: IDS Hit Counters</h2>
      <pre id="ids-hits" class="muted"></pre>
    </div>
  </div>

<script>
function esc(s) { return (s ?? "").toString().replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }
function fmtTime(ts) { return ts ? new Date(parseFloat(ts) * 1000).toLocaleTimeString() : ""; }

async function refresh() {
  let data;
  try {
    data = await (await fetch("/api/dashboard-data")).json();
  } catch (e) {
    document.getElementById("meta").textContent = "dashboard backend unreachable: " + e;
    return;
  }

  document.getElementById("meta").textContent =
    "last updated " + new Date(data.generated_at * 1000).toLocaleTimeString();

  const ct = document.getElementById("current-test");
  if (data.current_test && data.current_test.tc_id) {
    const secs = Math.max(0, Math.round(Date.now() / 1000 - data.current_test.started_at));
    ct.textContent = "Running now: " + data.current_test.tc_id + " (" + secs + "s)";
    ct.style.color = "var(--accent)";
  } else {
    ct.textContent = "No test case currently running";
    ct.style.color = "";
  }

  const banner = document.getElementById("core-banner");
  if (!data.core.reachable) {
    banner.style.display = "block";
    banner.textContent = "sacore-web (" + data.core.url + ") is unreachable — showing recommended " +
      "mitigation actions only; nothing below is actually being enforced. (" + (data.core.error || "") + ")";
  } else {
    banner.style.display = "none";
  }

  // Mitigations
  const mBody = document.getElementById("mitigations");
  mBody.innerHTML = data.mitigations.map(m => {
    const applied = m.applied === "1" || m.applied === 1;
    return `<tr>
      <td>${fmtTime(m.timestamp)}</td>
      <td>${esc(m.action)}</td>
      <td><span class="badge ${applied ? 'applied' : 'recommended'}">${applied ? 'APPLIED' : 'RECOMMENDED'}</span></td>
      <td>${esc(m.src_ip)}</td>
      <td class="score">${m.final_score ? parseFloat(m.final_score).toFixed(3) : ""}</td>
      <td class="wrap">${esc(m.detail)}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="6" class="muted">no mitigation events yet</td></tr>`;

  // Verdicts
  const vBody = document.getElementById("verdicts");
  vBody.innerHTML = data.verdicts.map(v => `<tr>
      <td>${fmtTime(v.timestamp)}</td>
      <td><span class="badge ${v.verdict === 'ATTACK' ? 'attack' : 'normal'}">${esc(v.verdict)}</span></td>
      <td class="score">${v.final_score ? parseFloat(v.final_score).toFixed(3) : ""}</td>
      <td>${esc(v.session_key)}</td>
      <td>${esc(v.src_ip)}</td>
      <td>${v.line1_network_score ? parseFloat(v.line1_network_score).toFixed(2) : "-"} /
          ${v.line1_packet_score ? parseFloat(v.line1_packet_score).toFixed(2) : "-"}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">no verdicts yet</td></tr>`;

  // Core blocked IPs
  const bBody = document.getElementById("blocked");
  const blocked = data.core.blocked_ips || [];
  bBody.innerHTML = blocked.map(b => `<tr>
      <td>${esc(b.ip)}</td><td class="wrap">${esc(b.reason)}</td>
      <td>${esc(b.added_at)}</td><td>${esc(b.expires_at) || "permanent"}</td>
    </tr>`).join("") || `<tr><td colspan="4" class="muted">none${data.core.reachable ? "" : " (sacore-web unreachable)"}</td></tr>`;

  document.getElementById("ids-hits").textContent =
    data.core.reachable ? JSON.stringify(data.core.ids_hits, null, 2) : "sacore-web unreachable";
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print(f"Mitigation dashboard: http://localhost:{DASHBOARD_PORT}")
    print(f"  Redis:     {REDIS_HOST}:{REDIS_PORT}")
    print(f"  sacore-web: {SACORE_URL}")
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT)
