/* Zero-dependency mock of the two backends the dashboard talks to:
 *   :8787  mitigation_dashboard.py  ->  GET /api/dashboard-data
 *   :5000  mmt-core REST API        ->  GET /api/security/*
 *
 * Generates a new verdict every ~3s (about 1 in 3 is an ATTACK) and the matching
 * mitigation rows, exactly in the shapes described in DASHBOARD_SPEC.md.
 *
 * Simulate mmt-core going down / coming back (mitigations flip to RECOMMENDED):
 *   curl "localhost:8787/mock/core?down=1"      curl "localhost:8787/mock/core?down=0"
 * Trip the rate limiter on demand (3 attacks from 127.0.0.1 inside the 60s window):
 *   curl "localhost:8787/mock/burst?n=3"
 */
const http = require('http');

const IPS = ['127.0.0.1', '10.45.0.7', '10.45.0.19', ''];
const LADDER = [300, 3600, 21600, 0]; // 5m -> 1h -> 6h -> permanent
const SIG = { name: 'ML_PIPELINE_ATTACK', pattern: 'ml_pipeline_attack', severity: 'CRITICAL', threshold: 3, window_s: 60, enabled: true, auto_block_ttl_s: 600 };

let coreDown = false;
let auditId = 0;
const verdicts = [];
const mitigations = [];
const audit = [];
const blocked = new Map(); // ip -> {reason, added_at, added_by, expires_at(ms|null)}
const offenses = {};
const hitLog = []; // sliding window: {ts, ip}
const hitCounter = {}; // lifetime: every /ids/test call (tripped or not)
const alertCounter = {}; // lifetime: only real trips

const now = () => Date.now() / 1000;
const rnd = (a, b) => a + Math.random() * (b - a);
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const iso = (sec) => new Date(sec * 1000).toISOString();

function addAudit(event_type, severity, source_ip, detail, extra = {}) {
  audit.unshift({ id: ++auditId, event_type, severity, source_ip, imsi: '', detail, extra_json: JSON.stringify(extra), created_at: iso(now()) });
  audit.length = Math.min(audit.length, 200);
}

function expireBlocks() {
  const t = Date.now();
  for (const [ip, b] of blocked) {
    if (b.expires_at != null && b.expires_at < t) {
      blocked.delete(ip);
      addAudit('IP_UNBLOCKED', 'INFO', ip, 'TTL expired');
    }
  }
}

function tick(force) {
  expireBlocks();
  const ts = now();
  const attack = force ? true : Math.random() < 0.33;
  const ip = force ? force.ip : pick(IPS);
  const net = attack ? rnd(0.4, 0.95) : rnd(0.02, 0.35);
  const pkt = attack ? rnd(0.3, 0.97) : rnd(0.02, 0.4);
  const override = !attack && Math.random() < 0.06;
  const final = override ? rnd(0.51, 0.6) : attack ? Math.max(net, pkt) : Math.max(net, pkt) * 0.8;
  const isAttack = attack || override;
  const escalated = isAttack || Math.random() < 0.1;
  const details = {
    fusion_reason: escalated ? (net > pkt ? 'escalated: network above its own boundary' : 'escalated: packet above its own boundary') : 'below all escalation boundaries',
    model_verdict: attack ? 'ATTACK' : 'NORMAL',
  };
  if (escalated) {
    Object.assign(details, { line2_network_prob: +rnd(0.2, 0.99).toFixed(3), line2_packet_prob: +rnd(0.2, 0.99).toFixed(3), net_flags_attack: net > 0.5, pkt_flags_attack: pkt > 0.5, or_logic: 'ATTACK if either available confirmer >= threshold' });
  }
  if (override) details.verdict_override = `final_score ${final.toFixed(3)} > 0.5 (score-threshold rule; model said NORMAL)`;

  verdicts.unshift({
    timestamp: String(ts), session_key: 'default_session', src_ip: ip, verdict: isAttack ? 'ATTACK' : 'NORMAL',
    final_score: final.toFixed(4), line1_network_score: net.toFixed(4), line1_packet_score: pkt.toFixed(4),
    line1_escalated: escalated ? '1' : '0', line2_invoked: escalated ? '1' : '0', packet_data_available: ip ? '1' : '0',
    details: JSON.stringify(details),
  });
  verdicts.length = Math.min(verdicts.length, 300);

  if (!isAttack) return;

  const base = { session_key: 'default_session', src_ip: ip, final_score: final.toFixed(4) };
  const canAct = !coreDown && ip !== '';
  const why = coreDown ? 'mmt-core unreachable: recommended only' : 'no src_ip available: investigate manually';
  const push = (action, applied, detail, extra = {}) =>
    mitigations.unshift({ ...base, timestamp: String(now()), action, applied: applied ? '1' : '0', detail, extra: JSON.stringify(extra) });

  if (ip) offenses[ip] = (offenses[ip] || 0) + 1;
  const count = ip ? offenses[ip] : 0;
  const ttl = LADDER[Math.min(count, LADDER.length) - 1] ?? 300;

  push('ip_quarantine', canAct, canAct ? `Blocked ${ip} via signalling firewall` : `Recommend blocking ${ip || 'source'}: ${why}`, { ttl_s: ttl, offense_count: count });
  push('rate_limit_signal', canAct, canAct ? 'Verdict fed to IDS signature ML_PIPELINE_ATTACK' : `Recommend rate limiting: ${why}`);
  if (count > 1) push('repeat_offender_escalation', canAct, canAct ? `Escalated ${ip} to offense #${count}` : `Recommend escalation: ${why}`, { ttl_s: ttl, offense_count: count });
  push('audit_sync', !coreDown, !coreDown ? 'Verdict written to mmt-core audit trail' : 'mmt-core unreachable: logged locally only');
  mitigations.length = Math.min(mitigations.length, 2000);

  if (!coreDown) {
    addAudit('ML_PIPELINE_VERDICT', 'INFO', ip, `ML verdict ATTACK score ${final.toFixed(3)}`, { score: final });
    if (canAct) {
      blocked.set(ip, { reason: 'ml_pipeline', added_at: iso(now()), added_by: 'ml-pipeline', expires_at: ttl === 0 ? null : Date.now() + ttl * 1000 });
      addAudit(ttl === 0 ? 'IP_BLOCKED' : 'IP_BLOCKED_TTL', 'WARNING', ip, `Blocked ${ip}`, { ttl_s: ttl });
      hitLog.push({ ts: now(), ip });
      hitCounter[SIG.name] = { count: (hitCounter[SIG.name] ? hitCounter[SIG.name].count : 0) + 1, last_ip: ip, last_hit: iso(now()) };
      const recent = hitLog.filter((h) => h.ts > now() - SIG.window_s && h.ip === ip).length;
      if (recent >= SIG.threshold) {
        alertCounter[SIG.name] = { count: (alertCounter[SIG.name] ? alertCounter[SIG.name].count : 0) + 1, last_ip: ip, last_hit: iso(now()) };
        addAudit('INTRUSION_DETECTED', 'CRITICAL', ip, `Signature ${SIG.name} tripped: ${recent} hits in ${SIG.window_s}s`, { signature: SIG.name, count: recent, threshold: SIG.threshold, window_s: SIG.window_s });
        for (let i = hitLog.length - 1; i >= 0; i--) if (hitLog[i].ip === ip) hitLog.splice(i, 1); // window resets after a trip
      }
    }
  }
}

const counters = () => ({ hits: hitCounter, alerts: alertCounter });

const blockedList = () => [...blocked.entries()].map(([ip, b]) => ({ ip, ...b, expires_at: b.expires_at == null ? null : iso(b.expires_at / 1000) }));

function status() {
  const counts = { DEBUG: 0, INFO: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 };
  audit.forEach((e) => { counts[e.severity] += 1; });
  const sources = {};
  blockedList().forEach((b) => { sources[b.ip] = { reason: b.reason, remaining_sec: b.expires_at ? Math.max(0, (Date.parse(b.expires_at) - Date.now()) / 1000) : null }; });
  return { summary: { blocked: blocked.size }, ids: { alerts: [], rules: [SIG], blocked_sources: sources }, rate_limiter: { violations: 0 }, gtpu: {}, audit_summary: counts };
}

function send(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(body));
}

// --- Our pipeline backend (mitigation_dashboard.py stand-in) ---
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/api/dashboard-data') {
    return send(res, 200, {
      generated_at: now(),
      verdicts: verdicts.slice(0, 100),
      mitigations: mitigations.slice(0, 200),
      core: coreDown ? { reachable: false, blocked_ips: [], ids_hits: {}, status: {} } : { reachable: true, blocked_ips: blockedList(), ids_hits: counters(), status: status() },
    });
  }
  if (url.pathname === '/mock/burst') { // force N attacks from one IP so the limiter trips quickly
    const n = Number(url.searchParams.get('n')) || 3;
    for (let i = 0; i < n; i++) tick({ ip: url.searchParams.get('ip') || '127.0.0.1' });
    return send(res, 200, { burst: n });
  }
  if (url.pathname === '/mock/core') {
    coreDown = url.searchParams.get('down') === '1';
    return send(res, 200, { coreDown });
  }
  send(res, 404, { error: 'not found' });
}).listen(8787, () => console.log('mock dashboard backend  -> http://localhost:8787/api/dashboard-data'));

// --- mmt-core stand-in ---
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (coreDown) return send(res, 503, { ok: false, error: 'mmt-core down (mock)' });
  switch (url.pathname) {
    case '/api/security/status': return send(res, 200, status());
    case '/api/security/blocked-ips': return send(res, 200, { ok: true, blocked: blockedList() });
    case '/api/security/audit': return send(res, 200, { ok: true, events: audit.slice(0, Number(url.searchParams.get('limit')) || 50) });
    case '/api/security/ids/hits': return send(res, 200, { ok: true, ...counters() });
    case '/api/security/ids/signatures': return send(res, 200, { ok: true, signatures: [SIG] });
    default: return send(res, 404, { ok: false });
  }
}).listen(5000, () => console.log('mock mmt-core REST API   -> http://localhost:5000/api/security/status'));

for (let i = 0; i < 12; i++) tick(); // seed some history
setInterval(tick, 3000);
console.log('Generating a verdict every 3s. Toggle core outage: curl "localhost:8787/mock/core?down=1"');
