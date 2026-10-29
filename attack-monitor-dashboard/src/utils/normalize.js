// Redis Streams are string-typed and mmt-core returns JSON-in-strings, so everything
// is coerced here once. UI components only ever see clean, typed objects.

export function toNum(v, fallback = 0) {
  const n = typeof v === 'number' ? v : parseFloat(v);
  return Number.isFinite(n) ? n : fallback;
}

export function toBool(v) {
  return v === true || v === 1 || v === '1' || v === 'true' || v === 'True';
}

export function parseJson(v) {
  if (v == null || v === '') return {};
  if (typeof v === 'object') return v;
  try {
    const parsed = JSON.parse(v);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

// Accepts unix seconds (float), unix ms, numeric strings, or ISO-ish strings.
export function toMs(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number' || /^\d+(\.\d+)?$/.test(String(v).trim())) {
    const n = Number(v);
    return n > 1e12 ? n : n * 1000;
  }
  let s = String(v).trim();
  if (/^\d{4}-\d{2}-\d{2} \d/.test(s)) s = s.replace(' ', 'T');
  // SQLite-style timestamps carry no zone; treat them as UTC.
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// Stable React keys without trusting ids (spec section 7: mmt-core ids can reset).
function assignKeys(rows, parts) {
  const seen = new Map();
  return rows.map((row) => {
    const base = parts(row).join('|');
    const n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    return { ...row, key: n === 1 ? base : `${base}#${n}` };
  });
}

const byTimeDesc = (a, b) => (b.ts ?? 0) - (a.ts ?? 0);
const asArray = (v) => (Array.isArray(v) ? v : []);

export function normalizeVerdicts(rows) {
  const list = asArray(rows).map((r) => ({
    ts: toMs(r.timestamp),
    sessionKey: r.session_key || '',
    srcIp: String(r.src_ip || '').trim(),
    verdict: String(r.verdict || 'NORMAL').toUpperCase(),
    finalScore: toNum(r.final_score),
    netScore: toNum(r.line1_network_score),
    pktScore: toNum(r.line1_packet_score),
    escalated: toBool(r.line1_escalated),
    line2: toBool(r.line2_invoked),
    packetAvailable: toBool(r.packet_data_available),
    details: parseJson(r.details),
  }));
  list.sort(byTimeDesc);
  return assignKeys(list, (r) => [r.ts, r.sessionKey, r.verdict, r.finalScore]);
}

export function normalizeMitigations(rows) {
  const list = asArray(rows).map((r) => ({
    ts: toMs(r.timestamp),
    sessionKey: r.session_key || '',
    srcIp: String(r.src_ip || '').trim(),
    finalScore: toNum(r.final_score),
    action: r.action || '',
    applied: toBool(r.applied),
    detail: r.detail || '',
    extra: parseJson(r.extra),
  }));
  list.sort(byTimeDesc);
  return assignKeys(list, (r) => [r.ts, r.action, r.srcIp, r.applied ? 1 : 0]);
}

export function normalizeBlocked(v) {
  const list = Array.isArray(v) ? v : asArray(v && v.blocked);
  return list.map((b) => ({
    key: `${b.ip}|${b.added_at}`,
    ip: b.ip,
    reason: b.reason || '',
    addedAt: toMs(b.added_at),
    addedBy: b.added_by || '',
    expiresAt: b.expires_at == null ? null : toMs(b.expires_at), // null = permanent
  }));
}

export function normalizeAudit(resp) {
  const events = asArray(resp && resp.events).map((e) => ({
    ts: toMs(e.created_at),
    eventType: e.event_type || '',
    severity: String(e.severity || 'INFO').toUpperCase(),
    sourceIp: e.source_ip || '',
    imsi: e.imsi || '',
    detail: e.detail || '',
    extra: parseJson(e.extra_json),
  }));
  events.sort(byTimeDesc);
  return assignKeys(events, (e) => [e.ts, e.eventType, e.sourceIp, e.severity]);
}

export function normalizeSignatures(resp) {
  const list = Array.isArray(resp) ? resp : asArray(resp && resp.signatures);
  return list.map((s) => ({
    name: s.name,
    pattern: s.pattern || '',
    severity: String(s.severity || '').toUpperCase(),
    threshold: s.threshold == null ? null : toNum(s.threshold),
    windowS: s.window_s == null ? null : toNum(s.window_s),
    enabled: s.enabled !== false,
    autoBlockTtlS: s.auto_block_ttl_s == null ? null : toNum(s.auto_block_ttl_s),
  }));
}

// { sig: {count,last_ip,last_hit} }  or  { hits: { ... }, alerts: {...} }
export function normalizeHits(v) {
  if (!v || typeof v !== 'object') return {};
  const src = v.hits && typeof v.hits === 'object' ? v.hits : v;
  const out = {};
  Object.entries(src).forEach(([name, h]) => {
    if (h && typeof h === 'object') {
      out[name] = { count: toNum(h.count), lastIp: h.last_ip || '', lastHit: toMs(h.last_hit) };
    }
  });
  return out;
}

export const SEVERITY_ORDER = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

export function normalizeSeverityCounts(summary) {
  if (!summary) return [];
  let src = summary;
  if (Array.isArray(summary)) {
    src = {};
    summary.forEach((r) => {
      if (r && r.severity != null) src[String(r.severity).toUpperCase()] = toNum(r.count);
    });
  } else if (summary.by_severity) {
    src = summary.by_severity;
  }
  return SEVERITY_ORDER.map((sev) => ({ severity: sev, count: toNum(src[sev] ?? src[sev.toLowerCase()]) }));
}

export function normalizeStatus(status) {
  const s = status && typeof status === 'object' ? status : {};
  const ids = s.ids || {};
  const blockedSources = ids.blocked_sources && typeof ids.blocked_sources === 'object' ? ids.blocked_sources : {};
  return {
    available: !!status && Object.keys(s).length > 0,
    summary: s.summary || null,
    rules: asArray(ids.rules),
    alerts: asArray(ids.alerts),
    blockedSources: Object.entries(blockedSources).map(([ip, v]) => ({
      ip,
      reason: (v && v.reason) || '',
      remainingSec: v && v.remaining_sec != null ? toNum(v.remaining_sec) : null,
    })),
    severityCounts: normalizeSeverityCounts(s.audit_summary),
  };
}

export function normalizeDashboard(data) {
  if (!data) return null;
  const core = data.core || {};
  return {
    generatedAt: toMs(data.generated_at),
    verdicts: normalizeVerdicts(data.verdicts),
    mitigations: normalizeMitigations(data.mitigations),
    core: {
      reachable: core.reachable !== false,
      blocked: normalizeBlocked(core.blocked_ips),
      hits: normalizeHits(core.ids_hits),
      status: normalizeStatus(core.status),
    },
  };
}
