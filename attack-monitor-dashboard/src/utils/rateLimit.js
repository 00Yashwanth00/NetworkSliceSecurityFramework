// Rate-limit proof logic (DASHBOARD_SPEC section 3.6). Kept free of React so it is easy to test.
//
// Two different counters come from GET /api/security/ids/hits:
//   hits[sig].count   - every call made to /ids/test, tripped or not  ("Hits", raw lifetime calls)
//   alerts[sig].count - only when the threshold was crossed           ("Trips", the real proof)
// Both are cumulative since mmt-core started (or the last hits reset). Neither is the live window.
import { toNum, toMs } from './normalize';

export const RATE_LIMIT_SIGNATURE = 'ML_PIPELINE_ATTACK';

function counterMap(obj) {
  const out = {};
  if (!obj || typeof obj !== 'object') return out;
  Object.entries(obj).forEach(([name, c]) => {
    if (c && typeof c === 'object') {
      out[name] = { count: toNum(c.count), lastIp: c.last_ip || '', lastHit: toMs(c.last_hit) };
    }
  });
  return out;
}

// Accepts the first usable source: the live /ids/hits response, then the bundled core.ids_hits.
// alertsKnown=false means the source had no `alerts` section, so "0 trips" would be a guess.
export function buildLimits(...sources) {
  for (const src of sources) {
    if (!src || typeof src !== 'object') continue;
    const hasHits = src.hits && typeof src.hits === 'object';
    const hasAlerts = src.alerts && typeof src.alerts === 'object';
    if (hasHits || hasAlerts) {
      return { available: true, alertsKnown: !!hasAlerts, hits: counterMap(src.hits), alerts: counterMap(src.alerts) };
    }
    const flat = counterMap(src); // older shape: { sig: {count,...} } meaning hits only
    if (Object.keys(flat).length) return { available: true, alertsKnown: false, hits: flat, alerts: {} };
  }
  return { available: false, alertsKnown: false, hits: {}, alerts: {} };
}

// One row per INTRUSION_DETECTED audit event for this signature: mmt-core's own record of a trip.
export function tripRecords(audit, signature = RATE_LIMIT_SIGNATURE) {
  return (audit || [])
    .filter((e) => e.eventType === 'INTRUSION_DETECTED' && e.extra && e.extra.signature === signature)
    .map((e) => ({
      key: e.key,
      ts: e.ts,
      ip: e.sourceIp,
      count: e.extra.count ?? null,
      threshold: e.extra.threshold ?? null,
      windowS: e.extra.window_s ?? null,
      detail: e.detail,
    }));
}

// APPROXIMATE only: our own Redis stream's call history, not mmt-core's internal bucket.
export function approxRecentSignals(mitigations, windowS, now = Date.now()) {
  if (!windowS) return null;
  return (mitigations || []).filter((m) => m.action === 'rate_limit_signal' && m.applied && m.ts != null && m.ts >= now - windowS * 1000).length;
}

// The rate_limit_signal row closest in time to a trip, if one is near enough to be plausible.
export function nearestSignal(mitigations, targetMs, maxGapMs = 30000) {
  let best = null;
  let bestGap = Infinity;
  (mitigations || []).forEach((m) => {
    if (m.action !== 'rate_limit_signal' || m.ts == null) return;
    const gap = Math.abs(m.ts - targetMs);
    if (gap < bestGap) { best = m; bestGap = gap; }
  });
  return best && bestGap <= maxGapMs ? best : null;
}

// Field-driven state: decided from counters, never from reading detail text.
export function deriveState({ coreReachable, limits, signature, signatureName = RATE_LIMIT_SIGNATURE }) {
  if (!coreReachable || !limits.available) {
    return { id: 'unknown', label: 'Cannot read mmt-core', text: "mmt-core's hit counters aren't available, so rate limiting can't be confirmed either way." };
  }
  if (!limits.alertsKnown) {
    return { id: 'unknown', label: 'Trip counter unavailable', text: "The backend didn't return mmt-core's alerts counter, so trips can't be confirmed." };
  }
  if (signature && signature.enabled === false) {
    return { id: 'disabled', label: 'Signature disabled', text: `${signatureName} is registered but disabled, so it can never trip.` };
  }
  const hits = limits.hits[signatureName] ? limits.hits[signatureName].count : 0;
  const trips = limits.alerts[signatureName] ? limits.alerts[signatureName].count : 0;
  if (trips > 0) return { id: 'tripped', label: 'Rate limiter has tripped', text: `mmt-core's own trip counter is ${trips}. It only increases when the threshold is crossed, so the limiter fired.` };
  if (hits > 0) return { id: 'signals', label: 'Signals received, no trip yet', text: 'mmt-core is receiving our signals but the threshold has not been crossed. That is expected until enough hits land inside one window.' };
  return { id: 'idle', label: 'No signals received yet', text: 'mmt-core has not counted any calls for this signature since it started.' };
}
