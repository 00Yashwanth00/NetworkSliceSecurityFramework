import { API_BASE, AUDIT_LIMIT } from '../config';

async function getJson(path, signal, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const forward = () => ctrl.abort();
  if (signal) signal.addEventListener('abort', forward);
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(API_BASE + path, {
      signal: ctrl.signal,
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${path}`);
    return await res.json();
  } catch (err) {
    if (err.name === 'AbortError') throw new Error(`Request to ${path} timed out`);
    throw err;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', forward);
  }
}

// Option A backend: one call bundles verdicts, mitigations and a core snapshot.
export function fetchDashboard(signal) {
  return getJson('/api/dashboard-data', signal);
}

// Extra mmt-core data the bundled call does not include (audit log + IDS signatures).
// Each part may fail on its own; we only throw (and trigger backoff) if both fail.
export async function fetchCoreExtras(signal) {
  const [audit, sigs, hits] = await Promise.allSettled([
    getJson(`/api/security/audit?limit=${AUDIT_LIMIT}`, signal),
    getJson('/api/security/ids/signatures', signal),
    getJson('/api/security/ids/hits', signal), // hits (all calls) + alerts (real trips), spec 3.6
  ]);
  if ([audit, sigs, hits].every((r) => r.status === 'rejected')) throw audit.reason;
  const val = (r) => (r.status === 'fulfilled' ? r.value : null);
  return { audit: val(audit), signatures: val(sigs), idsHits: val(hits) };
}
