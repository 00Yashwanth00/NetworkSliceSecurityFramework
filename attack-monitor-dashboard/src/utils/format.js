const pad = (n) => String(n).padStart(2, '0');

export function fmtTime(ms) {
  if (ms == null) return '–';
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function fmtDateTime(ms) {
  if (ms == null) return '–';
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(ms)}`;
}

export function fmtDuration(totalSec) {
  const s = Math.max(0, Math.round(totalSec));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const m = Math.round((s % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  return `${Math.round(s / 86400)}d`;
}

// ttl_s of 0 means permanent (spec 3.3)
export function fmtTtl(ttlSec) {
  if (ttlSec == null) return null;
  return Number(ttlSec) === 0 ? 'permanent' : fmtDuration(Number(ttlSec));
}

export function fmtScore(score) {
  return Number.isFinite(score) ? score.toFixed(3) : '–';
}

export function fmtAge(ms, now = Date.now()) {
  if (ms == null) return '–';
  const diff = Math.round((now - ms) / 1000);
  if (diff < 5) return 'just now';
  return `${fmtDuration(diff)} ago`;
}

export const ACTION_LABELS = {
  ip_quarantine: 'IP Quarantine',
  rate_limit_signal: 'Rate Limit Signal',
  repeat_offender_escalation: 'Escalation (Repeat Offender)',
  audit_sync: 'Audit Sync',
};

export const actionLabel = (action) => ACTION_LABELS[action] || action || 'Unknown action';
