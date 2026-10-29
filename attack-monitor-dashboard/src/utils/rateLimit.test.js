import { buildLimits, deriveState, tripRecords, nearestSignal, approxRecentSignals } from './rateLimit';

const SIG = 'ML_PIPELINE_ATTACK';
const live = { ok: true, hits: { [SIG]: { count: 9, last_ip: '1.1.1.1', last_hit: 1000 } }, alerts: { [SIG]: { count: 2, last_ip: '1.1.1.1', last_hit: 1000 } } };

test('buildLimits keeps hits and alerts separate', () => {
  const l = buildLimits(live);
  expect(l.hits[SIG].count).toBe(9);
  expect(l.alerts[SIG].count).toBe(2);
  expect(l.alertsKnown).toBe(true);
});

test('a hits-only source never claims zero trips', () => {
  const l = buildLimits({ [SIG]: { count: 5 } });
  expect(l.alertsKnown).toBe(false);
  expect(deriveState({ coreReachable: true, limits: l, signature: null }).id).toBe('unknown');
});

test('state is decided by trips, not hits', () => {
  const base = { coreReachable: true, signature: null };
  expect(deriveState({ ...base, limits: buildLimits(live) }).id).toBe('tripped');
  expect(deriveState({ ...base, limits: buildLimits({ hits: { [SIG]: { count: 4 } }, alerts: {} }) }).id).toBe('signals');
  expect(deriveState({ ...base, limits: buildLimits({ hits: {}, alerts: {} }) }).id).toBe('idle');
  expect(deriveState({ coreReachable: false, limits: buildLimits(live), signature: null }).id).toBe('unknown');
  expect(deriveState({ ...base, limits: buildLimits(live), signature: { enabled: false } }).id).toBe('disabled');
});

test('tripRecords only keeps INTRUSION_DETECTED for the signature', () => {
  const audit = [
    { key: 'a', ts: 1, eventType: 'INTRUSION_DETECTED', sourceIp: 'x', detail: '', extra: { signature: SIG, count: 3, threshold: 3, window_s: 60 } },
    { key: 'b', ts: 2, eventType: 'INTRUSION_DETECTED', sourceIp: 'x', detail: '', extra: { signature: 'OTHER' } },
    { key: 'c', ts: 3, eventType: 'IP_BLOCKED', sourceIp: 'x', detail: '', extra: { signature: SIG } },
  ];
  const r = tripRecords(audit);
  expect(r).toHaveLength(1);
  expect(r[0]).toMatchObject({ count: 3, threshold: 3, windowS: 60 });
});

test('nearestSignal and approxRecentSignals', () => {
  const m = [
    { key: 'far', action: 'rate_limit_signal', applied: true, ts: 1000 },
    { key: 'near', action: 'rate_limit_signal', applied: true, ts: 99000 },
    { key: 'rec', action: 'rate_limit_signal', applied: false, ts: 99500 },
    { key: 'q', action: 'ip_quarantine', applied: true, ts: 100000 },
  ];
  expect(nearestSignal(m, 100000).key).toBe('rec');
  expect(nearestSignal(m, 500000)).toBeNull();
  expect(approxRecentSignals(m, 60, 100000)).toBe(1); // only the applied one inside the window
});
