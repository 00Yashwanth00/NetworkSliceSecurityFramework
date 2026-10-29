import React from 'react';
import { Panel, Empty, IpCell } from './ui';
import { fmtDateTime, fmtDuration, fmtTime, fmtAge } from '../utils/format';
import { RATE_LIMIT_SIGNATURE, approxRecentSignals, deriveState, tripRecords } from '../utils/rateLimit';

function Counter({ label, value, note, strong }) {
  return (
    <div className={`rl-counter ${strong ? 'rl-counter-strong' : ''}`}>
      <div className="rl-counter-label">{label}</div>
      <div className="rl-counter-value mono">{value == null ? '?' : value}</div>
      <p className="muted rl-counter-note">{note}</p>
    </div>
  );
}

export default function RateLimitProof({ limits, signatures, audit, mitigations, coreReachable, flash }) {
  const name = RATE_LIMIT_SIGNATURE;
  const signature = (signatures || []).find((s) => s.name === name) || null;
  const state = deriveState({ coreReachable, limits, signature });

  const hits = limits.hits[name];
  const alert = limits.alerts[name];
  const trips = limits.alertsKnown ? (alert ? alert.count : 0) : null;
  const records = tripRecords(audit, name);
  const approx = signature ? approxRecentSignals(mitigations, signature.windowS) : null;

  return (
    <Panel title="Rate limiter proof" source="core" className={`rl rl-${state.id}`}>
      {flash && (
        <div className="rl-flash" role="status">
          <strong>New trip.</strong> mmt-core's trip counter rose by {flash.delta}. The closest Rate Limit Signal row in
          the mitigation feed is highlighted.
        </div>
      )}

      <div className="rl-state">
        <span className={`rl-state-badge rl-badge-${state.id}`}>{state.label}</span>
        <p>{state.text}</p>
      </div>

      <div className="rl-counters">
        <Counter label="Hits" value={limits.available ? (hits ? hits.count : 0) : null} note="Every call we made to mmt-core's IDS, tripped or not. Not proof on its own." />
        <Counter label="Trips" value={trips} strong note="Only increases when the threshold is crossed. Trips above 0 means the limiter fired." />
        <div className="rl-counter">
          <div className="rl-counter-label">Last tripped</div>
          {alert && alert.lastHit != null ? (
            <>
              <div className="rl-counter-value rl-when mono">{fmtTime(alert.lastHit)}</div>
              <p className="muted rl-counter-note">
                {fmtAge(alert.lastHit)} · for <IpCell ip={alert.lastIp} />
              </p>
            </>
          ) : (
            <>
              <div className="rl-counter-value rl-when muted">Never</div>
              <p className="muted rl-counter-note">No trip recorded since mmt-core started.</p>
            </>
          )}
        </div>
        <div className="rl-counter">
          <div className="rl-counter-label">Signature</div>
          {signature ? (
            <>
              <div className="rl-counter-value rl-when mono">{signature.threshold} in {signature.windowS}s</div>
              <p className="muted rl-counter-note">
                Trips at {signature.threshold} hits within {signature.windowS}s
                {signature.autoBlockTtlS != null && ` · auto-block ${signature.autoBlockTtlS === 0 ? 'permanent' : fmtDuration(signature.autoBlockTtlS)}`}
              </p>
            </>
          ) : (
            <>
              <div className="rl-counter-value rl-when muted">Unknown</div>
              <p className="muted rl-counter-note">{signatures ? `${name} is not in the registered signatures.` : 'Signature list not loaded.'}</p>
            </>
          )}
        </div>
      </div>

      <p className="muted rl-caveat">
        Hits and Trips are lifetime totals since mmt-core started or its counters were last reset. They do not show the current
        window, and mmt-core exposes no live progress toward the threshold.
      </p>

      {approx != null && (
        <p className="rl-approx">
          <span className="tag tag-muted">approximate</span> Our pipeline sent {approx} applied rate-limit {approx === 1 ? 'signal' : 'signals'} in
          the last {signature.windowS}s. This comes from our own Redis stream, not mmt-core's internal window.
        </p>
      )}

      <h3>Trip records from mmt-core's audit log</h3>
      {audit == null ? (
        <Empty>The audit log couldn't be loaded, so individual trips can't be listed.</Empty>
      ) : records.length === 0 ? (
        <Empty>
          {trips > 0
            ? 'No trip records in the latest audit events. They may be older than the events loaded here.'
            : 'No INTRUSION_DETECTED events for this signature in the latest audit events.'}
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Tripped at</th>
                <th scope="col">Source IP</th>
                <th scope="col">Count / threshold</th>
                <th scope="col">Window</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.key}>
                  <td className="mono nowrap">{fmtDateTime(r.ts)}</td>
                  <td><IpCell ip={r.ip} /></td>
                  <td className="mono">{r.count != null ? r.count : '–'} / {r.threshold != null ? r.threshold : '–'}</td>
                  <td className="mono">{r.windowS != null ? `${r.windowS}s` : '–'}</td>
                  <td className="detail-cell">{r.detail || <span className="muted">–</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
