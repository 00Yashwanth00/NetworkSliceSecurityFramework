import React from 'react';
import { Panel, Empty, SeverityBadge } from './ui';
import { fmtDuration } from '../utils/format';

function BlockedCard({ blocked, status, reachable }) {
  // Prefer the status panel's blocked_sources (spec 3.1); fall back to the blocked-ips table.
  const fromStatus = status.blockedSources;
  const count = status.available ? fromStatus.length : blocked.length;
  const list = status.available
    ? fromStatus.map((b) => ({ ip: b.ip, note: b.remainingSec == null ? 'permanent' : `${fmtDuration(b.remainingSec)} left` }))
    : blocked.map((b) => ({ ip: b.ip, note: b.expiresAt == null ? 'permanent' : 'timed' }));
  return (
    <Panel title="Blocked IPs" source="core" className="card-blocked">
      {!reachable && !status.available ? (
        <Empty>mmt-core is unreachable, so the real block list is unknown.</Empty>
      ) : (
        <>
          <p className="big-number">{count}</p>
          <p className="muted">currently blocked in mmt-core</p>
          {list.length > 0 && (
            <ul className="mini-list">
              {list.slice(0, 4).map((b) => (
                <li key={b.ip}>
                  <span className="mono">{b.ip}</span>
                  <span className="muted">{b.note}</span>
                </li>
              ))}
              {list.length > 4 && <li className="muted">+{list.length - 4} more</li>}
            </ul>
          )}
        </>
      )}
    </Panel>
  );
}

function AuditCard({ status }) {
  const rows = status.severityCounts;
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <Panel title="Audit events, last 24h" source="core" className="card-audit">
      {!status.available || rows.length === 0 ? (
        <Empty>No audit summary available yet.</Empty>
      ) : (
        <ul className="sev-bars">
          {rows.map((r) => (
            <li key={r.severity}>
              <SeverityBadge severity={r.severity} />
              <div className="sev-track">
                <div className={`sev-fill sev-fill-${r.severity.toLowerCase()}`} style={{ width: `${(r.count / max) * 100}%` }} />
              </div>
              <span className="mono sev-count">{r.count}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function SignatureCard({ status, limits, signatures }) {
  const names = signatures && signatures.length ? signatures.map((s) => s.name) : status.rules.map((r) => (typeof r === 'string' ? r : r.name)).filter(Boolean);
  const unique = Array.from(new Set([...names, ...Object.keys(limits.hits), ...Object.keys(limits.alerts)]));
  return (
    <Panel title="IDS signatures" source="core" className="card-sigs">
      {unique.length === 0 ? (
        <Empty>No IDS signatures reported.</Empty>
      ) : (
        <ul className="mini-list">
          {unique.map((name) => (
            <li key={name}>
              <span className="mono">{name}</span>
              <span className="muted" title="Hits = every call to the IDS. Trips = threshold actually crossed (the real proof).">
                {limits.hits[name] ? limits.hits[name].count : 0} hits ·{' '}
                <strong className="trips">{limits.alertsKnown ? (limits.alerts[name] ? limits.alerts[name].count : 0) : '?'} trips</strong>
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function StatusStrip({ core, limits, signatures }) {
  return (
    <div className="status-strip">
      <BlockedCard blocked={core.blocked} status={core.status} reachable={core.reachable} />
      <AuditCard status={core.status} />
      <SignatureCard status={core.status} limits={limits} signatures={signatures} />
    </div>
  );
}
