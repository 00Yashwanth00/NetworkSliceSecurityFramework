import React, { useMemo, useState } from 'react';
import { Panel, Empty, Chip, SeverityBadge, IpCell } from './ui';
import { fmtDateTime, fmtDuration, fmtTime } from '../utils/format';
import { SEVERITY_ORDER } from '../utils/normalize';

const EVENT_TYPES = ['ML_PIPELINE_VERDICT', 'IP_BLOCKED', 'IP_BLOCKED_TTL', 'INTRUSION_DETECTED'];

function BlockedTable({ blocked, reachable }) {
  if (!reachable) return <Empty>mmt-core is unreachable. The block list can't be read.</Empty>;
  if (blocked.length === 0) return <Empty>mmt-core has no blocked IPs right now.</Empty>;
  const now = Date.now();
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">IP</th>
            <th scope="col">Reason</th>
            <th scope="col">Added</th>
            <th scope="col">Expires</th>
          </tr>
        </thead>
        <tbody>
          {blocked.map((b) => (
            <tr key={b.key}>
              <td><IpCell ip={b.ip} /></td>
              <td>{b.reason || <span className="muted">–</span>}{b.addedBy && <span className="muted"> · by {b.addedBy}</span>}</td>
              <td className="mono nowrap">{fmtDateTime(b.addedAt)}</td>
              <td className="nowrap">
                {b.expiresAt == null ? (
                  <span className="tag tag-permanent">Permanent</span>
                ) : (
                  <span className="mono">
                    {fmtDateTime(b.expiresAt)} <span className="muted">({b.expiresAt > now ? `in ${fmtDuration((b.expiresAt - now) / 1000)}` : 'expired'})</span>
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditTable({ audit }) {
  const [type, setType] = useState('ALL');
  const [severity, setSeverity] = useState('ALL');

  const counts = useMemo(() => {
    const c = {};
    (audit || []).forEach((e) => { c[e.eventType] = (c[e.eventType] || 0) + 1; });
    return c;
  }, [audit]);

  if (audit == null) return <Empty>The audit log couldn't be loaded from mmt-core.</Empty>;

  // Filtering is client-side only: the API supports nothing but ?limit=N (spec 2.2).
  const rows = audit.filter((e) => (type === 'ALL' || e.eventType === type) && (severity === 'ALL' || e.severity === severity));
  const otherTypes = Object.keys(counts).filter((t) => !EVENT_TYPES.includes(t));

  return (
    <>
      <div className="filters">
        <div className="chips" role="group" aria-label="Filter by event type">
          <Chip active={type === 'ALL'} onClick={() => setType('ALL')} count={audit.length}>All</Chip>
          {EVENT_TYPES.map((t) => (
            <Chip key={t} active={type === t} onClick={() => setType(t)} count={counts[t] || 0}>{t}</Chip>
          ))}
          {otherTypes.map((t) => (
            <Chip key={t} active={type === t} onClick={() => setType(t)} count={counts[t]}>{t}</Chip>
          ))}
        </div>
        <label className="select-label">
          Severity
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="ALL">All severities</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      </div>
      {rows.length === 0 ? (
        <Empty>{audit.length === 0 ? 'The audit log is empty.' : 'No audit events match these filters.'}</Empty>
      ) : (
        <div className="table-wrap scroll-y audit-scroll">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Severity</th>
                <th scope="col">Event</th>
                <th scope="col">Source IP</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.key}>
                  <td className="mono nowrap">{fmtTime(e.ts)}</td>
                  <td><SeverityBadge severity={e.severity} /></td>
                  <td className="mono">{e.eventType}</td>
                  <td><IpCell ip={e.sourceIp} /></td>
                  <td className="detail-cell">{e.detail || <span className="muted">–</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function Signatures({ signatures, limits, rulesFallback }) {
  const list =
    signatures && signatures.length
      ? signatures
      : rulesFallback.map((r) => ({ name: typeof r === 'string' ? r : r.name, threshold: r.threshold ?? null, windowS: r.window_s ?? null, severity: r.severity || '', enabled: true })).filter((s) => s.name);
  if (list.length === 0) return <Empty>No IDS signatures reported.</Empty>;
  // Hits and Trips are lifetime counters, not the live window, so there is deliberately no progress bar.
  return (
    <ul className="sig-list">
      {list.map((s) => {
        const h = limits.hits[s.name];
        const t = limits.alerts[s.name];
        return (
          <li key={s.name} className={`sig ${s.enabled ? '' : 'is-disabled'}`}>
            <div className="sig-top">
              <span className="mono sig-name">{s.name}</span>
              {s.severity && <SeverityBadge severity={s.severity} />}
              {!s.enabled && <span className="tag tag-muted">disabled</span>}
            </div>
            <div className="sig-counts">
              <span title="Every call made to the IDS, tripped or not">Hits <strong className="mono">{h ? h.count : 0}</strong></span>
              <span title="Only increases when the threshold is crossed">Trips <strong className="mono trips">{limits.alertsKnown ? (t ? t.count : 0) : '?'}</strong></span>
            </div>
            <p className="muted sig-meta">
              {s.threshold != null && s.windowS != null ? `Trips at ${s.threshold} hits within ${s.windowS}s` : 'Threshold not reported'}
              {s.autoBlockTtlS != null && ` · auto-block ${s.autoBlockTtlS === 0 ? 'permanent' : fmtDuration(s.autoBlockTtlS)}`}
              {t && t.lastIp && ` · last tripped for ${t.lastIp}`}
            </p>
          </li>
        );
      })}
    </ul>
  );
}

export default function CorePanel({ core, limits, audit, signatures }) {
  return (
    <Panel title="mmt-core ground truth" source="core" className="panel-tall">
      <div className="core-scroll scroll-y">
        <h3>Blocked IPs</h3>
        <BlockedTable blocked={core.blocked} reachable={core.reachable} />

        <h3>IDS signatures</h3>
        <Signatures signatures={signatures} limits={limits} rulesFallback={core.status.rules} />

        <h3>Audit log <span className="muted">(latest 50)</span></h3>
        <AuditTable audit={audit} />
      </div>
    </Panel>
  );
}
