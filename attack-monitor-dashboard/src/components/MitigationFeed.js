import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Panel, Empty, AppliedBadge, IpCell, Chip } from './ui';
import { actionLabel, fmtTime, fmtTtl } from '../utils/format';

const BLOCKING_ACTIONS = new Set(['ip_quarantine', 'repeat_offender_escalation']);

function CoreCheck({ row, blockedIps, coreReachable }) {
  // Cross-check "we say APPLIED" against mmt-core's real block list.
  if (!BLOCKING_ACTIONS.has(row.action) || !row.applied || !row.srcIp || !coreReachable) return null;
  return blockedIps.has(row.srcIp) ? (
    <span className="tag tag-ok" title="mmt-core's block list currently contains this IP">in mmt-core block list</span>
  ) : (
    <span className="tag tag-warn" title="The block may have expired, or mmt-core may not actually have it. Check the mmt-core panel.">
      not in mmt-core block list now
    </span>
  );
}

function Row({ row, blockedIps, coreReachable, highlight }) {
  const ref = useRef(null);
  useEffect(() => {
    if (highlight && ref.current) ref.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [highlight]);
  const ttl = fmtTtl(row.extra.ttl_s);
  const offenses = row.extra.offense_count;
  return (
    <li ref={ref} className={`mit-row ${row.applied ? 'is-applied' : 'is-recommended'} ${highlight ? 'is-trip-match' : ''}`}>
      <div className="mit-top">
        <span className="mono muted nowrap">{fmtTime(row.ts)}</span>
        <span className="mit-action">{actionLabel(row.action)}</span>
        <AppliedBadge applied={row.applied} />
      </div>
      {row.detail && <p className="mit-detail">{row.detail}</p>}
      <div className="mit-meta">
        <IpCell ip={row.srcIp} />
        <span className="mono muted">score {row.finalScore.toFixed(3)}</span>
        {ttl && <span className="tag">TTL {ttl}</span>}
        {offenses != null && <span className="tag">offense #{offenses}</span>}
        <CoreCheck row={row} blockedIps={blockedIps} coreReachable={coreReachable} />
        {highlight && <span className="tag tag-trip">matches latest trip</span>}
      </div>
    </li>
  );
}

export default function MitigationFeed({ mitigations, loaded, blocked, coreReachable, highlightKey }) {
  const [filter, setFilter] = useState('all');
  const blockedIps = useMemo(() => new Set(blocked.map((b) => b.ip)), [blocked]);

  const applied = mitigations.filter((m) => m.applied).length;
  const recommended = mitigations.length - applied;
  const rows = mitigations.filter((m) => filter === 'all' || (filter === 'applied' ? m.applied : !m.applied)).slice(0, 150);

  return (
    <Panel title="Mitigation actions" source="pipeline" className="panel-tall">
      <div className="chips" role="group" aria-label="Filter by outcome">
        <Chip active={filter === 'all'} onClick={() => setFilter('all')} count={mitigations.length}>All</Chip>
        <Chip active={filter === 'applied'} onClick={() => setFilter('applied')} count={applied}>Applied</Chip>
        <Chip active={filter === 'recommended'} onClick={() => setFilter('recommended')} count={recommended}>Recommended</Chip>
      </div>
      {!loaded ? (
        <Empty>Loading mitigation actions…</Empty>
      ) : rows.length === 0 ? (
        <Empty>{mitigations.length === 0 ? 'No mitigation actions yet. Each ATTACK verdict produces 2–4 rows here.' : 'Nothing matches this filter.'}</Empty>
      ) : (
        <ul className="mit-list scroll-y">
          {rows.map((r) => (
            <Row key={r.key} row={r} blockedIps={blockedIps} coreReachable={coreReachable} highlight={r.key === highlightKey} />
          ))}
        </ul>
      )}
    </Panel>
  );
}
