import React, { useMemo } from 'react';
import { Panel, Empty, AppliedBadge, SourceTag, VerdictBadge, SeverityBadge } from './ui';
import { actionLabel, fmtTime, fmtScore } from '../utils/format';

// Stretch goal (spec 3.5): verdict -> our mitigation call -> mmt-core's own logged response,
// joined on src_ip + nearby timestamps. Joins are heuristic, so the UI says so.
const MIT_WINDOW_MS = 10000;
const CORE_BEFORE_MS = 5000;
const CORE_AFTER_MS = 30000;
const CORE_TYPES = new Set(['ML_PIPELINE_VERDICT', 'IP_BLOCKED', 'IP_BLOCKED_TTL', 'INTRUSION_DETECTED', 'IP_UNBLOCKED']);

export default function Correlation({ verdicts, mitigations, audit }) {
  const attacks = useMemo(() => {
    return verdicts
      .filter((v) => v.verdict === 'ATTACK' && v.ts != null)
      .slice(0, 5)
      .map((v) => {
        const mits = mitigations
          .filter((m) => m.ts != null && Math.abs(m.ts - v.ts) <= MIT_WINDOW_MS && m.srcIp === v.srcIp && m.sessionKey === v.sessionKey)
          .sort((a, b) => a.ts - b.ts);
        const coreEvents = (audit || [])
          .filter((e) => e.ts != null && CORE_TYPES.has(e.eventType) && e.ts >= v.ts - CORE_BEFORE_MS && e.ts <= v.ts + CORE_AFTER_MS)
          .filter((e) => !v.srcIp || !e.sourceIp || e.sourceIp === v.srcIp)
          .sort((a, b) => a.ts - b.ts);
        return { v, mits, coreEvents };
      });
  }, [verdicts, mitigations, audit]);

  return (
    <Panel title="Attack timelines" aside={<span className="muted">Matched by source IP and time (best effort)</span>}>
      {attacks.length === 0 ? (
        <Empty>No attack verdicts to correlate yet.</Empty>
      ) : (
        <div className="timelines">
          {attacks.map(({ v, mits, coreEvents }) => (
            <article className="timeline" key={v.key}>
              <header>
                <VerdictBadge verdict={v.verdict} />
                <span className="mono">{fmtTime(v.ts)}</span>
                <span className="mono muted">score {fmtScore(v.finalScore)}</span>
                <span className="mono">{v.srcIp || <span className="no-ip">no IP available</span>}</span>
              </header>
              <ol>
                {mits.map((m) => (
                  <li key={m.key} className="tl-step tl-pipeline">
                    <span className="mono muted">{fmtTime(m.ts)}</span>
                    <SourceTag source="pipeline" />
                    <span>{actionLabel(m.action)}</span>
                    <AppliedBadge applied={m.applied} />
                  </li>
                ))}
                {mits.length === 0 && <li className="tl-step muted">No pipeline mitigation rows found for this verdict.</li>}
                {coreEvents.map((e) => (
                  <li key={e.key} className="tl-step tl-core">
                    <span className="mono muted">{fmtTime(e.ts)}</span>
                    <SourceTag source="core" />
                    <span className="mono">{e.eventType}</span>
                    <SeverityBadge severity={e.severity} />
                  </li>
                ))}
                {coreEvents.length === 0 && <li className="tl-step muted">mmt-core logged nothing for this IP in the matching window.</li>}
              </ol>
            </article>
          ))}
        </div>
      )}
    </Panel>
  );
}
