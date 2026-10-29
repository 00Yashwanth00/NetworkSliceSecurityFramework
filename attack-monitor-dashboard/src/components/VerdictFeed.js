import React, { useState } from 'react';
import { Panel, Empty, VerdictBadge, ScoreBar, IpCell } from './ui';
import { VERDICT_ROWS } from '../config';
import { fmtTime, fmtDateTime } from '../utils/format';

function Path({ v }) {
  const override = v.details && v.details.verdict_override;
  return (
    <div className="path">
      <span className="tag">{v.line2 ? 'Line 1 + Line 2' : 'Line 1 only'}</span>
      {!v.packetAvailable && <span className="tag tag-muted" title="No packet-side data for this verdict">no packets</span>}
      {override && (
        <span className="tag tag-override" title="The model said NORMAL but the raw score crossed the threshold rule">
          score override
        </span>
      )}
    </div>
  );
}

function Details({ v }) {
  const d = v.details || {};
  const hasDetails = Object.keys(d).length > 0;
  return (
    <div className="expand">
      {d.verdict_override && (
        <p className="callout">
          <strong>Score override.</strong> The model verdict was {d.model_verdict || 'NORMAL'}, but the final score
          promoted it to ATTACK. <span className="muted">{d.verdict_override}</span>
        </p>
      )}
      {hasDetails ? (
        <dl className="kv">
          {d.fusion_reason && (<><dt>Fusion reason</dt><dd>{d.fusion_reason}</dd></>)}
          {d.model_verdict && (<><dt>Model verdict</dt><dd>{d.model_verdict}</dd></>)}
          {d.line2_network_prob != null && (<><dt>Line 2 network prob.</dt><dd className="mono">{Number(d.line2_network_prob).toFixed(3)}</dd></>)}
          {d.line2_packet_prob != null && (<><dt>Line 2 packet prob.</dt><dd className="mono">{Number(d.line2_packet_prob).toFixed(3)}</dd></>)}
          {d.net_flags_attack != null && (<><dt>Network flags attack</dt><dd>{String(d.net_flags_attack)}</dd></>)}
          {d.pkt_flags_attack != null && (<><dt>Packet flags attack</dt><dd>{String(d.pkt_flags_attack)}</dd></>)}
          {d.or_logic && (<><dt>Confirmation logic</dt><dd>{d.or_logic}</dd></>)}
          <dt>Escalated by Line 1</dt><dd>{v.escalated ? 'yes' : 'no'}</dd>
          <dt>Timestamp</dt><dd className="mono">{fmtDateTime(v.ts)}</dd>
        </dl>
      ) : (
        <p className="muted">No details were recorded for this verdict.</p>
      )}
      <details className="raw">
        <summary>Raw details JSON</summary>
        <pre>{JSON.stringify(d, null, 2)}</pre>
      </details>
    </div>
  );
}

export default function VerdictFeed({ verdicts, loaded, error }) {
  const [attacksOnly, setAttacksOnly] = useState(false);
  const [open, setOpen] = useState(() => new Set());

  const attackCount = verdicts.filter((v) => v.verdict === 'ATTACK').length;
  const rows = (attacksOnly ? verdicts.filter((v) => v.verdict === 'ATTACK') : verdicts).slice(0, VERDICT_ROWS);

  const toggle = (key) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <Panel
      title="Live verdicts"
      source="pipeline"
      aside={
        <label className="check">
          <input type="checkbox" checked={attacksOnly} onChange={(e) => setAttacksOnly(e.target.checked)} />
          Attacks only ({attackCount})
        </label>
      }
    >
      {!loaded ? (
        <Empty>Loading verdicts…</Empty>
      ) : rows.length === 0 ? (
        <Empty>
          {error && verdicts.length === 0
            ? 'Verdicts will appear once the backend is reachable.'
            : attacksOnly
            ? 'No attack verdicts in the current window.'
            : 'No verdicts yet. They appear as inference_service publishes to the verdicts stream.'}
        </Empty>
      ) : (
        <div className="table-wrap scroll-y feed-scroll">
          <table className="table verdict-table">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Verdict</th>
                <th scope="col">Final score</th>
                <th scope="col">Line 1 network</th>
                <th scope="col">Line 1 packet</th>
                <th scope="col">Path</th>
                <th scope="col">Session</th>
                <th scope="col">Source IP</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v) => {
                const isOpen = open.has(v.key);
                return (
                  <React.Fragment key={v.key}>
                    <tr className={`row-main ${v.verdict === 'ATTACK' ? 'row-attack' : ''} ${isOpen ? 'is-open' : ''}`}>
                      <td className="mono nowrap">
                        <button
                          type="button"
                          className="expander"
                          aria-expanded={isOpen}
                          aria-label={`${isOpen ? 'Hide' : 'Show'} details for verdict at ${fmtTime(v.ts)}`}
                          onClick={() => toggle(v.key)}
                        >
                          <span className="caret" aria-hidden="true">{isOpen ? '▾' : '▸'}</span>
                          {fmtTime(v.ts)}
                        </button>
                      </td>
                      <td><VerdictBadge verdict={v.verdict} /></td>
                      <td className="score-cell"><ScoreBar value={v.finalScore} label="Final score" /></td>
                      <td className="score-cell"><ScoreBar value={v.netScore} compact label="Line 1 network score" /></td>
                      <td className="score-cell"><ScoreBar value={v.pktScore} compact label="Line 1 packet score" /></td>
                      <td><Path v={v} /></td>
                      <td className="mono">{v.sessionKey || '–'}</td>
                      <td><IpCell ip={v.srcIp} /></td>
                    </tr>
                    {isOpen && (
                      <tr className="row-expand">
                        <td colSpan={8}><Details v={v} /></td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
