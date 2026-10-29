import React from 'react';
import { SCORE_THRESHOLD } from '../config';
import { fmtScore } from '../utils/format';

export function VerdictBadge({ verdict }) {
  const attack = verdict === 'ATTACK';
  return <span className={`badge verdict ${attack ? 'is-attack' : 'is-normal'}`}>{attack ? 'Attack' : 'Normal'}</span>;
}

// The single most important visual in the dashboard (spec 3.3):
// Applied = solid green, filled. Recommended = amber hatched outline ("this did not happen").
export function AppliedBadge({ applied }) {
  return applied ? (
    <span className="badge applied" title="mmt-core accepted this action: it was enforced">
      <span aria-hidden="true">✓</span> Applied
    </span>
  ) : (
    <span className="badge recommended" title="Advisory only: mmt-core was not reached or no IP was available, so nothing was enforced">
      <span aria-hidden="true">!</span> Recommended
    </span>
  );
}

export function SeverityBadge({ severity }) {
  return <span className={`badge sev sev-${String(severity).toLowerCase()}`}>{severity}</span>;
}

export function SourceTag({ source }) {
  return source === 'core' ? (
    <span className="source-tag source-core">mmt-core</span>
  ) : (
    <span className="source-tag source-pipeline">Pipeline (Redis)</span>
  );
}

export function IpCell({ ip }) {
  return ip ? <span className="mono">{ip}</span> : <span className="no-ip" title="Packet-side telemetry was not available, so no source IP was recorded">no IP available</span>;
}

// 0–1 bar with a tick at the decision threshold.
export function ScoreBar({ value, compact = false, label }) {
  const v = Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));
  const over = v >= SCORE_THRESHOLD;
  return (
    <div className={`score ${compact ? 'compact' : ''}`} role="img" aria-label={`${label || 'Score'} ${fmtScore(value)}${over ? ', above threshold' : ''}`}>
      <div className="score-track">
        <div className={`score-fill ${over ? 'over' : 'under'}`} style={{ width: `${v * 100}%` }} />
        <div className="score-tick" style={{ left: `${SCORE_THRESHOLD * 100}%` }} />
      </div>
      <span className={`score-num mono ${over ? 'over' : ''}`}>{fmtScore(value)}</span>
    </div>
  );
}

export function Chip({ active, onClick, children, count }) {
  return (
    <button type="button" className={`chip ${active ? 'active' : ''}`} aria-pressed={active} onClick={onClick}>
      {children}
      {count != null && <span className="chip-count">{count}</span>}
    </button>
  );
}

export function Panel({ title, source, aside, children, className = '' }) {
  return (
    <section className={`panel ${source ? `panel-${source}` : ''} ${className}`}>
      <header className="panel-head">
        <h2>{title}</h2>
        {source && <SourceTag source={source} />}
        {aside && <div className="panel-aside">{aside}</div>}
      </header>
      {children}
    </section>
  );
}

export function Empty({ children }) {
  return <p className="empty">{children}</p>;
}
