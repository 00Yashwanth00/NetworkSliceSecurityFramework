import React, { useMemo } from 'react';
import { Panel, Empty } from './ui';
import { fmtTime } from '../utils/format';

// Deliberately not reusing --attack/--applied/--recommended here: those
// already carry specific meaning elsewhere (verdict severity, applied vs
// recommended). This is a plain categorical palette, one color per source IP.
const SERIES_COLORS = ['#6fa8ff', '#ff6161', '#2fd28d', '#f3a93c', '#b793ff', '#58c4a0'];
const MAX_SERIES = 6; // cap so a future multi-IP environment doesn't render an unreadable chart

const WIDTH = 640;
const HEIGHT = 220;
const PAD = { top: 16, right: 16, bottom: 10, left: 28 };

// offense_count only lives on ip_quarantine / repeat_offender_escalation rows
// (see mitigation.py _strategy_quarantine) — rate_limit_signal and audit_sync
// rows never carry it.
const OFFENSE_ACTIONS = new Set(['ip_quarantine', 'repeat_offender_escalation']);

function buildSeries(mitigations) {
  const bySrc = new Map();
  for (const row of mitigations) {
    if (!OFFENSE_ACTIONS.has(row.action)) continue;
    const count = row.extra.offense_count;
    if (count == null || row.ts == null) continue;
    const key = row.srcIp || '(no IP)';
    if (!bySrc.has(key)) bySrc.set(key, []);
    bySrc.get(key).push({ ts: row.ts, count: Number(count), applied: row.applied });
  }
  const series = [...bySrc.entries()].map(([srcIp, points]) => {
    points.sort((a, b) => a.ts - b.ts);
    return { srcIp, points, latest: points[points.length - 1].count };
  });
  // Busiest offenders first, then cap — not just newest-first, so a
  // currently-escalating IP doesn't get crowded out by a one-off.
  series.sort((a, b) => b.latest - a.latest);
  return series.slice(0, MAX_SERIES);
}

function buildScales(series) {
  let minTs = Infinity;
  let maxTs = -Infinity;
  let maxCount = 1;
  series.forEach((s) =>
    s.points.forEach((p) => {
      if (p.ts < minTs) minTs = p.ts;
      if (p.ts > maxTs) maxTs = p.ts;
      if (p.count > maxCount) maxCount = p.count;
    })
  );
  if (!Number.isFinite(minTs)) {
    minTs = 0;
    maxTs = 1;
  }
  if (maxTs === minTs) maxTs = minTs + 1; // avoid a divide-by-zero with a single point
  const innerW = WIDTH - PAD.left - PAD.right;
  const innerH = HEIGHT - PAD.top - PAD.bottom;
  const x = (ts) => PAD.left + ((ts - minTs) / (maxTs - minTs)) * innerW;
  const y = (count) => PAD.top + innerH - (count / maxCount) * innerH;
  return { x, y, maxCount };
}

function yTicks(maxCount) {
  const step = maxCount <= 5 ? 1 : Math.ceil(maxCount / 5);
  const ticks = [];
  for (let v = 0; v <= maxCount; v += step) ticks.push(v);
  if (ticks[ticks.length - 1] !== maxCount) ticks.push(maxCount);
  return ticks;
}

function SeriesPath({ s, color, x, y }) {
  const path = s.points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.ts).toFixed(1)},${y(p.count).toFixed(1)}`).join(' ');
  return (
    <g>
      <path d={path} fill="none" stroke={color} strokeWidth="2" opacity="0.9" />
      {s.points.map((p, i) => (
        // Filled dot = this escalation was actually applied to mmt-core.
        // Hollow dot = recommended only (mmt-core was unreachable at the time) —
        // same visual language AppliedBadge uses elsewhere in this app.
        <circle
          key={i}
          cx={x(p.ts)}
          cy={y(p.count)}
          r={p.applied ? 3.5 : 3}
          fill={p.applied ? color : 'var(--panel-2)'}
          stroke={color}
          strokeWidth={p.applied ? 0 : 1.5}
        >
          <title>{`${s.srcIp} — offense #${p.count} at ${fmtTime(p.ts)} (${p.applied ? 'applied' : 'recommended'})`}</title>
        </circle>
      ))}
    </g>
  );
}

export default function EscalationChart({ mitigations }) {
  const series = useMemo(() => buildSeries(mitigations), [mitigations]);

  if (series.length === 0) {
    return (
      <Panel title="Offender escalation" source="pipeline">
        <Empty>
          No escalation activity yet. This fills in once a source IP is quarantined more than once in the
          same window (strategy 3 — repeat-offender escalation).
        </Empty>
      </Panel>
    );
  }

  const { x, y, maxCount } = buildScales(series);
  const ticks = yTicks(maxCount);

  return (
    <Panel title="Offender escalation" source="pipeline" aside={<span className="muted">offense # over time, per source IP</span>}>
      <div className="escalation-chart-wrap">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="escalation-chart"
          role="img"
          aria-label="Offender escalation count over time, per source IP"
        >
          {ticks.map((t) => (
            <g key={t}>
              <line x1={PAD.left} x2={WIDTH - PAD.right} y1={y(t)} y2={y(t)} className="esc-grid" />
              <text x={PAD.left - 6} y={y(t)} className="esc-axis-label" textAnchor="end" dominantBaseline="middle">
                {t}
              </text>
            </g>
          ))}
          {series.map((s, i) => (
            <SeriesPath key={s.srcIp} s={s} color={SERIES_COLORS[i % SERIES_COLORS.length]} x={x} y={y} />
          ))}
        </svg>
        <ul className="escalation-legend">
          {series.map((s, i) => (
            <li key={s.srcIp}>
              <span className="esc-swatch" style={{ background: SERIES_COLORS[i % SERIES_COLORS.length] }} />
              <span className="mono">{s.srcIp}</span>
              <span className="muted">— currently offense #{s.latest}</span>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}
