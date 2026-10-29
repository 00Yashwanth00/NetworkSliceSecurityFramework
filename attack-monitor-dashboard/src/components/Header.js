import React from 'react';
import { fmtTime } from '../utils/format';

function Pulse({ label, ok, detail, kind }) {
  return (
    <div className={`pulse pulse-${kind} ${ok ? 'ok' : 'down'}`}>
      <span className="pulse-dot" aria-hidden="true" />
      <div>
        <div className="pulse-label">{label}</div>
        <div className="pulse-detail">{detail}</div>
      </div>
    </div>
  );
}

export default function Header({ dash, extras, coreReachable }) {
  const pipelineOk = dash.loaded && !dash.error;
  let pipelineDetail = 'Connecting…';
  if (dash.loaded && pipelineOk) pipelineDetail = `Updated ${fmtTime(dash.lastUpdated)}`;
  if (dash.error) pipelineDetail = `Offline, retrying in ${Math.round(dash.nextDelayMs / 1000)}s`;

  const coreKnown = dash.data != null;
  const coreOk = coreKnown && coreReachable && !(extras.loaded && extras.error && !extras.data);
  let coreDetail = 'Waiting for pipeline';
  if (coreKnown) coreDetail = coreOk ? 'Reachable' : 'Unreachable, actions are advisory only';

  return (
    <header className="app-header">
      <div className="title-block">
        <h1>5G attack monitor</h1>
        <p>What was detected, what we did about it, and what mmt-core actually enforced.</p>
      </div>
      <div className="pulses">
        <Pulse kind="pipeline" label="Pipeline (Redis)" ok={pipelineOk} detail={pipelineDetail} />
        <Pulse kind="core" label="mmt-core" ok={coreOk} detail={coreDetail} />
      </div>
    </header>
  );
}
