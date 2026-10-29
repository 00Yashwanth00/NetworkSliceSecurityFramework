import React, { useMemo } from 'react';
import Header from './components/Header';
import StatusStrip from './components/StatusStrip';
import RateLimitProof from './components/RateLimitProof';
import VerdictFeed from './components/VerdictFeed';
import MitigationFeed from './components/MitigationFeed';
import CorePanel from './components/CorePanel';
import Correlation from './components/Correlation';
import usePolling from './hooks/usePolling';
import useTripWatch from './hooks/useTripWatch';
import { fetchDashboard, fetchCoreExtras } from './api/client';
import { normalizeDashboard, normalizeAudit, normalizeSignatures } from './utils/normalize';
import { buildLimits, nearestSignal, RATE_LIMIT_SIGNATURE } from './utils/rateLimit';
import { POLL_MS, MAX_BACKOFF_MS } from './config';
import EscalationChart from './components/EscalationChart';

const NONE = []; // stable reference so memo hooks don't re-run on every render
const EMPTY_CORE = {
  reachable: true,
  blocked: [],
  hits: {},
  status: { available: false, summary: null, rules: [], alerts: [], blockedSources: [], severityCounts: [] },
};

export default function App() {
  const dash = usePolling(fetchDashboard, { intervalMs: POLL_MS, maxIntervalMs: MAX_BACKOFF_MS });
  const extras = usePolling(fetchCoreExtras, { intervalMs: POLL_MS, maxIntervalMs: MAX_BACKOFF_MS });

  const model = useMemo(() => normalizeDashboard(dash.data), [dash.data]);
  const audit = useMemo(() => (extras.data && extras.data.audit ? normalizeAudit(extras.data.audit) : null), [extras.data]);
  const signatures = useMemo(() => (extras.data && extras.data.signatures ? normalizeSignatures(extras.data.signatures) : null), [extras.data]);

  // Live /ids/hits first (hits + alerts); fall back to the bundled snapshot from /api/dashboard-data.
  const limits = useMemo(
    () => buildLimits(extras.data && extras.data.idsHits, dash.data && dash.data.core && dash.data.core.ids_hits),
    [extras.data, dash.data]
  );

  const verdicts = model ? model.verdicts : NONE;
  const mitigations = model ? model.mitigations : NONE;
  const core = model ? model.core : EMPTY_CORE;

  const trips = limits.alertsKnown ? (limits.alerts[RATE_LIMIT_SIGNATURE] ? limits.alerts[RATE_LIMIT_SIGNATURE].count : 0) : null;
  const lastTrip = limits.alerts[RATE_LIMIT_SIGNATURE] ? limits.alerts[RATE_LIMIT_SIGNATURE].lastHit : null;
  const flash = useTripWatch(trips, lastTrip);
  const highlightKey = useMemo(() => {
    const row = flash ? nearestSignal(mitigations, flash.target) : null;
    return row ? row.key : null;
  }, [flash, mitigations]);

  return (
    <div className="app">
      <Header dash={dash} extras={extras} coreReachable={core.reachable} />

      {dash.error && (
        <div className="banner banner-error" role="alert">
          <strong>{dash.data ? 'Showing the last good data.' : "Can't reach the dashboard backend."}</strong>{' '}
          {dash.error.message}. Check that the backend is running (<span className="mono">mitigation_dashboard.py</span> on :8787, or{' '}
          <span className="mono">npm run mock</span>). Retrying in {Math.round(dash.nextDelayMs / 1000)}s.
        </div>
      )}
      {model && !core.reachable && (
        <div className="banner banner-warn" role="status">
          <strong>mmt-core is unreachable.</strong> New mitigation actions will show as Recommended: they are advisory and nothing is being enforced.
        </div>
      )}

      <main>
        <StatusStrip core={core} limits={limits} signatures={signatures} />
        <RateLimitProof
          limits={limits}
          signatures={signatures}
          audit={audit}
          mitigations={mitigations}
          coreReachable={core.reachable}
          flash={flash}
        />
        <VerdictFeed verdicts={verdicts} loaded={dash.loaded} error={dash.error} />
        <div className="split">
          <MitigationFeed
            mitigations={mitigations}
            loaded={dash.loaded}
            blocked={core.blocked}
            coreReachable={core.reachable}
            highlightKey={highlightKey}
          />
          <CorePanel core={core} limits={limits} audit={audit} signatures={signatures} />
        </div>
        <EscalationChart mitigations={mitigations} />
        <Correlation verdicts={verdicts} mitigations={mitigations} audit={audit} />
      </main>
    </div>
  );
}
