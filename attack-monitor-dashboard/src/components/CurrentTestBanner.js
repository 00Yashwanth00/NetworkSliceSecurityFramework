import React, { useEffect, useState } from 'react';
import { testTitle, TELEMETRY_INVISIBLE } from '../utils/testCatalog';

// Re-renders once a second purely to tick the elapsed-time display;
// does not trigger a fetch -- that's still driven by usePolling in App.js.
function useNowTick(active) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!active) return undefined;
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, [active]);
}

export default function CurrentTestBanner({ currentTest }) {
  useNowTick(!!currentTest);

  if (!currentTest || !currentTest.tcId) return null; // nothing running -- render nothing, not an empty banner

  const { tcId, startedAt } = currentTest;
  const title = testTitle(tcId);
  const elapsedSec = startedAt ? Math.max(0, Math.round(Date.now() / 1000 - startedAt)) : null;
  const invisible = TELEMETRY_INVISIBLE.has(tcId);

  return (
    <div className="banner banner-info" role="status">
      <strong className="mono">{tcId}</strong>
      {title ? <> — {title}</> : <span className="muted"> (not in the local test catalog — add it to testCatalog.js)</span>}
      {elapsedSec != null && <span className="muted"> · running {elapsedSec}s</span>}
      {invisible && (
        <div className="muted" style={{ marginTop: 4 }}>
          This attack is admin-API-only — it won't produce telemetry, so the Verdicts and Mitigation panels
          staying quiet during this run is expected, not a detection failure.
        </div>
      )}
    </div>
  );
}
