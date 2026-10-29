import { useEffect, useRef, useState } from 'react';

/**
 * Notices when mmt-core's trip counter (alerts[sig].count) goes up between polls.
 * Returns { delta, target } for ~10s after an increase, else null. `target` is the time of the
 * trip, used to find and highlight the matching rate_limit_signal row in the mitigation feed.
 * A counter that goes DOWN means mmt-core restarted or hits were reset: we just rebase.
 */
export default function useTripWatch(tripCount, lastTripMs) {
  const prev = useRef(null);
  const [flash, setFlash] = useState(null);

  useEffect(() => {
    if (tripCount == null) return;
    if (prev.current != null && tripCount > prev.current) {
      setFlash({ delta: tripCount - prev.current, target: lastTripMs != null ? lastTripMs : Date.now(), seen: Date.now() });
    }
    prev.current = tripCount;
  }, [tripCount, lastTripMs]);

  useEffect(() => {
    if (!flash) return undefined;
    const t = setTimeout(() => setFlash(null), 10000);
    return () => clearTimeout(t);
  }, [flash]);

  return flash;
}
