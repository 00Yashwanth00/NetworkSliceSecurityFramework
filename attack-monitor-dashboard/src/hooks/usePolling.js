import { useEffect, useRef, useState } from 'react';

/**
 * Well-behaved polling (spec section 6):
 *  - chained setTimeout, so ticks can never pile up behind a slow request
 *  - in-flight guard
 *  - pauses while the tab is hidden (Page Visibility API), resumes immediately on return
 *  - exponential backoff on repeated failure, capped at maxIntervalMs
 *  - keeps the last good data while an error is showing
 */
export default function usePolling(fetcher, { intervalMs = 2500, maxIntervalMs = 30000 } = {}) {
  const [state, setState] = useState({
    data: null,
    error: null,
    lastUpdated: null,
    failures: 0,
    nextDelayMs: intervalMs,
    loaded: false,
  });
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    let timer = null;
    let stopped = false;
    let inFlight = false;
    let failures = 0;
    const controller = new AbortController();

    const delayFor = () => Math.min(intervalMs * 2 ** failures, maxIntervalMs);

    const schedule = () => {
      if (stopped) return;
      clearTimeout(timer);
      timer = setTimeout(tick, delayFor());
    };

    async function tick() {
      timer = null;
      if (stopped) return;
      if (document.hidden) return; // the visibilitychange handler restarts us
      if (inFlight) {
        schedule();
        return;
      }
      inFlight = true;
      try {
        const data = await fetcherRef.current(controller.signal);
        if (stopped) return;
        failures = 0;
        setState({ data, error: null, lastUpdated: Date.now(), failures: 0, nextDelayMs: intervalMs, loaded: true });
      } catch (err) {
        if (stopped) return;
        failures += 1;
        setState((prev) => ({ ...prev, error: err, failures, nextDelayMs: delayFor(), loaded: true }));
      } finally {
        inFlight = false;
        schedule();
      }
    }

    const onVisibility = () => {
      if (!document.hidden && timer === null && !inFlight && !stopped) tick();
    };

    document.addEventListener('visibilitychange', onVisibility);
    tick();

    return () => {
      stopped = true;
      clearTimeout(timer);
      controller.abort();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [intervalMs, maxIntervalMs]);

  return state;
}
