# 5G attack monitor – React dashboard

Frontend for the ML-driven 5G attack detection & mitigation pipeline (see `DASHBOARD_SPEC.md`).
Plain React 18 + plain CSS, `.js` files only (no JSX extension, no Vite, no Tailwind).
Built on `react-scripts` (Create React App tooling), which is the "just React" setup.

## Run it

Requires Node.js 18+ and npm.

```bash
npm install
npm start          # http://localhost:3000
```

### No backend yet? Use the mock

In a second terminal:

```bash
npm run mock       # fake pipeline backend on :8787 and fake mmt-core on :5000
```

Simulate mmt-core going down (all new mitigations flip to the amber "Recommended" state):

```bash
curl "localhost:8787/mock/core?down=1"    # outage
curl "localhost:8787/mock/core?down=0"    # recovered
```

### Against the real system

1. Start `mitigation_dashboard.py` (FastAPI, port 8787) and mmt-core (port 5000).
2. `npm start`. That's it. The dev server proxies:
   - `/api/dashboard-data` → `http://localhost:8787` (verdicts, mitigations, core snapshot)
   - `/api/security/*`     → `http://localhost:5000` (audit log + IDS signatures)

   so the browser never talks to Redis or mmt-core directly and CORS isn't an issue.
3. Different hosts/ports? `cp .env.example .env`, edit, restart `npm start`.

## Production build

```bash
npm run build      # outputs ./build
```

The proxy only exists in the dev server. In production, serve `build/` from the same origin
as your backend and route `/api/dashboard-data` and `/api/security/*` to it (reverse proxy), or
set `REACT_APP_API_BASE` at build time and enable CORS on that backend.

## What's on screen

| Spec | Component |
|---|---|
| 3.1 Status strip (blocked IPs, 24h audit by severity, IDS hits) | `StatusStrip.js` |
| 3.2 Live verdict feed, expandable `details`, score-override flag | `VerdictFeed.js` |
| 3.3 Mitigation feed, Applied vs Recommended badge, TTL/offense count | `MitigationFeed.js` |
| 3.4 mmt-core panel: blocked IPs, filterable audit log, signature thresholds | `CorePanel.js` |
| 3.5 Attack timelines (stretch goal) | `Correlation.js` |

Pipeline-sourced panels have a blue top rule, mmt-core panels a violet one, so the two sources of truth never blur together.
"Applied" mitigation rows that mmt-core's real block list doesn't contain get a "not in mmt-core block list now" flag.

## Behaviour worth knowing

- **Polling** (`hooks/usePolling.js`): ~2.5s (`REACT_APP_POLL_MS`), never overlapping requests, paused while the tab is hidden,
  exponential backoff (up to 30s) after failures, last good data kept on screen during an outage.
- **Empty `src_ip`** renders as an amber "no IP available", never a blank cell.
- **`expires_at: null`** renders as "Permanent"; `ttl_s: 0` as "permanent".
- **List keys** are built from timestamp/type/IP, never from mmt-core's audit `id` (it can reset on core restart).
- **Audit filters** (event type, severity) run client-side over the latest 50 events, since the API only supports `?limit=N`.
- The bundled `/api/dashboard-data` call doesn't include the audit log or signature definitions, so the app makes one extra
  poll for those two mmt-core endpoints. If your backend later caches and bundles them (spec section 6), you can remove that second poll in `App.js`.

## Project layout

```
src/
  index.js, App.js, styles.css, config.js, setupProxy.js
  api/client.js            fetch helpers
  hooks/usePolling.js      polling hook
  utils/normalize.js       string/JSON → typed objects
  utils/format.js          times, TTLs, labels
  components/              Header, StatusStrip, VerdictFeed, MitigationFeed, CorePanel, Correlation, ui
mock-server/server.js      zero-dependency mock backends
```

## Rate limiter proof (spec 3.6)

Panel **"Rate limiter proof"**, directly under the status strip. Everything in it is driven by counters and
audit rows from mmt-core, never by reading `detail` text.

| What you see | Source | Meaning |
|---|---|---|
| **Trips** (violet outline) | `GET /api/security/ids/hits` → `alerts[ML_PIPELINE_ATTACK].count` | Only increases when the threshold is crossed. Above 0 = the limiter really fired |
| **Hits** | same call → `hits[...]` | Every call we made to the IDS, tripped or not. Not proof on its own |
| **Last tripped** | `alerts[...].last_hit` / `.last_ip` | When and for which IP |
| **Trip records** table | `GET /api/security/audit` → `INTRUSION_DETECTED` with `extra_json.signature == ML_PIPELINE_ATTACK` | Strongest proof: mmt-core's own record of each trip, with count/threshold/window |
| "approximate" line | our `mitigation:events` | Applied rate-limit signals in the last `window_s`. Not mmt-core's real window |

There is deliberately **no progress bar toward the threshold**: mmt-core doesn't expose one.
When Trips goes up between polls, a banner appears and the matching **Rate Limit Signal** row in the mitigation feed is outlined in violet.

Try it with the mock: `curl "localhost:8787/mock/burst?n=3"` forces 3 attacks from 127.0.0.1 and trips the limiter.

New/changed files: `utils/rateLimit.js`, `utils/rateLimit.test.js`, `hooks/useTripWatch.js`, `components/RateLimitProof.js`;
edited `App.js`, `api/client.js`, `components/{StatusStrip,CorePanel,MitigationFeed}.js`, `styles.css`, `mock-server/server.js`.
