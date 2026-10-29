# Dashboard Spec — ML-Driven 5G Attack Detection & Mitigation Monitor

This document is a build spec, not code. Hand it to whatever tool/agent will
build the frontend.

---

## 1. System context (read this first)

This dashboard sits on top of an existing pipeline, already built and
verified working end to end:

1. **Detection**: `inference_service.py` consumes live 5G core telemetry
   (per-interval network KPIs + per-flow packet features) from two Redis
   Streams, scores each independently through a two-line ML defense
   (fast Line 1 scorers → Line 2 confirmation only when Line 1 escalates),
   fuses the two scores, and publishes a verdict (`NORMAL` or `ATTACK`,
   with a `final_score` 0–1, a `src_ip`, and a `session_key`) to a Redis
   Stream called `verdicts`.
2. **Mitigation**: on every `ATTACK` verdict, a `MitigationEngine`
   (`mitigation.py`) runs up to 4 response strategies against **mmt-core**
   (the actual 5G core under test, a Go service exposing a REST API on
   `:5000`) and records the outcome of each to a Redis Stream called
   `mitigation:events`:
   - **Strategy 1 — IP Quarantine**: blocks the attacker's IP via mmt-core's
     signalling firewall, TTL graduated by score.
   - **Strategy 2 — Rate Limiting**: feeds the verdict into mmt-core's own
     IDS signature engine, which independently corroborates via a sliding
     window (N hits in W seconds) and can auto-block.
   - **Strategy 3 — Repeat-Offender Escalation**: a ladder (5m → 1h → 6h →
     permanent) tracked in our own Redis, re-applied via the same quarantine
     call with a longer TTL on repeat offenses.
   - **Strategy 4 — Audit Sync**: always runs, logs every verdict into
     mmt-core's own immutable security audit trail, regardless of whether
     1–3 succeeded.
3. Every mitigation call is **best-effort**: if mmt-core is unreachable, the
   action is marked `RECOMMENDED` instead of `APPLIED`, logged locally, and
   the pipeline keeps running. This distinction (`APPLIED` vs
   `RECOMMENDED`) is central to the dashboard's purpose — it must always be
   visible, never silently collapsed into one state.

**What the dashboard is for**: give an operator one screen that answers
"what's being detected, what did we do about it, and did it actually take
effect on the real core" — pulling from both our own pipeline's state
(Redis) and mmt-core's own ground truth (its REST API), side by side, so
discrepancies between "we think we blocked it" and "mmt-core actually has
it blocked" are visible rather than hidden.

---

## 2. Data sources

There are two independent sources of truth. The dashboard must query both
and should visually distinguish them — they can disagree (and have, during
development: see §6).

### 2.1 Our own pipeline state — Redis Streams

Not directly reachable from a browser. Needs a small backend/API layer in
front of Redis (see §4). Two streams:

**`verdicts`** — every scored verdict, fields (all strings, Redis Streams
are string-typed):
```
timestamp            float (unix seconds)
session_key          string
src_ip               string (may be empty — see §6 caveat)
verdict               "NORMAL" | "ATTACK"
final_score           float 0–1
line1_network_score   float 0–1
line1_packet_score    float 0–1
line1_escalated       "0" | "1"
line2_invoked         "0" | "1"
packet_data_available "0" | "1"
details               JSON string, see shape below
```
`details` JSON shape (varies slightly by path taken):
```json
{
  "fusion_reason": "below all escalation boundaries" | "escalated: network above its own boundary" | "escalated: packet above its own boundary" | "...",
  "model_verdict": "NORMAL" | "ATTACK",
  "line2_network_prob": 0.0,
  "line2_packet_prob": 0.0,
  "net_flags_attack": false,
  "pkt_flags_attack": false,
  "or_logic": "ATTACK if either available confirmer >= threshold",
  "verdict_override": "final_score 0.xxx > 0.5 (score-threshold rule; ...)"
}
```
`verdict_override` is only present when the score-threshold rule promoted a
model-NORMAL to a final ATTACK — worth flagging distinctly in the UI (it
means the model itself said NORMAL but the raw score was high enough to
override).

**`mitigation:events`** — one row per strategy outcome per verdict (so
each ATTACK verdict produces 2–4 rows), fields:
```
timestamp     float
session_key   string
src_ip        string
final_score   float
action        "ip_quarantine" | "rate_limit_signal" | "repeat_offender_escalation" | "audit_sync"
applied       "0" | "1"   <-- THE key field: APPLIED vs RECOMMENDED
detail        string (human-readable outcome)
extra         JSON string, varies by action (e.g. {"ttl_s":3600,"offense_count":2} for quarantine)
```

### 2.2 mmt-core ground truth — REST API on `http://localhost:5000`

These are **real, already-implemented, unauthenticated** endpoints on the
5G core itself — not something the dashboard's backend needs to build,
just call.

| Method | Path | Returns |
|---|---|---|
| GET | `/api/security/status` | Aggregated panel: `summary`, `ids.alerts` (recent INTRUSION_DETECTED rows), `ids.rules` (registered signatures), `ids.blocked_sources` (`{ip: {reason, remaining_sec}}`), `rate_limiter.violations`, `gtpu` stats, `audit_summary` (24h counts by severity). **Best single call for an overview panel.** |
| GET | `/api/security/blocked-ips` | `{ok, blocked: [{ip, reason, added_at, added_by, expires_at}]}`. `expires_at: null` = permanent. |
| GET | `/api/security/audit?limit=N` | `{ok, events: [{id, event_type, severity, source_ip, imsi, detail, extra_json, created_at}]}`. **No filtering params besides `limit`** — any filtering by event_type/severity/source_ip must happen client-side. `severity` is one of `DEBUG\|INFO\|WARNING\|ERROR\|CRITICAL`. `extra_json` is a JSON string, parse it. Relevant `event_type` values you'll see from this pipeline: `ML_PIPELINE_VERDICT` (our own audit-sync writes), `IP_BLOCKED` / `IP_BLOCKED_TTL` (mmt-core logging its own block action), `INTRUSION_DETECTED` (IDS signature tripped), `IP_UNBLOCKED` (TTL expiry or manual unblock). |
| GET | `/api/security/ids/hits` | `{ok, hits: {signature_name: {count, last_ip, last_hit}}, alerts: {...}}` — current sliding-window hit counters. |
| GET | `/api/security/ids/signatures` | `{ok, signatures: [{name, pattern, severity, threshold, window_s, enabled, auto_block_ttl_s}]}` — confirms the `ML_PIPELINE_ATTACK` signature is registered. |

No GET endpoint supports pagination beyond `limit` (no cursor/offset) — for
a real "load more" you'd need to track `id`/`created_at` client-side and
request a larger `limit`, there's no server-side cursor.

---

## 3. Required views

### 3.1 Overview / status strip (top of page)
Single `GET /api/security/status` call. Show:
- Count of currently blocked IPs (`ids.blocked_sources` length)
- 24h audit event counts by severity (`audit_summary`) — good for a small bar/donut
- Registered IDS signature(s) and their current hit count

### 3.2 Live verdict feed
From `verdicts` stream (our backend), newest-first, auto-refreshing (poll
every 2–3s is fine, this isn't high-frequency). Each row:
- timestamp
- verdict badge (`ATTACK` = red, `NORMAL` = green/neutral)
- `final_score` — a small bar or colored number is more useful than plain
  text, since the threshold (0.5 default) is what separates NORMAL/ATTACK
- `line1_network_score` / `line1_packet_score` side by side — useful to
  see which line actually caught it
- `session_key`, `src_ip`
- expandable row → raw `details` JSON (fusion_reason, line2 probs, flags)

### 3.3 Mitigation actions feed
From `mitigation:events` stream. Each row:
- timestamp
- `action` — map to a readable label:
  - `ip_quarantine` → "IP Quarantine"
  - `rate_limit_signal` → "Rate Limit Signal"
  - `repeat_offender_escalation` → "Escalation (Repeat Offender)"
  - `audit_sync` → "Audit Sync"
- **`applied` badge — this is the most important visual element in the
  whole dashboard.** `applied=1` → solid/green "APPLIED". `applied=0` →
  amber/outlined "RECOMMENDED" (mmt-core was unreachable; this is advisory
  only, nothing was actually enforced). Do not let these look similar —
  an operator should be able to tell at a glance which attacks were
  actually stopped vs. merely flagged.
- `src_ip`, `final_score`
- `detail` text (human-readable, already formatted server-side)
- from `extra` JSON: for `ip_quarantine`/`repeat_offender_escalation`,
  surface `ttl_s` (format: "permanent" if 0) and `offense_count`

### 3.4 mmt-core ground truth panel (side by side with 3.3, not merged)
This is deliberately a **separate panel**, not merged into 3.3, so a
viewer can visually cross-check "pipeline says APPLIED" against
"mmt-core actually shows it blocked":
- Table from `GET /api/security/blocked-ips` — ip, reason, added_at, expires_at
- Table/list from `GET /api/security/audit?limit=50`, filterable client-side
  by `event_type` (chips/dropdown for `ML_PIPELINE_VERDICT`, `IP_BLOCKED`,
  `IP_BLOCKED_TTL`, `INTRUSION_DETECTED`) and `severity`
- IDS signature state from `GET /api/security/ids/signatures` +
  `GET /api/security/ids/hits` — show threshold/window alongside current
  count so an operator can see how close a signature is to tripping

### 3.5 (Optional) Correlation view
Since `mitigation:events` and mmt-core's audit log both describe the same
real-world action from two angles, a nice-to-have is joining them on
`src_ip` + nearby timestamp to show, per attack, a short timeline: verdict
→ our mitigation call → mmt-core's own logged response. Not required for
v1; call out as a stretch goal if the builder has time.

---

## 4. Backend requirement (frontend cannot skip this)

Browsers can't speak the Redis protocol directly, so **something** needs to
sit between the frontend and Redis to expose `verdicts` /
`mitigation:events` as HTTP/JSON. Two options, pick one:

**Option A (fastest)**: reuse the existing `mitigation_dashboard.py`
(FastAPI). It already exposes `GET /api/dashboard-data` returning:
```json
{
  "generated_at": <float>,
  "verdicts": [ {...row...}, ... ],
  "mitigations": [ {...row...}, ... ],
  "core": {
    "reachable": true,
    "blocked_ips": [...],
    "ids_hits": {...},
    "status": {...}
  }
}
```
This already bundles everything in §2.1 and most of §2.2 in one call. The
new frontend can just point at `http://localhost:8787/api/dashboard-data`
and build UI on top — no new backend work needed, just richer rendering
than the current plain HTML/JS page.

**Option B (build fresh)**: if the other tool is building its own backend
anyway, it needs at minimum:
- `GET /verdicts?limit=N` → `XREVRANGE verdicts` wrapper
- `GET /mitigations?limit=N` → `XREVRANGE mitigation:events` wrapper
- proxy or direct calls to the mmt-core endpoints in §2.2 (CORS: mmt-core
  doesn't set CORS headers, so a same-origin proxy is likely needed if the
  frontend calls it directly from the browser — easier to have the backend
  proxy all of §2.2 too)

Either way: **the frontend should never talk to Redis or to mmt-core
directly from browser JS** — always through a backend/proxy layer.

---

## 5. Suggested tech-agnostic data flow

```
[mmt-core :5000]  <-- GET -->  [backend/proxy]  <-- GET -->  [frontend]
       ^                              ^
       |                              |
   (real blocks,                 [Redis: verdicts,
    audit log,                    mitigation:events]
    IDS state)
```

Poll interval: 2–3s is plenty (telemetry itself ticks every ~3s upstream).
No need for websockets/SSE unless the builder wants them — this isn't a
sub-second-latency use case.

---

## 6. Polling strategy (be explicit about this — don't leave it implicit)

**Use plain periodic polling, not WebSockets/SSE.** The underlying data
genuinely only updates on a ~3s cadence (that's `data-collector`'s own tick
interval), so a push channel buys no real latency improvement — it just
adds connection-state management, reconnect/backoff logic, and
infrastructure the builder would have to get right for zero benefit. Both
data sources are inherently pull-based already (`XREVRANGE` against Redis,
plain `GET` against mmt-core's REST API) — polling mirrors that directly.

**Backend must decouple "how often it refreshes" from "how many clients
are asking."** Do not let an incoming frontend request trigger a fresh
call to mmt-core / Redis every time:
- Run an internal refresh timer on the backend (~2–3s), update an
  in-memory snapshot, and serve every frontend request from that cached
  snapshot. If 3 browser tabs are open, that should **not** mean 3x the
  load on mmt-core's REST API for identical data.
- (The current `mitigation_dashboard.py` does *not* do this yet — it
  fetches fresh on every incoming request. Worth fixing when rebuilding:
  move the fetch-from-mmt-core/Redis logic onto a background timer task,
  and have the HTTP handler just return the latest cached snapshot.)

**Frontend polling should be well-behaved, not naive `setInterval`:**
- Match the backend's refresh cadence (~2–3s) — no point polling faster
  than the data actually changes.
- Guard against overlapping requests: skip a tick if the previous fetch
  hasn't resolved yet, rather than letting requests pile up under latency.
- Pause polling when the tab isn't visible (Page Visibility API) — no
  reason to keep hitting the backend from an idle background tab.
- On repeated fetch failure, back off (e.g. double the interval up to a
  cap) instead of retrying every 2–3s against something that's clearly
  down — consistent with the rest of this system's "degrade gracefully,
  never hammer a dead dependency" posture (see `RECOMMENDED` vs `APPLIED`
  in §3.3).

---

## 7. Known data caveats to design around

- **`src_ip` can be empty.** If the packet-side telemetry collector isn't
  running, `src_ip` on both verdicts and mitigation events will be `""`.
  The UI should render this as a distinct "no IP available" state, not a
  blank cell — it's meaningful (means Strategies 1–3 fell back to
  recommend-only / investigate-manually, see `mitigation:events`'
  `detail` text for that case).
- **Everything currently runs through one `session_key` ("default_session")
  and one `src_ip` (127.0.0.1 in dev)** because telemetry isn't yet
  per-UE/per-session tagged. Don't build the UI assuming rich multi-session
  breakdowns are populated today — design the schema/columns to support it
  (it's already in the data model), but expect a single session in
  practice until that's addressed upstream.
- **mmt-core's audit log `id` is not a stable/monotonic session
  identifier to rely on across core restarts** — during testing we saw the
  audit table's `id` sequence reset (e.g. back to 1) between queries taken
  minutes apart in the same session. Sort/dedupe by `created_at`, not by
  `id`, and don't assume `id` is a safe React/Vue list `key` across a
  core restart.
- **`/api/security/audit` has no filtering beyond `limit`** — build any
  event_type/severity filters as a client-side (or backend-side) filter
  over the full `limit`-bounded result set, not as query params the API
  doesn't support.
- **`expires_at: null` in `/blocked-ips` means permanent**, not "unknown" —
  render it as "Permanent", not blank.
- **`mitigation:events` is append-only and can grow large** — it's capped
  server-side at `maxlen=2000` (approximate trim), so very old events will
  silently age out. Don't build a feature that assumes full history is
  always available.

---

## 8. Suggested visual language (optional guidance, not a requirement)

- `ATTACK` verdict / `CRITICAL` severity → red
- `NORMAL` verdict / `INFO`/`DEBUG` severity → green or neutral gray
- `APPLIED` mitigation → solid green badge
- `RECOMMENDED` mitigation → amber/outline badge — visually "this did not
  actually happen," not a lesser shade of green
- `WARNING` severity (mmt-core's own `IP_BLOCKED` logging) → amber
- Score — a 0–1 bar or gauge reads faster than a bare decimal, especially
  near the 0.5 threshold boundary
