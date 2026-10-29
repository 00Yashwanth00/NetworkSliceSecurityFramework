# Mitigation layer — run instructions

New/changed files:

| File | What |
|---|---|
| `mitigation.py` | **New.** The 4 mitigation strategies, called against mmt-core's existing REST API. |
| `setup_ids_signature.py` | **New.** One-time script — registers the IDS signature Strategy 2 relies on. |
| `mitigation_dashboard.py` | **New.** Read-only live dashboard (verdicts, mitigations applied/recommended, mmt-core security state). |
| `inference_service.py` | **Modified.** Now imports `MitigationEngine` and calls it after every published verdict. |
| `orchestrator.py`, `tail_verdicts.py` | Unchanged — included for completeness. |

No files under `mmt-studio-5g6g-main/core/` are touched. Everything here talks to mmt-core only over its existing HTTP API.

## 0. Prerequisites already running

- Redis reachable (default `localhost:6379`).
- Your `model_line1_network/`, `model_line1_packet/`, `model_line2_network/`, `model_line2_packet/` directories sitting next to these files (same layout `orchestrator.py` already expects — run everything from the `ml-engine` directory, or set paths accordingly).
- `sacore-web` (mmt-core) reachable — bare metal (`./run.sh` in `core/`) or via the orchestrate stack (`./run_studio.sh` → web UI on `http://localhost:5000`). Optional for Strategies 1–3 to actually enforce anything, but the pipeline runs fine without it (everything just falls back to RECOMMENDED).

If sacore-web lives somewhere other than `localhost:5000` (e.g. the Docker bridge IP `172.30.0.10:5000`), export `SACORE_URL` before every step below:

```bash
export SACORE_URL=http://172.30.0.10:5000
```

## 1. Install the extra deps

```bash
pip install -r requirements-mitigation.txt
```

## 2. One-time: register the rate-limit IDS signature (Strategy 2)

```bash
python setup_ids_signature.py
```

Re-run this any time you change `IDS_SIGNATURE_THRESHOLD` / `IDS_SIGNATURE_WINDOW_S` / `IDS_SIGNATURE_AUTO_BLOCK_TTL_S`. Safe to run repeatedly (upsert).

If sacore-web isn't up yet, this will fail loudly and tell you to re-run later — Strategy 2 still *sends* events without it, they just won't auto-promote/auto-block until the signature exists.

## 3. Start the inference service (now with mitigation wired in)

```bash
python inference_service.py
```

You'll see normal Line 1/Line 2 logs plus, on every `ATTACK` verdict, one line per strategy, e.g.:

```
Published verdict for 10.45.3.12: ATTACK (Score: 0.812, src_ip='10.45.3.12')
  [mitigation:ip_quarantine] APPLIED — Quarantined 10.45.3.12 for 3600s (...)
  [mitigation:rate_limit_signal] APPLIED — Rate-limit signature 'ML_PIPELINE_ATTACK' recorded hit for 10.45.3.12
  [mitigation:audit_sync] APPLIED — Logged to mmt-core security audit trail
```

or, if sacore-web is down:

```
  [mitigation:ip_quarantine] RECOMMENDED — RECOMMENDED: block 10.45.3.12 for 3600s -- sacore-web unreachable: ...
  [mitigation:rate_limit_signal] RECOMMENDED — RECOMMENDED: feed 10.45.3.12 into rate-limit signature ... 
  [mitigation:audit_sync] RECOMMENDED — Audit sync to mmt-core failed -- local record only: ...
```

Either way, nothing crashes — the fusion loop keeps running.

## 4. Feed it telemetry (as before)

```bash
python packet_collector_live.py --interface <iface> --redis-host localhost
# plus whatever publishes to telemetry.network (your data-collector)
```

## 5. Watch it

Pick either or both:

```bash
# raw console tail
python tail_verdicts.py

# or the dashboard
python mitigation_dashboard.py
# -> open http://localhost:8787
```

The dashboard shows a red banner and switches every mitigation row to a **RECOMMENDED** badge automatically if sacore-web is unreachable — that's the fallback behavior you asked for, no code changes needed to toggle it.

## Config knobs (env vars, all optional)

| Var | Default | Controls |
|---|---|---|
| `SACORE_URL` | `http://localhost:5000` | Where mmt-core's REST API lives |
| `SACORE_HTTP_TIMEOUT` | `3.0` | Seconds before a mitigation call is treated as failed |
| `ESCALATION_WINDOW_S` | `3600` | Repeat-offender counting window (Strategy 3) |
| `IDS_SIGNATURE_THRESHOLD` | `3` | Hits within window before Strategy 2 auto-blocks |
| `IDS_SIGNATURE_WINDOW_S` | `60` | Strategy 2 sliding window |
| `IDS_SIGNATURE_AUTO_BLOCK_TTL_S` | `1800` | Auto-block TTL once Strategy 2 trips |
| `ATTACK_SCORE_THRESHOLD` | `0.5` | (existing, inference_service.py) score-override floor |
| `DASHBOARD_PORT` | `8787` | mitigation_dashboard.py port |

Quarantine score tiers (Strategy 1) and the escalation ladder (Strategy 3) are edited directly in `mitigation.py` (`QUARANTINE_TIERS`, `ESCALATION_LADDER_S`) — they're policy, not runtime config.
