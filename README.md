# 5G Network Slice Attack Detection & Mitigation Pipeline

An ML-driven pipeline that watches live telemetry from a 5G core (mmt-studio),
scores it with a two-line defense model, publishes **NORMAL / ATTACK** verdicts,
and automatically responds to attacks through mmt-core's security API. A web
dashboard shows what was detected, what was done about it, and what mmt-core
actually enforced.

---

## 1. Architecture

```
                 ┌────────────────────┐
  mmt-core  ───► │  data-collector    │  polls core APIs every 3 s
 (sacore-web)    │  (Java)            │
                 └─────────┬──────────┘
                           │ XADD telemetry.network
                           ▼
 packet telemetry ──► telemetry.packet ──►┌────────────────────────────────┐
 (separate feeder)                        │  Redis                         │
                                          │  streams: telemetry.*, verdicts│
                                          │           mitigation:events    │
                                          └───────────────┬────────────────┘
                                                          │
                        ┌─────────────────────────────────┴───────────┐
                        │  inference_service.py (ml-engine)           │
                        │   Line 1 scoring (network + packet models)  │
                        │   → fusion → Line 2 confirmation if flagged │
                        │   → verdict + score-threshold rule          │
                        │   → MitigationEngine (mitigation.py)        │
                        └───────┬─────────────────────────────┬───────┘
                                │ XADD verdicts               │ REST
                                ▼                             ▼
                      mitigation_dashboard.py        mmt-core security API
                      (FastAPI, :8787)               /api/security/*  (:5000)
                                │
                                ▼
                      attack-monitor-dashboard (React, :3000)
```

| Component | Folder / file | Port | Role |
|---|---|---|---|
| mmt-core (sacore-web) | `mmt-studio-5g6g-main/core` | 5000 | 5G core under test and its security API |
| SA Tester | `mmt-studio-5g6g-main/tester` | – | Runs attack and test cases against the core |
| Data collector | `data-collector` | – | Publishes network KPIs to `telemetry.network` |
| Redis | system service | 6379 | Streams between all components |
| Inference service | `ml-engine/inference_service.py` | – | Scoring, fusion, verdicts, mitigation |
| Orchestrator | `ml-engine/orchestrator.py` | – | Two-line defense models (loaded by the service) |
| Mitigation engine | `ml-engine/mitigation.py` | – | Calls mmt-core to block / rate-limit / audit |
| Dashboard backend | `mitigation_dashboard.py` | 8787 | Read-only API over Redis + mmt-core |
| Dashboard frontend | `attack-monitor-dashboard` | 3000 | React UI |

---

## 2. How detection works

1. **Line 1** scores network telemetry and packet telemetry independently with
   anomaly models. Scores are normalized to 0–1 using calibration files.
2. **Fusion** decides whether to escalate (either modality above its own
   normal-traffic boundary, or the weighted average above the combined
   boundary).
3. **Line 2** (attack classifiers) confirms escalated cases. The final score is
   `0.3 × Line 1 + 0.7 × Line 2`.
4. **Score-threshold rule:** any final score above `ATTACK_SCORE_THRESHOLD`
   (default `0.45`) is published as `ATTACK`, even if Line 1 did not escalate.
   It only promotes NORMAL to ATTACK and never demotes a model-confirmed ATTACK.

Verdicts are written to the `verdicts` Redis stream.

---

## 3. Mitigation strategies and score bands

Every ATTACK verdict goes through `mitigation.py`. Strategies run in this
order: quarantine (with escalation folded in), rate limit, audit sync.

| Final score | Verdict | 1. Quarantine | 2. Rate limit | 4. Audit sync |
|---|---|---|---|---|
| `< 0.45` | NORMAL | – | – | – |
| `0.45 – 0.55` | ATTACK | skipped | skipped | yes (audit-only) |
| `0.55 – 0.65` | ATTACK | 5 min | yes | yes |
| `0.65 – 0.80` | ATTACK | 1 hour | yes | yes |
| `≥ 0.80` | ATTACK | permanent | yes | yes |

* **Strategy 1: IP quarantine.** `POST /api/security/blocked-ips/ttl`.
* **Strategy 2: Rate limiting.** Each qualifying verdict sends one signal to the
  IDS signature `ML_PIPELINE_ATTACK` via `POST /api/security/ids/test`. The
  signature trips when one IP sends **3 signals within 60 s**; mmt-core then
  auto-blocks the IP for **600 s**.
* **Strategy 3: Repeat-offender escalation.** Offenses per IP are counted in
  Redis over `ESCALATION_WINDOW_S` (default 3600 s). The block TTL becomes the
  longer of the score tier and the ladder: 5 min → 1 h → 6 h → permanent.
* **Strategy 4: Audit sync.** `POST /api/security/audit`, always attempted.

Every action is recorded in the `mitigation:events` Redis stream as
**APPLIED** (mmt-core confirmed it) or **RECOMMENDED** (could not be enforced,
for example because mmt-core was unreachable or the IDS signature was missing).

Attacks with no `src_ip` cannot be quarantined or rate-limited; they produce a
single RECOMMENDED row for manual investigation.

### Tunable settings (environment variables)

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `ATTACK_SCORE_THRESHOLD` | `0.45` | inference_service | Score above which a verdict becomes ATTACK |
| `QUARANTINE_SCORE_THRESHOLD` | `0.55` | mitigation | Minimum score for strategy 1 |
| `RATE_LIMIT_SCORE_THRESHOLD` | `0.55` | mitigation | Minimum score for strategy 2 |
| `ESCALATION_WINDOW_S` | `3600` | mitigation | Repeat-offender counting window |
| `SACORE_URL` | `http://localhost:5000` | mitigation, dashboard backend | mmt-core address |
| `SACORE_HTTP_TIMEOUT` | `3.0` | mitigation | Per-request timeout in seconds |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | mitigation, dashboard backend | Redis address |
| `DASHBOARD_PORT` | `8787` | dashboard backend | Backend port |

The quarantine TTL tiers (`QUARANTINE_TIERS`), the escalation ladder and the
IDS signature definition (`IDS_SIGNATURE_SPEC`) are constants at the top of
`mitigation.py`.

---

## 4. Prerequisites

* Linux with **Docker** (mmt-core and the tester run in containers)
* **Redis** server
* **Python 3.10+** with: `redis`, `httpx`, `fastapi`, `uvicorn`, `numpy`,
  `pandas`, `joblib`, `scikit-learn` (and whatever library your models were
  trained with)
* **Node.js 18+** and npm
* **Java 17+** and Maven (only to rebuild the collector)

Model files must exist under `ml-engine/`:

```
ml-engine/
├── inference_service.py
├── orchestrator.py
├── mitigation.py
├── model_line1_network/   line1_model.pkl, feature_columns.json, score_calibration.json
├── model_line1_packet/    line1_model.pkl, feature_columns.json, score_calibration.json
├── model_line2_network/   attack_classifier.pkl, feature_columns.json
└── model_line2_packet/    attack_classifier.pkl, feature_columns.json
```

### One-time install

```bash
# Redis
sudo apt install redis-server

# Python packages
pip install redis httpx fastapi uvicorn numpy pandas joblib scikit-learn

# Dashboard frontend
cd attack-monitor-dashboard && npm install

# Data collector (only if you changed the source)
cd data-collector && mvn clean package
```

---

## 5. Running it

Use **one terminal per step**, and start the components **in this order**.

> **Order matters.** `inference_service.py` deletes the `telemetry.network`,
> `telemetry.packet` and `verdicts` streams on startup, and its consumers only
> read messages that arrive afterwards. Start it **before** the collector.

### Step 1: Redis

```bash
sudo systemctl start redis-server
redis-cli ping        # expect: PONG
```

### Step 2: mmt-core (port 5000)

If it is already running, skip this step:

```bash
curl http://localhost:5000/api/security/status
```

Otherwise start it:

```bash
cd mmt-studio-5g6g-main/core
./run.sh run
```

### Step 3: Inference service

Run it from the folder that contains the model directories:

```bash
cd ml-engine
python3 inference_service.py
```

Wait for `Consumer groups created. Ready to consume live telemetry.`

This process also starts a background task that keeps the rate-limit signature
registered in mmt-core (see section 7).

### Step 4: Dashboard backend (port 8787)

```bash
python3 mitigation_dashboard.py
```

### Step 5: Dashboard frontend (port 3000)

```bash
cd attack-monitor-dashboard
npm start             # opens http://localhost:3000
```

Different hosts or ports? Copy `.env.example` to `.env`, edit it, and restart
`npm start`.

### Step 6: Data collector

```bash
cd data-collector
java -jar target/data-collector-1.0-SNAPSHOT.jar
```

Run it from the `data-collector` folder because CSV output goes to
`./collected-data`. Settings live in
`src/main/resources/application.properties` (core URL, poll interval,
Redis stream, session label).

### Step 7: Run tests and attacks

Open the **SA Tester** in your browser and run a test case. Watch the
dashboard at <http://localhost:3000>.

Wait for the tester log line `Core: tester baseline pushed` before judging the
dashboard (see section 7).

### Stopping

Press `Ctrl-C` in each terminal, in reverse order. Stream data in `verdicts`
and `telemetry.*` is cleared the next time the inference service starts;
`mitigation:events` is not.

---

## 6. Verifying that it works

```bash
redis-cli xlen telemetry.network     # grows about every 3 s
redis-cli xlen verdicts              # grows as the service scores
redis-cli xlen mitigation:events     # grows on ATTACK verdicts

curl http://localhost:5000/api/security/ids/signatures   # lists ML_PIPELINE_ATTACK
curl http://localhost:5000/api/security/ids/hits         # hit and trip counters
curl http://localhost:5000/api/security/blocked-ips      # active blocks
```

**Test the rate limiter without waiting for an attack.** Three signals from one
IP inside 60 s should trip it. Use a fake IP so you don't block localhost:

```bash
for i in 1 2 3; do
  curl -s -X POST http://localhost:5000/api/security/ids/test \
    -H 'Content-Type: application/json' \
    -d '{"event_type":"ML_PIPELINE_ATTACK","source_ip":"10.9.9.9","detail":"manual test"}'; echo
done
```

Expected replies: `detected:false`, `detected:false`, `detected:true`. Then
`/ids/hits` shows 3 hits and 1 trip, and `10.9.9.9` appears in the blocked list
for 600 s.

**What the dashboard shows:**

| Panel | Source | Meaning |
|---|---|---|
| Live verdicts | Redis `verdicts` | Normal / Attack, scores, path (Line 1 only or Line 1 + Line 2), source IP |
| Mitigation feed | Redis `mitigation:events` | Each action with an Applied or Recommended badge |
| Blocked IPs, Audit events, IDS signatures | mmt-core | What is actually enforced right now |
| Rate limiter proof | mmt-core | Hits, trips, last tripped, signature thresholds |

**Rate-limiter counters.** Hits count every signal that reached mmt-core.
Trips count every hit from the 3rd onward within the window, so 7 hits in one
burst show as 5 trips. Both are in-memory counters inside mmt-core and reset
when the core restarts or `/api/security/hits/reset` is called.

---

## 7. Important behaviour to know about

**The SA Tester resets mmt-core at the start of every test.** Its
`reset_to_baseline()` step restarts the core process, waits for it to come back,
wipes the database with `drop-db-data`, pushes its baseline configuration and
restarts `satraffic`. Consequences:

* The dashboard shows **"mmt-core is unreachable"** for a few seconds to a
  minute at the start of each test. This is expected.
* Blocks, trip records, audit events and rate-limit counters from the previous
  test are erased.
* The `ML_PIPELINE_ATTACK` signature is wiped too. `mitigation.py` registers it
  again automatically: the first qualifying ATTACK verdict re-registers it, and
  the background task `keep_signature_registered` restores it within a few
  seconds of any wipe.
* Mitigation actions attempted while the core is down are logged as
  **RECOMMENDED** (not enforced).

**"Applied" means verified.** mmt-core's `/ids/test` endpoint answers HTTP 200
even when the signature does not exist, so a 200 alone proves nothing. The
rate-limit strategy first confirms the signature exists and is enabled, and
reports RECOMMENDED if it is not.

**Blocking localhost.** In a local test the attacker IP is `127.0.0.1`. A trip
or quarantine will block it for several minutes and may cut your tester off from
the core. Unblock it with:

```bash
curl -X DELETE http://localhost:5000/api/security/blocked-ips/127.0.0.1
```

**Packet telemetry.** The collector only publishes to `telemetry.network`.
Something else must publish to `telemetry.packet`. If
`redis-cli xlen telemetry.packet` stays at 0, verdicts will be "Line 1 only"
and may lack a source IP.

---

## 8. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Rate limiter shows Hits 0 and "Signature Unknown" | Signature missing in mmt-core | Confirm `inference_service.py` is running the keep-alive task; or register it by hand (below) |
| Mitigation rows say "signature … is not registered/enabled" | Signature wiped or core unreachable | Check `curl localhost:5000/api/security/ids/signatures`; look for `registering it` in the service log |
| `NameError: IDS_SIGNATURE_SPEC` in the log | Old or partial `mitigation.py` | Use the full `mitigation.py` from this repo and restart the service |
| Attack verdict but "no src_ip available" | Packet data missing or expired at fusion time | Make sure the packet feeder is running; check the service log for the `src_ip` it extracted |
| Red banner "mmt-core is unreachable" | Core restarting during a test, or request timeout | Wait for the tester's baseline-pushed log line; raise `SACORE_HTTP_TIMEOUT` if the core is merely slow |
| Audit summary empty | Core unreachable, or audit log just wiped by the tester | Fills as soon as the core responds and a new ATTACK verdict logs an audit event |
| No verdicts at all | Service started after the collector, or Redis streams empty | Restart the inference service first, then the collector |
| `Failed to load models!` | Wrong working directory or missing model folders | Run from `ml-engine/` and check the layout in section 4 |

Register the rate-limit signature by hand:

```bash
curl -X POST http://localhost:5000/api/security/ids/signatures \
  -H 'Content-Type: application/json' \
  -d '{"name":"ML_PIPELINE_ATTACK","pattern":"ML_PIPELINE_ATTACK","severity":"CRITICAL","threshold":3,"window_s":60,"enabled":true,"auto_block_ttl_s":600}'
```

---

## 9. Changing the thresholds

To shift where attacks start or where each action begins:

1. `inference_service.py`: change the default of `ATTACK_SCORE_THRESHOLD`, or
   set the environment variable.
2. `mitigation.py`: change `QUARANTINE_TIERS` and the two gate variables.
3. `attack-monitor-dashboard/src/config.js`: set `SCORE_THRESHOLD` to the same
   value as the attack threshold so the dashboard's score marker matches.
4. Restart `inference_service.py`. All values are read at startup.

The Line 1 escalation boundaries and `line2_decision_threshold` in
`orchestrator.py` are separate. They control which cases are escalated and
confirmed, not the final-score bands above. Changing them alters what the
models treat as suspicious, so re-check your normal-traffic test cases after any
change.

---

## 10. Repository layout

```
.
├── ml-engine/
│   ├── inference_service.py     # stream consumers, fusion, verdicts
│   ├── orchestrator.py          # two-line defense models
│   ├── mitigation.py            # mitigation strategies + signature upkeep
│   └── model_line*/             # trained models and calibration files
├── mitigation_dashboard.py      # FastAPI read-only backend (:8787)
├── attack-monitor-dashboard/    # React frontend (:3000)
├── data-collector/              # Java telemetry collector
└── mmt-studio-5g6g-main/
    ├── core/                    # mmt-core (sacore-web, Go)
    ├── tester/                  # SA Tester
    └── orchestrate/             # container orchestration
```
