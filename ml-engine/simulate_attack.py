#!/usr/bin/env python3
"""
simulate_attack.py

Injects a synthetic ATTACK verdict directly into MitigationEngine, bypassing
Redis Streams, the orchestrator, and the ML models entirely.

Why this exists: when something looks broken end-to-end, you want to know
WHICH layer is broken -- the ML models not flagging real attack traffic, or
the mitigation/dashboard/mmt-core wiring itself. This script tests only the
second half: mitigation.py -> sacore-web -> dashboard. If this script's
output shows APPLIED and the dashboard/blocked-ips list updates, that whole
chain is proven to work and any remaining issue is in telemetry capture or
the ML models -- not in mitigation.

Does NOT touch inference_service.py, Redis telemetry streams, or the tester.
Only writes a MitigationOutcome's worth of state (mitigation:events stream +
whatever sacore-web does with the block/IDS/audit calls).

Usage:
    python simulate_attack.py                          # one ATTACK, score 0.95
    python simulate_attack.py --ip 203.0.113.9 --score 0.6
    python simulate_attack.py --repeat 4                # fire 4x to exercise
                                                         # the repeat-offender
                                                         # escalation ladder
                                                         # (Strategy 3)
    python simulate_attack.py --no-ip                   # tests the "no src_ip
                                                         # available" branch
"""

import argparse
import asyncio
import logging

import redis.asyncio as redis
from mitigation import MitigationEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("simulate_attack")

# 203.0.113.0/24 is TEST-NET-3 (RFC 5737) -- reserved for documentation/testing,
# guaranteed not to collide with anything real on your network or in the
# baseline UE IP pools (10.45.0.0/16 etc).
DEFAULT_IP = "203.0.113.9"


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default=DEFAULT_IP, help="synthetic attacker IP")
    ap.add_argument("--score", type=float, default=0.95, help="final_score to simulate")
    ap.add_argument("--session", default="sim-session", help="session_key to simulate")
    ap.add_argument("--repeat", type=int, default=1,
                     help="fire this many verdicts in a row (tests the repeat-offender ladder)")
    ap.add_argument("--no-ip", action="store_true",
                     help="simulate a verdict with NO src_ip (tests the 'investigate manually' branch)")
    args = ap.parse_args()

    r = redis.Redis(host="localhost", port=6379, decode_responses=True)
    engine = MitigationEngine(redis_client=r)

    try:
        for i in range(args.repeat):
            payload = {
                "verdict": "ATTACK",
                "final_score": args.score,
                "session_key": args.session,
                "src_ip": "" if args.no_ip else args.ip,
                "line1_network_score": args.score,
                "line1_packet_score": args.score,
                "details": '{"note": "synthetic verdict from simulate_attack.py"}',
            }
            log.info("--- firing synthetic verdict %d/%d (score=%.2f, ip=%s) ---",
                      i + 1, args.repeat, args.score, payload["src_ip"] or "<none>")
            outcomes = await engine.handle_verdict(payload)
            for o in outcomes:
                tag = "APPLIED" if o.applied else "RECOMMENDED"
                log.info("  [%s] %s -- %s", o.action.value, tag, o.detail)
    finally:
        await engine.close()

    print("\nNow check:")
    print(f"  curl -s {__import__('os').environ.get('SACORE_URL', 'http://localhost:5000')}"
          f"/api/security/blocked-ips | python3 -m json.tool")
    print("  ...and the dashboard at http://localhost:8787 -- the row(s) above should appear there too.")


if __name__ == "__main__":
    asyncio.run(main())
