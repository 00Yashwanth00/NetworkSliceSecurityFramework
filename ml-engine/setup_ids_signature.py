#!/usr/bin/env python3
"""
setup_ids_signature.py

One-time setup for mitigation.py's Strategy 2 (rate limiting).

mitigation.py feeds every ATTACK verdict into mmt-core's IDS signature
engine via POST /api/security/ids/test with event_type="ML_PIPELINE_ATTACK".
That only turns into a sliding-window rate-limit (with auto-block once N
hits land inside a time window) if a matching IDS signature already exists
in mmt-core -- this script registers it.

Safe to re-run any time (POST /api/security/ids/signatures is an upsert by
name): run it once before starting inference_service.py, and again any time
you change the threshold/window/auto-block env vars below.

Usage:
    python setup_ids_signature.py
    SACORE_URL=http://172.30.0.10:5000 python setup_ids_signature.py
"""

import os
import sys

import httpx

SACORE_URL = os.environ.get("SACORE_URL", "http://localhost:5000")

SIGNATURE = {
    "name": "ML_PIPELINE_ATTACK",
    # Matched by exact event_type==name inside mmt-core's SignatureMatches,
    # so the pattern value itself is never actually evaluated for this
    # signature -- it's only required by the API's validation.
    "pattern": "ML_PIPELINE_ATTACK",
    "severity": "CRITICAL",
    "threshold": int(os.environ.get("IDS_SIGNATURE_THRESHOLD", "3")),
    "window_s": int(os.environ.get("IDS_SIGNATURE_WINDOW_S", "60")),
    "enabled": True,
    "auto_block_ttl_s": int(os.environ.get("IDS_SIGNATURE_AUTO_BLOCK_TTL_S", "1800")),
}


def main():
    print(f"Registering IDS signature '{SIGNATURE['name']}' on {SACORE_URL} ...")
    print(f"  threshold={SIGNATURE['threshold']} hits / window_s={SIGNATURE['window_s']}s "
          f"-> auto_block_ttl_s={SIGNATURE['auto_block_ttl_s']}")
    try:
        resp = httpx.post(f"{SACORE_URL}/api/security/ids/signatures", json=SIGNATURE, timeout=5.0)
        resp.raise_for_status()
    except Exception as e:
        print(f"FAILED to register signature: {e}", file=sys.stderr)
        print(
            "mitigation.py will still POST events to /api/security/ids/test, but they "
            "won't auto-promote to an alert or auto-block until this signature exists. "
            "Re-run this script once sacore-web is reachable.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("OK:", resp.json())
    verify = httpx.get(f"{SACORE_URL}/api/security/ids/signatures", timeout=5.0).json()
    names = [s["name"] for s in verify.get("signatures", [])]
    print("Current signatures on sacore-web:", names)
    if SIGNATURE["name"] not in names:
        print("WARNING: signature not found in listing after registration.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
