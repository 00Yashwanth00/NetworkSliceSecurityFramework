#!/usr/bin/env python3
"""
mitigation.py

Automated mitigation layer for the ML inference pipeline. Reacts to each
verdict published by inference_service.py by calling mmt-studio-core's
EXISTING, already-wired security admin API on sacore-web -- no core/ Go
code changes required.

    Strategy 1  IP quarantine              POST /api/security/blocked-ips/ttl
    Strategy 2  Rate limiting (sliding      POST /api/security/ids/test
                window, auto-block)         (signature ML_PIPELINE_ATTACK,
                                             auto-registered by this module)
    Strategy 3  Repeat-offender escalation  same blocked-ips/ttl call, with a
                                             TTL escalated via a counter kept
                                             in our own Redis (not mmt-core)
    Strategy 4  Audit/dashboard sync        POST /api/security/audit
                (always-succeeds fallback)

Score bands (final_score -> action), after the 0.05 downward shift:

    <  0.45          NORMAL (decided in inference_service.py, no mitigation)
    0.45 - 0.55      ATTACK, audit-only (strategy 4)
    0.55 - 0.65      + quarantine 5 min (floor) + rate-limit signal
    0.65 - 0.80      + quarantine 1 hour        + rate-limit signal
    >= 0.80          + quarantine permanent     + rate-limit signal
    (strategy 3 can lengthen any quarantine for repeat offenders)

Design contract: every call to sacore-web is best-effort. If sacore-web is
unreachable, slow, or returns an error, we log it, mark the action as
RECOMMENDED (applied=False) instead of applied, and keep going -- the
inference pipeline must never stall or crash because a mitigation call
failed. Every outcome -- applied or recommended-only -- is written to the
`mitigation:events` Redis stream so mitigation_dashboard.py can render the
full picture even when sacore-web was down for the whole session.

IDS signature note: the SA Tester calls POST /api/admin/drop-db-data on every
test entry, which wipes security_ids_signatures. mmt-core's /ids/test endpoint
answers 200 {"detected": false} even when the signature does not exist, so a
bare HTTP 200 proves nothing. This module therefore (a) verifies the
signature exists before counting a rate-limit action as applied, (b)
re-registers it if missing, and (c) offers keep_signature_registered(), a
background loop that restores it within seconds of a wipe.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import httpx
import redis.asyncio as redis

logger = logging.getLogger("mitigation")

# --- Configuration -----------------------------------------------------
SACORE_URL = os.environ.get("SACORE_URL", "http://localhost:5000")
HTTP_TIMEOUT = float(os.environ.get("SACORE_HTTP_TIMEOUT", "3.0"))

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

# Strategy 1 -- direct quarantine tiers: (min final_score, ttl_seconds).
# Checked highest-threshold-first; ttl_s=0 means permanent (matches
# mmt-core's own BlockIPWithTTL convention). The last entry is the floor --
# any verdict that passes the quarantine gate gets at least this TTL.
QUARANTINE_TIERS = [
    (0.80, 0),       # >= 0.80  -> permanent
    (0.65, 3600),    # >= 0.65  -> 1 hour
    (0.0, 300),      # floor    -> 5 minutes
]

# Strategy 2 -- the IDS signature this module keeps registered in mmt-core.
IDS_SIGNATURE_NAME = "ML_PIPELINE_ATTACK"

# Registered (or re-registered) whenever it is found missing. Trips when one
# source IP sends `threshold` signals within `window_s`; on a trip mmt-core
# also blocks the IP for `auto_block_ttl_s`. The name must equal
# IDS_SIGNATURE_NAME and `enabled` must be True (omitted = disabled).
IDS_SIGNATURE_SPEC = {
    "name": IDS_SIGNATURE_NAME,
    "pattern": IDS_SIGNATURE_NAME,
    "severity": "CRITICAL",
    "threshold": 3,
    "window_s": 60,
    "enabled": True,
    "auto_block_ttl_s": 600,
}

# How long a successful "signature exists" check is trusted before asking
# mmt-core again. Kept short so a tester wipe leaves only a brief blind spot.
SIGNATURE_CHECK_TTL_S = 5.0

# Gates for strategies 1 and 2. Below BOTH gates an ATTACK verdict still gets
# strategy 4 (audit sync) -- so it's never silently dropped -- but triggers no
# block and no IDS signal. Both default to 0.55 (the old 0.6 shifted down by
# 0.05). They are separate so quarantine can be tuned independently, e.g.
#   QUARANTINE_SCORE_THRESHOLD=0.6 RATE_LIMIT_SCORE_THRESHOLD=0.45
# Set a gate to 0.0 to apply that strategy to every ATTACK verdict with a
# src_ip.
RATE_LIMIT_SCORE_THRESHOLD = float(os.environ.get("RATE_LIMIT_SCORE_THRESHOLD", "0.55"))
QUARANTINE_SCORE_THRESHOLD = float(os.environ.get("QUARANTINE_SCORE_THRESHOLD", "0.55"))

# Strategy 3 -- repeat-offender escalation ladder, keyed on offense count
# within ESCALATION_WINDOW_S (tracked in OUR Redis, independent of
# mmt-core). 0 = permanent.
ESCALATION_LADDER_S = [300, 3600, 21600, 0]   # 5m -> 1h -> 6h -> permanent
ESCALATION_WINDOW_S = int(os.environ.get("ESCALATION_WINDOW_S", "3600"))
OFFENDER_KEY_PREFIX = "mitigation:offender:"

MITIGATION_EVENTS_STREAM = "mitigation:events"
MITIGATION_EVENTS_MAXLEN = 2000


class MitigationAction(str, Enum):
    QUARANTINE = "ip_quarantine"          # Strategy 1
    RATE_LIMIT = "rate_limit_signal"      # Strategy 2
    ESCALATE = "repeat_offender_escalation"  # Strategy 3 (tags the quarantine
                                           # call when escalation -- not the
                                           # score tier -- decided the TTL)
    AUDIT_SYNC = "audit_sync"             # Strategy 4


@dataclass
class MitigationOutcome:
    action: MitigationAction
    applied: bool          # True: sacore-web confirmed it took effect
    detail: str = ""       # human-readable summary (dashboard + logs)
    extra: dict = field(default_factory=dict)


class MitigationEngine:
    """
    Call `await engine.handle_verdict(payload)` once per verdict published
    to the `verdicts` stream (payload is the same dict inference_service.py
    writes with xadd). No-ops for verdict != "ATTACK".
    """

    def __init__(self, redis_client: Optional["redis.Redis"] = None):
        self.r = redis_client or redis.Redis(
            host=REDIS_HOST, port=REDIS_PORT, decode_responses=True
        )
        self._client = httpx.AsyncClient(base_url=SACORE_URL, timeout=HTTP_TIMEOUT)
        # monotonic timestamp of the last successful signature check
        self._sig_cache: Optional[float] = None

    async def close(self):
        await self._client.aclose()

    # ---------------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------------
    async def handle_verdict(self, verdict_payload: dict) -> List[MitigationOutcome]:
        if verdict_payload.get("verdict") != "ATTACK":
            return []

        src_ip = str(verdict_payload.get("src_ip") or "").strip()
        session_key = verdict_payload.get("session_key", "")
        final_score = float(verdict_payload.get("final_score", 0.0) or 0.0)
        details = verdict_payload.get("details", "")

        outcomes: List[MitigationOutcome] = []

        if not src_ip:
            # No IP to act on (e.g. correlation only had an IMSI/session_key
            # that isn't IP-shaped). Strategies 1-3 need a real IP; record
            # that as a recommendation for a human to chase down.
            outcomes.append(MitigationOutcome(
                action=MitigationAction.QUARANTINE,
                applied=False,
                detail=(f"RECOMMENDED: no src_ip available for "
                        f"session={session_key!r} -- investigate session "
                        f"manually (score={final_score:.3f})"),
            ))
        else:
            # Order is fixed: quarantine (1, with 3 folded in) -> rate limit (2).
            if final_score >= QUARANTINE_SCORE_THRESHOLD:
                outcomes.append(await self._strategy_quarantine(src_ip, final_score, session_key))
            if final_score >= RATE_LIMIT_SCORE_THRESHOLD:
                outcomes.append(await self._strategy_rate_limit(src_ip, final_score, session_key, details))

            if not outcomes:
                # Below both gates: ATTACK verdict with a real src_ip, but not
                # confident enough to block or rate-limit yet. No outcome row
                # here -- strategy 4 below records why, so this never shows up
                # looking like a dropped/failed action (it's a deliberate skip,
                # not a failure, and must not be confused with the RECOMMENDED
                # state that specifically means "mmt-core was unreachable").
                logger.info(
                    "[mitigation] %s: score %.3f below gates (quarantine %.2f, "
                    "rate-limit %.2f) -- audit-only",
                    src_ip, final_score,
                    QUARANTINE_SCORE_THRESHOLD, RATE_LIMIT_SCORE_THRESHOLD,
                )

        # Strategy 4 always runs last and always produces a record, even if
        # the HTTP POST itself fails.
        outcomes.append(await self._strategy_audit_sync(verdict_payload, outcomes))

        await self._record_events(verdict_payload, outcomes)
        return outcomes

    # ---------------------------------------------------------------
    # Strategy 1 + 3: quarantine, with repeat-offender escalation
    # ---------------------------------------------------------------
    def _tier_ttl(self, score: float) -> int:
        for threshold, ttl in QUARANTINE_TIERS:
            if score >= threshold:
                return ttl
        return QUARANTINE_TIERS[-1][1]

    async def _bump_offender(self, ip: str) -> int:
        """Fixed-window counter: first hit sets the TTL, later hits in the
        same window just increment -- a true 'N offenses per window', not a
        sliding one."""
        key = OFFENDER_KEY_PREFIX + ip
        count = await self.r.incr(key)
        if count == 1:
            await self.r.expire(key, ESCALATION_WINDOW_S)
        return count

    async def _strategy_quarantine(self, src_ip: str, final_score: float,
                                    session_key: str) -> MitigationOutcome:
        tier_ttl = self._tier_ttl(final_score)
        offense_count = await self._bump_offender(src_ip)
        ladder_ttl = ESCALATION_LADDER_S[min(offense_count - 1, len(ESCALATION_LADDER_S) - 1)]

        # 0 (permanent) always wins; otherwise take the longer of the two.
        escalated = ladder_ttl > tier_ttl or ladder_ttl == 0
        if tier_ttl == 0 or ladder_ttl == 0:
            final_ttl = 0
        else:
            final_ttl = max(tier_ttl, ladder_ttl)

        action = MitigationAction.ESCALATE if (escalated and offense_count > 1) else MitigationAction.QUARANTINE
        ttl_desc = "permanent" if final_ttl == 0 else f"{final_ttl}s"
        reason = (f"ML pipeline ATTACK verdict (score={final_score:.3f}, "
                  f"session={session_key}, offense #{offense_count} in last "
                  f"{ESCALATION_WINDOW_S}s)")

        try:
            resp = await self._client.post("/api/security/blocked-ips/ttl", json={
                "ip": src_ip, "reason": reason, "ttl_s": final_ttl,
            })
            resp.raise_for_status()
            msg = f"Quarantined {src_ip} for {ttl_desc} ({reason})"
            logger.warning("[mitigation] %s", msg)
            return MitigationOutcome(
                action=action, applied=True, detail=msg,
                extra={"ttl_s": final_ttl, "offense_count": offense_count},
            )
        except Exception as e:
            msg = f"RECOMMENDED: block {src_ip} for {ttl_desc} -- sacore-web unreachable: {e}"
            logger.error("[mitigation] Quarantine call failed for %s: %s", src_ip, e)
            return MitigationOutcome(
                action=action, applied=False, detail=msg,
                extra={"ttl_s": final_ttl, "offense_count": offense_count},
            )

    # ---------------------------------------------------------------
    # IDS signature upkeep (needed by strategy 2)
    # ---------------------------------------------------------------
    async def _signature_registered(self) -> bool:
        """True if ML_PIPELINE_ATTACK exists AND is enabled in mmt-core.
        If it is missing (e.g. the tester's drop-db-data wiped it), register
        it again and re-check. A successful check is trusted for
        SIGNATURE_CHECK_TTL_S seconds; failures are never cached."""
        now = time.monotonic()
        if self._sig_cache is not None and now - self._sig_cache < SIGNATURE_CHECK_TTL_S:
            return True

        async def _exists() -> bool:
            r = await self._client.get("/api/security/ids/signatures")
            r.raise_for_status()
            return any(
                s.get("name") == IDS_SIGNATURE_NAME and s.get("enabled")
                for s in r.json().get("signatures", [])
            )

        try:
            if not await _exists():
                logger.warning("[mitigation] %s missing in mmt-core -- registering it",
                               IDS_SIGNATURE_NAME)
                r = await self._client.post("/api/security/ids/signatures",
                                            json=IDS_SIGNATURE_SPEC)
                r.raise_for_status()
                if not await _exists():
                    logger.error("[mitigation] registered %s but it is still not "
                                 "listed/enabled", IDS_SIGNATURE_NAME)
                    self._sig_cache = None
                    return False
            self._sig_cache = now
            return True
        except Exception as e:
            logger.error("[mitigation] signature check/register failed: %s", e)
            self._sig_cache = None
            return False

    async def keep_signature_registered(self, interval: float = 10.0):
        """Background loop: restores the signature within `interval` seconds of
        a wipe, whether or not any attack is happening. Start it once from
        inference_service.main() with asyncio.create_task(...)."""
        while True:
            try:
                self._sig_cache = None          # force a real check
                await self._signature_registered()
            except Exception as e:              # never let the loop die
                logger.error("[mitigation] keep_signature_registered error: %s", e)
            await asyncio.sleep(interval)

    # ---------------------------------------------------------------
    # Strategy 2: sliding-window rate limiting via mmt-core's IDS
    # signature engine (threshold/window/auto-block come from
    # IDS_SIGNATURE_SPEC)
    # ---------------------------------------------------------------
    async def _strategy_rate_limit(self, src_ip: str, final_score: float,
                                    session_key: str, details) -> MitigationOutcome:
        detail = f"ML ATTACK verdict score={final_score:.3f} session={session_key} details={details}"

        # /ids/test returns 200 even when the signature does not exist, so
        # verify first -- otherwise "applied" would be a false claim.
        if not await self._signature_registered():
            msg = (f"RECOMMENDED: signature '{IDS_SIGNATURE_NAME}' is not registered/enabled "
                   f"in mmt-core, so no rate limiting happened for {src_ip}")
            logger.error("[mitigation] %s", msg)
            return MitigationOutcome(action=MitigationAction.RATE_LIMIT,
                                      applied=False, detail=msg)

        try:
            resp = await self._client.post("/api/security/ids/test", json={
                "event_type": IDS_SIGNATURE_NAME,
                "source_ip": src_ip,
                "detail": detail,
            })
            resp.raise_for_status()
            tripped = bool(resp.json().get("detected"))
            msg = (f"Rate-limit signature '{IDS_SIGNATURE_NAME}' "
                   f"{'TRIPPED -> auto-block fired' if tripped else 'recorded hit'} for {src_ip}")
            logger.info("[mitigation] %s", msg)
            return MitigationOutcome(action=MitigationAction.RATE_LIMIT, applied=True,
                                      detail=msg, extra={"tripped": tripped})
        except Exception as e:
            msg = (f"RECOMMENDED: feed {src_ip} into rate-limit signature "
                   f"'{IDS_SIGNATURE_NAME}' -- sacore-web unreachable: {e}")
            logger.error("[mitigation] Rate-limit signal failed for %s: %s", src_ip, e)
            return MitigationOutcome(action=MitigationAction.RATE_LIMIT, applied=False, detail=msg)

    # ---------------------------------------------------------------
    # Strategy 4: always-succeeds audit/dashboard sync
    # ---------------------------------------------------------------
    async def _strategy_audit_sync(self, verdict_payload: dict,
                                    prior_outcomes: List[MitigationOutcome]) -> MitigationOutcome:
        final_score = float(verdict_payload.get("final_score", 0.0) or 0.0)
        if prior_outcomes:
            summary = "; ".join(o.detail for o in prior_outcomes)
        elif verdict_payload.get("src_ip"):
            summary = (f"score {final_score:.3f} below mitigation gates "
                       f"(quarantine {QUARANTINE_SCORE_THRESHOLD}, "
                       f"rate-limit {RATE_LIMIT_SCORE_THRESHOLD}) -- "
                       f"no block or rate-limit signal, audit-only")
        else:
            summary = "no action taken"
        try:
            resp = await self._client.post("/api/security/audit", json={
                "event_type": "ML_PIPELINE_VERDICT",
                "severity": "CRITICAL",
                "source_ip": verdict_payload.get("src_ip", ""),
                "detail": (f"verdict=ATTACK score={final_score:.3f} "
                           f"session={verdict_payload.get('session_key')} :: {summary}"),
                "extra": {
                    "session_key": verdict_payload.get("session_key"),
                    "final_score": final_score,
                    "line1_network_score": verdict_payload.get("line1_network_score"),
                    "line1_packet_score": verdict_payload.get("line1_packet_score"),
                },
            })
            resp.raise_for_status()
            return MitigationOutcome(action=MitigationAction.AUDIT_SYNC, applied=True,
                                      detail="Logged to mmt-core security audit trail")
        except Exception as e:
            logger.error("[mitigation] Audit sync failed: %s", e)
            return MitigationOutcome(action=MitigationAction.AUDIT_SYNC, applied=False,
                                      detail=f"Audit sync to mmt-core failed -- local record only: {e}")

    # ---------------------------------------------------------------
    # Local record -- survives even a fully unreachable sacore-web
    # ---------------------------------------------------------------
    async def _record_events(self, verdict_payload: dict, outcomes: List[MitigationOutcome]):
        for o in outcomes:
            try:
                await self.r.xadd(
                    MITIGATION_EVENTS_STREAM,
                    {
                        "timestamp": time.time(),
                        "session_key": verdict_payload.get("session_key", ""),
                        "src_ip": verdict_payload.get("src_ip", ""),
                        "final_score": final_score_str(verdict_payload),
                        "action": o.action.value,
                        "applied": int(o.applied),
                        "detail": o.detail,
                        "extra": json.dumps(o.extra),
                    },
                    maxlen=MITIGATION_EVENTS_MAXLEN,
                    approximate=True,
                )
            except Exception as e:
                logger.error("[mitigation] Failed to record mitigation event locally: %s", e)


def final_score_str(verdict_payload: dict) -> float:
    return float(verdict_payload.get("final_score", 0.0) or 0.0)
