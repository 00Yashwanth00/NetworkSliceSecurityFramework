#!/usr/bin/env python3
"""
mitigation.py

Automated mitigation layer for the ML inference pipeline. Reacts to each
verdict published by inference_service.py by calling mmt-studio-core's
EXISTING, already-wired security admin API on sacore-web -- no core/ Go
code changes required.

    Strategy 1  IP quarantine              POST /api/security/blocked-ips/ttl
    Strategy 2  Rate limiting (sliding      POST /api/security/ids/test
                window, auto-block)         (signature registered once via
                                             setup_ids_signature.py)
    Strategy 3  Repeat-offender escalation  same blocked-ips/ttl call, with a
                                             TTL escalated via a counter kept
                                             in our own Redis (not mmt-core)
    Strategy 4  Audit/dashboard sync        POST /api/security/audit
                (always-succeeds fallback)

Design contract: every call to sacore-web is best-effort. If sacore-web is
unreachable, slow, or returns an error, we log it, mark the action as
RECOMMENDED (applied=False) instead of applied, and keep going -- the
inference pipeline must never stall or crash because a mitigation call
failed. Every outcome -- applied or recommended-only -- is written to the
`mitigation:events` Redis stream so mitigation_dashboard.py can render the
full picture even when sacore-web was down for the whole session.
"""

from __future__ import annotations

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
# ANY verdict=="ATTACK" gets at least this TTL, even if final_score sits
# below 0.5 (possible when Line 2 flags an ATTACK on a blended score that
# landed under the fusion boundary).
QUARANTINE_TIERS = [
    (0.85, 0),       # >= 0.85  -> permanent
    (0.70, 3600),    # >= 0.70  -> 1 hour
    (0.0, 300),      # floor    -> 5 minutes
]

# Strategy 2 -- the IDS signature setup_ids_signature.py registers once.
# Must match SIGNATURE["name"] in that script.
IDS_SIGNATURE_NAME = "ML_PIPELINE_ATTACK"

# Shared gate for strategies 1 + 2: only quarantine AND feed the rate
# limiter when final_score is at least this confident. Below it, an ATTACK
# verdict still gets strategy 4 (audit sync) -- so it's never silently
# dropped -- but doesn't trigger a block or an IDS signal. This exists so a
# single borderline verdict (e.g. 0.51) doesn't immediately escalate the
# same way a high-confidence one (e.g. 0.90) does.
# Default sits a bit above the bare NORMAL/ATTACK floor (0.5, set by
# inference_service.py's ATTACK_SCORE_THRESHOLD) rather than at it, so only
# verdicts the model is reasonably confident about get the aggressive
# response. Tune with RATE_LIMIT_SCORE_THRESHOLD; set to 0.0 to restore the
# previous behavior (every ATTACK verdict with a src_ip gets both).
RATE_LIMIT_SCORE_THRESHOLD = float(os.environ.get("RATE_LIMIT_SCORE_THRESHOLD", "0.6"))

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
        elif final_score >= RATE_LIMIT_SCORE_THRESHOLD:
            outcomes.append(await self._strategy_quarantine(src_ip, final_score, session_key))
            outcomes.append(await self._strategy_rate_limit(src_ip, final_score, session_key, details))
        else:
            # Below the gate: ATTACK verdict, real src_ip, but not
            # confident enough to block or rate-limit yet. No outcome row
            # here -- strategy 4 below records why, so this never shows up
            # looking like a dropped/failed action (it's a deliberate skip,
            # not a failure, and must not be confused with the RECOMMENDED
            # state that specifically means "mmt-core was unreachable").
            logger.info(
                "[mitigation] %s: score %.3f below RATE_LIMIT_SCORE_THRESHOLD (%.2f) -- "
                "skipping quarantine + rate limit, audit-only",
                src_ip, final_score, RATE_LIMIT_SCORE_THRESHOLD,
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
    # Strategy 2: sliding-window rate limiting via mmt-core's IDS
    # signature engine (threshold/window/auto-block set once, see
    # setup_ids_signature.py)
    # ---------------------------------------------------------------
    async def _strategy_rate_limit(self, src_ip: str, final_score: float,
                                    session_key: str, details) -> MitigationOutcome:
        detail = f"ML ATTACK verdict score={final_score:.3f} session={session_key} details={details}"
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
            summary = (f"score {final_score:.3f} below RATE_LIMIT_SCORE_THRESHOLD "
                       f"({RATE_LIMIT_SCORE_THRESHOLD}) -- no block or rate-limit signal, audit-only")
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
