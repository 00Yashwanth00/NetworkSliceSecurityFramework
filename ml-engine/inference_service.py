#!/usr/bin/env python3
"""
inference_service.py

End-to-end inference service that consumes live telemetry from Redis Streams
(telemetry.network and telemetry.packet), scores them independently using the
Line 1 models, correlates them by time window, and publishes final verdicts
(including Line 2 confirmation if escalated) to a 'verdicts' stream.

Follows the design outlined in PipelinePlan.pdf.
"""

import asyncio
import json
import logging
import os
import sys
import time
from typing import Optional

import redis.asyncio as redis
from orchestrator import TwoLineDefenseOrchestrator, Line1Result
from mitigation import MitigationEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("inference_service")

# --- Configuration ---
REDIS_HOST = "localhost"
REDIS_PORT = 6379
STREAM_NETWORK = "telemetry.network"
STREAM_PACKET = "telemetry.packet"
STREAM_VERDICTS = "verdicts"
GROUP_NAME = "inference-service"

# Time to keep intermediate Line 1 scores in Redis before they expire (seconds)
# Gives the packet flow time to complete after a network tick is observed.
FUSION_TTL = 30

# Score-threshold rule: any case whose final score is ABOVE this value is
# published as ATTACK, even if Line 1 did not escalate it or Line 2 did not
# confirm it. It only ever promotes NORMAL -> ATTACK; an ATTACK from the model
# is never demoted. Override without editing code:  ATTACK_SCORE_THRESHOLD=0.6
ATTACK_SCORE_THRESHOLD = float(os.environ.get("ATTACK_SCORE_THRESHOLD", "0.5"))


class InferenceService:
    def __init__(self, orchestrator: TwoLineDefenseOrchestrator):
        self.orch = orchestrator
        self.r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        self.mitigation = MitigationEngine(redis_client=self.r)

    async def flush_on_startup(self):
        """Wipe all pipeline-owned keys so this session starts with a clean slate."""
        keys_to_delete = [STREAM_NETWORK, STREAM_PACKET, STREAM_VERDICTS]

        # Also delete any lingering fusion cache keys from the previous session
        fusion_keys = await self.r.keys("fusion:*")
        keys_to_delete.extend(fusion_keys)

        if keys_to_delete:
            await self.r.delete(*keys_to_delete)
            logger.info(f"Flushed {len(keys_to_delete)} pipeline key(s) from previous session: {keys_to_delete}")
        else:
            logger.info("No stale pipeline keys found — starting fresh.")

    async def setup(self):
        """Flush stale data, then create consumer groups for this session."""
        await self.r.ping()

        # Always start with a clean slate — wipe data from any previous test run
        await self.flush_on_startup()

        for stream in (STREAM_NETWORK, STREAM_PACKET):
            try:
                # Create the group pointing to the very end ($) so we only
                # consume messages produced AFTER this service starts.
                await self.r.xgroup_create(stream, GROUP_NAME, mkstream=True, id="$")
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise
        logger.info("Consumer groups created. Ready to consume live telemetry.")

    async def _read_and_process(self, stream_name: str, consumer_name: str, process_fn):
        """Generic loop to read from a stream and process messages."""
        logger.info(f"Started consumer {consumer_name} on {stream_name}")
        while True:
            try:
                # Read 10 items max, block for 2 seconds if empty
                result = await self.r.xreadgroup(
                    GROUP_NAME, consumer_name, {stream_name: ">"}, count=10, block=2000
                )
                if not result:
                    continue

                for _stream, messages in result:
                    for message_id, data in messages:
                        try:
                            # Safely attempt to process the message
                            await process_fn(message_id, data)
                        except Exception as e:
                            logger.error(f"Error processing message {message_id} from {stream_name}: {e}")
                        finally:
                            # Always ACK the message so we don't process it again
                            await self.r.xack(stream_name, GROUP_NAME, message_id)
            except Exception as e:
                logger.error(f"Stream read error on {stream_name}: {e}")
                await asyncio.sleep(2)

    # =========================================================================
    # TASK 1: Network Scorer
    # =========================================================================
    async def run_network_scorer(self):
        async def process(message_id: str, data: dict):
            # Parse numerics
            sample = self._parse_payload(data)
            
            # Step 1: Score independently
            result = self.orch.score_network(sample)
            
            # Use IMSI or fallback to a global default session for correlation
            # (In production, the collector should inject IMSI/UE IP into the payload)
            session_key = sample.get("session_key", "default_session")
            
            # Step 2: Cache the result for fusion (using Redis Hash)
            cache_key = f"fusion:{session_key}:net"
            await self._cache_result(cache_key, result, sample)
            
            # The network tick DRIVES fusion. Trigger it immediately.
            await self._run_fusion(session_key)

        await self._read_and_process(STREAM_NETWORK, "net-scorer-1", process)

    # =========================================================================
    # TASK 2: Packet Scorer
    # =========================================================================
    async def run_packet_scorer(self):
        async def process(message_id: str, data: dict):
            sample = self._parse_payload(data)
            result = self.orch.score_packet(sample)
            
            # Use src_ip as session_key, or fallback to default
            session_key = sample.get("session_key", "default_session")
            
            cache_key = f"fusion:{session_key}:pkt"
            await self._cache_result(cache_key, result, sample)

        await self._read_and_process(STREAM_PACKET, "pkt-scorer-1", process)

    # =========================================================================
    # FUSION LOGIC
    # =========================================================================
    async def _run_fusion(self, session_key: str):
        """Called whenever a new network score arrives."""
        net_key = f"fusion:{session_key}:net"
        pkt_key = f"fusion:{session_key}:pkt"
        
        # Read whatever we have right now
        net_data = await self.r.hgetall(net_key)
        pkt_data = await self.r.hgetall(pkt_key)
        
        if not net_data:
            return  # Should not happen since we just wrote it
            
        net_result, net_sample = self._deserialize_result(net_data)
        
        if pkt_data:
            pkt_result, pkt_sample = self._deserialize_result(pkt_data)
            packet_available = True
        else:
            pkt_result, pkt_sample = None, None
            packet_available = False
            
        # Fusion Stage
        fusion = self.orch.fuse(net_result, pkt_result)
        
        verdict = "NORMAL"
        line2_invoked = False
        final_score = fusion.line1_score
        details = {"fusion_reason": fusion.reason}
        
        # Escalation / Line 2 Stage
        if fusion.escalate:
            verdict, l2_score, confirm_details = self.orch.confirm(net_sample, pkt_sample, fusion.line1_score)
            line2_invoked = True
            final_score = self.orch.final_alpha * fusion.line1_score + (1 - self.orch.final_alpha) * l2_score
            details.update(confirm_details)

        # Score-threshold rule (see ATTACK_SCORE_THRESHOLD above).
        details["model_verdict"] = verdict
        if final_score > ATTACK_SCORE_THRESHOLD and verdict != "ATTACK":
            verdict = "ATTACK"
            details["verdict_override"] = (
                f"final_score {final_score:.3f} > {ATTACK_SCORE_THRESHOLD} "
                f"(score-threshold rule; model had said NORMAL, escalated={bool(fusion.escalate)})"
            )

        # Extract the best available source IP for mitigation.
        # Priority: packet-level src_ip > session_key (if IP-shaped) > empty
        src_ip = ""
        if pkt_sample:
            src_ip = str(pkt_sample.get("src_ip", "") or "")
        if not src_ip and session_key != "default_session":
            # session_key may be an IP if injected by the collector
            import re
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', session_key):
                src_ip = session_key

        # Publish Verdict
        payload = {
            "timestamp": time.time(),
            "session_key": session_key,
            "src_ip": src_ip,
            "verdict": verdict,
            "final_score": final_score,
            "line1_network_score": net_result.score if net_result else 0.0,
            "line1_packet_score": pkt_result.score if pkt_result else 0.0,
            "line1_escalated": int(fusion.escalate),
            "line2_invoked": int(line2_invoked),
            "packet_data_available": int(packet_available),
            "details": json.dumps(details)
        }
        
        await self.r.xadd(STREAM_VERDICTS, payload)
        override = " [score-threshold override]" if "verdict_override" in details else ""
        logger.info(f"Published verdict for {session_key}: {verdict}{override} (Score: {final_score:.3f}, src_ip={src_ip!r})")

        # Fire mitigation strategies (no-op for verdict == "NORMAL"). Every
        # call inside is best-effort -- a failure here never raises back
        # into the fusion loop, and every outcome (applied or
        # recommendation-only) lands in the mitigation:events Redis stream
        # for mitigation_dashboard.py.
        try:
            outcomes = await self.mitigation.handle_verdict(payload)
            for o in outcomes:
                tag = "APPLIED" if o.applied else "RECOMMENDED"
                logger.info(f"  [mitigation:{o.action.value}] {tag} — {o.detail}")
        except Exception as e:
            logger.error(f"Mitigation engine raised unexpectedly for {session_key}: {e}")

    # =========================================================================
    # HELPERS
    # =========================================================================
    def _parse_payload(self, data: dict) -> dict:
        """Redis Streams payloads are strings. Convert to numbers where appropriate."""
        parsed = {}
        for k, v in data.items():
            if v == "":
                parsed[k] = None
            else:
                try:
                    if "." in v:
                        parsed[k] = float(v)
                    else:
                        parsed[k] = int(v)
                except ValueError:
                    parsed[k] = v
        return parsed
        
    async def _cache_result(self, cache_key: str, result: Line1Result, original_sample: dict):
        """Store the Line 1 result and raw sample in a Redis hash with TTL."""
        data = {
            "score": result.score,
            "above_own_boundary": int(result.above_own_boundary),
            "raw_row": json.dumps(result.raw_row),
            "original_sample": json.dumps(original_sample)
        }
        await self.r.hset(cache_key, mapping=data)
        await self.r.expire(cache_key, FUSION_TTL)
        
    def _deserialize_result(self, data: dict):
        result = Line1Result(
            score=float(data["score"]),
            above_own_boundary=bool(int(data["above_own_boundary"])),
            raw_row=json.loads(data["raw_row"])
        )
        sample = json.loads(data["original_sample"])
        return result, sample

async def main():
    logger.info("Loading ML Models...")
    try:
        orch = TwoLineDefenseOrchestrator(model_dir=".")
    except Exception as e:
        logger.error(f"Failed to load models! {e}")
        logger.error("Make sure you are running this from the ml-engine directory where models exist.")
        sys.exit(1)
        
    service = InferenceService(orch)
    try:
        await service.setup()
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        logger.error("Make sure redis-server is running (sudo systemctl start redis-server)")
        sys.exit(1)

    # Run tasks concurrently
    tasks = [
        asyncio.create_task(service.run_network_scorer()),
        asyncio.create_task(service.run_packet_scorer())
    ]
    
    logger.info("Inference service is now running. Waiting for telemetry...")
    try:
        await asyncio.gather(*tasks)
    finally:
        await service.mitigation.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
