#!/usr/bin/env python3
"""
orchestrator.py

Two-line defense orchestrator, refactored so its stages can be called
independently by an async, message-broker-driven pipeline instead of only
as one synchronous predict(network_sample, packet_sample) call.

Why this refactor: network telemetry (steady ~3s heartbeat) and packet/flow
features (finalized only when a flow completes, inherently lagged and
bursty) arrive on independent schedules in production. Forcing them into
one synchronous call means either blocking the fast network stream on the
slow packet stream, or pairing unrelated rows -- both wrong. The live
pipeline instead:
  1. Scores each stream the moment its own data arrives (score_network /
     score_packet), independently.
  2. Periodically fuses whatever scores are currently available for a
     session/time-window (fuse), deciding there whether to escalate.
  3. Only when escalated, gathers the raw rows for that window and calls
     confirm() -- Line 2 -- to produce a final verdict.

predict() is kept as a thin wrapper composing these four stages in
sequence, so existing offline/batch evaluation code (evaluate_orchestrator.py)
keeps working unchanged; it is NOT how the live pipeline will call this
class.

Escalation rule (this refactor's actual behavioral change, not just a
reorganization): escalate if EITHER individual Line 1 score is at or above
its OWN calibrated boundary, OR the combined weighted score is at or above
the combined boundary -- not the combined score alone. A weighted average
dilutes a strong single-modality signal (network says 0.9, packet says 0.1
-> average 0.5, which could sit below the combined boundary even though
one model was nearly certain). This was measured directly: under the old
combined-only rule, only 6.2% of evaluation samples ever reached Line 2,
driving cascade recall down to 0.084. The OR-based rule is meant to fix
that without changing anything about how Line 1's reported score or the
final blended score are computed -- both still use the weighted average,
exactly as specified; only the escalation TRIGGER changes.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

import joblib
import numpy as np
import pandas as pd

DEAD_NETWORK_FEATURES = [
    "authFailureRate", "authMacFailures", "authSqnFailures", "secFailureRate",
    "serviceRequestRate", "pagingRate", "ngapSetupFailureRate",
    "qosFlowFailureRate", "sliceSelectionFailureRate", "anomalyAlertCount",
]
DROP_NETWORK_ALWAYS = ["timestamp", "sessionLabel"]
DROP_PACKET_ALWAYS = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp", "Label"]


@dataclass
class Line1Result:
    """Output of scoring ONE stream (network or packet) independently.
    This is what a live scorer would publish/cache per session -- it
    deliberately carries no knowledge of the other stream."""
    score: float                      # normalized [0, 1], higher = more anomalous
    above_own_boundary: bool          # this modality alone thinks it's worth escalating
    raw_row: dict                     # the prepared (cleaned) row, kept for a later confirm() call


@dataclass
class FusionResult:
    line1_score: float                # weighted-average combined score (reported/used downstream)
    escalate: bool
    reason: str


@dataclass
class PredictionResult:
    verdict: str                      # "NORMAL" or "ATTACK"
    final_score: float
    line1_score: float
    line1_network_score: float
    line1_packet_score: float
    line1_escalated: bool
    line2_invoked: bool
    line2_network_prob: Optional[float] = None
    line2_packet_prob: Optional[float] = None
    line2_verdict: Optional[str] = None
    details: dict = field(default_factory=dict)


def _one_hot_row(raw: dict, categorical_col: str, prefix: str, value) -> dict:
    out = dict(raw)
    out.pop(categorical_col, None)
    out[f"{prefix}_{value}"] = 1
    return out


def _align_to_schema(row: dict, feature_columns: list) -> pd.DataFrame:
    aligned = {c: row.get(c, 0) for c in feature_columns}
    return pd.DataFrame([aligned], columns=feature_columns)


class TwoLineDefenseOrchestrator:
    def __init__(
        self,
        model_dir: str = ".",
        line1_network_weight: float = 0.5,
        line1_packet_weight: float = 0.5,
        line2_decision_threshold: float = 0.5,
        final_alpha: float = 0.3,
    ):
        w_sum = line1_network_weight + line1_packet_weight
        self.w_net = line1_network_weight / w_sum
        self.w_pkt = line1_packet_weight / w_sum
        self.line2_decision_threshold = line2_decision_threshold
        self.final_alpha = final_alpha

        base = Path(model_dir)
        self.line1_net_model, self.line1_net_features, self.line1_net_calib = \
            self._load_line1(base / "model_line1_network")
        self.line1_pkt_model, self.line1_pkt_features, self.line1_pkt_calib = \
            self._load_line1(base / "model_line1_packet")
        self.line2_net_model, self.line2_net_features = \
            self._load_line2(base / "model_line2_network")
        self.line2_pkt_model, self.line2_pkt_features = \
            self._load_line2(base / "model_line2_packet")

        # Per-modality normalized boundaries, used by the OR-based
        # escalation rule in fuse().
        self.net_boundary_norm = self._normalize(
            self.line1_net_calib["p90_normal_boundary"], self.line1_net_calib)
        self.pkt_boundary_norm = self._normalize(
            self.line1_pkt_calib["p90_normal_boundary"], self.line1_pkt_calib)
        # Combined boundary, for the "or the weighted average also crosses
        # its own line" clause -- kept from the original design.
        self.combined_boundary = self.w_net * self.net_boundary_norm + self.w_pkt * self.pkt_boundary_norm

    @staticmethod
    def _load_line1(d: Path):
        model = joblib.load(d / "line1_model.pkl")
        with open(d / "feature_columns.json") as f:
            features = json.load(f)["feature_columns"]
        with open(d / "score_calibration.json") as f:
            calib = json.load(f)
        return model, features, calib

    @staticmethod
    def _load_line2(d: Path):
        model = joblib.load(d / "attack_classifier.pkl")
        with open(d / "feature_columns.json") as f:
            features = json.load(f)["feature_columns"]
        return model, features

    @staticmethod
    def _normalize(raw_score: float, calib: dict) -> float:
        lo, hi = calib["score_min"], calib["score_max"]
        if hi <= lo:
            return 0.0
        return float(np.clip((raw_score - lo) / (hi - lo), 0.0, 1.0))

    # ---- feature preparation (mirrors the preprocess_*.py cleaning rules) ----
    # Shared by both Line 1 and Line 2 network/packet paths: the dead-column
    # drop and one-hot rules are identical between the Line 1 and Line 2
    # preprocessing scripts for a given modality, so one prepare method per
    # modality serves both lines -- only the feature SCHEMA each model was
    # trained on differs, and that's handled by _align_to_schema per model.

    def _prepare_network_row(self, sample: dict) -> dict:
        row = {k: v for k, v in sample.items()
               if k not in DEAD_NETWORK_FEATURES and k not in DROP_NETWORK_ALWAYS}
        if "sliceType" in sample:
            row = _one_hot_row(row, "sliceType", "sliceType", sample["sliceType"])
        return row

    def _prepare_packet_row(self, sample: dict) -> dict:
        row = {k: v for k, v in sample.items() if k not in DROP_PACKET_ALWAYS}
        if "protocol" in sample:
            row = _one_hot_row(row, "protocol", "protocol", sample["protocol"])
        for k, v in list(row.items()):
            if isinstance(v, float) and np.isinf(v):
                row[k] = 0.0
        return row

    # =========================================================================
    # STAGE 1a/1b -- independent per-stream scoring. Call these the moment
    # each stream's own data arrives; neither needs the other stream present.
    # =========================================================================

    def score_network(self, network_sample: dict) -> Line1Result:
        row = self._prepare_network_row(network_sample)
        X = _align_to_schema(row, self.line1_net_features)
        raw = float(-self.line1_net_model.score_samples(X)[0])
        score = self._normalize(raw, self.line1_net_calib)
        return Line1Result(score=score, above_own_boundary=score >= self.net_boundary_norm, raw_row=row)

    def score_packet(self, packet_sample: dict) -> Line1Result:
        row = self._prepare_packet_row(packet_sample)
        X = _align_to_schema(row, self.line1_pkt_features)
        raw = float(-self.line1_pkt_model.score_samples(X)[0])
        score = self._normalize(raw, self.line1_pkt_calib)
        return Line1Result(score=score, above_own_boundary=score >= self.pkt_boundary_norm, raw_row=row)

    # =========================================================================
    # STAGE 2 -- fusion. Called by whatever drives the time-window join (the
    # network heartbeat, in the design discussed) once it has a network
    # score and, if one is available within the lookback window, a packet
    # score. Pass None for whichever side has no data yet -- fusion still
    # produces a usable result (see the network-only fallback below).
    # =========================================================================

    def fuse(self, net_result: Optional[Line1Result], pkt_result: Optional[Line1Result]) -> FusionResult:
        net_score = net_result.score if net_result else 0.0
        pkt_score = pkt_result.score if pkt_result else 0.0

        if net_result is None and pkt_result is None:
            raise ValueError("fuse() needs at least one of net_result/pkt_result")

        if pkt_result is None:
            # No packet score landed in the lookback window yet -- a real,
            # legitimate state (flow hasn't completed), not an error.
            # Fall back to network-only: use its own boundary directly
            # rather than diluting against an assumed-0 packet score.
            return FusionResult(
                line1_score=net_score,
                escalate=net_result.above_own_boundary,
                reason="packet score unavailable in window -- network-only fallback",
            )
        if net_result is None:
            return FusionResult(
                line1_score=pkt_score,
                escalate=pkt_result.above_own_boundary,
                reason="network score unavailable -- packet-only fallback",
            )

        combined = self.w_net * net_score + self.w_pkt * pkt_score
        escalate = (
            net_result.above_own_boundary
            or pkt_result.above_own_boundary
            or combined >= self.combined_boundary
        )
        reason = (
            "escalated: " + " / ".join(filter(None, [
                "network above its own boundary" if net_result.above_own_boundary else None,
                "packet above its own boundary" if pkt_result.above_own_boundary else None,
                "combined weighted score above combined boundary"
                if combined >= self.combined_boundary else None,
            ]))
            if escalate else "below all escalation boundaries"
        )
        return FusionResult(line1_score=combined, escalate=escalate, reason=reason)

    # =========================================================================
    # STAGE 3 -- Line 2 confirmation. Only called when fuse() escalates.
    # Takes the RAW samples (not the Line1Result.raw_row -- Line 2 has its
    # own feature schema/model, kept fully independent of Line 1's) plus
    # the already-computed line1_score, which is blended into final_score
    # but never fed into either Line 2 model as an input feature.
    # =========================================================================

    def confirm(self, network_sample: Optional[dict], packet_sample: Optional[dict],
                line1_score: float) -> Tuple[str, float, dict]:
        """Returns (verdict, line2_score, details). Handles either sample
        being unavailable (e.g. escalated on network-only fallback) by
        skipping that confirmer rather than failing."""
        net_prob = pkt_prob = None
        net_flags = pkt_flags = False

        if network_sample is not None:
            row = self._prepare_network_row(network_sample)
            X = _align_to_schema(row, self.line2_net_features)
            net_prob = float(self.line2_net_model.predict_proba(X)[0, 1])
            net_flags = net_prob >= self.line2_decision_threshold

        if packet_sample is not None:
            row = self._prepare_packet_row(packet_sample)
            X = _align_to_schema(row, self.line2_pkt_features)
            pkt_prob = float(self.line2_pkt_model.predict_proba(X)[0, 1])
            pkt_flags = pkt_prob >= self.line2_decision_threshold

        available = [p for p in (net_prob, pkt_prob) if p is not None]
        line2_score = max(available) if available else 0.0
        verdict = "ATTACK" if (net_flags or pkt_flags) else "NORMAL"

        details = {
            "line2_network_prob": net_prob,
            "line2_packet_prob": pkt_prob,
            "net_flags_attack": net_flags,
            "pkt_flags_attack": pkt_flags,
            "or_logic": "ATTACK if either available confirmer >= threshold",
        }
        return verdict, line2_score, details

    # =========================================================================
    # predict() -- thin composition of the four stages above, kept for
    # offline/batch evaluation (evaluate_orchestrator.py). The live pipeline
    # calls score_network / score_packet / fuse / confirm directly instead,
    # on independent schedules, per the async design.
    # =========================================================================

    def predict(self, network_sample: dict, packet_sample: dict) -> PredictionResult:
        net_result = self.score_network(network_sample)
        pkt_result = self.score_packet(packet_sample)
        fusion = self.fuse(net_result, pkt_result)

        if not fusion.escalate:
            return PredictionResult(
                verdict="NORMAL",
                final_score=fusion.line1_score,
                line1_score=fusion.line1_score,
                line1_network_score=net_result.score,
                line1_packet_score=pkt_result.score,
                line1_escalated=False,
                line2_invoked=False,
                details={"reason": fusion.reason},
            )

        verdict, line2_score, details = self.confirm(network_sample, packet_sample, fusion.line1_score)
        final_score = self.final_alpha * fusion.line1_score + (1 - self.final_alpha) * line2_score

        return PredictionResult(
            verdict=verdict,
            final_score=final_score,
            line1_score=fusion.line1_score,
            line1_network_score=net_result.score,
            line1_packet_score=pkt_result.score,
            line1_escalated=True,
            line2_invoked=True,
            line2_network_prob=details["line2_network_prob"],
            line2_packet_prob=details["line2_packet_prob"],
            line2_verdict=verdict,
            details={**details, "fusion_reason": fusion.reason},
        )


if __name__ == "__main__":
    orch = TwoLineDefenseOrchestrator(model_dir=".")

    dummy_network_sample = {c: 0 for c in orch.line1_net_features}
    dummy_network_sample.update({"sliceType": 1, "regAttemptRate": 0, "connectedUeCount": 0})
    dummy_packet_sample = {c: 0 for c in orch.line1_pkt_features}
    dummy_packet_sample.update({"protocol": 6})

    print("--- predict() smoke test (unchanged interface) ---")
    print(orch.predict(dummy_network_sample, dummy_packet_sample))

    print("\n--- independent-stage smoke test (new interface) ---")
    net_only = orch.score_network(dummy_network_sample)
    print("score_network:", net_only.score, "above_own_boundary:", net_only.above_own_boundary)
    fusion = orch.fuse(net_only, None)
    print("fuse (packet unavailable):", fusion)
