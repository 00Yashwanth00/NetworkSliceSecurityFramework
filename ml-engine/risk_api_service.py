"""
FastAPI REST Service exposing real-time ML Anomaly Detection and Risk Evaluation.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from data_preprocessor import (
    MacroDataPreprocessor,
    MicroDataPreprocessor,
    ATTACK_CATEGORIES
)
from risk_calculator import calculate_risk_score

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

app = FastAPI(
    title="5G Network Slice Security Framework — Risk Evaluation Service",
    description="Real-time ML Anomaly Detection, Risk Scoring (0-100) and Mitigation Engine",
    version="1.0.0"
)

# Global Model Containers
macro_preprocessor = None
macro_iso_forest = None
macro_xgb_clf = None

micro_preprocessor = None
micro_iso_forest = None
micro_rf_clf = None


def load_models():
    global macro_preprocessor, macro_iso_forest, macro_xgb_clf
    global micro_preprocessor, micro_iso_forest, micro_rf_clf

    try:
        macro_prep_path = os.path.join(MODELS_DIR, "macro_preprocessor.joblib")
        macro_iso_path = os.path.join(MODELS_DIR, "macro_iso_forest.joblib")
        macro_xgb_path = os.path.join(MODELS_DIR, "macro_xgb_clf.joblib")

        if os.path.exists(macro_prep_path) and os.path.exists(macro_iso_path) and os.path.exists(macro_xgb_path):
            macro_preprocessor = joblib.load(macro_prep_path)
            macro_iso_forest = joblib.load(macro_iso_path)
            macro_xgb_clf = joblib.load(macro_xgb_path)
            print("Loaded Macro-Telemetry models successfully.")

        micro_prep_path = os.path.join(MODELS_DIR, "micro_preprocessor.joblib")
        micro_iso_path = os.path.join(MODELS_DIR, "micro_iso_forest.joblib")
        micro_rf_path = os.path.join(MODELS_DIR, "micro_rf_clf.joblib")

        if os.path.exists(micro_prep_path) and os.path.exists(micro_iso_path) and os.path.exists(micro_rf_path):
            micro_preprocessor = joblib.load(micro_prep_path)
            micro_iso_forest = joblib.load(micro_iso_path)
            micro_rf_clf = joblib.load(micro_rf_path)
            print("Loaded Micro-Flow models successfully.")

    except Exception as e:
        print(f"Error loading models: {e}")


@app.on_event("startup")
async def startup_event():
    load_models()


class TelemetryRiskRequest(BaseModel):
    sliceType: Optional[str] = "eMBB"
    regAttemptRate: Optional[float] = 0.0
    regFailureRate: Optional[float] = 0.0
    regSuccessRate: Optional[float] = 1.0
    authAttemptRate: Optional[float] = 0.0
    authFailureRate: Optional[float] = 0.0
    authSuccessRate: Optional[float] = 1.0
    authMacFailures: Optional[int] = 0
    authSqnFailures: Optional[int] = 0
    secFailureRate: Optional[float] = 0.0
    sessionAttemptRate: Optional[float] = 0.0
    sessionFailureRate: Optional[float] = 0.0
    sessionSuccessRate: Optional[float] = 1.0
    activePduSessions: Optional[int] = 0
    sessionsInThisSlice: Optional[int] = 0
    qosFlowFailureRate: Optional[float] = 0.0
    ulPacketRate: Optional[float] = 0.0
    dlPacketRate: Optional[float] = 0.0
    ulByteRate: Optional[float] = 0.0
    dlByteRate: Optional[float] = 0.0
    ulDropped: Optional[int] = 0
    dlDropped: Optional[int] = 0
    packetLossRate: Optional[float] = 0.0
    gtpuErrors: Optional[int] = 0
    rateLimitEvents: Optional[int] = 0
    intrusionEvents: Optional[int] = 0
    blockedIpCount: Optional[int] = 0
    unknownGnbEvents: Optional[int] = 0
    nfLoadLevel: Optional[int] = 0
    qosStatus: Optional[int] = 0
    anomalyAlertCount: Optional[int] = 0


@app.get("/health")
def health_check():
    return {
        "status": "UP",
        "macro_models_loaded": macro_xgb_clf is not None,
        "micro_models_loaded": micro_rf_clf is not None
    }


@app.post("/api/v1/evaluate-risk")
def evaluate_risk(request: TelemetryRiskRequest):
    sample_dict = request.dict()

    if macro_preprocessor is None or macro_xgb_clf is None:
        # Fallback to rule-based evaluation if models not trained yet
        macro_prob = 0.0
        category = "BENIGN"
    else:
        X_sample = macro_preprocessor.transform_sample(sample_dict)

        # Stage 1: Unsupervised Anomaly Probability
        raw_iso = macro_iso_forest.decision_function(X_sample)[0]  # Higher = normal, lower = anomaly
        iso_prob = float(np.clip(0.5 - (raw_iso * 2.0), 0.0, 1.0))

        # Stage 2: Supervised Attack Category Probability
        probs = macro_xgb_clf.predict_proba(X_sample)[0]
        cat_idx = int(np.argmax(probs))
        macro_prob = float(1.0 - probs[0])  # 1 - P(BENIGN)
        macro_prob = max(macro_prob, iso_prob)

        category = ATTACK_CATEGORIES.get(cat_idx, "UNKNOWN_ANOMALY")

    # Compute continuous 0-100 Risk Score & Mitigation
    risk_score, risk_tier, policy_action = calculate_risk_score(
        macro_anomaly_prob=macro_prob,
        macro_attack_category=category,
        micro_anomaly_prob=0.0,
        sample_data=sample_dict
    )

    return {
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "policy_action": policy_action,
        "threat_category": category,
        "anomaly_probability": round(macro_prob, 4),
        "slice_type": request.sliceType
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5002)
