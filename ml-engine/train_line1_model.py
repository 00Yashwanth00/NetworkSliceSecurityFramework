#!/usr/bin/env python3
"""
train_line1_model.py

Trains a Line 1 (one-class) anomaly detector: Isolation Forest, trained on
normal traffic only. Generic -- works for both the network and packet
preprocessed datasets (same --data/--features contract as train_model.py).

Why Isolation Forest: no assumption that normal traffic forms one compact,
roughly-spherical region (unlike One-Class SVM with an RBF kernel), robust
to the mixed scales and sparsity in this data (rate features near 0 most
of the time, occasional large bursts), and gives a continuous anomaly
score cheaply -- important since Line 1 runs on every sample, not just
the escalated ones.

What this also does, beyond just fitting the model:
  1. Splits normal data into train/validation so the reported false-alarm
     rate is on data the model didn't memorize.
  2. Calibrates score thresholds from percentiles of validation-normal
     scores (NOT arbitrary numbers) -- these are what the orchestrator
     will use to decide "confidently normal" vs "uncertain/anomalous".
  3. If given labeled attack data (--attack-data), scores it too, purely
     for evaluation -- never used in training. This is the only way to
     get a real sense of a one-class model's detection capability.
  4. Saves the model + a score_calibration.json with everything needed to
     turn a raw Isolation Forest score into the 0-1 "anomaly confidence"
     the orchestrator combines across Line 1's two models.

Usage:
    python train_line1_model.py \
        --data ./processed_line1_network/processed_line1_network.csv \
        --features ./processed_line1_network/feature_columns.json \
        --out-dir ./model_line1_network \
        --attack-data slice_telemetry_attacks.csv \
        --attack-preprocessor network
"""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

# Re-declared here (rather than imported) so this script has no dependency
# on the preprocess_* scripts -- it can run standalone against any
# already-processed CSV.
DEAD_NETWORK_FEATURES = [
    "authFailureRate", "authMacFailures", "authSqnFailures", "secFailureRate",
    "serviceRequestRate", "pagingRate", "ngapSetupFailureRate",
    "qosFlowFailureRate", "sliceSelectionFailureRate", "anomalyAlertCount",
]
DROP_NETWORK_ALWAYS = ["timestamp", "sessionLabel"]
DROP_PACKET_ALWAYS = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp"]


def build_matrix(df: pd.DataFrame, feature_columns: list) -> pd.DataFrame:
    """Aligns an arbitrary dataframe to a fixed feature schema: adds any
    missing one-hot column as 0, drops anything extra, fixes column order.
    Used both for scoring held-out attack data here and, in the
    orchestrator, for scoring single real-time samples."""
    for c in feature_columns:
        if c not in df.columns:
            df[c] = 0
    return df[feature_columns]


def prep_attack_for_eval(path: str, kind: str, feature_columns: list) -> pd.DataFrame:
    """Loads a raw attack CSV and applies the SAME cleaning the matching
    preprocess_line1_*.py script would, then aligns it to feature_columns.
    Only used for evaluation -- never for training."""
    df = pd.read_csv(path, low_memory=False)
    if kind == "network":
        df = df.dropna(subset=["timestamp"])
        to_drop = [c for c in DEAD_NETWORK_FEATURES + DROP_NETWORK_ALWAYS if c in df.columns]
        df = df.drop(columns=to_drop)
        if "sliceType" in df.columns:
            df = pd.get_dummies(df, columns=["sliceType"], prefix="sliceType")
    else:  # packet
        if "Label" in df.columns:
            df = df[df["Label"].notna()]
            df = df.drop(columns=["Label"])
        to_drop = [c for c in DROP_PACKET_ALWAYS if c in df.columns]
        df = df.drop(columns=to_drop)
        if "protocol" in df.columns:
            df = pd.get_dummies(df, columns=["protocol"], prefix="protocol")
        numeric_cols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)
    return build_matrix(df, feature_columns)


def main():
    ap = argparse.ArgumentParser(description="Train a Line 1 one-class anomaly detector")
    ap.add_argument("--data", required=True, help="Path to processed_line1_*.csv (normal only)")
    ap.add_argument("--features", required=True, help="Path to feature_columns.json")
    ap.add_argument("--out-dir", required=True, help="Output directory for the trained model")
    ap.add_argument("--contamination", type=float, default=0.05,
                     help="Expected fraction of 'anomalous-looking' outliers within normal data itself")
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--val-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--attack-data", default=None,
                     help="Optional path to a RAW (unprocessed) attack CSV, for evaluation only")
    ap.add_argument("--attack-kind", choices=["network", "packet"], default=None,
                     help="Required if --attack-data is given: which cleaning rules to apply")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.features) as f:
        meta = json.load(f)
    feature_columns = meta["feature_columns"]

    df = pd.read_csv(args.data)
    X = build_matrix(df, feature_columns)
    print(f"Loaded {len(X)} normal rows, {len(feature_columns)} features")

    X_train, X_val = train_test_split(X, test_size=args.val_size, random_state=args.seed)
    print(f"Train: {len(X_train)}   Validation: {len(X_val)}")

    clf = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=args.seed,
        n_jobs=-1,
    )
    clf.fit(X_train)

    # score_samples: higher = more normal. Flip sign so higher = more
    # anomalous, which is the convention the orchestrator expects
    # (matches how Line 2's predict_proba(attack) also reads "higher = worse").
    val_scores = -clf.score_samples(X_val)

    print("\n" + "=" * 60)
    print("VALIDATION (held-out normal data)")
    print("=" * 60)
    print(f"Anomaly score percentiles: "
          f"p50={np.percentile(val_scores,50):.4f}  "
          f"p90={np.percentile(val_scores,90):.4f}  "
          f"p99={np.percentile(val_scores,99):.4f}  "
          f"max={val_scores.max():.4f}")
    flagged_rate = (clf.predict(X_val) == -1).mean()
    print(f"Fraction of held-out NORMAL flagged anomalous: {flagged_rate:.3f} "
          f"(should be close to --contamination={args.contamination})")

    # Calibration: min/max over validation-normal scores define the 0-1
    # normalization range the orchestrator uses so Line 1's two models
    # (network, packet) are on a comparable scale before being weighted
    # together, regardless of each model's own raw score range.
    score_min = float(val_scores.min())
    score_max = float(val_scores.max())
    # p90 = "confidently normal" boundary: below this, don't bother Line 2.
    p90 = float(np.percentile(val_scores, 90))

    attack_eval = None
    if args.attack_data:
        if not args.attack_kind:
            raise SystemExit("--attack-kind is required when --attack-data is given")
        X_attack = prep_attack_for_eval(args.attack_data, args.attack_kind, feature_columns)
        attack_scores = -clf.score_samples(X_attack)
        detect_rate = (clf.predict(X_attack) == -1).mean()
        print("\n" + "=" * 60)
        print("EVALUATION ONLY (labeled attack data, not used in training)")
        print("=" * 60)
        print(f"n_attack_rows = {len(X_attack)}")
        print(f"Attack score percentiles: "
              f"p50={np.percentile(attack_scores,50):.4f}  "
              f"p10={np.percentile(attack_scores,10):.4f}")
        print(f"Fraction of ATTACK rows flagged anomalous (recall proxy): {detect_rate:.3f}")
        print(f"Fraction of attack scores above the p90-normal boundary: "
              f"{(attack_scores > p90).mean():.3f}")
        attack_eval = {
            "n_attack_rows": int(len(X_attack)),
            "detect_rate_at_contamination_threshold": float(detect_rate),
            "detect_rate_at_p90_boundary": float((attack_scores > p90).mean()),
        }

    model_path = out_dir / "line1_model.pkl"
    joblib.dump(clf, model_path)

    with open(out_dir / "feature_columns.json", "w") as f:
        json.dump(meta, f, indent=2)

    calibration = {
        "score_min": score_min,
        "score_max": score_max,
        "p90_normal_boundary": p90,
        "contamination": args.contamination,
        "note": ("Raw score = -clf.score_samples(x); higher = more anomalous. "
                 "Orchestrator normalizes with (raw - score_min) / (score_max - score_min), "
                 "clipped to [0, 1]. Below p90_normal_boundary (raw scale) = "
                 "confidently normal -> Line 2 not invoked."),
    }
    with open(out_dir / "score_calibration.json", "w") as f:
        json.dump(calibration, f, indent=2)

    results = {"validation_flagged_rate": float(flagged_rate), "attack_eval": attack_eval}
    with open(out_dir / "training_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved model to          {model_path}")
    print(f"Saved feature schema to {out_dir / 'feature_columns.json'}")
    print(f"Saved calibration to    {out_dir / 'score_calibration.json'}")
    print(f"Saved metrics to        {out_dir / 'training_results.json'}")


if __name__ == "__main__":
    main()
