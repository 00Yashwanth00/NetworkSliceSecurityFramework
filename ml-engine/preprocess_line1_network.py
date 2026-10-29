#!/usr/bin/env python3
"""
preprocess_line1_network.py

Preprocessing for Line 1's network-telemetry anomaly detector. Unlike the
Line 2 preprocessing (preprocess_data.py), this uses ONLY normal traffic --
Line 1 is a one-class model that learns what normal looks like and scores
deviation from it, so attack rows have no place in this file at all.

Same feature hygiene as the Line 2 network preprocessor, applied
consistently so the two lines see comparable inputs:
  - Drops the 10 features confirmed dead (always 0 across every collection
    run so far).
  - One-hot encodes sliceType (categorical, not ordinal).
  - Leaves -1 sentinels ("no attempts this interval") as literal values.

Usage:
    python preprocess_line1_network.py \
        --normal slice_telemetry.csv \
        --out-dir ./processed_line1_network
"""

import argparse
import json
from pathlib import Path

import pandas as pd

DEAD_FEATURES = [
    "authFailureRate", "authMacFailures", "authSqnFailures", "secFailureRate",
    "serviceRequestRate", "pagingRate", "ngapSetupFailureRate",
    "qosFlowFailureRate", "sliceSelectionFailureRate", "anomalyAlertCount",
]
DROP_ALWAYS = ["timestamp", "sessionLabel"]


def main():
    ap = argparse.ArgumentParser(description="Preprocess normal-only network telemetry for Line 1")
    ap.add_argument("--normal", required=True, help="Path to slice_telemetry.csv (normal)")
    ap.add_argument("--out-dir", default="./processed_line1_network")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.normal)
    before = len(df)
    df = df.dropna(subset=["timestamp"]).reset_index(drop=True)
    if before != len(df):
        print(f"Dropped {before - len(df)} row(s) with missing timestamp")

    to_drop = [c for c in DEAD_FEATURES + DROP_ALWAYS if c in df.columns]
    df = df.drop(columns=to_drop)
    print(f"Dropped {len(to_drop)} column(s): {to_drop}")

    if "sliceType" in df.columns:
        df = pd.get_dummies(df, columns=["sliceType"], prefix="sliceType")

    feature_columns = list(df.columns)

    out_csv = out_dir / "processed_line1_network.csv"
    df.to_csv(out_csv, index=False)

    meta = {
        "feature_columns": feature_columns,
        "n_rows": len(df),
        "dropped_columns": to_drop,
        "note": "normal-only dataset for a one-class (Line 1) model -- no label column",
    }
    with open(out_dir / "feature_columns.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nWrote {out_csv}  ({len(df)} rows, {len(feature_columns)} features)")
    print(f"Wrote {out_dir / 'feature_columns.json'}")


if __name__ == "__main__":
    main()
