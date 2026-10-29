#!/usr/bin/env python3
"""
preprocess_data.py

Merges the normal and attack slice-telemetry CSVs into a single labeled,
train-ready dataset for the Line 2 (supervised) network confirmer.

Usage:
    python preprocess_data.py \
        --normal slice_telemetry.csv \
        --attacks slice_telemetry_attacks.csv \
        --out-dir ./processed
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


def load_and_label(path: str, label: int) -> pd.DataFrame:
    df = pd.read_csv(path)
    before = len(df)
    df = df.dropna(subset=["timestamp"]).reset_index(drop=True)
    dropped = before - len(df)
    if dropped:
        print(f"  [{path}] dropped {dropped} row(s) with missing timestamp")
    df["label"] = label
    return df


def main():
    ap = argparse.ArgumentParser(description="Preprocess slice telemetry into a train-ready dataset")
    ap.add_argument("--normal", required=True)
    ap.add_argument("--attacks", required=True)
    ap.add_argument("--out-dir", default="./processed")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading data...")
    normal = load_and_label(args.normal, label=0)
    attack = load_and_label(args.attacks, label=1)
    print(f"  normal: {len(normal)} rows   attack: {len(attack)} rows")

    df = pd.concat([normal, attack], ignore_index=True)

    to_drop = [c for c in DEAD_FEATURES + DROP_ALWAYS if c in df.columns]
    df = df.drop(columns=to_drop)
    print(f"\nDropped {len(to_drop)} column(s): {to_drop}")

    if "sliceType" in df.columns:
        df = pd.get_dummies(df, columns=["sliceType"], prefix="sliceType")

    feature_columns = [c for c in df.columns if c != "label"]
    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    out_csv = out_dir / "processed_dataset.csv"
    df.to_csv(out_csv, index=False)

    meta = {
        "feature_columns": feature_columns,
        "label_column": "label",
        "label_meaning": {"0": "normal", "1": "attack"},
        "n_rows": len(df),
        "n_normal": int((df["label"] == 0).sum()),
        "n_attack": int((df["label"] == 1).sum()),
        "dropped_columns": to_drop,
    }
    with open(out_dir / "feature_columns.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nWrote {out_csv}  ({len(df)} rows, {len(feature_columns)} features)")
    print(f"Class balance: {meta['n_normal']} normal / {meta['n_attack']} attack")


if __name__ == "__main__":
    main()
