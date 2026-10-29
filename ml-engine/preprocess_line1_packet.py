#!/usr/bin/env python3
"""
preprocess_line1_packet.py

Preprocessing for Line 1's packet-level (flow) anomaly detector.
Normal-only, same reasoning as preprocess_line1_network.py: Line 1 is a
one-class model, so no attack rows belong in its training data at all.

Same feature hygiene as the Line 2 packet preprocessor:
  - Drops src_ip/dst_ip/src_port/dst_port/timestamp (identifiers that
    don't generalize -- ports in particular were found to correlate with
    which test harness generated a flow, not with attack behavior).
  - One-hot encodes protocol.
  - Replaces +/-inf (e.g. flow_byts_s when flow_duration==0) with 0.

Usage:
    python preprocess_line1_packet.py \
        --normal flow_dataset.csv \
        --out-dir ./processed_line1_packet
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

DROP_ALWAYS = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp"]


def main():
    ap = argparse.ArgumentParser(description="Preprocess normal-only flow data for Line 1")
    ap.add_argument("--normal", required=True, help="Path to flow_dataset.csv (normal)")
    ap.add_argument("--out-dir", default="./processed_line1_packet")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.normal, low_memory=False)
    if "Label" in df.columns:
        # Defensive: this script is for the normal-only file, but if a
        # Label column exists, make sure everything is actually normal.
        non_normal = df["Label"].notna() & (df["Label"] != "BENIGN")
        if non_normal.any():
            raise SystemExit(f"{non_normal.sum()} row(s) in the 'normal' file are labeled as an "
                              f"attack -- refusing to include them in a one-class training set.")
        df = df.drop(columns=["Label"])

    to_drop = [c for c in DROP_ALWAYS if c in df.columns]
    df = df.drop(columns=to_drop)
    print(f"Dropped {len(to_drop)} column(s): {to_drop}")

    if "protocol" in df.columns:
        df = pd.get_dummies(df, columns=["protocol"], prefix="protocol")

    numeric_cols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
    inf_count = np.isinf(df[numeric_cols]).sum().sum()
    if inf_count:
        print(f"Replacing {inf_count} +/-inf value(s) with 0")
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)

    feature_columns = list(df.columns)

    out_csv = out_dir / "processed_line1_packet.csv"
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
