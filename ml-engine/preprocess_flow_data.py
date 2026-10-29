#!/usr/bin/env python3
"""
preprocess_flow_data.py

Merges the normal and attack packet-level (flow) CSVs into a single
labeled, train-ready dataset for the Line 2 (supervised) packet confirmer.

Usage:
    python preprocess_flow_data.py \
        --normal flow_dataset.csv \
        --attacks flow_dataset_attacks.csv \
        --out-dir ./processed_flow
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

DROP_ALWAYS = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp"]


def main():
    ap = argparse.ArgumentParser(description="Preprocess flow-level data into a train-ready dataset")
    ap.add_argument("--normal", required=True)
    ap.add_argument("--attacks", required=True)
    ap.add_argument("--out-dir", default="./processed_flow")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Loading data...")
    normal = pd.read_csv(args.normal, low_memory=False)
    normal["label"] = 0
    print(f"  normal: {len(normal)} rows (all labeled 0 -- no Label column in this file)")

    attack_raw = pd.read_csv(args.attacks, low_memory=False)
    if "Label" not in attack_raw.columns:
        raise SystemExit("Attack file has no 'Label' column")

    n_total = len(attack_raw)
    attack = attack_raw[attack_raw["Label"].notna()].copy()
    n_dropped = n_total - len(attack)
    print(f"  attack: {n_total} rows total, {n_dropped} unlabeled ({100*n_dropped/n_total:.1f}%) dropped, "
          f"{len(attack)} usable")

    multiclass_label = attack["Label"].copy()
    attack["label"] = 1
    attack = attack.drop(columns=["Label"])

    df = pd.concat([normal, attack], ignore_index=True)

    to_drop = [c for c in DROP_ALWAYS if c in df.columns]
    df = df.drop(columns=to_drop)
    print(f"\nDropped {len(to_drop)} column(s): {to_drop}")

    if "protocol" in df.columns:
        df = pd.get_dummies(df, columns=["protocol"], prefix="protocol")

    numeric_cols = [c for c in df.columns if c != "label" and pd.api.types.is_numeric_dtype(df[c])]
    inf_count = np.isinf(df[numeric_cols]).sum().sum()
    if inf_count:
        print(f"Replacing {inf_count} +/-inf value(s) with 0")
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)

    feature_columns = [c for c in df.columns if c != "label"]
    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    out_csv = out_dir / "processed_flow_dataset.csv"
    df.to_csv(out_csv, index=False)

    meta = {
        "feature_columns": feature_columns,
        "label_column": "label",
        "label_meaning": {"0": "normal", "1": "attack"},
        "n_rows": len(df),
        "n_normal": int((df["label"] == 0).sum()),
        "n_attack": int((df["label"] == 1).sum()),
        "dropped_columns": to_drop,
        "attack_rows_dropped_unlabeled": int(n_dropped),
        "attack_multiclass_breakdown": multiclass_label.value_counts().to_dict(),
    }
    with open(out_dir / "feature_columns.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nWrote {out_csv}  ({len(df)} rows, {len(feature_columns)} features)")
    print(f"Class balance: {meta['n_normal']} normal / {meta['n_attack']} attack")


if __name__ == "__main__":
    main()
