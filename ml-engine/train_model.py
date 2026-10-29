#!/usr/bin/env python3
"""
train_model.py

Trains a Random Forest classifier (Line 2 confirmer) on a preprocessed,
labeled dataset. Generic -- works for both the network and packet
Line 2 datasets since it just takes --data/--features paths.

Usage:
    python train_model.py --data ./processed/processed_dataset.csv \
                           --features ./processed/feature_columns.json \
                           --out-dir ./model
"""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)
from sklearn.model_selection import train_test_split


def main():
    ap = argparse.ArgumentParser(description="Train the Line 2 attack/normal confirmer")
    ap.add_argument("--data", required=True)
    ap.add_argument("--features", required=True)
    ap.add_argument("--out-dir", default="./model")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-estimators", type=int, default=300)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.features) as f:
        meta = json.load(f)
    feature_columns = meta["feature_columns"]

    df = pd.read_csv(args.data)
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        raise SystemExit(f"Dataset is missing expected feature columns: {missing}")

    X = df[feature_columns]
    y = df["label"]
    print(f"Loaded {len(df)} rows, {len(feature_columns)} features")
    print(f"Class balance: {(y == 0).sum()} normal / {(y == 1).sum()} attack")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )
    print(f"\nTrain: {len(X_train)} rows   Test: {len(X_test)} rows")

    clf = RandomForestClassifier(
        n_estimators=args.n_estimators, class_weight="balanced",
        random_state=args.seed, n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_test, y_proba)
    except ValueError:
        auc = float("nan")
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 60)
    print("HELD-OUT TEST SET METRICS")
    print("=" * 60)
    print(f"Accuracy:  {acc:.4f}\nPrecision: {prec:.4f}\nRecall:    {rec:.4f}\n"
          f"F1:        {f1:.4f}\nROC-AUC:   {auc:.4f}")
    print("\nConfusion matrix [normal, attack]:\n", cm)
    print("\n" + classification_report(y_test, y_pred, target_names=["normal", "attack"], zero_division=0))

    importances = sorted(zip(feature_columns, clf.feature_importances_), key=lambda x: -x[1])
    print("Feature importances:")
    for name, imp in importances:
        print(f"  {name:28s} {imp:.4f}")

    joblib.dump(clf, out_dir / "attack_classifier.pkl")
    with open(out_dir / "feature_columns.json", "w") as f:
        json.dump(meta, f, indent=2)
    results = {
        "n_train": len(X_train), "n_test": len(X_test),
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "roc_auc": auc,
        "confusion_matrix": cm.tolist(),
        "feature_importances": {name: float(imp) for name, imp in importances},
    }
    with open(out_dir / "training_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved model to {out_dir / 'attack_classifier.pkl'}")


if __name__ == "__main__":
    main()
