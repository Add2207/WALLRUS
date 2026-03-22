"""
WALLRUS - Phase 2 ML Training Script
=====================================
Train an anomaly / attack classifier on a labelled HTTP request dataset.

Usage:
    python scripts/train.py --data data/processed/labelled_requests.csv
    python scripts/train.py --data data/processed/labelled_requests.csv --model lgbm

Expected CSV columns:
    raw_request   — raw HTTP request text (string)
    label         — 0 (benign) or 1 (malicious)

Output:
    data/models/waf_model.joblib     — serialised model
    data/models/feature_names.json   — feature name list for inference
    data/models/eval_report.txt      — classification report

Suggested datasets:
    - CSIC 2010 HTTP Dataset
    - ISCX 2012
    - Custom labelled set from WAFinity / your own traffic logs
"""

from __future__ import annotations

import json
import sys
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, roc_auc_score, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Uncomment for LightGBM:
# import lightgbm as lgb

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from wallrus.core.parser import parse_http_request, ParseError
from wallrus.ml.detector import RequestFeatureExtractor


# ── Argument parsing ──────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(description="Train WALLRUS ML anomaly detector")
    parser.add_argument("--data",   required=True, help="Path to labelled CSV")
    parser.add_argument("--model",  default="rf", choices=["rf", "lgbm", "isolation"],
                        help="Model type: rf (Random Forest), lgbm, isolation (unsupervised)")
    parser.add_argument("--output", default="data/models/waf_model.joblib",
                        help="Output path for saved model")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed",      type=int,   default=42)
    return parser.parse_args()


# ── Feature extraction ────────────────────────────────────────────────────────
def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    extractor = RequestFeatureExtractor()
    rows, labels = [], []

    for _, row in df.iterrows():
        raw = row["raw_request"]
        lbl = int(row["label"])
        try:
            request  = parse_http_request(raw)
            features = extractor.extract(request)
            rows.append(features)
            labels.append(lbl)
        except (ParseError, Exception) as e:
            # Skip unparseable rows — log them for inspection
            print(f"  [skip] ParseError: {e}")
            continue

    return np.array(rows), np.array(labels)


# ── Model builders ────────────────────────────────────────────────────────────
def build_rf(seed: int) -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        ))
    ])


def build_isolation(seed: int) -> IsolationForest:
    return IsolationForest(
        n_estimators=150,
        contamination=0.1,  # adjust to your expected malicious rate
        random_state=seed,
    )


def build_lgbm(seed: int):
    try:
        import lightgbm as lgb
    except ImportError:
        raise ImportError("lightgbm not installed: pip install lightgbm")
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    lgb.LGBMClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.05,
            class_weight="balanced",
            random_state=seed,
        ))
    ])


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()

    print(f"\n[WALLRUS] Loading dataset: {args.data}")
    df = pd.read_csv(args.data)
    print(f"  Rows: {len(df)}  |  Label distribution:\n{df['label'].value_counts()}\n")

    print("[WALLRUS] Extracting features…")
    X, y = build_feature_matrix(df)
    print(f"  Feature matrix: {X.shape}  |  Labels: {y.shape}")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.model == "isolation":
        # Unsupervised — train on benign samples only
        X_benign = X[y == 0]
        print(f"\n[WALLRUS] Training IsolationForest on {len(X_benign)} benign samples…")
        model = build_isolation(args.seed)
        model.fit(X_benign)
        joblib.dump(model, output_path)
        print(f"  Saved → {output_path}")
        return

    # Supervised
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    if args.model == "lgbm":
        model = build_lgbm(args.seed)
    else:
        model = build_rf(args.seed)

    print(f"\n[WALLRUS] Training {args.model.upper()} on {len(X_train)} samples…")
    model.fit(X_train, y_train)

    # ── Evaluation ────────────────────────────────────────────────────────────
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    report  = classification_report(y_test, y_pred,
                                    target_names=["benign", "malicious"])
    auc     = roc_auc_score(y_test, y_proba)
    cm      = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 60)
    print(" EVALUATION RESULTS")
    print("=" * 60)
    print(report)
    print(f"  ROC-AUC: {auc:.4f}")
    print(f"  Confusion Matrix:\n{cm}\n")

    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=StratifiedKFold(5),
                                scoring="roc_auc", n_jobs=-1)
    print(f"  5-fold CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print("=" * 60)

    # ── Save artifacts ────────────────────────────────────────────────────────
    joblib.dump(model, output_path)
    print(f"\n  Model saved → {output_path}")

    feat_path = output_path.parent / "feature_names.json"
    with open(feat_path, "w") as f:
        json.dump(RequestFeatureExtractor.FEATURE_NAMES, f, indent=2)
    print(f"  Features saved → {feat_path}")

    eval_path = output_path.parent / "eval_report.txt"
    with open(eval_path, "w") as f:
        f.write(report)
        f.write(f"\nROC-AUC: {auc:.4f}\n")
        f.write(f"CV: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n")
    print(f"  Eval report → {eval_path}\n")


if __name__ == "__main__":
    main()
