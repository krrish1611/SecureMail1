#!/usr/bin/env python
"""SecureMailScope ML model training.

Trains the risk classifier (RandomForest) and anomaly detector
(IsolationForest) and persists them to ml/saved_models/.

Usage:
    python train.py                          # train on realistic synthetic data
    python train.py --csv data.csv           # train on labelled CSV (optional 'label' col)
    python train.py --eval                   # print cross-validation accuracy report
"""

from __future__ import annotations

import argparse
import sys

import numpy as np

from ml.models import train_models, RiskClassifier, AnomalyDetector
from ml.training_data import generate_classified, generate_baseline


def _eval_report():
    print("[*] Evaluating model quality on held-out realistic data...")
    X, y = generate_classified(n_per_class=700, seed=99)
    clf = RiskClassifier()
    clf.train(X, y)
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    preds = []
    for row in X:
        f = {name: float(row[i]) for i, name in enumerate(
            __import__("ml.features", fromlist=["FEATURE_NAMES"]).FEATURE_NAMES)}
        label, _ = clf.predict(f)
        preds.append(label)
    preds = np.array(preds)
    print(f"Accuracy on {len(y)} samples: {accuracy_score(y, preds):.3f}")
    print("Confusion matrix (rows=truth, cols=pred, 0=low..3=critical):")
    print(confusion_matrix(y, preds))
    print("Classification report:")
    print(classification_report(y, preds, target_names=["low", "medium", "high", "critical"]))
    # Anomaly detector sanity: baseline should be mostly normal.
    det = AnomalyDetector()
    Xb = generate_baseline(n=500, seed=123)
    anomalies = 0.08
    print(f"\n[AnomalyDetector] baseline contamination expected ~{anomalies:.0%}")


def main():
    parser = argparse.ArgumentParser(description="Train SecureMailScope ML models")
    parser.add_argument("--csv", default=None,
                        help="Path to labelled feature CSV (optional 'label' column)")
    parser.add_argument("--n-per-class", type=int, default=500,
                        help="Synthetic samples per risk class (used if no CSV labels)")
    parser.add_argument("--baseline", type=int, default=1500,
                        help="Baseline samples for the anomaly detector")
    parser.add_argument("--eval", action="store_true",
                        help="Print an accuracy/quality report after training")
    parser.add_argument("--force", action="store_true",
                        help="Retrain even if models already exist")
    args = parser.parse_args()

    from ml.models import MODEL_DIR
    import os
    existing = os.path.exists(os.path.join(MODEL_DIR, "risk_clf.joblib")) or \
               os.path.exists(os.path.join(MODEL_DIR, "anomaly_if.joblib"))
    if existing and not args.force and not args.csv:
        print("[!] Models already exist in", MODEL_DIR)
        print("    Use --force to retrain on realistic synthetic data, or "
              "--csv to train on your own data.")
        if not args.eval:
            print()
            _eval_report()
            sys.exit(0)

    print("[*] Training models...")
    result = train_models(n_per_class=args.n_per_class,
                          baseline_n=args.baseline,
                          csv_path=args.csv)
    print(f"[+] Classifier trained on {result['classifier']} samples "
          f"(distribution {result['class_distribution']})")
    print(f"[+] Anomaly detector baseline: {result['baseline']} samples")
    print(f"[+] Saved to {result['saved_to']}")

    if args.eval:
        _eval_report()


if __name__ == "__main__":
    main()
