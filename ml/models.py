"""Machine learning models for cryptographic risk analysis.

Contains:
- IsolationForest-based anomaly detector (unsupervised)
- RandomForest risk classifier (trained on synthetic labelled data)
- Posture scoring: combines rule findings + ML scores into a 0..100 score
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from core.models import Session, Severity, SEVERITY_NAMES
from ml.features import FEATURE_NAMES, extract_features, severity_weight
from ml.training_data import generate_classified, generate_baseline, load_from_csv

_DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")

# Vercel Lambda mounts /var/task as read-only; /tmp is the only writable path.
# Detect read-only filesystem and redirect model persistence to /tmp.
def _resolve_model_dir() -> str:
    d = _DEFAULT_MODEL_DIR
    try:
        os.makedirs(d, exist_ok=True)
        test_file = os.path.join(d, ".test_write")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return d
    except OSError:
        fallback = os.path.join("/tmp", "ml_saved_models")
        os.makedirs(fallback, exist_ok=True)
        return fallback

MODEL_DIR = _resolve_model_dir()
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")


def _load_config() -> Dict:
    """Load scoring config from ml/config.yml (with built-in defaults)."""
    defaults = {
        "posture": {"rule_weight": 0.6, "ml_weight": 0.4,
                    "severity_deduct_pts": {
                        "critical": 18.0, "high": 12.0, "medium": 6.0,
                        "low": 3.0, "info": 1.0}},
        "ml": {"clf_base_range": 80.0, "anomaly_healthy_bonus": 20.0},
        "models": {"contamination": 0.08, "n_estimators": 100},
    }
    if os.path.exists(CONFIG_PATH):
        try:
            import yaml
            with open(CONFIG_PATH) as f:
                loaded = yaml.safe_load(f) or {}
            for section, values in loaded.items():
                if isinstance(values, dict):
                    defaults[section].update(values)
        except Exception:
            pass
    return defaults


CONFIG = _load_config()


def _load_model(filename: str, fallback_type="forest"):
    path = os.path.join(MODEL_DIR, filename)
    if os.path.exists(path):
        import joblib
        return joblib.load(path)
    return None


def _save_model(model, filename: str):
    os.makedirs(MODEL_DIR, exist_ok=True)
    import joblib
    joblib.dump(model, os.path.join(MODEL_DIR, filename))


def train_models(n_per_class: int = 500, baseline_n: int = 1500,
                 csv_path: Optional[str] = None, sessions: Optional[List[Any]] = None,
                 source_name: str = "synthetic", seed: int = 7) -> Dict:
    """Train both ML models and persist them to MODEL_DIR.

    Trains on realistic labelled data, user-supplied CSV, or inspected SOC sessions
    for the risk classifier, and on normal-traffic baseline for the anomaly detector.
    """
    from ml.training_data import (
        generate_classified, generate_baseline, load_from_csv, extract_baseline_from_sessions
    )

    if csv_path:
        X, y = load_from_csv(csv_path)
        if y is None:
            # No labels provided: train a generic classifier from realistic data
            # so that predict/predict_proba still work.
            Xb, yb = generate_classified(n_per_class=n_per_class, seed=seed)
            y = yb
            X = np.vstack([X, Xb])
        baseline = generate_baseline(n=baseline_n, seed=seed)
        source = "csv"
    elif sessions:
        Xs, ys, X_base = extract_baseline_from_sessions(sessions)
        # Augment with anchor synthetic distributions so all risk classes are covered
        anchor_n = max(50, n_per_class // 4)
        Xb, yb = generate_classified(n_per_class=anchor_n, seed=seed)
        if len(Xs) > 0:
            X = np.vstack([Xb, Xs])
            y = np.concatenate([yb, ys])
        else:
            X, y = Xb, yb

        # Combine empirical normal baseline with synthetic baseline
        base_synth = generate_baseline(n=baseline_n, seed=seed)
        if len(X_base) > 0:
            baseline = np.vstack([base_synth, X_base])
        else:
            baseline = base_synth
        source = source_name or "sessions"
    else:
        X, y = generate_classified(n_per_class=n_per_class, seed=seed)
        baseline = generate_baseline(n=baseline_n, seed=seed)
        source = "synthetic"

    clf = RiskClassifier()
    clf.train(X, y)
    clf.save()

    det = AnomalyDetector()
    det.train(baseline)
    det.save()

    import datetime
    import json
    metadata = {
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "n_per_class": n_per_class,
        "baseline_n": baseline_n,
        "classifier_sample_count": len(X),
        "baseline_sample_count": len(baseline),
        "class_distribution": {str(int(k)): int(v) for k, v in
                               zip(*np.unique(y, return_counts=True))},
    }
    with open(os.path.join(MODEL_DIR, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    return {
        "classifier": len(X),
        "baseline": len(baseline),
        "source": source,
        "class_distribution": {str(int(k)): int(v) for k, v in
                               zip(*np.unique(y, return_counts=True))},
        "saved_to": MODEL_DIR,
    }


class RiskClassifier:
    """RandomForest classifier for session risk: low/med/high/critical."""

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self._load()

    def _load(self):
        self.model = _load_model("risk_clf.joblib")
        self.scaler = _load_model("risk_scaler.joblib")

    def save(self):
        _save_model(self.model, "risk_clf.joblib")
        _save_model(self.scaler, "risk_scaler.joblib")

    @property
    def ready(self) -> bool:
        return self.model is not None and self.scaler is not None

    def train(self, X: np.ndarray, y: np.ndarray):
        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)
        self.model = RandomForestClassifier(
            n_estimators=CONFIG["models"]["n_estimators"], random_state=42,
            class_weight="balanced")
        if len(y) != len(Xs):
            # If unlabeled samples were prepended to X (e.g. from unlabeled CSV),
            # fit the classifier on the labeled rows while keeping the full-dataset scaler.
            self.model.fit(Xs[-len(y):], y)
        else:
            self.model.fit(Xs, y)

    def predict(self, features: Dict[str, float]) -> Tuple[int, float]:
        """Return (label 0..3, confidence)."""
        if not self.ready:
            self._bootstrap()
        x = np.array([features.get(k, 0.0) for k in FEATURE_NAMES]).reshape(1, -1)
        x = self.scaler.transform(x)
        proba = self.model.predict_proba(x)[0]
        label = int(np.argmax(proba))
        return label, float(proba[label])

    def _bootstrap(self):
        X, y = generate_classified()
        self.train(X, y)
        self.save()


class AnomalyDetector:
    """IsolationForest for detecting anomalous TLS sessions."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._load()

    def _load(self):
        self.model = _load_model("anomaly_if.joblib")
        self.scaler = _load_model("anomaly_scaler.joblib")

    def save(self):
        _save_model(self.model, "anomaly_if.joblib")
        _save_model(self.scaler, "anomaly_scaler.joblib")

    @property
    def ready(self) -> bool:
        return self.model is not None and self.scaler is not None

    def train(self, X: np.ndarray):
        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)
        self.model = IsolationForest(contamination=CONFIG["models"]["contamination"],
                                     random_state=42)
        self.model.fit(Xs)

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """Return (is_anomaly, anomaly_score [-1=anomaly, +1=normal])."""
        if not self.ready:
            self._bootstrap()
        x = np.array([features.get(k, 0.0) for k in FEATURE_NAMES]).reshape(1, -1)
        x = self.scaler.transform(x)
        pred = self.model.predict(x)[0]
        score = float(self.model.decision_function(x)[0])
        return pred == -1, score

    def _bootstrap(self):
        X = generate_baseline()
        self.train(X)
        self.save()


def rule_based_posture_score(session: Session) -> float:
    """Compute a 0..100 posture score purely from rule findings.

    100 = perfect; each finding subtracts.
    """
    base = 100.0
    severity_deduct = CONFIG["posture"]["severity_deduct_pts"]
    for f in session.findings:
        base -= severity_deduct.get(SEVERITY_NAMES[f.severity], 1.0)
    return max(0.0, min(100.0, base))


def ml_posture_score(features: Dict[str, float], risk_score: float,
                     anomaly: bool) -> float:
    """Combine ML outputs into a 0..100 posture score component."""
    # risk_score is confidence from classifier (0..1); higher confidence of high-risk = lower posture.
    cfg = CONFIG["ml"]
    ml_component = max(0.0, min(100.0,
        (1.0 - risk_score) * cfg["clf_base_range"] +
        (cfg["anomaly_healthy_bonus"] if not anomaly else 0.0)))
    return ml_component


RISK_LABELS = {0: "low", 1: "medium", 2: "high", 3: "critical"}


class MLPostureScorer:
    """Orchestrates ML-based analysis and posture scoring for a session."""

    def __init__(self):
        self.classifier = RiskClassifier()
        self.anomaly_detector = AnomalyDetector()

    def score_session(self, session: Session) -> Dict:
        features = extract_features(session)
        risk_label_int, risk_confidence = self.classifier.predict(features)
        is_anomaly, anomaly_score = self.anomaly_detector.predict(features)
        rule_score = rule_based_posture_score(session)
        ml_component = ml_posture_score(features, risk_confidence, is_anomaly)
        # Combine rule-based and ML components per config
        cfg = CONFIG["posture"]
        final = cfg["rule_weight"] * rule_score + cfg["ml_weight"] * ml_component
        final = max(0.0, min(100.0, round(final, 1)))
        label = RISK_LABELS.get(risk_label_int, "low")
        session.posture_score = final
        session.risk_label = label
        session.ml_score = risk_confidence
        session.ml_anomaly = is_anomaly
        session.ml_anomaly_score = anomaly_score
        return {
            "features": features,
            "risk_label": label,
            "risk_confidence": round(risk_confidence, 4),
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "rule_score": round(rule_score, 1),
            "ml_component": round(ml_component, 1),
            "posture_score": final,
        }
