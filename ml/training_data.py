"""Realistic synthetic training-data generation for SecureMailScope ML models.

Produces coherent feature vectors across labelled risk classes (0=low ..
3=critical) plus a baseline pool used to fit the anomaly detector (IsolationForest)
so that genuinely unusual traffic stands out rather than everything being flagged.
"""

from __future__ import annotations

from typing import Tuple, Dict, List

import numpy as np
import pandas as pd

from ml.features import FEATURE_NAMES


def _idx(name: str) -> int:
    """Return the column index for a feature name."""
    return FEATURE_NAMES.index(name)


# Per-class feature profiles. Each key is a feature name; value is a
# (low, high) range for continuous features or a probability for binary ones.
_PROFILES: Dict[int, Dict[str, tuple]] = {
    0: {  # low risk - modern, well-configured
        "is_starttls": (0.75,),
        "is_encrypted": (0.97,),
        "plaintext": (0.02,),
        "starttls_stripped": (0.0,),
        "creds_plaintext": (0.0,),
        "tls_version_rank": (4.0, 5.0),          # TLS 1.2 / 1.3
        "cipher_strength": (8.0, 10.0),
        "has_forward_secrecy": (0.98,),
        "cert_valid_chain": (0.97,),
        "cert_expired": (0.0,),
        "cert_self_signed": (0.0,),
        "pubkey_size": (2048.0, 4096.0),
        "uses_sha1_sig": (0.0,),
        "sess_bytes": (2500.0, 25000.0),
        "num_packets": (14.0, 60.0),
        "duration_s": (0.4, 4.0),
        "weak_offered": (0.03,),
    },
    1: {  # medium - functional but dated
        "is_starttls": (0.6,),
        "is_encrypted": (0.9,),
        "plaintext": (0.1,),
        "starttls_stripped": (0.05,),
        "creds_plaintext": (0.05,),
        "tls_version_rank": (3.0, 4.0),          # TLS 1.1 / 1.2
        "cipher_strength": (4.0, 7.0),
        "has_forward_secrecy": (0.5,),
        "cert_valid_chain": (0.8,),
        "cert_expired": (0.1,),
        "cert_self_signed": (0.1,),
        "pubkey_size": (1024.0, 2048.0),
        "uses_sha1_sig": (0.3,),
        "sess_bytes": (1800.0, 20000.0),
        "num_packets": (10.0, 50.0),
        "duration_s": (0.6, 6.0),
        "weak_offered": (0.4,),
    },
    2: {  # high - clearly poor config
        "is_starttls": (0.4,),
        "is_encrypted": (0.7,),
        "plaintext": (0.3,),
        "starttls_stripped": (0.25,),
        "creds_plaintext": (0.3,),
        "tls_version_rank": (2.0, 3.0),          # TLS 1.0 / 1.1
        "cipher_strength": (1.0, 4.0),
        "has_forward_secrecy": (0.15,),
        "cert_valid_chain": (0.4,),
        "cert_expired": (0.35,),
        "cert_self_signed": (0.4,),
        "pubkey_size": (512.0, 1024.0),
        "uses_sha1_sig": (0.7,),
        "sess_bytes": (900.0, 15000.0),
        "num_packets": (6.0, 35.0),
        "duration_s": (0.8, 8.0),
        "weak_offered": (0.8,),
    },
    3: {  # critical - broken / attack indicators
        "is_starttls": (0.2,),
        "is_encrypted": (0.4,),
        "plaintext": (0.6,),
        "starttls_stripped": (0.5,),
        "creds_plaintext": (0.7,),
        "tls_version_rank": (0.0, 2.0),          # SSLv3 / TLS 1.0
        "cipher_strength": (0.0, 1.0),
        "has_forward_secrecy": (0.03,),
        "cert_valid_chain": (0.05,),
        "cert_expired": (0.7,),
        "cert_self_signed": (0.8,),
        "pubkey_size": (256.0, 1024.0),
        "uses_sha1_sig": (0.9,),
        "sess_bytes": (400.0, 10000.0),
        "num_packets": (4.0, 25.0),
        "duration_s": (0.2, 5.0),
        "weak_offered": (0.95,),
    },
}

_BINARY = {"is_starttls", "is_encrypted", "plaintext", "starttls_stripped", "creds_plaintext",
           "has_forward_secrecy", "cert_valid_chain", "cert_expired",
           "cert_self_signed", "uses_sha1_sig", "weak_offered"}


def _profile_sample(rng: np.random.RandomState,
                    profile: Dict[str, tuple]) -> np.ndarray:
    x = np.zeros(len(FEATURE_NAMES))
    for i, name in enumerate(FEATURE_NAMES):
        if name not in profile:
            x[i] = 0.0
            continue
        spec = profile[name]
        if name in _BINARY:
            (p,) = spec
            x[i] = 1.0 if rng.rand() < p else 0.0
        else:
            lo, hi = spec
            x[i] = rng.uniform(lo, hi)
    return x


def generate_classified(n_per_class: int = 500, seed: int = 7) -> Tuple[np.ndarray, np.ndarray]:
    """Generate balanced labelled data across the four risk classes."""
    rng = np.random.RandomState(seed)
    X_list, y_list = [], []
    for label, profile in _PROFILES.items():
        for _ in range(n_per_class):
            X_list.append(_profile_sample(rng, profile))
            y_list.append(label)
    X = np.array(X_list)
    y = np.array(y_list, dtype=int)
    # Shuffle preserving the pairings.
    order = rng.permutation(len(X))
    return X[order], y[order]


def generate_class_samples(label: int, n: int = 200, seed: int = 42) -> np.ndarray:
    """Generate n synthetic feature vectors for a specific risk class (0=low..3=critical)."""
    rng = np.random.RandomState(seed)
    profile = _PROFILES[label]
    return np.array([_profile_sample(rng, profile) for _ in range(n)])


def generate_baseline(n: int = 1500, seed: int = 11) -> np.ndarray:
    """Generate a 'normal traffic' baseline for the anomaly detector.

    The overwhelming majority is well-configured (low risk) with a small
    proportion of medium risk; genuine critical deviations then appear anomalous.
    """
    rng = np.random.RandomState(seed)
    X_list = []
    # ~85% low
    for _ in range(int(n * 0.85)):
        X_list.append(_profile_sample(rng, _PROFILES[0]))
    # ~12% medium
    for _ in range(int(n * 0.12)):
        X_list.append(_profile_sample(rng, _PROFILES[1]))
    # ~3% high (occasionally seen on legacy networks)
    for _ in range(int(n * 0.03)):
        X_list.append(_profile_sample(rng, _PROFILES[2]))
    X = np.array(X_list)
    rng.shuffle(X)
    return X


def load_from_csv(path: str) -> Tuple[np.ndarray, np.ndarray]:
    """Load either a labelled (last column = label) or feature-only CSV."""
    df = pd.read_csv(path)
    cols = [c for c in df.columns if c in FEATURE_NAMES]
    if not cols:
        raise ValueError("CSV must contain at least one feature column from: %s" % FEATURE_NAMES)
    X = df[cols].fillna(0.0).to_numpy(dtype=float)
    assert X.shape[1] == len(FEATURE_NAMES) or X.shape[1] < len(FEATURE_NAMES)
    if X.shape[1] < len(FEATURE_NAMES):
        # Pad missing feature columns with zeros.
        padded = np.zeros((X.shape[0], len(FEATURE_NAMES)))
        for i, c in enumerate(cols):
            padded[:, FEATURE_NAMES.index(c)] = X[:, i]
        X = padded
    y = None
    if "label" in df.columns:
        y = df["label"].astype(int).to_numpy()
    return X, y


def to_csv(X: np.ndarray, y: np.ndarray, path: str):
    """Persist a labelled feature matrix as CSV (with 'label' column)."""
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y
    df.to_csv(path, index=False)


def extract_baseline_from_sessions(sessions: List[any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Extract classifier training pairs (X, y) and anomaly baseline vectors (X_base) from sessions.

    Works with Session objects or serialized session dictionaries.
    Returns:
        (X, y, X_base)
    """
    from ml.features import extract_features
    from core.models import Session

    X_list = []
    y_list = []
    base_list = []

    for s in sessions:
        if isinstance(s, dict):
            if "features" in s and isinstance(s["features"], dict):
                feats = s["features"]
            else:
                try:
                    sess_obj = Session(**{k: v for k, v in s.items() if k in getattr(Session, "__annotations__", {})})
                    feats = extract_features(sess_obj)
                except Exception:
                    feats = {name: float(s.get(name, 0.0)) for name in FEATURE_NAMES}
            risk_label = s.get("risk_label", "low")
            posture_score = float(s.get("posture_score", 100.0) or 100.0)
        else:
            feats = extract_features(s)
            risk_label = getattr(s, "risk_label", "low") or "low"
            posture_score = float(getattr(s, "posture_score", 100.0) or 100.0)

        vec = np.array([float(feats.get(name, 0.0)) for name in FEATURE_NAMES])
        X_list.append(vec)

        # Determine risk label 0..3
        label_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if risk_label in label_map:
            label = label_map[risk_label]
        elif posture_score >= 85:
            label = 0
        elif posture_score >= 70:
            label = 1
        elif posture_score >= 40:
            label = 2
        else:
            label = 3
        y_list.append(label)

        # Baseline pool for AnomalyDetector (normal approved mail traffic)
        if label in (0, 1) or posture_score >= 70:
            base_list.append(vec)

    if not base_list and X_list:
        base_list = list(X_list)

    return (
        np.array(X_list) if X_list else np.empty((0, len(FEATURE_NAMES))),
        np.array(y_list, dtype=int) if y_list else np.empty((0,), dtype=int),
        np.array(base_list) if base_list else np.empty((0, len(FEATURE_NAMES)))
    )

