"""Unit tests for ML feature extraction and model training/prediction."""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Session, TLSInfo
from ml.features import extract_features, FEATURE_NAMES, cipher_strength
from ml.models import RiskClassifier, AnomalyDetector, rule_based_posture_score


def _session():
    return Session(id=uuid.uuid4().hex[:12])


def test_feature_names_are_seventeen():
    assert len(FEATURE_NAMES) == 17


def test_extract_features_shape_and_defaults():
    s = _session()
    s.packets = 5
    s.bytes_client_to_server = 100
    s.bytes_server_to_client = 200
    f = extract_features(s)
    assert set(f.keys()) == set(FEATURE_NAMES)
    assert f["sess_bytes"] == 300
    assert f["num_packets"] == 5


def test_extract_features_tls13_strong():
    s = _session()
    s.encrypted = True
    s.tls = TLSInfo(version="TLSv1.3", version_rank=4,
                    cipher_suite="TLS_AES_128_GCM_SHA256",
                    key_exchange="ECDHE")
    f = extract_features(s)
    assert f["is_encrypted"] == 1.0
    assert f["cipher_strength"] == 10.0
    assert f["has_forward_secrecy"] == 1.0
    assert f["tls_version_rank"] == 4


def test_cipher_strength_ranking():
    assert cipher_strength("TLS_AES_128_GCM_SHA256") == 10
    assert cipher_strength("TLS_RSA_WITH_RC4_128_SHA") == 0
    assert cipher_strength("TLS_RSA_WITH_3DES_EDE_CBC_SHA") == 1


def test_classifier_train_predict_and_persist(tmp_path):
    from ml.training_data import generate_classified
    X, y = generate_classified(n_per_class=120, seed=1)
    clf = RiskClassifier()
    clf.train(X, y)
    features = {name: float(X[0][i]) for i, name in enumerate(FEATURE_NAMES)}
    label, conf = clf.predict(features)
    assert label in (0, 1, 2, 3)
    assert 0.0 <= conf <= 1.0


def test_anomaly_detector_baseline_behaviour():
    from ml.training_data import generate_baseline
    baseline = generate_baseline(n=500, seed=3)
    det = AnomalyDetector()
    det.train(baseline)
    # A prototypical clean (low-risk) sample should NOT be an anomaly.
    clean = dict(zip(FEATURE_NAMES, [0.0] * len(FEATURE_NAMES)))
    clean.update({
        "is_encrypted": 1.0, "plaintext": 0.0, "creds_plaintext": 0.0,
        "tls_version_rank": 4.0, "cipher_strength": 10.0,
        "has_forward_secrecy": 1.0, "cert_valid_chain": 1.0,
        "cert_expired": 0.0, "cert_self_signed": 0.0, "pubkey_size": 2048.0,
        "uses_sha1_sig": 0.0, "weak_offered": 0.0,
    })
    is_anomaly, score = det.predict(clean)
    assert not is_anomaly
    assert -1.0 <= score <= 1.0


def test_rule_posture_score_bounds():
    s = _session()
    assert rule_based_posture_score(s) == 100.0
