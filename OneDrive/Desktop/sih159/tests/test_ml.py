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


def test_train_models_with_sessions():
    from ml.models import train_models
    s1 = _session()
    s1.encrypted = True
    s1.tls = TLSInfo(version="TLSv1.3", cipher_suite="TLS_AES_128_GCM_SHA256")
    s1.posture_score = 95.0

    s2 = _session()
    s2.plaintext = True
    s2.posture_score = 25.0

    res = train_models(n_per_class=50, baseline_n=100, sessions=[s1, s2], source_name="test_sessions")
    assert res["classifier"] > 0
    assert res["baseline"] > 0
    assert res["source"] == "test_sessions"


def test_train_models_api_and_upload():
    from fastapi.testclient import TestClient
    from backend.app.main import app
    from backend.app.routers.analyze import _jobs

    client = TestClient(app)

    # 1. Test training on active sessions
    s = _session()
    s.encrypted = True
    _jobs["test_job_ml"] = {"sessions": [s], "pcap": "test.pcap"}

    resp = client.post("/api/tools/ml/train", json={"source": "active_sessions", "job_id": "test_job_ml", "n_per_class": 50, "baseline_n": 100})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "Active SOC Sessions" in data["details"]["source"]

    # 2. Test CSV upload
    csv_content = (
        "is_starttls,is_encrypted,plaintext,starttls_stripped,creds_plaintext,"
        "tls_version_rank,cipher_strength,has_forward_secrecy,cert_valid_chain,"
        "cert_expired,cert_self_signed,pubkey_size,uses_sha1_sig,sess_bytes,num_packets,duration_s,weak_offered,label\n"
        "1.0,1.0,0.0,0.0,0.0,4.0,10.0,1.0,1.0,0.0,0.0,2048.0,0.0,5000.0,20.0,1.5,0.0,0\n"
        "0.0,0.0,1.0,0.0,1.0,0.0,0.0,0.0,0.0,1.0,1.0,512.0,1.0,800.0,5.0,0.5,1.0,3\n"
    )
    resp_upload = client.post(
        "/api/tools/ml/train-upload?n_per_class=50&baseline_n=100",
        files={"file": ("custom_baseline.csv", csv_content.encode("utf-8"), "text/csv")}
    )
    assert resp_upload.status_code == 200
    assert resp_upload.json()["status"] == "ok"

