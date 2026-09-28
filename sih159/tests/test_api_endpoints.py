"""Tests for new API endpoints: Hardening generator and Webhook alerts."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.routers.analyze import _jobs
from core.models import Session, Finding, Severity, TLSInfo, CertificateInfo, DnsSecurityInfo
from core.rules import RuleEngine


@pytest.fixture
def client():
    return TestClient(app)


def test_api_webhook_test_slack(client):
    resp = client.post("/api/alerts/test", json={
        "provider": "slack",
        "dry_run": True,
        "min_severity": "high",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["dispatched"] is True
    assert data["provider"] == "slack"
    assert "blocks" in data["payload"]


def test_api_webhook_test_discord(client):
    resp = client.post("/api/alerts/test", json={
        "provider": "discord",
        "dry_run": True,
        "min_severity": "high",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["dispatched"] is True
    assert data["provider"] == "discord"
    assert "embeds" in data["payload"]


def test_api_webhook_test_siem(client):
    resp = client.post("/api/alerts/test", json={
        "provider": "siem",
        "dry_run": True,
        "min_severity": "critical",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["dispatched"] is True
    assert data["provider"] == "siem"
    assert data["payload"]["event_type"] == "securemailscope_crypto_alert"


def test_api_hardening_endpoint(client):
    # Register mock session in _jobs
    engine = RuleEngine()
    test_session = Session(
        id="mock_session_h1",
        protocol="smtp",
        server_ip="192.168.1.55",
        tls=TLSInfo(version="TLSv1.0", cipher_suite="TLS_RSA_WITH_RC4_128_SHA"),
        dns_security=DnsSecurityInfo(domain="mail.example.org", mta_sts_valid=False),
    )
    engine.evaluate_all(test_session)
    _jobs["mock_job_h1"] = {"sessions": [test_session], "pcap": "mock.pcap"}

    resp = client.get("/api/sessions/mock_session_h1/hardening")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "mock_session_h1"
    assert "postfix" in data["snippets"]
    assert "dovecot" in data["snippets"]
    assert "exim" in data["snippets"]
    assert "sendmail" in data["snippets"]
    postfix = data["snippets"]["postfix"]
    assert postfix["daemon"] == "Postfix"
    assert "!TLSv1" in postfix["config_text"]


def test_api_session_detail_includes_pqc_and_attribution(client):
    engine = RuleEngine()
    test_session = Session(
        id="mock_session_pqc1",
        protocol="smtp",
        encrypted=True,
        server_ip="10.0.0.1",
        tls=TLSInfo(version="TLSv1.3", key_exchange="ECDHE", key_exchange_group="0x6399"),
    )
    engine.evaluate_all(test_session)
    _jobs["mock_job_pqc1"] = {"sessions": [test_session], "pcap": "mock.pcap"}

    resp = client.get("/api/jobs/mock_job_pqc1/sessions/mock_session_pqc1")
    assert resp.status_code == 200
    data = resp.json()
    assert "pqc" in data
    assert data["pqc"]["pqc_status"] == "QUANTUM_RESISTANT"
    assert data["pqc"]["quantum_safe_kem"] is True
    assert "attribution" in data
    assert data["attribution"]["client_name"] != ""
