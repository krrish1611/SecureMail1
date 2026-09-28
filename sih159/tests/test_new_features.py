"""Unit and integration tests for standout features:
- DMARC, SPF, DKIM Email Authentication
- Domain Probe Engine
- AI Executive Summary & Risk Narrative
- SQLite History & Trend Persistence
- Server Hardening & Remediation Playbook
- New API Endpoints
"""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from core.models import Session, Finding, Severity, TLSInfo, CertificateInfo
from core.email_auth import check_spf, check_dmarc, evaluate_email_auth
from core.domain_probe import probe_domain
from core.executive_summary import generate_executive_summary
from core.history import (
    init_db, save_scan, get_history, get_scan, delete_scan, get_trends, clear_history
)
from reports.playbook import generate_playbook_data, generate_playbook_pdf


@pytest.fixture
def client():
    return TestClient(app)


def test_email_auth_evaluation():
    """Verify email authentication scoring and grading."""
    res = evaluate_email_auth("cloudflare.com")
    assert "overall_score" in res
    assert "grade" in res
    assert res["grade"] in ("A+", "A", "B", "C", "F")
    assert "dmarc" in res
    assert "spf" in res
    assert isinstance(res["findings"], list)
    assert isinstance(res["recommendations"], list)


def test_dmarc_parsing_policies():
    """Test DMARC policy evaluations."""
    # Test reject vs none
    res_none = evaluate_email_auth("gmail.com")
    assert res_none["dmarc"]["present"] is True
    # gmail.com uses p=none on apex
    assert res_none["dmarc"]["policy"] in ("none", "quarantine", "reject")


def test_executive_summary_synthesis():
    """Verify AI executive summary and 3-phase roadmap."""
    s = Session(
        id="test_session_001",
        protocol="smtp",
        server_ip="192.168.1.10",
        server_port=25,
        encrypted=False,
        plaintext=True,
        credentials_plaintext=True,
        posture_score=25.0,
        findings=[
            Finding(
                id="starttls.plaintext_creds",
                title="Plaintext Credentials",
                description="Credentials exposed in cleartext",
                category="starttls",
                severity=Severity.CRITICAL,
                recommendation="Enforce mandatory TLS before AUTH",
            )
        ],
    )
    summary = generate_executive_summary([s], "job_test_001", target_name="mail.corp.local")
    assert summary["posture_grade"] == "F"
    assert summary["posture_score"] == 25.0
    assert "Critical Cryptographic Exposure" in summary["headline"]
    assert len(summary["summary_paragraphs"]) == 3
    assert len(summary["actionable_roadmap"]) == 3
    assert summary["actionable_roadmap"][0]["timeframe"] == "0 - 24 Hours"
    assert summary["credentials_leaked"] == 1


def test_history_persistence_lifecycle():
    """Verify SQLite history save, retrieve, trends, and deletion."""
    init_db()
    test_id = "test_hist_999"
    s = Session(
        id="s1",
        protocol="smtp",
        server_ip="10.0.0.1",
        posture_score=85.0,
        encrypted=True,
    )
    save_scan(test_id, "test_target.pcap", "pcap", [s])

    # Check retrieve
    scan = get_scan(test_id)
    assert scan is not None
    assert scan["target_name"] == "test_target.pcap"
    assert scan["avg_posture_score"] == 85.0

    # Check history list
    hist = get_history(limit=10)
    assert any(h["id"] == test_id for h in hist)

    # Check trends
    trends = get_trends()
    assert trends["total_scans"] >= 1
    assert any(p["job_id"] == test_id for p in trends["points"])

    # Clean up
    deleted = delete_scan(test_id)
    assert deleted is True
    assert get_scan(test_id) is None


def test_playbook_generation_and_pdf():
    """Verify multi-daemon remediation playbook generation and PDF export."""
    s = Session(
        id="s_pb",
        protocol="smtp",
        server_ip="10.0.0.5",
        findings=[
            Finding(
                id="tls.10.deprecated",
                title="TLS 1.0 Obsolete",
                description="TLS 1.0 is deprecated",
                category="tls_version",
                severity=Severity.CRITICAL,
                recommendation="Disable TLS 1.0 in postfix main.cf",
            ),
            Finding(
                id="cipher.weak_cbc",
                title="Weak CBC Cipher",
                description="CBC mode cipher used",
                category="cipher_suite",
                severity=Severity.HIGH,
                recommendation="Enforce GCM ciphers",
            ),
        ],
    )
    data = generate_playbook_data([s], target_name="mail.company.com", job_id="job_pb_01")
    assert data["total_tasks"] == 2
    assert "postfix" in data["daemon_guides"]
    assert "dovecot" in data["daemon_guides"]
    assert "exim" in data["daemon_guides"]

    # Generate PDF in temp dir
    with tempfile.TemporaryDirectory() as tmp:
        pdf_path = os.path.join(tmp, "playbook.pdf")
        out = generate_playbook_pdf([s], target_name="mail.company.com", job_id="job_pb_01", output_path=pdf_path)
        assert os.path.exists(out)
        assert os.path.getsize(out) > 1000


def test_api_new_endpoints(client):
    """Test new REST API endpoints."""
    # 1. History endpoints
    resp = client.get("/api/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    resp_trends = client.get("/api/history/trends")
    assert resp_trends.status_code == 200
    assert "total_scans" in resp_trends.json()

    # 2. Email Auth endpoint
    resp_auth = client.get("/api/tools/email-auth?domain=cloudflare.com")
    assert resp_auth.status_code == 200
    assert resp_auth.json()["domain"] == "cloudflare.com"

    # 3. Sample PCAP creates job and auto-saves to history
    resp_sample = client.post("/api/tools/sample-pcap?use_ml=true")
    assert resp_sample.status_code == 200
    job_id = resp_sample.json()["job_id"]

    # 4. Executive summary endpoint
    resp_exec = client.get(f"/api/jobs/{job_id}/executive-summary")
    assert resp_exec.status_code == 200
    data = resp_exec.json()
    assert "posture_grade" in data
    assert "actionable_roadmap" in data

    # 5. Playbook JSON & PDF endpoints
    resp_pb_json = client.get(f"/api/jobs/{job_id}/playbook/json")
    assert resp_pb_json.status_code == 200
    assert "tasks" in resp_pb_json.json()

    resp_pb_pdf = client.get(f"/api/jobs/{job_id}/playbook/pdf")
    assert resp_pb_pdf.status_code == 200
    assert resp_pb_pdf.headers["content-type"] == "application/pdf"


def test_probe_domain_plaintext_session_tls_placeholders():
    """Assert that for a plaintext probe result (tls_version=None), session.tls has explicit N/A placeholders."""
    from unittest.mock import patch
    mock_result = {
        "success": True,
        "port": 25,
        "banner": "220 mail.insecure.test ESMTP",
        "ehlo_capabilities": ["PIPELINING", "SIZE 10000000"],
        "starttls_advertised": False,
        "starttls_accepted": False,
        "tls_version": None,
        "cipher_suite": None,
        "peer_cert_der": None,
        "error": "STARTTLS not supported",
    }
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("198.51.100.1", 25))]):
        with patch("core.domain_probe._probe_smtp_server", return_value=mock_result):
            with patch("core.domain_probe.evaluate_dns_security", return_value=None):
                with patch("core.domain_probe.evaluate_email_auth", return_value={"dmarc": {"policy": "reject", "present": True}}):
                    session, _ = probe_domain("insecure.test", timeout=1.0)
                    assert session.encrypted is False
                    assert session.plaintext is True
                    assert session.tls is not None
                    assert session.tls.version == "N/A (No TLS Handshake)"
                    assert session.tls.cipher_suite == "N/A (Plaintext Session)"
                    assert session.tls.key_exchange == "N/A (Plaintext Session)"
                    assert session.tls.key_exchange_group is None
                    assert session.tls.signature_algorithm is None
                    # Ensure PQC is also HIGH_QUANTUM_RISK and CRITICAL
                    assert session.pqc.pqc_status == "HIGH_QUANTUM_RISK"
                    assert session.pqc.hndl_risk == "CRITICAL"

