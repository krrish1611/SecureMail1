"""Unit and integration tests for PQC Radar, Remediate Tab, Email Protocol Compliance, and MITM Simulator."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_mitm_simulation_endpoint(client):
    """Test /api/tools/mitm-simulate returns cleartext, tls12, and pqc_tls13 scenarios."""
    resp = client.get("/api/tools/mitm-simulate")
    assert resp.status_code == 200
    data = resp.json()

    assert "sample_email" in data
    assert "from" in data["sample_email"]
    assert "subject" in data["sample_email"]

    assert "scenarios" in data
    scenarios = {s["scenario"]: s for s in data["scenarios"]}
    assert "cleartext" in scenarios
    assert "tls12" in scenarios
    assert "pqc_tls13" in scenarios

    # Cleartext checks
    ct = scenarios["cleartext"]
    assert ct["is_encrypted"] is False
    assert ct["hndl_risk"] == "CRITICAL"
    assert data["sample_email"]["subject"] in ct["attacker_view"]["captured_subject"]

    # TLS 1.2 checks
    tls12 = scenarios["tls12"]
    assert tls12["is_encrypted"] is True
    assert tls12["is_quantum_safe"] is False
    assert tls12["hndl_risk"] == "HIGH"
    assert "TLSv1.2" in tls12["tls_version"]

    # PQC TLS 1.3 checks
    pqc = scenarios["pqc_tls13"]
    assert pqc["is_encrypted"] is True
    assert pqc["is_quantum_safe"] is True
    assert pqc["hndl_risk"] == "LOW"
    assert "TLSv1.3" in pqc["tls_version"]
    assert "MLKEM" in pqc["key_exchange"]


def test_job_pqc_radar_endpoint(client):
    """Test /api/jobs/{job_id}/pqc-radar with a sample PCAP job."""
    resp_sample = client.post("/api/tools/sample-pcap?use_ml=true")
    assert resp_sample.status_code == 200
    job_id = resp_sample.json()["job_id"]

    resp = client.get(f"/api/jobs/{job_id}/pqc-radar")
    assert resp.status_code == 200
    data = resp.json()

    assert data["job_id"] == job_id
    assert "total_sessions" in data
    assert data["total_sessions"] > 0
    assert "quantum_resistant" in data
    assert "transitional" in data
    assert "high_risk" in data
    assert "migration_readiness_score" in data
    assert 0 <= data["migration_readiness_score"] <= 100

    # Check NIST FIPS breakdown
    assert "nist_fips_203" in data
    assert "FIPS 203" in data["nist_fips_203"]["standard"]
    assert "nist_fips_204" in data
    assert "FIPS 204" in data["nist_fips_204"]["standard"]
    assert "nist_fips_205" in data
    assert "FIPS 205" in data["nist_fips_205"]["standard"]

    # Check HNDL breakdown
    assert "hndl_breakdown" in data
    for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        assert lvl in data["hndl_breakdown"]


def test_job_remediate_endpoint(client):
    """Test /api/jobs/{job_id}/remediate with a sample PCAP job."""
    resp_sample = client.post("/api/tools/sample-pcap?use_ml=true")
    assert resp_sample.status_code == 200
    job_id = resp_sample.json()["job_id"]

    resp = client.get(f"/api/jobs/{job_id}/remediate")
    assert resp.status_code == 200
    data = resp.json()

    assert data["job_id"] == job_id
    assert "total_issues" in data
    assert "issues" in data
    assert "snippets" in data

    # Verify MTA snippets
    snippets = data["snippets"]
    assert "postfix" in snippets
    assert "dovecot" in snippets
    assert "exim" in snippets
    assert "sendmail" in snippets

    assert "config_text" in snippets["postfix"]
    assert "main.cf" in snippets["postfix"]["target_file"]

    # Verify Exchange PowerShell config
    assert "exchange_config" in data
    assert "Set-TransportConfig" in data["exchange_config"] or "Tls" in data["exchange_config"]

    # Verify script download URLs
    assert "download_links" in data
    assert f"/api/jobs/{job_id}/hardening-script?platform=linux" in data["download_links"]["linux"]
    assert f"/api/jobs/{job_id}/hardening-script?platform=windows" in data["download_links"]["windows"]


def test_job_email_compliance_endpoint(client):
    """Test /api/jobs/{job_id}/email-compliance endpoint."""
    resp_sample = client.post("/api/tools/sample-pcap?use_ml=true")
    assert resp_sample.status_code == 200
    job_id = resp_sample.json()["job_id"]

    resp = client.get(f"/api/jobs/{job_id}/email-compliance")
    assert resp.status_code == 200
    data = resp.json()

    assert data["job_id"] == job_id
    assert "overall_score" in data
    assert "overall_grade" in data
    assert "checks" in data
    assert len(data["checks"]) >= 2

    # Check that MTA-STS and DANE / TLSA are always assessed
    standards = [c["standard"] for c in data["checks"]]
    assert any("MTA-STS" in s for s in standards)
    assert any("DANE" in s for s in standards)


def test_pqc_radar_nonexistent_job(client):
    """Test 404 for invalid job_id."""
    resp = client.get("/api/jobs/nonexistent_job_12345/pqc-radar")
    assert resp.status_code == 404


def test_mitm_custom_crypto_simulation(client):
    """Test real cryptographic execution with custom payload, AES-GCM, and wire hex dump."""
    req_data = {
        "from_addr": "ceo@victimcorp.org",
        "to_addr": "lawyer@legalcorp.org",
        "subject": "Merger Acquisition NDA Document",
        "body": "Confidential merger agreement terms enclosed. Wire $5M escrow.",
        "auth_user": "ceo@victimcorp.org",
        "auth_password": "SuperSecretPass!2026",
        "attachment": "Merger_Agreement.pdf",
    }
    resp = client.post("/api/tools/mitm-simulate", json=req_data)
    assert resp.status_code == 200
    data = resp.json()

    assert data["is_real_crypto"] is True
    assert data["sample_email"]["subject"] == "Merger Acquisition NDA Document"

    scenarios = {s["scenario"]: s for s in data["scenarios"]}

    # Verify Cleartext exposes custom credentials
    ct = scenarios["cleartext"]
    assert "SuperSecretPass!2026" in ct["attacker_view"]["captured_credentials"]
    assert "Merger Acquisition NDA Document" in ct["attacker_view"]["captured_subject"]
    assert "0000" in ct["wire_hex_dump"]
    assert "EHLO" in ct["wire_hex_dump"] or "AUTH" in ct["wire_hex_dump"]

    # Verify TLS 1.2 has real AES-256-GCM hex dump and HNDL alert
    tls12 = scenarios["tls12"]
    assert tls12["crypto_details"]["cipher"] == "AES-256-GCM (Authenticated Encryption)"
    assert len(tls12["crypto_details"]["auth_tag"]) == 32  # 16 bytes = 32 hex chars
    assert "0000" in tls12["wire_hex_dump"]
    assert tls12["hndl_details"]["quantum_decryptable_today"] is False
    assert "Shor" in tls12["hndl_details"]["reason"]

    # Verify PQC TLS 1.3 has hybrid ML-KEM details
    pqc = scenarios["pqc_tls13"]
    assert "ML-KEM-768" in pqc["crypto_details"]["kex"]
    assert "0000" in pqc["wire_hex_dump"]
    assert pqc["hndl_risk"] == "LOW"

