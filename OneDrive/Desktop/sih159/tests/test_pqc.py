"""Tests for Post-Quantum Cryptography (PQC) readiness and HNDL assessment."""

import pytest
from core.models import Session, TLSInfo, CertificateInfo, Severity
from core.pqc import assess_pqc_readiness, parse_named_group, PQC_NAMED_GROUPS
from core.rules import RuleEngine


def test_known_pqc_named_groups_lookup():
    # Int lookup
    g1 = parse_named_group(0x6399)
    assert g1 is not None
    assert g1["name"] == "X25519MLKEM768"
    assert g1["quantum_safe"] is True

    # Hex string lookup
    g2 = parse_named_group("0x11ec")
    assert g2 is not None
    assert g2["name"] == "SecP256r1MLKEM768"

    # Name lookup
    g3 = parse_named_group("x25519kyber768draft00")
    assert g3 is not None
    assert g3["security_level"] == 3


def test_hybrid_kem_quantum_resistant_assessment():
    pqc = assess_pqc_readiness(
        tls_version="TLSv1.3",
        key_exchange="ECDHE",
        key_exchange_group=0x6399,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cert_sig_alg="sha256WithRSAEncryption",
        is_encrypted=True,
    )
    assert pqc.pqc_status == "QUANTUM_RESISTANT"
    assert pqc.quantum_safe_kem is True
    assert pqc.hybrid_key_exchange is True
    assert pqc.kem_algorithm == "ML-KEM-768 (Kyber-768)"
    assert pqc.hndl_risk == "LOW"
    assert pqc.quantum_vulnerability_score == 10.0


def test_static_rsa_high_quantum_risk():
    pqc = assess_pqc_readiness(
        tls_version="TLSv1.2",
        key_exchange="RSA (static)",
        key_exchange_group=None,
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        cert_sig_alg="sha256WithRSAEncryption",
        is_encrypted=True,
    )
    assert pqc.pqc_status == "HIGH_QUANTUM_RISK"
    assert pqc.hndl_risk == "CRITICAL"
    assert pqc.quantum_vulnerability_score == 95.0


def test_pqc_rule_emits_findings():
    engine = RuleEngine()

    # Quantum safe session
    session_safe = Session(
        id="pqc_safe_01",
        protocol="smtp",
        encrypted=True,
        tls=TLSInfo(
            version="TLSv1.3",
            key_exchange="ECDHE",
            key_exchange_group="0x6399",
            cipher_suite="TLS_AES_256_GCM_SHA384",
        ),
    )
    findings_safe = engine.evaluate_all(session_safe)
    pqc_safe_ids = [f.id for f in findings_safe if f.id.startswith("pqc.")]
    assert "pqc.hybrid_active" in pqc_safe_ids
    assert session_safe.pqc.pqc_status == "QUANTUM_RESISTANT"

    # Static RSA vulnerable session
    session_vuln = Session(
        id="pqc_vuln_01",
        protocol="smtp",
        encrypted=True,
        tls=TLSInfo(
            version="TLSv1.2",
            key_exchange="RSA (static)",
            cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        ),
    )
    findings_vuln = engine.evaluate_all(session_vuln)
    pqc_vuln_ids = [f.id for f in findings_vuln if f.id.startswith("pqc.")]
    assert "pqc.harvest_decrypt_critical" in pqc_vuln_ids
    assert session_vuln.pqc.hndl_risk == "CRITICAL"


def test_parse_named_group_classical_secp256r1_returns_none():
    """Regression test: classical secp256r1 must not match hybrid SecP256r1MLKEM768."""
    assert parse_named_group("secp256r1") is None
    assert parse_named_group("SECP256R1") is None


def test_unencrypted_failed_probe_assessed_as_high_quantum_risk():
    """Regression test: unencrypted / failed TLS probe must be scored as HIGH_QUANTUM_RISK and CRITICAL HNDL risk."""
    # With fallback tls_version string and key_exchange_group="secp256r1"
    pqc = assess_pqc_readiness(
        tls_version="TLSv1.2",
        key_exchange="ECDHE",
        key_exchange_group="secp256r1",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        cert_sig_alg="sha256WithRSAEncryption",
        is_encrypted=False,
    )
    assert pqc.pqc_status == "HIGH_QUANTUM_RISK"
    assert pqc.hndl_risk == "CRITICAL"
    assert pqc.quantum_vulnerability_score == 100.0

    # With tls_version=None
    pqc_none = assess_pqc_readiness(
        tls_version=None,
        key_exchange="ECDHE",
        key_exchange_group="secp256r1",
        cipher_suite=None,
        cert_sig_alg=None,
        is_encrypted=False,
    )
    assert pqc_none.pqc_status == "HIGH_QUANTUM_RISK"
    assert pqc_none.hndl_risk == "CRITICAL"
    assert pqc_none.quantum_vulnerability_score == 100.0

