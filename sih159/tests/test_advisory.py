"""Tests for MTA-STS & DANE advisory checker (RFC 8461 & RFC 7672)."""

import datetime as dt
import hashlib
import os
import sys
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Session, TLSInfo, CertificateInfo, DnsSecurityInfo, Finding
from core.advisory import (
    parse_mta_sts_txt,
    generate_mta_sts_recommendations,
    validate_dane_tlsa,
    _extract_domain_and_host,
    evaluate_dns_security,
)
from core.rules import RuleEngine


@pytest.fixture
def dummy_cert_der():
    """Generate a valid self-signed DER certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.org"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# MTA-STS TXT Parsing
# ---------------------------------------------------------------------------

def test_parse_mta_sts_txt_valid():
    record = "v=STSv1; id=20230901120000;"
    rec, valid, pid = parse_mta_sts_txt(record)
    assert valid is True
    assert "v=STSv1" in rec
    assert pid == "20230901120000"


def test_parse_mta_sts_txt_quoted_and_spaces():
    record = '  v=STSv1 ;  id="20241010-v1" ; '
    rec, valid, pid = parse_mta_sts_txt(record)
    assert valid is True
    assert "v=STSv1" in rec
    assert pid == "20241010-v1"


def test_parse_mta_sts_txt_invalid():
    rec, valid, pid = parse_mta_sts_txt("v=spf1 include:_spf.google.com ~all")
    assert valid is False
    assert pid is None
    rec, valid, pid = parse_mta_sts_txt("")
    assert valid is False
    rec, valid, pid = parse_mta_sts_txt("id=12345")
    assert valid is False


# ---------------------------------------------------------------------------
# Recommendations Generation
# ---------------------------------------------------------------------------

def test_generate_mta_sts_recommendations():
    dns_txt, policy = generate_mta_sts_recommendations("securemail.org", ["mx1.securemail.org"])
    assert "_mta-sts.securemail.org" in dns_txt
    assert "v=STSv1" in dns_txt
    assert "version: STSv1" in policy
    assert "mode: enforce" in policy
    assert "mx: mx1.securemail.org" in policy
    assert "max_age: 604800" in policy


# ---------------------------------------------------------------------------
# DANE TLSA Validation
# ---------------------------------------------------------------------------

def test_validate_dane_tlsa_full_cert_sha256(dummy_cert_der):
    cert_sha256 = hashlib.sha256(dummy_cert_der).hexdigest()
    tlsa_record = f"3 0 1 {cert_sha256}"
    valid, status = validate_dane_tlsa([tlsa_record], dummy_cert_der)
    assert valid is True
    assert status == "matched"


def test_validate_dane_tlsa_full_cert_sha512(dummy_cert_der):
    cert_sha512 = hashlib.sha512(dummy_cert_der).hexdigest()
    tlsa_record = f"3 0 2 {cert_sha512}"
    valid, status = validate_dane_tlsa([tlsa_record], dummy_cert_der)
    assert valid is True
    assert status == "matched"


def test_validate_dane_tlsa_spki_sha256(dummy_cert_der):
    parsed_cert = x509.load_der_x509_certificate(dummy_cert_der)
    spki_bytes = parsed_cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_sha256 = hashlib.sha256(spki_bytes).hexdigest()
    tlsa_record = f"3 1 1 {spki_sha256}"
    valid, status = validate_dane_tlsa([tlsa_record], dummy_cert_der)
    assert valid is True
    assert status == "matched"


def test_validate_dane_tlsa_mismatch(dummy_cert_der):
    tlsa_record = "3 0 1 " + "0" * 64
    valid, status = validate_dane_tlsa([tlsa_record], dummy_cert_der)
    assert valid is False
    assert status == "mismatch"


def test_validate_dane_tlsa_no_records(dummy_cert_der):
    valid, status = validate_dane_tlsa([], dummy_cert_der)
    assert valid is None
    assert status == "not_published"


def test_validate_dane_tlsa_invalid_format(dummy_cert_der):
    valid, status = validate_dane_tlsa(["invalid-tlsa-format"], dummy_cert_der)
    assert valid is False
    assert status == "invalid_format"


# ---------------------------------------------------------------------------
# Domain & Host Extraction
# ---------------------------------------------------------------------------

def test_extract_domain_and_host_from_sni():
    session = Session(id="s1", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.tls = TLSInfo(server_name="smtp.corporate.com")
    domain, host = _extract_domain_and_host(session)
    assert domain == "corporate.com"
    assert host == "smtp.corporate.com"


def test_extract_domain_and_host_from_cert_cn():
    session = Session(id="s2", protocol="IMAP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=993)
    session.certificate = CertificateInfo(subject="CN=imap.bank.co.uk, O=Bank")
    domain, host = _extract_domain_and_host(session)
    assert domain == "bank.co.uk"
    assert host == "imap.bank.co.uk"


def test_extract_domain_and_host_fallback():
    session = Session(id="s3", protocol="POP3", client_ip="1.1.1.1", client_port=1234, server_ip="192.168.1.50", server_port=110)
    domain, host = _extract_domain_and_host(session)
    assert domain is None
    assert host is None


# ---------------------------------------------------------------------------
# Offline Evaluation
# ---------------------------------------------------------------------------

def test_evaluate_dns_security_offline():
    session = Session(id="s4", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.tls = TLSInfo(server_name="mail.defense.gov")
    
    # Evaluate with check_online=False
    info = evaluate_dns_security(session, check_online=False)
    assert info is not None
    assert info.domain == "defense.gov"
    assert info.hostname == "mail.defense.gov"
    assert info.recommended_mta_sts_dns is not None
    assert "_mta-sts.defense.gov" in info.recommended_mta_sts_dns
    assert info.recommended_mta_sts_policy is not None


# ---------------------------------------------------------------------------
# Rule Engine Findings
# ---------------------------------------------------------------------------

def test_dns_rule_mta_sts_enforce():
    session = Session(id="s5", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.dns_security = DnsSecurityInfo(
        domain="example.org",
        mta_sts_valid=True,
        mta_sts_mode="enforce",
        mta_sts_id="20240101",
    )
    engine = RuleEngine()
    findings = []
    engine.evaluate_dns_security(session, findings)
    rule_ids = [f.id for f in findings]
    assert "mta_sts.enforce" in rule_ids
    assert any(f.severity == 0 for f in findings)


def test_dns_rule_mta_sts_testing():
    session = Session(id="s6", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.dns_security = DnsSecurityInfo(
        domain="example.org",
        mta_sts_valid=True,
        mta_sts_mode="testing",
    )
    engine = RuleEngine()
    findings = []
    engine.evaluate_dns_security(session, findings)
    rule_ids = [f.id for f in findings]
    assert "mta_sts.testing" in rule_ids
    assert any(f.severity == 1 for f in findings)


def test_dns_rule_mta_sts_missing_on_smtp():
    session = Session(id="s7", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.dns_security = DnsSecurityInfo(
        domain="unprotected-mail.org",
        mta_sts_valid=False,
    )
    engine = RuleEngine()
    findings = []
    engine.evaluate_dns_security(session, findings)
    rule_ids = [f.id for f in findings]
    assert "mta_sts.missing" in rule_ids


def test_dns_rule_dane_verified():
    session = Session(id="s8", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.dns_security = DnsSecurityInfo(
        domain="dane-mail.org",
        hostname="mail.dane-mail.org",
        dane_tlsa_records=["3 0 1 abcdef"],
        dane_valid=True,
        dane_match_status="matched",
    )
    engine = RuleEngine()
    findings = []
    engine.evaluate_dns_security(session, findings)
    rule_ids = [f.id for f in findings]
    assert "dane.verified" in rule_ids


def test_dns_rule_dane_mismatch():
    session = Session(id="s9", protocol="SMTP", client_ip="1.1.1.1", client_port=1234, server_ip="2.2.2.2", server_port=25)
    session.dns_security = DnsSecurityInfo(
        domain="dane-mail.org",
        hostname="mail.dane-mail.org",
        dane_tlsa_records=["3 0 1 abcdef"],
        dane_valid=False,
        dane_match_status="mismatch",
    )
    engine = RuleEngine()
    findings = []
    engine.evaluate_dns_security(session, findings)
    rule_ids = [f.id for f in findings]
    assert "dane.mismatch" in rule_ids
    assert any(f.severity == 3 for f in findings)
