"""Unit tests for X.509 certificate parsing, chain validation and revocation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from core.certs import (
    parse_certificate, validate_certificates, validate_chain, load_trust_store,
)
import datetime as dt


def _der(cert):
    return cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)


def test_parse_signed_leaf(cert_chain):
    info = parse_certificate(cert_chain["leaf_der"])
    assert info is not None
    assert info.self_signed is False
    assert info.subject == "CN=mail.example.com"
    assert info.key_size == 2048


def test_parse_self_signed_detection():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    info = parse_certificate(_der(cert))
    assert info is not None
    assert info.self_signed is True


def test_validate_chain_trusted_with_custom_store(cert_chain):
    leaf_der = cert_chain["leaf_der"]
    inter_der = cert_chain["inter_der"]
    # Trust the root directly.
    trust_store = [cert_chain["root"]]
    valid, issues, trusted = validate_chain(leaf_der, [inter_der], trust_store)
    assert valid is True
    assert trusted is True
    assert not any("validation failed" in i for i in issues)


def test_validate_chain_untrusted(cert_chain):
    leaf_der = cert_chain["leaf_der"]
    inter_der = cert_chain["inter_der"]
    other_root = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    foreign_root = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")]))
        .public_key(other_root.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(other_root, hashes.SHA256())
    )
    valid, issues, trusted = validate_chain(leaf_der, [inter_der], [foreign_root])
    assert valid is False
    assert trusted is False


def test_validate_certificates_full_chain(cert_chain):
    certs_der = [cert_chain["leaf_der"], cert_chain["inter_der"], cert_chain["root_der"]]
    parsed, leaf, chain_valid, issues = validate_certificates(
        certs_der, trust_store=[cert_chain["root"]])
    assert leaf is not None
    assert chain_valid is True
    assert leaf.trusted is True


def test_validate_certificates_self_signed_untrusted():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    parsed, leaf, chain_valid, issues = validate_certificates([_der(cert)])
    assert leaf is not None
    assert leaf.self_signed is True
    assert chain_valid is False
    assert leaf.trusted is False


def test_load_trust_store_nonempty():
    store = load_trust_store()
    assert isinstance(store, list) and len(store) > 0


def test_rules_flag_untrusted(cert_chain):
    """Rules should emit a finding for an untrusted/self-signed cert."""
    from core.models import CertificateInfo, Severity
    from core.rules import RuleEngine
    from core.models import Session
    import uuid
    from dataclasses import replace

    parsed, leaf, chain_valid, issues = validate_certificates(
        [cert_chain["leaf_der"], cert_chain["inter_der"], cert_chain["root_der"]])
    session = Session(id=uuid.uuid4().hex[:12])
    # Even trusted, ensure rules don't crash; then test untrusted case separately.
    session.certificate = leaf
    engine = RuleEngine()
    engine.evaluate_all(session)  # should not raise
    assert session.findings is not None

    # Force untrusted and confirm findings.
    u_leaf = replace(leaf, trusted=False, chain_valid=True, revoked=False)
    sess2 = Session(id=uuid.uuid4().hex[:12])
    sess2.certificate = u_leaf
    e2 = RuleEngine()
    e2.evaluate_all(sess2)
    ids = [f.id for f in sess2.findings]
    assert "cert.untrusted" in ids
