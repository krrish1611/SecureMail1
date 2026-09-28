"""Shared pytest fixtures and path setup."""

import os
import sys

import pytest

# Ensure the project root is importable.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime as dt


@pytest.fixture(scope="session")
def sample_pcap():
    return os.path.join(ROOT, "deps", "sample_traffic.pcap")


def _make_cert(subject_name, issuer_name, pubkey, issuer_key, not_valid_days=365,
               ca=False):  # noqa: E501
    """Build a self-signed->signed cert; returns (cert_obj, key_obj)."""
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=not_valid_days))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=False, content_commitment=False,
                          key_encipherment=False, data_encipherment=False,
                          key_agreement=False, key_cert_sign=True,
                          crl_sign=True, encipher_only=None, decipher_only=None),
            critical=True)
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.example.com")]), critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    return cert


@pytest.fixture(scope="session")
def cert_chain():
    """Generate a root CA -> intermediate -> leaf chain. Returns DER bytes list (leaf first)."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_cert = _make_cert("root-ca", "root-ca", root_key.public_key(), root_key, ca=True)
    inter_cert = _make_cert("inter-ca", "root-ca", inter_key.public_key(), root_key, ca=True)
    leaf_cert = _make_cert("mail.example.com", "inter-ca",
                           leaf_key.public_key(), inter_key, ca=False)

    def der(c):
        return c.public_bytes(serialization.Encoding.DER)
    return {
        "root": root_cert, "inter": inter_cert, "leaf": leaf_cert,
        "leaf_der": der(leaf_cert), "inter_der": der(inter_cert),
        "root_der": der(root_cert),
        "leaf_key": leaf_key,
    }
