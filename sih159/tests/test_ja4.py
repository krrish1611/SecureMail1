"""Tests for JA4+ fingerprinting engine (JA4, JA4S, JA4X)."""

import datetime as dt
import importlib.util
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ja4 import is_grease, compute_ja4, compute_ja4s, compute_ja4x
from core.certs import parse_certificate
from core.tls import parse_tls_stream

GEN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "deps", "generate_sample_pcap.py"
)
_spec = importlib.util.spec_from_file_location("genpcap", GEN)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def test_grease_detection():
    # RFC 8701 GREASE values
    assert is_grease(0x0A0A) is True
    assert is_grease(0x1A1A) is True
    assert is_grease(0xFAFA) is True
    # Non-grease values
    assert is_grease(0x002F) is False
    assert is_grease(0x1301) is False
    assert is_grease(0x0033) is False


def test_ja4_client_fingerprint_tls13():
    # TLS 1.3 ClientHello with SNI, ciphers, and ALPN
    fp = compute_ja4(
        ciphers=[0x1301, 0x1302, 0x0A0A],  # 0x0A0A is GREASE
        extensions=[0x0000, 0x0010, 0x002B, 0x0033, 0x1A1A],  # SNI, ALPN, supp_vers, key_share, GREASE
        protocol_version=0x0303,
        supported_versions=[0x0304, 0x0303, 0x2A2A],  # 0x0304 is TLS 1.3
        sni="mail.example.com",
        alpn="smtp",
        sig_algs=[0x0403, 0x0804],
        transport="t",
    )
    parts = fp.split("_")
    assert len(parts) == 3
    part_a, part_b, part_c = parts
    # Format: [transport][version][sni][cipher_count][ext_count][alpn]
    # 't' + '13' + 'd' + '02' (2 non-grease ciphers) + '02' (supp_vers & key_share non-grease, non-sni, non-alpn) + 'sp'
    assert part_a == "t13d0202sp"
    assert len(part_b) == 12
    assert len(part_c) == 12


def test_ja4_client_fingerprint_tls12_no_sni():
    fp = compute_ja4(
        ciphers=[0x0035, 0x002F],
        extensions=[0x000A, 0x000B],
        protocol_version=0x0303,
        supported_versions=None,
        sni=None,
        alpn=None,
        sig_algs=None,
        transport="t",
    )
    parts = fp.split("_")
    assert len(parts) == 3
    part_a, part_b, part_c = parts
    # 't' + '12' + 'i' + '02' + '02' + '00'
    assert part_a == "t12i020200"
    assert len(part_b) == 12
    assert len(part_c) == 12


def test_ja4s_server_fingerprint():
    fp = compute_ja4s(
        cipher=0x1301,
        extensions=[0x002B, 0x0033],
        negotiated_version=0x0304,
        alpn="smtp",
        transport="t",
    )
    parts = fp.split("_")
    assert len(parts) == 3
    part_a, part_b, part_c = parts
    # 't' + '13' + '02' + 'sp'
    assert part_a == "t1302sp"
    assert part_b == "1301"
    assert len(part_c) == 12


def test_ja4x_certificate_fingerprint():
    # Generate a realistic self-signed X.509 cert in memory
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMail Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.securemail.internal"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("mail.securemail.internal")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    ja4x = compute_ja4x(cert)
    assert ja4x is not None
    parts = ja4x.split("_")
    assert len(parts) == 3
    assert len(parts[0]) == 12
    assert len(parts[1]) == 12
    assert len(parts[2]) == 12

    # parse_certificate integration test
    from cryptography.hazmat.primitives import serialization
    der = cert.public_bytes(serialization.Encoding.DER)
    info = parse_certificate(der)
    assert info is not None
    assert info.ja4x == ja4x


def test_full_tls_stream_ja4_ja4s():
    # Reconstruct from synthetic ClientHello and ServerHello
    random = bytes(range(32))
    ch = gen._client_hello(
        0x0303, random, [0x1301],
        sni="mail.example.com", tls13=True, key_share_group=0x001D
    )
    sh = gen._server_hello(0x0304, 0x1301, tls13=True)
    tls_info = parse_tls_stream(sh, ch)

    assert tls_info.ja4 is not None
    assert tls_info.ja4.startswith("t13d")
    assert tls_info.ja4s is not None
    assert tls_info.ja4s.startswith("t13")
    assert "_1301_" in tls_info.ja4s
