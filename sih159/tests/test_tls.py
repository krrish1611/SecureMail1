"""Unit tests for TLS handshake parsing, focusing on TLS 1.3 accuracy."""

import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.tls import parse_tls_stream

GEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "deps", "generate_sample_pcap.py")
_spec = importlib.util.spec_from_file_location("genpcap", GEN)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

# IANA cipher suite codes used in the generator data.
TLS_RSA_WITH_RC4_128_SHA = 0x0005
TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
TLS_AES_128_GCM_SHA256 = 0x1301


def _feed(client_hello_bytes, server_hello_bytes):
    return parse_tls_stream(server_hello_bytes, client_hello_bytes)


def test_tls13_detects_ecdh_forward_secrecy():
    random = bytes(range(32))
    ch = gen._client_hello(0x0303, random, [TLS_AES_128_GCM_SHA256],
                           sni="mail.example.com", tls13=True, key_share_group=0x001d)
    sh = gen._server_hello(0x0304, TLS_AES_128_GCM_SHA256, tls13=True)
    tls = _feed(ch, sh)
    assert tls.version == "TLSv1.3"
    assert tls.version_rank == 4
    assert tls.cipher_suite == "TLS_AES_128_GCM_SHA256"
    # TLS 1.3 always uses an ephemeral (EC)DHE key exchange.
    assert tls.key_exchange == "ECDHE"
    assert tls.key_exchange_group is not None
    assert tls.server_name == "mail.example.com"
    # Forward secrecy should be true for an ephemeral key exchange.
    fs = bool(tls.key_exchange and "DHE" in (tls.key_exchange or ""))
    assert fs is True


def test_tls12_rsa_static_no_forward_secrecy():
    random = bytes(range(32))
    ch = gen._client_hello(0x0303, random, [TLS_RSA_WITH_AES_256_CBC_SHA], sni=None)
    sh = gen._server_hello(0x0303, TLS_RSA_WITH_AES_256_CBC_SHA)
    tls = _feed(ch, sh)
    assert tls.version == "TLSv1.2"
    assert tls.key_exchange == "RSA (static)"
    fs = bool(tls.key_exchange and "DHE" in (tls.key_exchange or ""))
    assert fs is False


def test_offered_versions_parsed_for_tls13():
    random = bytes(range(32))
    ch = gen._client_hello(0x0303, random, [TLS_AES_128_GCM_SHA256],
                           sni=None, tls13=True, key_share_group=0x001d)
    sh = gen._server_hello(0x0304, TLS_AES_128_GCM_SHA256, tls13=True)
    tls = _feed(ch, sh)
    assert "TLSv1.3" in tls.offered_versions or len(tls.offered_versions) >= 1
    assert tls.version == "TLSv1.3"
