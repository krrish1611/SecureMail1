"""End-to-end analyzer tests against the synthetic sample PCAP."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.capture import reassemble
from core.analyzer import analyze_all
from core.models import Severity


def test_sample_pcap_produces_four_sessions(sample_pcap):
    assert os.path.exists(sample_pcap), "sample_traffic.pcap must exist"
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    assert len(sessions) == 4
    protocols = {s.protocol for s in sessions}
    assert {"smtp", "imap", "pop3"} <= protocols


def test_weak_rc4_smtp_flagged(sample_pcap):
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    smtp_rc4 = [s for s in sessions
                if s.protocol == "smtp" and s.tls and s.tls.cipher_suite == "TLS_RSA_WITH_RC4_128_SHA"]
    assert len(smtp_rc4) == 1
    s = smtp_rc4[0]
    ids = [f.id for f in s.findings]
    assert "cipher.rc4" in ids


def test_tls13_pop3_no_weak_findings(sample_pcap):
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    pop3 = [s for s in sessions if s.protocol == "pop3"]
    assert len(pop3) == 1
    s = pop3[0]
    assert s.encrypted is True
    assert s.tls and s.tls.version == "TLSv1.3"
    ids = [f.id for f in s.findings]
    assert "tls.weak_cipher" not in ids


def test_plaintext_credential_smtp(sample_pcap):
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    plain = [s for s in sessions if s.credentials_plaintext]
    assert len(plain) >= 1


def test_imap_tls1_0_finding(sample_pcap):
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    imap = [s for s in sessions if s.protocol == "imap"]
    assert len(imap) == 1
    ids = [f.id for f in imap[0].findings]
    assert "tls.10" in ids
