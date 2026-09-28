"""Unit tests for protocol detection and plaintext credential detection."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.protocols import detect_credentials_plaintext, ProtocolDetector


def test_smtp_auth_login_standalone():
    assert detect_credentials_plaintext("smtp", b"550 ok\r\nAUTH LOGIN\r\n") == (True, "AUTH LOGIN")


def test_smtp_auth_login_initial_response():
    """AUTH LOGIN <base64> (initial-response form) must be flagged."""
    assert detect_credentials_plaintext("smtp", b"AUTH LOGIN dXNlcg==\r\n") == (True, "AUTH LOGIN")


def test_smtp_auth_plain_initial_response():
    assert detect_credentials_plaintext("smtp", b"AUTH PLAIN AHRlc3Q=\r\n") == (True, "AUTH PLAIN")


def test_smtp_normal_conversation_not_flagged():
    assert detect_credentials_plaintext("smtp", b"220 mx ESMTP\r\nEHLO client\r\n") == (False, None)


def test_imap_login_detected():
    assert detect_credentials_plaintext("imap", b"LOGIN user secret\r\n") == (True, "LOGIN")


def test_pop3_user_detected():
    assert detect_credentials_plaintext("pop3", b"USER alice\r\n") == (True, "USER/PASS")


def test_detector_identifies_email_protocols():
    det = ProtocolDetector()
    assert det.detect(b"220 mx.example.com ESMTP\r\n", b"EHLO x\r\n") == "smtp"
    assert det.detect(b"* OK IMAP4rev1 ready\r\n", b"a1 CAPABILITY\r\n") == "imap"
    assert det.detect(b"+OK POP3 ready\r\n", b"USER x\r\n") == "pop3"
    assert det.detect(b"HTTP/1.1 200 OK\r\n", b"GET / HTTP/1.1\r\n") is None
