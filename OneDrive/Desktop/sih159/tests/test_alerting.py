"""Tests for Multi-Channel Webhook Alerting Engine (Slack, Discord, SIEM)."""

import pytest
from core.models import Session, TLSInfo, Finding, Severity
from core.alerting import WebhookDispatcher


def test_slack_formatting_payload():
    session = Session(
        id="slack_alert_01",
        protocol="smtp",
        server_ip="192.168.1.10",
        server_port=25,
        client_ip="10.0.0.5",
        client_port=43210,
        posture_score=35.0,
        risk_label="critical",
        tls=TLSInfo(version="TLSv1.0", ja4="t10d050400_abc123_def456"),
        findings=[
            Finding(
                id="starttls.stripped",
                title="STARTTLS downgrade attack detected (stripped)",
                description="Active stripping detected.",
                category="starttls",
                severity=Severity.CRITICAL,
                recommendation="Enforce mandatory TLS.",
                cwe="CWE-757",
            )
        ],
    )
    dispatcher = WebhookDispatcher(provider="slack", dry_run=True)
    payload = dispatcher.format_slack(session, session.findings)
    assert "blocks" in payload
    assert len(payload["blocks"]) >= 4
    # Context section contains JA4
    block_texts = [str(b) for b in payload["blocks"]]
    assert any("t10d050400_abc123_def456" in t for t in block_texts)


def test_discord_formatting_payload():
    session = Session(
        id="discord_alert_01",
        protocol="imap",
        server_ip="192.168.1.10",
        server_port=143,
        client_ip="10.0.0.5",
        client_port=55555,
        findings=[
            Finding(
                id="cert.revoked",
                title="Certificate is revoked",
                description="OCSP returned revoked.",
                category="certificate",
                severity=Severity.CRITICAL,
                recommendation="Rotate certificate.",
            )
        ],
    )
    dispatcher = WebhookDispatcher(provider="discord", dry_run=True)
    payload = dispatcher.format_discord(session, session.findings)
    assert "embeds" in payload
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert embed["color"] == 0xD32F2F  # Red for critical


def test_siem_formatting_payload():
    session = Session(
        id="siem_alert_01",
        protocol="pop3",
        server_ip="10.0.0.1",
        server_port=110,
        client_ip="10.0.0.2",
        client_port=33333,
        findings=[
            Finding(
                id="starttls.plaintext_creds",
                title="Credentials sent in plaintext",
                description="Plaintext auth.",
                category="starttls",
                severity=Severity.CRITICAL,
                recommendation="Use TLS.",
            )
        ],
    )
    dispatcher = WebhookDispatcher(provider="siem", dry_run=True)
    payload = dispatcher.format_siem(session, session.findings)
    assert payload["event_type"] == "securemailscope_crypto_alert"
    assert payload["session_id"] == "siem_alert_01"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["id"] == "starttls.plaintext_creds"


def test_dry_run_dispatch_and_threshold_filtering():
    session_low = Session(
        id="low_01",
        protocol="smtp",
        findings=[
            Finding(
                id="tls.cipher.cbc_sha1",
                title="CBC mode cipher",
                description="CBC",
                category="tls.cipher",
                severity=Severity.LOW,
                recommendation="Prefer GCM",
            )
        ],
    )
    dispatcher = WebhookDispatcher(min_severity=Severity.HIGH, dry_run=True)
    res_low = dispatcher.dispatch(session_low)
    assert res_low["dispatched"] is False
    assert "threshold" in res_low["reason"].lower()

    # Session with HIGH finding
    session_high = Session(
        id="high_01",
        protocol="smtp",
        findings=[
            Finding(
                id="tls.10",
                title="TLS 1.0",
                description="Deprecated",
                category="tls.version",
                severity=Severity.HIGH,
                recommendation="Disable TLS 1.0",
            )
        ],
    )
    res_high = dispatcher.dispatch(session_high)
    assert res_high["dispatched"] is True
    assert res_high["mode"] == "dry_run"
    assert len(dispatcher.sent_alerts) == 1
