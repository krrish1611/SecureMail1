"""Tests for JA4 Threat Actor & Client Attribution Engine."""

import pytest
from core.models import Session, TLSInfo, Finding, Severity
from core.attribution import attribute_session
from core.rules import RuleEngine


def test_attribute_modern_mua():
    session = Session(
        id="mua_01",
        protocol="smtp",
        encrypted=True,
        tls=TLSInfo(
            version="TLSv1.3",
            server_name="mail.enterprise.org",
            ja4="t13d151200_a1b2c3d4e5f6_7a8b9c0d1e2f",
            extensions=["server_name", "supported_groups", "key_share", "alpn", "signature_algorithms", "status_request", "extended_master_secret", "renegotiation_info"],
        ),
    )
    attr = attribute_session(session)
    assert attr.client_category == "email_client"
    assert not attr.is_threat
    assert not attr.masquerading_detected


def test_attribute_scripting_client():
    session = Session(
        id="script_01",
        protocol="smtp",
        encrypted=True,
        tls=TLSInfo(
            version="TLSv1.3",
            server_name=None,
            ja4="t13i040300_4d8a1c9e2b3f_123456789abc",
            extensions=["supported_groups", "key_share", "signature_algorithms"],
        ),
    )
    attr = attribute_session(session)
    assert attr.client_category == "scripting_tool"
    assert attr.is_automation is True


def test_masquerading_detection_triggers_critical_finding():
    # Client claiming to be Microsoft Outlook in AUTH/banner but having scripting JA4 fingerprint
    session = Session(
        id="spoof_01",
        protocol="smtp",
        encrypted=True,
        auth_command_observed="AUTH LOGIN (User-Agent: Outlook 365 MUA)",
        tls=TLSInfo(
            version="TLSv1.3",
            ja4="t13i040300_4d8a1c9e2b3f_123456789abc",
            extensions=["supported_groups", "key_share", "signature_algorithms"],
        ),
    )
    engine = RuleEngine()
    findings = engine.evaluate_all(session)

    assert session.attribution is not None
    assert session.attribution.masquerading_detected is True
    assert session.attribution.is_threat is True

    threat_findings = [f for f in findings if f.id == "threat.masquerading"]
    assert len(threat_findings) == 1
    assert threat_findings[0].severity == Severity.CRITICAL
    assert threat_findings[0].cwe == "CWE-290"
