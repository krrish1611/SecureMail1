"""Tests for 1-Click Server Hardening Config Generator."""

import pytest
from core.models import Session, TLSInfo, Finding, Severity, DnsSecurityInfo
from reports.hardening import (
    generate_postfix_config,
    generate_dovecot_config,
    generate_exim_config,
    generate_sendmail_config,
    generate_hardening_package,
)


def test_postfix_hardening_includes_tls12_and_dane():
    session = Session(
        id="test_post_01",
        protocol="smtp",
        server_ip="192.168.1.10",
        findings=[
            Finding(
                id="tls.10",
                title="Obsolete TLS 1.0 negotiated",
                description="TLS 1.0 is deprecated.",
                category="tls.version",
                severity=Severity.HIGH,
                recommendation="Disable TLS 1.0; require TLS 1.2+.",
            ),
            Finding(
                id="cipher.rc4",
                title="Weak cipher suite in use",
                description="RC4 cipher is broken.",
                category="tls.cipher",
                severity=Severity.CRITICAL,
                recommendation="Disable RC4.",
            ),
        ],
        dns_security=DnsSecurityInfo(domain="example.org", mta_sts_valid=False),
    )

    postfix = generate_postfix_config(session)
    assert postfix.daemon == "Postfix"
    assert postfix.target_file == "/etc/postfix/main.cf"
    assert "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1" in postfix.config_text
    assert "smtp_dns_support_level = dnssec" in postfix.config_text
    assert "smtp_tls_security_level = dane" in postfix.config_text
    assert "smtpd_tls_auth_only = yes" in postfix.config_text
    assert len(postfix.remediated_findings) >= 2


def test_dovecot_hardening_requires_ssl():
    session = Session(
        id="test_dov_01",
        protocol="imap",
        findings=[
            Finding(
                id="starttls.plaintext_creds",
                title="Credentials sent in plaintext",
                description="Plaintext auth before TLS.",
                category="starttls",
                severity=Severity.CRITICAL,
                recommendation="Disable plaintext auth.",
            )
        ],
    )
    dovecot = generate_dovecot_config(session)
    assert dovecot.daemon == "Dovecot"
    assert "ssl = required" in dovecot.config_text
    assert "disable_plaintext_auth = yes" in dovecot.config_text
    assert "ssl_min_protocol = TLSv1.2" in dovecot.config_text


def test_full_hardening_package():
    session = Session(
        id="test_pkg_01",
        protocol="smtp",
        server_ip="10.0.0.1",
        tls=TLSInfo(server_name="mail.corp.com"),
    )
    pkg = generate_hardening_package(session)
    assert pkg.session_id == "test_pkg_01"
    assert pkg.domain == "mail.corp.com"
    assert "postfix" in pkg.snippets
    assert "dovecot" in pkg.snippets
    assert "exim" in pkg.snippets
    assert "sendmail" in pkg.snippets
    assert pkg.snippets["postfix"].reload_command != ""
