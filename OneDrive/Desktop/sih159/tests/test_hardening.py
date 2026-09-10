"""Tests for 1-Click Server Hardening Config Generator."""

import pytest
from core.models import Session, TLSInfo, Finding, Severity, DnsSecurityInfo
from reports.hardening import (
    generate_postfix_config,
    generate_dovecot_config,
    generate_exim_config,
    generate_sendmail_config,
    generate_hardening_package,
    generate_hardening_script_sh,
    generate_hardening_script_ps1,
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


def test_hardening_script_sh_generation():
    session = Session(
        id="test_sh_01",
        protocol="smtp",
        server_ip="10.0.0.25",
        tls=TLSInfo(server_name="mail.secure.org"),
    )
    pkg = generate_hardening_package(session)
    script = generate_hardening_script_sh(pkg, target_name="mail.secure.org")
    assert "#!/usr/bin/env bash" in script
    assert "postconf -e" in script
    assert "smtpd_tls_mandatory_protocols" in script
    assert "dovecot" in script
    assert "mail.secure.org" in script
    assert "test_sh_01" in script


def test_hardening_script_ps1_generation():
    session = Session(
        id="test_ps1_01",
        protocol="smtp",
        server_ip="10.0.0.25",
        tls=TLSInfo(server_name="mail.secure.org"),
    )
    pkg = generate_hardening_package(session)
    ps1 = generate_hardening_script_ps1(pkg, target_name="mail.secure.org")
    assert "SecureMailScope Windows SChannel" in ps1
    assert "SCHANNEL\\Protocols" in ps1
    assert "TLS 1.2" in ps1
    assert "TLS 1.3" in ps1
    assert "mail.secure.org" in ps1


def test_hardening_script_api_endpoint():
    from fastapi.testclient import TestClient
    from backend.app.main import app
    from backend.app.routers.analyze import _jobs

    client = TestClient(app)
    session = Session(
        id="test_job_sess_01",
        protocol="smtp",
        server_ip="192.168.1.50",
        tls=TLSInfo(server_name="mx.domain.com"),
    )
    _jobs["job_hardening_test"] = {
        "sessions": [session],
        "target_name": "mx.domain.com",
    }

    # Test Linux .sh endpoint
    resp_sh = client.get("/api/jobs/job_hardening_test/hardening-script?platform=linux")
    assert resp_sh.status_code == 200
    assert resp_sh.headers["content-type"].startswith("application/x-sh")
    assert "attachment" in resp_sh.headers["content-disposition"]
    assert "postfix" in resp_sh.text

    # Test Windows .ps1 endpoint
    resp_ps1 = client.get("/api/jobs/job_hardening_test/hardening-script?platform=windows")
    assert resp_ps1.status_code == 200
    assert resp_ps1.headers["content-type"].startswith("text/plain")
    assert "attachment" in resp_ps1.headers["content-disposition"]
    assert "SCHANNEL" in resp_ps1.text

    # Test Session direct endpoint
    resp_sess = client.get("/api/sessions/test_job_sess_01/hardening-script?platform=linux")
    assert resp_sess.status_code == 200
    assert "postfix" in resp_sess.text

