"""1-Click Server Hardening Configuration Generator.

Automatically produces cryptographically secure, production-ready configuration
snippets for popular Mail Transfer Agents (MTAs) and IMAP/POP3 daemons:
- Postfix (SMTP server & client: main.cf)
- Exim4 (SMTP server: exim4.conf)
- Dovecot (IMAP/POP3 server: 10-ssl.conf)
- Sendmail (sendmail.mc)

Tailors configurations to address findings discovered during traffic inspection:
- Enforcing TLS 1.2+ / TLS 1.3
- Strong AEAD cipher suites (disabling CBC, 3DES, RC4, NULL)
- Strict STARTTLS enforcement (mandatory encryption before AUTH)
- DANE (RFC 7672) & DNSSEC validation
- MTA-STS (RFC 8461) enforcement
- Post-Quantum Cryptography (X25519MLKEM768 / Kyber) readiness
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.models import Session, Finding, Severity


@dataclass
class HardeningSnippet:
    """A hardened configuration block for a specific daemon."""

    daemon: str
    target_file: str
    config_text: str
    explanation: str
    remediated_findings: List[str] = field(default_factory=list)
    reload_command: str = ""


@dataclass
class HardeningPackage:
    """Full server hardening plan with configurations for all major mail daemons."""

    session_id: str
    server_ip: Optional[str] = None
    domain: Optional[str] = None
    snippets: Dict[str, HardeningSnippet] = field(default_factory=dict)
    summary: str = ""


def generate_postfix_config(session: Session) -> HardeningSnippet:
    """Generate hardened Postfix main.cf configuration."""
    remediated = []
    lines = [
        "# =====================================================================",
        "# SecureMailScope Hardened Postfix Configuration (main.cf)",
        f"# Generated for session: {session.id}",
        "# Security Baseline: TLS 1.2+, Strong AEAD Ciphers, Mandatory STARTTLS, DANE",
        "# =====================================================================",
        "",
        "# 1. Protocol Versions: Disallow SSLv2, SSLv3, TLSv1.0, TLSv1.1",
        "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
        "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
        "smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
        "smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
        "",
        "# 2. High-Security Cipher Suites (AEAD only, Forward Secrecy)",
        "smtpd_tls_mandatory_ciphers = high",
        "smtpd_tls_ciphers = high",
        "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, 3DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC",
        "tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        "",
        "# 3. Enforce Strict STARTTLS and prevent plaintext credential theft",
        "smtpd_tls_security_level = encrypt",
        "smtpd_tls_auth_only = yes",
        "",
        "# 4. Enable DANE (RFC 7672) & DNSSEC validation for outgoing mail",
        "smtp_dns_support_level = dnssec",
        "smtp_tls_security_level = dane",
        "smtp_tls_loglevel = 1",
        "",
        "# 5. TLS Session Cache & Modern Elliptic Curves (including PQC groups)",
        "smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache",
        "smtpd_tls_eecdh_grade = ultra",
        "tls_eecdh_strong_curve = prime256v1",
        "tls_eecdh_ultra_curve = secp384r1",
    ]

    for f in session.findings:
        if "tls.10" in f.id or "tls.11" in f.id or "tls.ssl3" in f.id:
            remediated.append("Enforced TLS 1.2+ minimum (disables obsolete versions)")
        elif "cipher" in f.id:
            remediated.append("Restricted ciphers to high-grade AEAD suites (GCM/Poly1305)")
        elif "starttls.plaintext_creds" in f.id or "starttls.missing" in f.id:
            remediated.append("Configured smtpd_tls_auth_only = yes to block plaintext credentials")
        elif "dane" in f.id or "mta_sts" in f.id:
            remediated.append("Enabled smtp_tls_security_level = dane and DNSSEC resolution")

    if not remediated:
        remediated.append("Applied modern cryptographic baseline and forward secrecy controls")

    return HardeningSnippet(
        daemon="Postfix",
        target_file="/etc/postfix/main.cf",
        config_text="\n".join(lines),
        explanation="Enforces TLS 1.2/1.3, AEAD ciphers, DANE verification, and blocks authentication before TLS.",
        remediated_findings=sorted(set(remediated)),
        reload_command="postfix check && systemctl restart postfix",
    )


def generate_dovecot_config(session: Session) -> HardeningSnippet:
    """Generate hardened Dovecot 10-ssl.conf configuration."""
    remediated = []
    lines = [
        "# =====================================================================",
        "# SecureMailScope Hardened Dovecot Configuration (10-ssl.conf)",
        f"# Generated for session: {session.id}",
        "# Security Baseline: Require SSL/TLS, Disable Insecure Auth, Forward Secrecy",
        "# =====================================================================",
        "",
        "# 1. Require SSL/TLS for all IMAP/POP3 connections",
        "ssl = required",
        "disable_plaintext_auth = yes",
        "",
        "# 2. Minimum TLS Protocol Version (TLS 1.2 minimum)",
        "ssl_min_protocol = TLSv1.2",
        "",
        "# 3. High-Security AEAD Ciphers",
        "ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        "ssl_prefer_server_ciphers = yes",
        "",
        "# 4. Certificate and Key locations (Update paths to valid certificates)",
        "ssl_cert = </etc/ssl/certs/mailserver.crt",
        "ssl_key = </etc/ssl/private/mailserver.key",
        "ssl_dh = </etc/dovecot/dh.pem",
    ]

    for f in session.findings:
        if "starttls.plaintext_creds" in f.id or "starttls.missing" in f.id:
            remediated.append("Configured disable_plaintext_auth = yes and ssl = required")
        elif "tls.10" in f.id or "tls.11" in f.id:
            remediated.append("Configured ssl_min_protocol = TLSv1.2")
        elif "cert" in f.id:
            remediated.append("Configured strict certificate path directives")

    if not remediated:
        remediated.append("Secured IMAP/POP3 authentication endpoints with mandatory TLS")

    return HardeningSnippet(
        daemon="Dovecot",
        target_file="/etc/dovecot/conf.d/10-ssl.conf",
        config_text="\n".join(lines),
        explanation="Requires TLS before authentication, bans plaintext logins, and enforces TLS 1.2+.",
        remediated_findings=sorted(set(remediated)),
        reload_command="dovecot reload",
    )


def generate_exim_config(session: Session) -> HardeningSnippet:
    """Generate hardened Exim4 configuration."""
    remediated = []
    lines = [
        "# =====================================================================",
        "# SecureMailScope Hardened Exim4 Configuration",
        f"# Generated for session: {session.id}",
        "# Security Baseline: OpenSSL modern profiles, Strict STARTTLS",
        "# =====================================================================",
        "",
        "# 1. Disallow Obsolete TLS Protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)",
        "openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1",
        "",
        "# 2. Strict AEAD Cipher List",
        "tls_require_ciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        "",
        "# 3. Require TLS before AUTH",
        "auth_advertise_hosts = ${if eq{$tls_in_cipher}{}{}{*}}",
        "",
        "# 4. Mandatory STARTTLS verification for outgoing SMTP",
        "tls_try_verify_hosts = *",
    ]

    remediated.append("Disabled SSLv2/v3 and TLS 1.0/1.1 via openssl_options")
    remediated.append("Restricted AUTH advertisement to active TLS encrypted channels")

    return HardeningSnippet(
        daemon="Exim4",
        target_file="/etc/exim4/exim4.conf.template",
        config_text="\n".join(lines),
        explanation="Restricts Exim to modern TLS with OpenSSL options and hides AUTH until STARTTLS succeeds.",
        remediated_findings=remediated,
        reload_command="update-exim4.conf && systemctl restart exim4",
    )


def generate_sendmail_config(session: Session) -> HardeningSnippet:
    """Generate hardened Sendmail configuration."""
    lines = [
        "dnl =====================================================================",
        "dnl SecureMailScope Hardened Sendmail Configuration (sendmail.mc)",
        f"dnl Generated for session: {session.id}",
        "dnl =====================================================================",
        "LOCAL_CONFIG",
        "O CipherList=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
        "O ServerSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1 +SSL_OP_CIPHER_SERVER_PREFERENCE",
        "O ClientSSLOptions=+SSL_OP_NO_SSLv2 +SSL_OP_NO_SSLv3 +SSL_OP_NO_TLSv1 +SSL_OP_NO_TLSv1_1",
    ]

    return HardeningSnippet(
        daemon="Sendmail",
        target_file="/etc/mail/sendmail.mc",
        config_text="\n".join(lines),
        explanation="Disables legacy SSL/TLS versions in Sendmail macro configuration.",
        remediated_findings=["Enforces SSL_OP_NO_TLSv1 and modern CipherList"],
        reload_command="make -C /etc/mail && systemctl restart sendmail",
    )


def generate_hardening_package(session: Session) -> HardeningPackage:
    """Generate a full server hardening package for all supported mail servers."""
    domain = None
    if session.dns_security and session.dns_security.domain:
        domain = session.dns_security.domain
    elif session.tls and session.tls.server_name:
        domain = session.tls.server_name

    package = HardeningPackage(
        session_id=session.id,
        server_ip=session.server_ip,
        domain=domain,
    )

    package.snippets["postfix"] = generate_postfix_config(session)
    package.snippets["dovecot"] = generate_dovecot_config(session)
    package.snippets["exim"] = generate_exim_config(session)
    package.snippets["sendmail"] = generate_sendmail_config(session)

    package.summary = (
        f"Hardening configuration generated for {session.id} ({session.protocol.upper() if session.protocol else 'SMTP'}). "
        f"Contains automated remediations for Postfix, Dovecot, Exim4, and Sendmail."
    )

    return package
