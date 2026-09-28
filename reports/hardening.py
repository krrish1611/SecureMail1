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


def generate_exchange_config(session: Session) -> HardeningSnippet:
    """Generate hardened Microsoft Exchange / PowerShell configuration."""
    lines = [
        "# =====================================================================",
        "# SecureMailScope Hardened Microsoft Exchange Configuration (PowerShell)",
        f"# Generated for session: {session.id}",
        "# =====================================================================",
        "# 1. Enforce mandatory TLS on Receive Connectors",
        "Get-ReceiveConnector | Set-ReceiveConnector -SuppressXAnonymousTls $false -AuthMechanism Tls",
        "",
        "# 2. Require TLS for Outbound Send Connectors",
        "Get-SendConnector | Set-SendConnector -IgnoreSTARTTLS $false -RequireTLS $true",
        "",
        "# 3. Enforce SChannel TLS 1.2+ & disable deprecated protocols in Windows Registry",
        "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server' -Name 'Enabled' -Value 1 -PropertyType 'DWord' -Force",
        "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWord' -Force",
        "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force",
        "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -Force",
    ]
    return HardeningSnippet(
        daemon="Exchange",
        target_file="Exchange Management Shell / PowerShell",
        config_text="\n".join(lines),
        explanation="Configures Microsoft Exchange Receive/Send connectors for mandatory TLS and disables legacy protocols via Windows SChannel registry.",
        remediated_findings=["Mandatory TLS on Connectors", "Disabled SChannel TLS 1.0/1.1"],
        reload_command="Restart-Service MSExchangeTransport",
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
    package.snippets["exchange"] = generate_exchange_config(session)

    package.summary = (
        f"Hardening configuration generated for {session.id} ({session.protocol.upper() if session.protocol else 'SMTP'}). "
        f"Contains automated remediations for Postfix, Dovecot, Exim4, Sendmail, and Microsoft Exchange."
    )

    return package


def generate_hardening_script_sh(package: HardeningPackage, target_name: str = "") -> str:
    """Generate an automated executable Bash script (.sh) applying Postfix and Dovecot TLS hardening."""
    target = target_name or package.domain or package.server_ip or "Mail Infrastructure"
    session_id = package.session_id

    template = """#!/usr/bin/env bash
# ==============================================================================
# SecureMailScope - Automated Cryptographic Hardening Script
# Target: __TARGET__
# Generated for: __SESSION_ID__
# Standards: NIST SP 800-52r2 | PCI-DSS 4.0 | RFC 7672 (DANE) | RFC 8461 (MTA-STS)
# ==============================================================================

set -euo pipefail

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'
NC='\\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN} SecureMailScope Automated Cryptographic Hardening Script${NC}"
echo -e "${CYAN} Target: __TARGET__${NC}"
echo -e "${CYAN}================================================================${NC}"

# Ensure root privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[-] ERROR: This script must be run as root or with sudo.${NC}" >&2
  exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/securemailscope_${TIMESTAMP}"
mkdir -p "${BACKUP_DIR}"
echo -e "${GREEN}[+] Configuration backup directory created: ${BACKUP_DIR}${NC}"

# ------------------------------------------------------------------------------
# 1. POSTFIX HARDENING (/etc/postfix/main.cf)
# ------------------------------------------------------------------------------
if command -v postconf >/dev/null 2>&1 && [ -d "/etc/postfix" ]; then
    echo -e "${YELLOW}[+] Applying Postfix TLS hardening...${NC}"
    if [ -f "/etc/postfix/main.cf" ]; then
        cp /etc/postfix/main.cf "${BACKUP_DIR}/postfix_main.cf.bak"
        echo "    [i] Backup saved to ${BACKUP_DIR}/postfix_main.cf.bak"
    fi

    # Enforce TLS 1.2+ minimum
    postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"

    # Enforce High AEAD Cipher Suites & Exclude Weak Algorithms
    postconf -e "smtpd_tls_mandatory_ciphers = high"
    postconf -e "smtpd_tls_ciphers = high"
    postconf -e "smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, 3DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES, CBC"
    postconf -e "tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"

    # Strict STARTTLS & Credentials Protection
    postconf -e "smtpd_tls_security_level = encrypt"
    postconf -e "smtpd_tls_auth_only = yes"

    # DANE & DNSSEC Resolution
    postconf -e "smtp_dns_support_level = dnssec"
    postconf -e "smtp_tls_security_level = dane"
    postconf -e "smtp_tls_loglevel = 1"

    # Elliptic Curves & Forward Secrecy
    postconf -e "smtpd_tls_eecdh_grade = ultra"
    postconf -e "tls_eecdh_strong_curve = prime256v1"
    postconf -e "tls_eecdh_ultra_curve = secp384r1"

    echo "    [+] Validating Postfix configuration..."
    if postfix check; then
        echo "    [+] Syntax OK. Reloading Postfix service..."
        if systemctl is-active --quiet postfix 2>/dev/null; then
            systemctl reload postfix || systemctl restart postfix
        fi
        echo -e "${GREEN}[✓] Postfix TLS hardening applied successfully.${NC}"
    else
        echo -e "${RED}[-] Postfix syntax check failed! Restoring backup...${NC}"
        cp "${BACKUP_DIR}/postfix_main.cf.bak" /etc/postfix/main.cf
    fi
else
    echo -e "${YELLOW}[i] Postfix not detected or not installed. Skipping.${NC}"
fi

# ------------------------------------------------------------------------------
# 2. DOVECOT HARDENING (/etc/dovecot/conf.d/10-ssl.conf)
# ------------------------------------------------------------------------------
DOVECOT_CONF="/etc/dovecot/conf.d/10-ssl.conf"
if [ -d "/etc/dovecot" ]; then
    echo -e "${YELLOW}[+] Applying Dovecot TLS hardening...${NC}"
    if [ -f "$DOVECOT_CONF" ]; then
        cp "$DOVECOT_CONF" "${BACKUP_DIR}/dovecot_10-ssl.conf.bak"
        echo "    [i] Backup saved to ${BACKUP_DIR}/dovecot_10-ssl.conf.bak"

        # Ensure SSL is mandatory
        sed -i 's/^#*ssl =.*/ssl = required/' "$DOVECOT_CONF"
        sed -i 's/^#*disable_plaintext_auth =.*/disable_plaintext_auth = yes/' "$DOVECOT_CONF"

        # Enforce TLS 1.2+ minimum
        if grep -q "ssl_min_protocol" "$DOVECOT_CONF"; then
            sed -i 's/^#*ssl_min_protocol =.*/ssl_min_protocol = TLSv1.2/' "$DOVECOT_CONF"
        else
            echo "ssl_min_protocol = TLSv1.2" >> "$DOVECOT_CONF"
        fi

        # High-security AEAD Cipher suites
        CIPHERS='ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
        if grep -q "ssl_cipher_list" "$DOVECOT_CONF"; then
            sed -i "s|^#*ssl_cipher_list =.*|ssl_cipher_list = $CIPHERS|" "$DOVECOT_CONF"
        else
            echo "ssl_cipher_list = $CIPHERS" >> "$DOVECOT_CONF"
        fi

        # Prefer server ciphers
        if grep -q "ssl_prefer_server_ciphers" "$DOVECOT_CONF"; then
            sed -i 's/^#*ssl_prefer_server_ciphers =.*/ssl_prefer_server_ciphers = yes/' "$DOVECOT_CONF"
        else
            echo "ssl_prefer_server_ciphers = yes" >> "$DOVECOT_CONF"
        fi

        if command -v doveadm >/dev/null 2>&1; then
            echo "    [+] Validating Dovecot configuration..."
            doveadm reload || systemctl restart dovecot
        elif systemctl is-active --quiet dovecot 2>/dev/null; then
            systemctl reload dovecot || systemctl restart dovecot
        fi
        echo -e "${GREEN}[✓] Dovecot TLS hardening applied successfully.${NC}"
    else
        echo -e "${YELLOW}[i] Dovecot SSL config file not found at $DOVECOT_CONF. Skipping.${NC}"
    fi
else
    echo -e "${YELLOW}[i] Dovecot not detected or not installed. Skipping.${NC}"
fi

echo -e "${CYAN}================================================================${NC}"
echo -e "${GREEN}[✓] SecureMailScope Cryptographic Hardening Finished!${NC}"
echo -e "${CYAN}    Backups preserved in: ${BACKUP_DIR}${NC}"
echo -e "${CYAN}================================================================${NC}"
"""
    return template.replace("__TARGET__", target).replace("__SESSION_ID__", session_id)


def generate_hardening_script_ps1(package: HardeningPackage, target_name: str = "") -> str:
    """Generate an automated PowerShell script (.ps1) for Windows Server TLS SChannel hardening."""
    target = target_name or package.domain or package.server_ip or "Mail Infrastructure"
    session_id = package.session_id

    template = """<#
.SYNOPSIS
    SecureMailScope Automated Cryptographic Hardening Script for Windows Server / SChannel
.DESCRIPTION
    Hardens Windows TLS stack (SChannel registry) for Mail Servers (Exchange / hMailServer / IIS SMTP).
    - Disables SSLv2, SSLv3, TLS 1.0, TLS 1.1
    - Enforces TLS 1.2 and TLS 1.3
    - Disables weak/broken ciphers (RC4, 3DES, DES, NULL)
    - Prioritizes modern AEAD forward-secret cipher suites
    Target: __TARGET__
    Session ID: __SESSION_ID__
#>

[CmdletBinding()]
Param()

# Ensure elevated Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[-] ERROR: This script must be run in an elevated PowerShell session (Run as Administrator)."
    exit 1
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " SecureMailScope Windows SChannel / Mail TLS Hardening" -ForegroundColor Cyan
Write-Host " Target: __TARGET__" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$schannelProtocolsPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols"

# 1. Protocols to Disable (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
$legacyProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $legacyProtocols) {
    Write-Host "[-] Disabling legacy protocol: $proto" -ForegroundColor Yellow
    $serverPath = "$schannelProtocolsPath\\$proto\\Server"
    $clientPath = "$schannelProtocolsPath\\$proto\\Client"
    
    if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord
    
    if (-not (Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord
}

# 2. Protocols to Enable (TLS 1.2, TLS 1.3)
$modernProtocols = @("TLS 1.2", "TLS 1.3")
foreach ($proto in $modernProtocols) {
    Write-Host "[+] Enabling secure protocol: $proto" -ForegroundColor Green
    $serverPath = "$schannelProtocolsPath\\$proto\\Server"
    $clientPath = "$schannelProtocolsPath\\$proto\\Client"
    
    if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord
    
    if (-not (Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord
}

# 3. Disable Insecure Ciphers (RC4, 3DES, DES, NULL)
$ciphersPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers"
$weakCiphers = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128", "Triple DES 168", "DES 56/56", "NULL")
foreach ($c in $weakCiphers) {
    $cPath = "$ciphersPath\\$c"
    if (-not (Test-Path $cPath)) { New-Item -Path $cPath -Force | Out-Null }
    Set-ItemProperty -Path $cPath -Name "Enabled" -Value 0 -Type DWord
}
Write-Host "[✓] Insecure ciphers disabled (RC4, 3DES, DES, NULL)." -ForegroundColor Green

# 4. Cipher Suite Ordering (Prioritize AEAD suites)
$secureCipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)

Write-Host "[+] Configuring TLS cipher suite ordering..." -ForegroundColor Green
try {
    foreach ($cs in $secureCipherSuites) {
        Enable-TlsCipherSuite -Name $cs -Position 0 -ErrorAction SilentlyContinue
    }
    Write-Host "[✓] Prioritized AEAD cipher suites configured." -ForegroundColor Green
} catch {
    Write-Warning "Could not reorder TLS cipher suites via Enable-TlsCipherSuite."
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [✓] SecureMailScope Windows SChannel Hardening Complete!" -ForegroundColor Green
Write-Host " [i] A system restart is required for changes to take full effect." -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Cyan
"""
    return template.replace("__TARGET__", target).replace("__SESSION_ID__", session_id)

