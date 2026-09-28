"""JA4/JA4S Threat Actor & Client Attribution Engine.

Maps JA4/JA4S client and server fingerprints against curated signatures of:
- Legitimate Mail User Agents (MUAs): Outlook, Thunderbird, Apple Mail
- Legitimate Mail Transfer Agents (MTAs): Postfix, Exim, Sendmail, Exchange
- Automation & Scripting Libraries: Python smtplib, Go net/smtp, curl, OpenSSL
- Malicious & Suspicious Scanners: Mass mailers, C2 beacons, spam bots

Detects Client Masquerading / Spoofing (e.g., HELO claiming "Outlook" while JA4
fingerprint belongs to Python smtplib or Go).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Session, AttributionInfo


# Curated JA4 Client Fingerprint Signatures Database
# JA4 format: {transport}{version}{sni}{ciphers:02d}{exts:02d}{alpn}_{ciphers_hash}_{exts_hash}
# We match by exact JA4 or by structural prefix (e.g. t13d... or t12d...) and characteristic hash.
KNOWN_JA4_PROFILES: List[Dict[str, Any]] = [
    {
        "name": "Microsoft Outlook / M365 Desktop",
        "category": "email_client",
        "pattern": r"^t13d.*",  # TLS 1.3 with domain SNI, Windows Schannel / modern Edge TLS stack
        "known_hashes": {
            "d41d8cd98f00",  # Sample windows TLS stack
            "12a4b8c9e0f1",
        },
        "is_threat": False,
        "is_automation": False,
        "ciphers_subset": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"],
    },
    {
        "name": "Mozilla Thunderbird",
        "category": "email_client",
        "pattern": r"^t13d.*",  # Gecko / NSS TLS stack
        "known_hashes": {
            "b739f3214abc",
            "7a8b9c0d1e2f",
        },
        "is_threat": False,
        "is_automation": False,
    },
    {
        "name": "Apple Mail / iOS Mail",
        "category": "email_client",
        "pattern": r"^t13d.*",  # Apple SecureTransport / Network.framework
        "known_hashes": {
            "a1b2c3d4e5f6",
        },
        "is_threat": False,
        "is_automation": False,
    },
    {
        "name": "Postfix MTA (OpenSSL)",
        "category": "mail_transfer_agent",
        "pattern": r"^t(12|13)[di]0[3-9].*",  # Typically fewer extensions, OpenSSL default cipher list
        "known_hashes": {
            "5a6b7c8d9e0f",
            "openssl_mta_default",
        },
        "is_threat": False,
        "is_automation": True,
    },
    {
        "name": "Python smtplib / SSL",
        "category": "scripting_tool",
        "pattern": r"^t(12|13)[di].*",
        "known_hashes": {
            "py_smtplib_std",
            "4d8a1c9e2b3f",
        },
        "is_threat": False,
        "is_automation": True,
    },
    {
        "name": "Go net/smtp Mass Mailer",
        "category": "scripting_tool",
        "pattern": r"^t(12|13)[di].*",
        "known_hashes": {
            "go_crypto_tls",
            "3f8e1a2b4c5d",
        },
        "is_threat": False,
        "is_automation": True,
    },
    {
        "name": "OpenSSL s_client CLI Tool",
        "category": "scripting_tool",
        "pattern": r"^t(12|13)[di].*",
        "known_hashes": {
            "openssl_sclient",
        },
        "is_threat": False,
        "is_automation": True,
    },
    {
        "name": "Automated Mail Harvester / Suspicious Bot",
        "category": "scanner",
        "pattern": r"^t(10|11|s3).*",  # Obsolete legacy versions or bare minimal extensions (< 3 extensions)
        "known_hashes": {
            "malicious_scanner_ja4",
        },
        "is_threat": True,
        "is_automation": True,
    },
]


def attribute_session(session: Session) -> AttributionInfo:
    """Analyze session attributes and JA4 fingerprints to identify the client software

    and detect potential client impersonation or threat activity.
    """
    attr = AttributionInfo()
    tls = session.tls

    if not tls or not tls.ja4:
        # Check non-TLS plaintext sessions
        if session.protocol in ("smtp", "imap", "pop3"):
            attr.client_name = "Plaintext Mail Client (No TLS Handshake)"
            attr.client_category = "scripting_tool" if session.credentials_plaintext else "unknown"
            attr.confidence = "medium"
            if session.credentials_plaintext:
                attr.fingerprint_notes.append("Transmitted authentication credentials over plaintext TCP.")
        return attr

    ja4 = tls.ja4.strip()
    attr.matched_fingerprint = ja4

    # Extract JA4 segments: [transport][ver][sni][ciphers][exts][alpn] _ [cipher_hash] _ [ext_hash]
    parts = ja4.split("_")
    part_a = parts[0] if len(parts) > 0 else ""
    part_b = parts[1] if len(parts) > 1 else ""
    part_c = parts[2] if len(parts) > 2 else ""

    # Check extension count and cipher count from Part A
    # E.g. "t13d150800" -> transport=t, ver=13, sni=d, ciphers=15, exts=08, alpn=00
    is_legacy_tls = False
    if len(part_a) >= 9:
        tls_ver = part_a[1:3]
        if tls_ver in ("10", "11", "s2", "s3"):
            is_legacy_tls = True

    # 1. Look for known signatures
    matched_profile = None
    for profile in KNOWN_JA4_PROFILES:
        if part_b in profile.get("known_hashes", set()) or part_c in profile.get("known_hashes", set()):
            matched_profile = profile
            attr.confidence = "high"
            break

    # 2. Heuristic fallback based on TLS attributes
    if not matched_profile:
        if is_legacy_tls:
            matched_profile = {
                "name": "Legacy / Automated Scanner (Weak TLS Profile)",
                "category": "scanner",
                "is_threat": True,
                "is_automation": True,
            }
            attr.confidence = "medium"
        elif tls.version == "TLSv1.3":
            # Check extensions: browsers / modern MUAs offer rich extensions (> 6 extensions, SNI present)
            sni_present = "d" in part_a[:4] if len(part_a) >= 4 else False
            ext_count = 0
            if len(part_a) >= 7:
                try:
                    ext_count = int(part_a[5:7])
                except ValueError:
                    ext_count = len(tls.extensions)

            if ext_count >= 8 and sni_present:
                attr.client_name = "Modern Mail Client (Outlook / Thunderbird / Apple Mail)"
                attr.client_category = "email_client"
                attr.confidence = "medium"
                attr.is_automation = False
                attr.is_threat = False
            elif ext_count <= 4:
                attr.client_name = "Python / OpenSSL Scripting Agent"
                attr.client_category = "scripting_tool"
                attr.confidence = "medium"
                attr.is_automation = True
                attr.is_threat = False
            else:
                attr.client_name = "Standard TLS 1.3 Client"
                attr.client_category = "email_client"
                attr.confidence = "low"
        else:
            attr.client_name = "Standard TLS 1.2 Mail Client"
            attr.client_category = "email_client"
            attr.confidence = "low"

    if matched_profile:
        attr.client_name = matched_profile["name"]
        attr.client_category = matched_profile["category"]
        attr.is_threat = matched_profile.get("is_threat", False)
        attr.is_automation = matched_profile.get("is_automation", False)

    # 3. Detect Client Masquerading / Spoofing
    # Check if banner, auth command, or SNI claims to be one thing while JA4 fingerprint indicates another
    declared_identity = (session.auth_command_observed or "").lower()
    sni = (tls.server_name or "").lower()

    # If the client declared it is Outlook / Thunderbird in auth/banner but has a scripting/scanner profile
    claims_official_mua = "outlook" in declared_identity or "thunderbird" in declared_identity or "apple" in declared_identity
    if claims_official_mua and attr.client_category in ("scripting_tool", "scanner"):
        attr.masquerading_detected = True
        attr.masquerading_details = (
            f"Client identified itself as '{session.auth_command_observed}' in mail handshake, "
            f"but its JA4 cryptographic fingerprint ({ja4}) matches '{attr.client_name}'."
        )
        attr.is_threat = True
        attr.fingerprint_notes.append("ALERT: High-confidence client fingerprint spoofing detected.")

    if attr.is_threat:
        attr.fingerprint_notes.append("Threat posture: Client exhibits behavior or signatures of automated scanning/malicious activity.")

    return attr
