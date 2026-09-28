"""Cryptographic feature engineering for ML analysis.

Transforms each Session into a numeric feature vector used by the risk
classifier and anomaly detector.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from core.models import Session, Severity, SEVERITY_NAMES

# Cipher-strength heuristic scores (higher = stronger/more modern).
CIPHER_STRENGTH = {
    "TLS_AES_128_GCM_SHA256": 10,
    "TLS_AES_256_GCM_SHA384": 10,
    "TLS_CHACHA20_POLY1305_SHA256": 10,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 9,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 9,
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 9,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 9,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 6,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 6,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 6,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 5,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 5,
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 4,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 4,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 2,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 2,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 1,
    "TLS_RSA_WITH_RC4_128_SHA": 0,
    "TLS_RSA_WITH_RC4_128_MD5": 0,
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5": 0,
    "TLS_RSA_WITH_DES_CBC_SHA": 0,
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": 1,
}


def cipher_strength(cipher: Optional[str]) -> float:
    """Return a 0..10 strength score for a cipher name."""
    if not cipher:
        return 0.0
    if cipher in CIPHER_STRENGTH:
        return float(CIPHER_STRENGTH[cipher])
    upper = cipher.upper()
    if "RC4" in upper or "DES" in upper:
        return 0.0
    if "3DES" in upper:
        return 1.0
    if "GCM" in upper and "ECDHE" in upper:
        return 9.0
    if "CHACHA" in upper:
        return 10.0
    if "GCM" in upper:
        return 4.0
    if "CBC" in upper:
        return 3.0
    return 3.0


FEATURE_NAMES = [
    "is_starttls", "is_encrypted", "plaintext", "starttls_stripped", "creds_plaintext",
    "tls_version_rank", "cipher_strength", "has_forward_secrecy", "cert_valid_chain",
    "cert_expired", "cert_self_signed", "pubkey_size", "uses_sha1_sig",
    "sess_bytes", "num_packets", "duration_s", "weak_offered",
]


def extract_features(session: Session) -> Dict[str, float]:
    """Extract a numeric dict of features for a session."""
    tls = session.tls
    cert = session.certificate

    version_rank = tls.version_rank if tls and tls.version_rank else 0
    cs = cipher_strength(tls.cipher_suite) if tls else 0.0
    has_fs = bool(tls and tls.key_exchange and "DHE" in (tls.key_exchange or ""))
    cert_valid = bool(cert and cert.chain_valid is True and not cert.expired)
    weak_offered = 0
    if tls and tls.offered_versions:
        weak_offered = 1 if any(v in ("SSLv3", "TLSv1.0", "TLSv1.1") for v in tls.offered_versions) else 0
    if tls and tls.version and tls.version in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
        weak_offered = 1

    duration = 0.0
    if session.start_ts and session.end_ts:
        duration = max(session.end_ts - session.start_ts, 0.0)

    pubkey_size = 0
    if cert and cert.key_size:
        pubkey_size = float(cert.key_size)

    uses_sha1 = 0
    if cert and cert.signature_algorithm and "SHA1" in cert.signature_algorithm.upper():
        uses_sha1 = 1
    if tls and tls.signature_algorithm and "sha1" in tls.signature_algorithm:
        uses_sha1 = 1

    return {
        "is_starttls": 1.0 if session.starttls else 0.0,
        "is_encrypted": 1.0 if session.encrypted else 0.0,
        "plaintext": 1.0 if session.plaintext else 0.0,
        "starttls_stripped": 1.0 if session.starttls_stripped else 0.0,
        "creds_plaintext": 1.0 if session.credentials_plaintext else 0.0,
        "tls_version_rank": float(version_rank),
        "cipher_strength": cs,
        "has_forward_secrecy": 1.0 if has_fs else 0.0,
        "cert_valid_chain": 1.0 if cert_valid else 0.0,
        "cert_expired": 1.0 if (cert and cert.expired) else 0.0,
        "cert_self_signed": 1.0 if (cert and cert.self_signed) else 0.0,
        "pubkey_size": float(pubkey_size),
        "uses_sha1_sig": float(uses_sha1),
        "sess_bytes": float(session.bytes_client_to_server + session.bytes_server_to_client),
        "num_packets": float(session.packets),
        "duration_s": duration,
        "weak_offered": float(weak_offered),
    }


def severity_weight(session: Session) -> float:
    """Aggregate finding severities into a 0..1 risk weight."""
    w = 0.0
    for f in session.findings:
        w += {Severity.INFO: 0.1, Severity.LOW: 0.2,
              Severity.MEDIUM: 0.4, Severity.HIGH: 0.7,
              Severity.CRITICAL: 1.0}[f.severity]
    return min(w, 1.0)