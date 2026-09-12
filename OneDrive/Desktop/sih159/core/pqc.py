"""Post-Quantum Cryptography (PQC) readiness and Harvest Now, Decrypt Later (HNDL) assessment.

Evaluates TLS sessions for quantum resistance against Shor's algorithm, analyzing:
- Key Encapsulation Mechanisms (KEMs): NIST FIPS 203 (ML-KEM/Kyber) and hybrid schemes
- Digital Signature Algorithms: NIST FIPS 204 (ML-DSA/Dilithium), Falcon, SPHINCS+
- Quantum Vulnerability Horizon (QVH) and retrospective decryption risk
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Known PQC and Hybrid Key Exchange Named Groups (IANA TLS Supported Groups / drafts)
# Reference: draft-ietf-tls-hybrid-design, NIST FIPS 203, OpenSSL 3.4 / BoringSSL
PQC_NAMED_GROUPS: Dict[int, Dict[str, Any]] = {
    0x6399: {
        "name": "X25519MLKEM768",
        "standard": "NIST FIPS 203 / IETF Draft",
        "type": "hybrid",
        "classical": "X25519",
        "pqc": "ML-KEM-768 (Kyber-768)",
        "quantum_safe": True,
        "security_level": 3,  # AES-192 equivalent
    },
    0x11EC: {
        "name": "SecP256r1MLKEM768",
        "standard": "NIST FIPS 203 / IETF Draft",
        "type": "hybrid",
        "classical": "SecP256r1 (P-256)",
        "pqc": "ML-KEM-768 (Kyber-768)",
        "quantum_safe": True,
        "security_level": 3,
    },
    0x2F3A: {
        "name": "X25519Kyber768Draft00",
        "standard": "Pre-standard Draft (Cloudflare/Google)",
        "type": "hybrid",
        "classical": "X25519",
        "pqc": "Kyber-768",
        "quantum_safe": True,
        "security_level": 3,
    },
    0x639A: {
        "name": "X25519MLKEM1024",
        "standard": "NIST FIPS 203 / IETF Draft",
        "type": "hybrid",
        "classical": "X25519",
        "pqc": "ML-KEM-1024",
        "quantum_safe": True,
        "security_level": 5,  # AES-256 equivalent
    },
    0x0200: {
        "name": "MLKEM768",
        "standard": "NIST FIPS 203 (Pure KEM)",
        "type": "pure_pqc",
        "classical": None,
        "pqc": "ML-KEM-768",
        "quantum_safe": True,
        "security_level": 3,
    },
}

# Post-quantum signature algorithms
PQC_SIGNATURE_ALGORITHMS = {
    "ML-DSA-44": "NIST FIPS 204 (Dilithium-2)",
    "ML-DSA-65": "NIST FIPS 204 (Dilithium-3)",
    "ML-DSA-87": "NIST FIPS 204 (Dilithium-5)",
    "FALCON-512": "NIST Selected",
    "FALCON-1024": "NIST Selected",
    "SPHINCS+": "NIST FIPS 205 (SLH-DSA)",
}


from .models import PqcInfo


def parse_named_group(group_id_or_name: Any) -> Optional[Dict[str, Any]]:
    """Look up named group information from int code or canonical string name."""
    if isinstance(group_id_or_name, int):
        return PQC_NAMED_GROUPS.get(group_id_or_name)
    if isinstance(group_id_or_name, str):
        cleaned = group_id_or_name.strip().lower().replace("-", "").replace("_", "")
        for gid, info in PQC_NAMED_GROUPS.items():
            candidate = info["name"].lower().replace("-", "").replace("_", "")
            if cleaned == candidate:
                return info
            # Also check hex string e.g. "0x6399"
            if group_id_or_name.lower().startswith("0x"):
                try:
                    if int(group_id_or_name, 16) == gid:
                        return info
                except ValueError:
                    pass
    return None


def assess_pqc_readiness(
    tls_version: Optional[str],
    key_exchange: Optional[str],
    key_exchange_group: Optional[Any],
    cipher_suite: Optional[str],
    cert_sig_alg: Optional[str],
    is_encrypted: bool = True,
) -> PqcInfo:
    """Evaluate cryptographic posture against quantum decryption attacks.

    Determines whether the session uses NIST post-quantum hybrid KEMs, assess
    Harvest-Now-Decrypt-Later (HNDL) risk, and computes the Quantum Vulnerability Score.
    """
    pqc = PqcInfo()

    if not is_encrypted or not tls_version:
        pqc.pqc_status = "HIGH_QUANTUM_RISK"
        pqc.hndl_risk = "CRITICAL"
        pqc.quantum_vulnerability_score = 100.0
        pqc.remediation_steps = [
            "Enable TLS 1.3 encryption on mail transfer and user access endpoints.",
            "Deploy hybrid post-quantum key exchange (X25519MLKEM768) to protect against traffic interception.",
        ]
        return pqc

    # Check key exchange group for PQC / Hybrid
    group_info = parse_named_group(key_exchange_group)
    if not group_info and key_exchange:
        group_info = parse_named_group(key_exchange)

    if group_info and group_info.get("quantum_safe"):
        pqc.quantum_safe_kem = True
        pqc.hybrid_key_exchange = (group_info.get("type") == "hybrid")
        pqc.kem_algorithm = group_info.get("pqc")
        pqc.classical_algorithm = group_info.get("classical")
        pqc.pqc_status = "QUANTUM_RESISTANT"
        pqc.hndl_risk = "LOW"
        pqc.quantum_vulnerability_score = 10.0
        pqc.standard_compliance.append(group_info.get("standard", "NIST FIPS 203"))
        pqc.remediation_steps = [
            "Maintain hybrid PQC key exchange deployments as NIST FIPS 203 standards finalize in MTA software.",
            "Plan roadmap for post-quantum X.509 certificate signatures (ML-DSA / Falcon) when CA ecosystems support them.",
        ]
        return pqc

    # Check for legacy or static key exchange (No forward secrecy -> Critical HNDL risk)
    ke_str = (key_exchange or "").upper()
    is_static_rsa = "RSA (STATIC)" in ke_str or (ke_str == "RSA")
    is_obsolete_tls = tls_version in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")

    if is_static_rsa or is_obsolete_tls:
        pqc.pqc_status = "HIGH_QUANTUM_RISK"
        pqc.hndl_risk = "CRITICAL"
        pqc.quantum_vulnerability_score = 95.0
        pqc.remediation_steps = [
            "Immediately disable static RSA key exchange and obsolete TLS versions (TLS 1.0/1.1).",
            "A quantum computer running Shor's algorithm can retrospectively decrypt all recorded traffic with zero forward secrecy.",
            "Upgrade to TLS 1.3 with hybrid post-quantum key exchange (X25519MLKEM768).",
        ]
        return pqc

    # Modern classical TLS (e.g. TLS 1.2 or TLS 1.3 with ECDHE / X25519 / P-256)
    # Forward secure against classical adversaries, but susceptible to Harvest Now, Decrypt Later (HNDL)
    pqc.pqc_status = "TRANSITIONAL"
    pqc.classical_algorithm = key_exchange or "ECDHE"
    if tls_version == "TLSv1.3":
        pqc.hndl_risk = "MEDIUM"
        pqc.quantum_vulnerability_score = 45.0
        pqc.remediation_steps = [
            "Current session uses modern TLS 1.3 with classical ECDHE forward secrecy.",
            "Enable hybrid post-quantum key exchange (e.g., X25519MLKEM768 / group 0x6399) to safeguard against Harvest-Now-Decrypt-Later (HNDL) eavesdropping.",
        ]
    else:
        pqc.hndl_risk = "HIGH"
        pqc.quantum_vulnerability_score = 65.0
        pqc.remediation_steps = [
            "Upgrade from TLS 1.2 to TLS 1.3.",
            "Enable NIST FIPS 203 hybrid ML-KEM key exchange in mail server TLS configuration.",
        ]

    # Check signature algorithm
    if cert_sig_alg:
        for pqc_sig, desc in PQC_SIGNATURE_ALGORITHMS.items():
            if pqc_sig.lower() in cert_sig_alg.lower():
                pqc.quantum_safe_signature = True
                pqc.signature_scheme = pqc_sig
                pqc.standard_compliance.append(desc)
                pqc.quantum_vulnerability_score = max(5.0, pqc.quantum_vulnerability_score - 15.0)
                break

    return pqc
