"""Shared constants, severity levels, and data structures for SecureMailScope."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Severity of a security finding."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_NAMES = {
    Severity.INFO: "info",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}

# Rating of a TLS version; higher is better.
TLS_VERSION_RANK = {
    "TLSv1.0": 1,
    "TLSv1.1": 2,
    "TLSv1.2": 3,
    "TLSv1.3": 4,
}


@dataclass
class TLSInfo:
    """Details extracted from a TLS handshake."""

    version: Optional[str] = None          # e.g. "TLSv1.2"
    version_rank: int = 0
    cipher_suite: Optional[str] = None      # IANA name e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    cipher_hex: Optional[str] = None        # e.g. 0xC02F
    key_exchange: Optional[str] = None      # e.g. ECDHE / DHE / RSA / ECDH
    key_exchange_group: Optional[str] = None
    signature_algorithm: Optional[str] = None
    ae: Optional[str] = None                # authenticated encryption
    server_name: Optional[str] = None       # SNI
    offered_versions: List[str] = field(default_factory=list)
    offered_ciphers: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    ja4s: Optional[str] = None
    certificate: Optional[Any] = None
    resumed_session: bool = False


@dataclass
class CertificateInfo:
    """Parsed and validated X.509 certificate details."""

    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    serial_number: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    san: List[str] = field(default_factory=list)
    self_signed: bool = False
    trusted: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    days_to_expiry: Optional[int] = None
    chain_valid: Optional[bool] = None
    chain_issues: List[str] = field(default_factory=list)
    ocsp_url: Optional[str] = None
    crl_urls: List[str] = field(default_factory=list)
    revoked: Optional[bool] = None
    revocation_status: Optional[str] = None   # good / revoked / unknown / skipped
    revocation_method: Optional[str] = None   # ocsp / crl / none
    ja4x: Optional[str] = None
    pem: Optional[str] = None


@dataclass
class DnsSecurityInfo:
    """MTA-STS (RFC 8461) and DANE TLSA (RFC 7672) downgrade protection posture."""

    domain: Optional[str] = None
    hostname: Optional[str] = None
    mta_sts_record: Optional[str] = None
    mta_sts_valid: Optional[bool] = None
    mta_sts_mode: Optional[str] = None          # enforce / testing / none / not_published
    mta_sts_id: Optional[str] = None
    dane_tlsa_records: List[str] = field(default_factory=list)
    dane_valid: Optional[bool] = None
    dane_match_status: Optional[str] = None     # matched / mismatch / not_published / skipped
    recommended_mta_sts_dns: Optional[str] = None
    recommended_mta_sts_policy: Optional[str] = None


@dataclass
class PqcInfo:
    """Post-Quantum Cryptography posture and quantum readiness details."""

    pqc_status: str = "HIGH_QUANTUM_RISK"  # QUANTUM_RESISTANT, TRANSITIONAL, HIGH_QUANTUM_RISK
    quantum_safe_kem: bool = False
    hybrid_key_exchange: bool = False
    kem_algorithm: Optional[str] = None
    classical_algorithm: Optional[str] = None
    quantum_safe_signature: bool = False
    signature_scheme: Optional[str] = None
    hndl_risk: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW (Harvest Now, Decrypt Later)
    quantum_vulnerability_score: float = 85.0  # 0 to 100
    standard_compliance: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)


@dataclass
class AttributionInfo:
    """Attribution analysis for a client or server session based on JA4 fingerprinting."""

    client_name: str = "Unknown Client"
    client_category: str = "unknown"  # email_client, mail_transfer_agent, scripting_tool, scanner, suspicious
    confidence: str = "low"  # high, medium, low
    matched_fingerprint: Optional[str] = None
    is_threat: bool = False
    is_known_threat: bool = False
    is_automation: bool = False
    masquerading_detected: bool = False
    masquerading_details: Optional[str] = None
    fingerprint_notes: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single security finding raised against a session."""

    id: str
    title: str
    description: str
    category: str
    severity: Severity
    recommendation: str
    cwe: Optional[str] = None
    cve: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """A reconstructed bidirectional TCP stream with crypto analysis."""

    id: str
    protocol: Optional[str] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    bytes_client_to_server: int = 0
    bytes_server_to_client: int = 0
    packets: int = 0
    plaintext: bool = False
    encrypted: bool = False
    starttls: bool = False
    starttls_upgraded: bool = False
    starttls_stripped: bool = False
    credentials_plaintext: bool = False
    auth_command_observed: Optional[str] = None
    tls: Optional[TLSInfo] = None
    certificate: Optional[CertificateInfo] = None
    dns_security: Optional[DnsSecurityInfo] = None
    pqc: Optional[PqcInfo] = None
    attribution: Optional[AttributionInfo] = None
    findings: List[Finding] = field(default_factory=list)
    ml_score: Optional[float] = None          # 0..1 risk likelihood from ML
    ml_anomaly: bool = False
    ml_anomaly_score: Optional[float] = None
    posture_score: Optional[float] = None     # 0..100
    risk_label: str = "unknown"               # low/medium/high/critical

    def severity_count(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[SEVERITY_NAMES[f.severity]] += 1
        return counts

