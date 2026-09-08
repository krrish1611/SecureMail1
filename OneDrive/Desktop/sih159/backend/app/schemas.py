"""Pydantic schemas for the API layer."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class SessionSummary(BaseModel):
    session_id: str
    protocol: Optional[str] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    encrypted: bool = False
    plaintext: bool = False
    starttls: bool = False
    starttls_stripped: bool = False
    posture_score: Optional[float] = None
    risk_label: str = "unknown"
    finding_count: int = 0
    severity_summary: Dict[str, int] = {}


class TLSDetails(BaseModel):
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    key_exchange_group: Optional[str] = None
    signature_algorithm: Optional[str] = None
    server_name: Optional[str] = None
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    ja4s: Optional[str] = None
    offered_ciphers: List[str] = []


class CertDetails(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    san: List[str] = []
    self_signed: bool = False
    expired: bool = False
    days_to_expiry: Optional[int] = None
    chain_valid: Optional[bool] = None
    trusted: Optional[bool] = None
    revoked: Optional[bool] = None
    revocation_status: Optional[str] = None
    revocation_method: Optional[str] = None
    ja4x: Optional[str] = None


class FindingModel(BaseModel):
    id: str
    title: str
    description: str
    category: str
    severity: str
    recommendation: str
    cwe: Optional[str] = None
    cve: Optional[str] = None


class DnsSecurityModel(BaseModel):
    domain: Optional[str] = None
    hostname: Optional[str] = None
    mta_sts_record: Optional[str] = None
    mta_sts_valid: Optional[bool] = None
    mta_sts_mode: Optional[str] = None
    mta_sts_id: Optional[str] = None
    dane_tlsa_records: List[str] = []
    dane_valid: Optional[bool] = None
    dane_match_status: Optional[str] = None
    recommended_mta_sts_dns: Optional[str] = None
    recommended_mta_sts_policy: Optional[str] = None


class PqcDetails(BaseModel):
    pqc_status: str = "HIGH_QUANTUM_RISK"
    quantum_safe_kem: bool = False
    hybrid_key_exchange: bool = False
    kem_algorithm: Optional[str] = None
    classical_algorithm: Optional[str] = None
    quantum_safe_signature: bool = False
    signature_scheme: Optional[str] = None
    hndl_risk: str = "HIGH"
    quantum_vulnerability_score: float = 85.0
    standard_compliance: List[str] = []
    remediation_steps: List[str] = []


class AttributionDetails(BaseModel):
    client_name: str = "Unknown Client"
    client_category: str = "unknown"
    confidence: str = "low"
    matched_fingerprint: Optional[str] = None
    is_threat: bool = False
    is_automation: bool = False
    masquerading_detected: bool = False
    masquerading_details: Optional[str] = None
    fingerprint_notes: List[str] = []


class HardeningSnippetModel(BaseModel):
    daemon: str
    target_file: str
    config_text: str
    explanation: str
    remediated_findings: List[str] = []
    reload_command: str = ""


class HardeningPackageModel(BaseModel):
    session_id: str
    server_ip: Optional[str] = None
    domain: Optional[str] = None
    snippets: Dict[str, HardeningSnippetModel] = {}
    summary: str = ""


class WebhookTestRequest(BaseModel):
    url: Optional[str] = None
    provider: str = "slack"  # slack, discord, siem
    dry_run: bool = True
    min_severity: str = "high"


class WebhookTestResponse(BaseModel):
    dispatched: bool
    mode: Optional[str] = None
    provider: str
    findings_count: int = 0
    payload: Dict[str, Any] = {}
    error: Optional[str] = None


class SessionDetail(BaseModel):
    session_id: str
    protocol: Optional[str] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    packets: int = 0
    encrypted: bool = False
    plaintext: bool = False
    starttls: bool = False
    starttls_stripped: bool = False
    credentials_plaintext: bool = False
    tls: Optional[TLSDetails] = None
    certificate: Optional[CertDetails] = None
    dns_security: Optional[DnsSecurityModel] = None
    pqc: Optional[PqcDetails] = None
    attribution: Optional[AttributionDetails] = None
    posture_score: Optional[float] = None
    risk_label: str = "unknown"
    ml_score: Optional[float] = None
    ml_anomaly: bool = False
    findings: List[FindingModel] = []
    severity_summary: Dict[str, int] = {}


class OverallStats(BaseModel):
    total_sessions: int = 0
    encrypted_sessions: int = 0
    plaintext_sessions: int = 0

    avg_posture_score: float = 0.0
    severity_counts: Dict[str, int] = {}
    anomalies: int = 0
    protocols: Dict[str, int] = {}


class AnalyzeResponse(BaseModel):
    status: str = "ok"
    message: str = ""
    job_id: Optional[str] = None
    pcap_filename: Optional[str] = None
    session_count: int = 0
    overall: Optional[OverallStats] = None


class ComplianceCheckModel(BaseModel):
    control_id: str
    control_name: str
    framework: str
    citation: str
    status: str             # "PASS" | "FAIL" | "N/A"
    detail: str = ""


class FrameworkSummaryModel(BaseModel):
    framework: str
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    na: int = 0
    verdict: str = "N/A"    # "COMPLIANT" | "NON-COMPLIANT" | "N/A"


class ControlFrameworkResult(BaseModel):
    status: str
    citation: str


class ControlSummaryModel(BaseModel):
    control_id: str
    control_name: str
    frameworks: Dict[str, ControlFrameworkResult] = {}


class ComplianceReportModel(BaseModel):
    frameworks: List[FrameworkSummaryModel] = []
    controls_summary: List[ControlSummaryModel] = []
    per_session: Dict[str, List[ComplianceCheckModel]] = {}

