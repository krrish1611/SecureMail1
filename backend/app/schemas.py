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


class DomainProbeRequest(BaseModel):
    domain: str
    use_ml: bool = True
    timeout: float = 6.0


class EmailAuthDetails(BaseModel):
    domain: str
    overall_score: float = 0.0
    grade: str = "N/A"
    grade_color: str = "#767270"
    summary: str = ""
    spf: Dict[str, Any] = {}
    dmarc: Dict[str, Any] = {}
    dkim: Dict[str, Any] = {}
    bimi: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []
    recommendations: List[str] = []


class ExecutiveSummaryModel(BaseModel):
    job_id: str
    target_name: str
    posture_grade: str
    grade_color: str
    posture_score: float
    headline: str
    executive_brief: str
    summary_paragraphs: List[str] = []
    severity_counts: Dict[str, int] = {}
    encrypted_ratio: float = 0.0
    plaintext_sessions: int = 0
    credentials_leaked: int = 0
    downgrade_attacks: int = 0
    top_vulnerabilities: List[Dict[str, Any]] = []
    post_quantum_assessment: Dict[str, Any] = {}
    compliance_summary: Dict[str, Any] = {}
    actionable_roadmap: List[Dict[str, Any]] = []


class HistoricalScanSummary(BaseModel):
    id: str
    timestamp: str
    target_name: str
    scan_type: str
    session_count: int
    avg_posture_score: float
    risk_label: str
    encrypted_sessions: int
    plaintext_sessions: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    hndl_risk: str
    compliance_verdict: str


class HistoryTrendsResponse(BaseModel):
    total_scans: int = 0
    overall_avg_score: float = 0.0
    total_critical_detected: int = 0
    points: List[Dict[str, Any]] = []


# --- Feature: PQC Readiness Radar ---

class PqcRadarResponse(BaseModel):
    job_id: str
    total_sessions: int = 0
    quantum_resistant: int = 0
    transitional: int = 0
    high_risk: int = 0
    migration_readiness_score: float = 0.0
    hndl_breakdown: Dict[str, int] = {}  # CRITICAL/HIGH/MEDIUM/LOW counts
    nist_fips_203: Dict[str, Any] = {}  # ML-KEM / Kyber compliance
    nist_fips_204: Dict[str, Any] = {}  # ML-DSA / Dilithium compliance
    nist_fips_205: Dict[str, Any] = {}  # SLH-DSA / SPHINCS+ compliance
    kem_algorithms_seen: List[str] = []
    signature_schemes_seen: List[str] = []
    per_session_summary: List[Dict[str, Any]] = []
    recommendations: List[str] = []


# --- Feature: Remediate (Job-level hardening) ---

class RemediateIssue(BaseModel):
    id: str
    title: str
    severity: str
    category: str  # tls | email_auth | protocol | pqc
    count: int = 1

class RemediateResponse(BaseModel):
    job_id: str
    total_issues: int = 0
    issues: List[RemediateIssue] = []
    snippets: Dict[str, HardeningSnippetModel] = {}
    exchange_config: Optional[str] = None
    download_links: Dict[str, str] = {}


# --- Feature: Email Protocol Compliance Matrix ---

class EmailProtocolCheck(BaseModel):
    standard: str
    status: str  # PASS | FAIL | WARN | N/A
    record_value: Optional[str] = None
    grade: str = "N/A"
    details: str = ""
    recommendation: str = ""

class EmailComplianceResponse(BaseModel):
    job_id: str
    domain: Optional[str] = None
    overall_score: float = 0.0
    overall_grade: str = "N/A"
    checks: List[EmailProtocolCheck] = []
    email_auth: Optional[Dict[str, Any]] = None


# --- Feature: MITM Simulation Playground ---

class MitmSimulateRequest(BaseModel):
    from_addr: Optional[str] = "cfo@acme-corp.com"
    to_addr: Optional[str] = "finance-team@acme-corp.com"
    subject: Optional[str] = "Q3 Board Meeting — Confidential Financial Results"
    body: Optional[str] = "Hi Team,\n\nAttached are the Q3 financial results for board review.\nRevenue: $42.7M (+18% YoY)\nNet Income: $8.3M\nProjected Q4: $51.2M\n\nPlease treat as STRICTLY CONFIDENTIAL until the public earnings call on Oct 15.\n\nBest,\nSarah Chen\nCFO, ACME Corp"
    auth_user: Optional[str] = "cfo@acme-corp.com"
    auth_password: Optional[str] = "Qu4rt3rly$ecure!2026"
    attachment: Optional[str] = "Q3_Financial_Results_CONFIDENTIAL.xlsx (2.4 MB)"
    job_id: Optional[str] = None
    session_id: Optional[str] = None

class MitmScenario(BaseModel):
    scenario: str  # cleartext | tls12 | pqc_tls13
    label: str
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    is_encrypted: bool = False
    is_quantum_safe: bool = False
    hndl_risk: str = "N/A"
    original_email: Dict[str, str] = {}
    attacker_view: Dict[str, str] = {}
    risk_color: str = "#767270"
    risk_label: str = "Unknown"
    wire_hex_dump: Optional[str] = None
    crypto_details: Optional[Dict[str, Any]] = None
    hndl_details: Optional[Dict[str, Any]] = None

class MitmSimulateResponse(BaseModel):
    scenarios: List[MitmScenario] = []
    sample_email: Dict[str, str] = {}
    available_sessions: List[Dict[str, Any]] = []
    selected_session_id: Optional[str] = None
    is_real_crypto: bool = True

