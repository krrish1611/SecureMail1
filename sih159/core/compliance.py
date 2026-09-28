"""Compliance evaluation engine for PCI-DSS 4.0, NIST SP 800-52r2, and HIPAA.

Evaluates each session's cryptographic posture against regulatory controls
and produces per-session and aggregate compliance verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import Session


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ComplianceCheck:
    """Result of a single compliance control check."""
    control_id: str
    control_name: str
    framework: str          # "PCI-DSS 4.0" | "NIST 800-52r2" | "HIPAA"
    citation: str           # e.g. "Req 4.2.1"
    status: str             # "PASS" | "FAIL" | "N/A"
    detail: str = ""
    session_id: Optional[str] = None


@dataclass
class FrameworkSummary:
    """Aggregate compliance summary for one framework."""
    framework: str
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    na: int = 0
    verdict: str = "N/A"   # "COMPLIANT" | "NON-COMPLIANT" | "N/A"


@dataclass
class ComplianceReport:
    """Full compliance report across all frameworks and sessions."""
    frameworks: List[FrameworkSummary] = field(default_factory=list)
    checks: List[ComplianceCheck] = field(default_factory=list)
    per_session: Dict[str, List[ComplianceCheck]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Control definitions
# ---------------------------------------------------------------------------

CONTROLS = [
    {
        "id": "C01",
        "name": "TLS version >= 1.2",
        "frameworks": {
            "PCI-DSS 4.0": "Req 2.2.7, 4.2.1",
            "NIST 800-52r2": "§3.1",
            "HIPAA": "§164.312(e)(1)",
        },
    },
    {
        "id": "C02",
        "name": "No weak ciphers (RC4/DES/3DES/EXPORT/NULL)",
        "frameworks": {
            "PCI-DSS 4.0": "Req 2.2.7, 4.2.1",
            "NIST 800-52r2": "§3.3.1",
            "HIPAA": "§164.312(e)(2)(ii)",
        },
    },
    {
        "id": "C03",
        "name": "Forward secrecy (ECDHE/DHE)",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.3.1",
            "HIPAA": "§164.312(e)(2)(ii)",
        },
    },
    {
        "id": "C04",
        "name": "AEAD cipher mode (GCM/ChaCha20)",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.3.1",
            "HIPAA": "§164.312(e)(2)(ii)",
        },
    },
    {
        "id": "C05",
        "name": "Valid, trusted certificate",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.4",
            "HIPAA": "§164.312(e)(1)",
        },
    },
    {
        "id": "C06",
        "name": "Certificate not expired",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.4",
            "HIPAA": "§164.312(e)(1)",
        },
    },
    {
        "id": "C07",
        "name": "Strong public key (RSA >= 2048 / EC >= 256)",
        "frameworks": {
            "PCI-DSS 4.0": "Req 2.2.7",
            "NIST 800-52r2": "§3.2",
            "HIPAA": "§164.312(e)(2)(ii)",
        },
    },
    {
        "id": "C08",
        "name": "No SHA-1 certificate signatures",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.4.3",
            "HIPAA": "§164.312(e)(2)(ii)",
        },
    },
    {
        "id": "C09",
        "name": "Encryption required (not plaintext)",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.1",
            "HIPAA": "§164.312(e)(1)",
        },
    },
    {
        "id": "C10",
        "name": "No plaintext credentials",
        "frameworks": {
            "PCI-DSS 4.0": "Req 8.3.2",
            "NIST 800-52r2": "§3.5",
            "HIPAA": "§164.312(d)",
        },
    },
    {
        "id": "C11",
        "name": "No STARTTLS stripping",
        "frameworks": {
            "PCI-DSS 4.0": "Req 4.2.1",
            "NIST 800-52r2": "§3.1",
            "HIPAA": "§164.312(e)(1)",
        },
    },
]

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "EXPORT", "NULL")


# ---------------------------------------------------------------------------
# Per-session evaluation
# ---------------------------------------------------------------------------

def _check_control(ctrl: dict, session: Session) -> List[ComplianceCheck]:
    """Evaluate one control against a session, emitting one check per framework."""
    cid = ctrl["id"]
    results = []

    status, detail = _eval_control(cid, session)

    for fw, citation in ctrl["frameworks"].items():
        results.append(ComplianceCheck(
            control_id=cid,
            control_name=ctrl["name"],
            framework=fw,
            citation=citation,
            status=status,
            detail=detail,
            session_id=session.id,
        ))
    return results


def _eval_control(cid: str, s: Session) -> tuple:
    """Return (status, detail) for a control ID against a session."""

    if cid == "C01":
        if not s.encrypted and s.plaintext:
            return "FAIL", "Session is unencrypted (no TLS)"
        if not s.tls or not s.tls.version:
            return "N/A", "No TLS handshake detected"
        ver = s.tls.version
        if ver in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
            return "FAIL", f"Negotiated {ver} (requires >= TLS 1.2)"
        return "PASS", f"Negotiated {ver}"

    if cid == "C02":
        if not s.tls or not s.tls.cipher_suite:
            return "N/A", "No cipher suite negotiated"
        cs = s.tls.cipher_suite.upper()
        for marker in WEAK_CIPHER_MARKERS:
            if marker in cs:
                return "FAIL", f"Weak cipher: {s.tls.cipher_suite} contains {marker}"
        return "PASS", f"Cipher: {s.tls.cipher_suite}"

    if cid == "C03":
        if not s.tls or not s.tls.key_exchange:
            return "N/A", "No key exchange info"
        ke = s.tls.key_exchange
        if "ECDHE" in ke or "DHE" in ke or "X25519" in ke or "X448" in ke:
            return "PASS", f"Forward secrecy via {ke}"
        if s.tls.version == "TLSv1.3":
            return "PASS", "TLS 1.3 mandates forward secrecy"
        return "FAIL", f"Static key exchange: {ke} (no forward secrecy)"

    if cid == "C04":
        if not s.tls or not s.tls.cipher_suite:
            return "N/A", "No cipher suite negotiated"
        cs = s.tls.cipher_suite.upper()
        if "GCM" in cs or "CHACHA" in cs or "CCM" in cs:
            return "PASS", f"AEAD cipher: {s.tls.cipher_suite}"
        if s.tls.version == "TLSv1.3":
            return "PASS", "TLS 1.3 requires AEAD ciphers"
        return "FAIL", f"Non-AEAD cipher: {s.tls.cipher_suite}"

    if cid == "C05":
        cert = s.certificate
        if not cert:
            return "N/A", "No certificate presented"
        if cert.self_signed:
            return "FAIL", "Self-signed certificate"
        if cert.chain_valid is False:
            return "FAIL", "Invalid certificate chain"
        if cert.trusted is False:
            return "FAIL", "Certificate not trusted by a public CA"
        if cert.revoked:
            return "FAIL", "Certificate is revoked"
        return "PASS", "Certificate is valid and trusted"

    if cid == "C06":
        cert = s.certificate
        if not cert:
            return "N/A", "No certificate presented"
        if cert.expired:
            return "FAIL", f"Certificate expired on {cert.not_after}"
        if cert.not_yet_valid:
            return "FAIL", "Certificate not yet valid"
        return "PASS", f"Valid until {cert.not_after}"

    if cid == "C07":
        cert = s.certificate
        if not cert or not cert.public_key_algorithm:
            return "N/A", "No public key info"
        if cert.public_key_algorithm == "RSA":
            if cert.key_size and cert.key_size < 2048:
                return "FAIL", f"RSA key is {cert.key_size}-bit (requires >= 2048)"
            return "PASS", f"RSA {cert.key_size}-bit key"
        if "EC" in cert.public_key_algorithm:
            if cert.key_size and cert.key_size < 256:
                return "FAIL", f"EC key is {cert.key_size}-bit (requires >= 256)"
            return "PASS", f"{cert.public_key_algorithm} {cert.key_size}-bit key"
        return "PASS", f"{cert.public_key_algorithm} {cert.key_size or '?'}-bit key"

    if cid == "C08":
        cert = s.certificate
        if not cert or not cert.signature_algorithm:
            return "N/A", "No certificate signature info"
        if "SHA1" in cert.signature_algorithm.upper():
            return "FAIL", f"SHA-1 signature: {cert.signature_algorithm}"
        return "PASS", f"Signature: {cert.signature_algorithm}"

    if cid == "C09":
        if s.encrypted:
            return "PASS", "Session is encrypted"
        if s.plaintext:
            return "FAIL", "Session transmitted data in plaintext"
        return "N/A", "Unable to determine encryption status"

    if cid == "C10":
        if s.credentials_plaintext:
            return "FAIL", f"Credentials sent in plaintext ({s.auth_command_observed or 'AUTH'})"
        if s.encrypted:
            return "PASS", "No plaintext credentials observed"
        if s.plaintext and not s.credentials_plaintext:
            return "PASS", "Plaintext session but no credentials observed"
        return "N/A", "No authentication detected"

    if cid == "C11":
        if s.starttls_stripped:
            return "FAIL", "STARTTLS was stripped (downgrade attack)"
        if s.starttls and s.starttls_upgraded:
            return "PASS", "STARTTLS successfully upgraded"
        if s.encrypted and not s.starttls:
            return "PASS", "Implicit TLS (no STARTTLS needed)"
        if s.plaintext and not s.starttls:
            return "N/A", "STARTTLS not attempted"
        return "PASS", "No STARTTLS stripping detected"

    return "N/A", "Unknown control"


def evaluate_compliance(session: Session) -> List[ComplianceCheck]:
    """Evaluate all compliance controls against a single session."""
    checks = []
    for ctrl in CONTROLS:
        checks.extend(_check_control(ctrl, session))
    return checks


# ---------------------------------------------------------------------------
# Aggregate evaluation
# ---------------------------------------------------------------------------

def evaluate_compliance_all(sessions: List[Session]) -> ComplianceReport:
    """Evaluate compliance across all sessions and produce a full report."""
    report = ComplianceReport()
    all_checks: List[ComplianceCheck] = []

    for session in sessions:
        session_checks = evaluate_compliance(session)
        report.per_session[session.id] = session_checks
        all_checks.extend(session_checks)

    report.checks = all_checks

    # Build per-framework summaries
    frameworks = ("PCI-DSS 4.0", "NIST 800-52r2", "HIPAA")
    for fw in frameworks:
        fw_checks = [c for c in all_checks if c.framework == fw]
        passed = sum(1 for c in fw_checks if c.status == "PASS")
        failed = sum(1 for c in fw_checks if c.status == "FAIL")
        na = sum(1 for c in fw_checks if c.status == "N/A")
        total = len(fw_checks)

        verdict = "N/A"
        if total > 0 and (passed + na) > 0:
            verdict = "NON-COMPLIANT" if failed > 0 else "COMPLIANT"

        report.frameworks.append(FrameworkSummary(
            framework=fw,
            total_controls=total,
            passed=passed,
            failed=failed,
            na=na,
            verdict=verdict,
        ))

    return report


def compliance_report_to_dict(report: ComplianceReport) -> dict:
    """Serialize a ComplianceReport to a JSON-friendly dict."""
    return {
        "frameworks": [
            {
                "framework": fs.framework,
                "total_controls": fs.total_controls,
                "passed": fs.passed,
                "failed": fs.failed,
                "na": fs.na,
                "verdict": fs.verdict,
            }
            for fs in report.frameworks
        ],
        "controls_summary": _controls_summary(report),
        "per_session": {
            sid: [
                {
                    "control_id": c.control_id,
                    "control_name": c.control_name,
                    "framework": c.framework,
                    "citation": c.citation,
                    "status": c.status,
                    "detail": c.detail,
                }
                for c in checks
            ]
            for sid, checks in report.per_session.items()
        },
    }


def _controls_summary(report: ComplianceReport) -> List[dict]:
    """Build a per-control aggregate summary across all sessions."""
    summary = []
    for ctrl in CONTROLS:
        ctrl_checks = [c for c in report.checks if c.control_id == ctrl["id"]]
        # Group by framework
        fw_results = {}
        for fw, citation in ctrl["frameworks"].items():
            fw_c = [c for c in ctrl_checks if c.framework == fw]
            has_fail = any(c.status == "FAIL" for c in fw_c)
            has_pass = any(c.status == "PASS" for c in fw_c)
            all_na = all(c.status == "N/A" for c in fw_c)
            if all_na:
                fw_results[fw] = {"status": "N/A", "citation": citation}
            elif has_fail:
                fw_results[fw] = {"status": "FAIL", "citation": citation}
            else:
                fw_results[fw] = {"status": "PASS", "citation": citation}
        summary.append({
            "control_id": ctrl["id"],
            "control_name": ctrl["name"],
            "frameworks": fw_results,
        })
    return summary
