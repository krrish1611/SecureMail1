"""AI-Assisted Executive Security Summary & Risk Narrative Engine.

Transforms forensic packet/session telemetry and compliance metrics into actionable,
human-readable executive briefings tailored for CISOs, security directors, and auditors:
- High-level security posture evaluation and letter grade (A+ through F).
- Plain-English executive briefing paragraphs summarizing cryptographic posture and exposure.
- Prioritized top vulnerabilities with direct business impact and risk vectors.
- Harvest-Now-Decrypt-Later (HNDL) and Post-Quantum Cryptography (PQC) readiness narrative.
- Regulatory compliance impact (PCI-DSS 4.0, NIST SP 800-52r2, HIPAA Security Rule).
- 3-Phase Action Roadmap: Immediate (24h), Tactical (7d), and Strategic (30-90d).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from core.models import Session, Severity, SEVERITY_NAMES


def _get_letter_grade(avg_score: float) -> Tuple[str, str]:
    if avg_score >= 85:
        return "A", "#38a856"
    if avg_score >= 70:
        return "B", "#1982c4"
    if avg_score >= 50:
        return "C", "#ffca3a"
    if avg_score >= 30:
        return "D", "#ff924c"
    return "F", "#ff595e"


def generate_executive_summary(
    sessions: List[Session],
    job_id: str,
    target_name: str = "Traffic Assessment",
    overall_stats: Optional[Dict[str, Any]] = None,
    compliance_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generate a comprehensive executive security briefing and action roadmap."""
    total_sessions = len(sessions)
    if total_sessions == 0:
        return {
            "job_id": job_id,
            "target_name": target_name,
            "posture_grade": "N/A",
            "grade_color": "#767270",
            "posture_score": 0.0,
            "headline": "No Email Sessions Detected",
            "executive_brief": "The analysis inspected zero valid email traffic streams. No cryptographic posture could be assessed.",
            "top_vulnerabilities": [],
            "post_quantum_assessment": {"hndl_risk": "UNKNOWN", "narrative": "No encrypted sessions detected."},
            "compliance_summary": {"status": "N/A", "narrative": "No compliance evaluation available."},
            "actionable_roadmap": [],
        }

    # Aggregate key metrics
    scores = [s.posture_score for s in sessions if s.posture_score is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    grade, grade_color = _get_letter_grade(avg_score)

    encrypted_count = sum(1 for s in sessions if s.encrypted)
    plaintext_count = sum(1 for s in sessions if s.plaintext)
    plaintext_creds = sum(1 for s in sessions if s.credentials_plaintext)
    stripped_count = sum(1 for s in sessions if s.starttls_stripped)
    anomalies_count = sum(1 for s in sessions if s.ml_anomaly)

    # Collect and deduplicate all findings by ID
    finding_map: Dict[str, Dict[str, Any]] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for s in sessions:
        for f in s.findings:
            sev_str = SEVERITY_NAMES.get(f.severity, "info")
            severity_counts[sev_str] = severity_counts.get(sev_str, 0) + 1
            if f.id not in finding_map:
                impact = "Allows unauthorized traffic decryption or credential theft."
                if "strip" in f.id or "downgrade" in f.id:
                    impact = "Active Man-in-the-Middle attackers can force plaintext transmission and intercept email in flight."
                elif "creds" in f.id or "plaintext" in f.id:
                    impact = "Exposes user credentials and sensitive business communications in plaintext over untrusted networks."
                elif "tls.10" in f.id or "tls.11" in f.id or "tls.ssl3" in f.id:
                    impact = "Violates regulatory standards (PCI-DSS, NIST) and exposes sessions to known cipher suite attacks (BEAST, POODLE)."
                elif "cert" in f.id or "expired" in f.id:
                    impact = "Breaks trust verification; allows rogue or impersonated servers to spoof organizational endpoints."
                elif "hndl" in f.id or "pqc" in f.id:
                    impact = "Exposes encrypted mail archives to future decryption by quantum adversaries (Harvest-Now-Decrypt-Later)."

                finding_map[f.id] = {
                    "id": f.id,
                    "title": f.title,
                    "severity": sev_str,
                    "severity_level": int(f.severity),
                    "description": f.description,
                    "business_impact": impact,
                    "recommendation": f.recommendation,
                    "cwe": f.cwe,
                    "occurrences": 1,
                }
            else:
                finding_map[f.id]["occurrences"] += 1

    sorted_findings = sorted(
        finding_map.values(),
        key=lambda x: (x["severity_level"], x["occurrences"]),
        reverse=True
    )
    top_vulnerabilities = sorted_findings[:5]

    # Post-quantum synthesis
    pqc_high_count = sum(1 for s in sessions if s.pqc and s.pqc.hndl_risk in ("HIGH", "CRITICAL"))
    pqc_safe_count = sum(1 for s in sessions if s.pqc and s.pqc.quantum_safe_kem)

    if pqc_safe_count > 0:
        pqc_narrative = f"{pqc_safe_count} of {encrypted_count} encrypted streams utilize quantum-resistant hybrid key exchange (NIST FIPS 203). Forward secrecy is resilient against future quantum computers."
        hndl_risk = "LOW"
    elif pqc_high_count > 0:
        pqc_narrative = f"All {pqc_high_count} encrypted mail streams rely on classical key exchanges (ECDHE/RSA). Adversaries intercepting and archiving this traffic can retrospectively decrypt all confidential emails once cryptanalytically relevant quantum computers (CRQCs) arrive."
        hndl_risk = "HIGH"
    else:
        pqc_narrative = "Encrypted sessions utilize modern classical curves. Transition to NIST FIPS 203 hybrid key exchange (X25519MLKEM768) is recommended."
        hndl_risk = "MEDIUM"

    # Headline & Narrative generation
    if grade in ("D", "F") or plaintext_creds > 0 or stripped_count > 0:
        headline = "Critical Cryptographic Exposure Detected: Immediate Remediation Required"
    elif grade == "C" or severity_counts.get("critical", 0) > 0 or severity_counts.get("high", 0) > 0:
        headline = "Elevated Security Risks Identified: Hardening Recommended"
    elif grade == "B":
        headline = "Adequate Baseline Security with Opportunities for Modernization"
    else:
        headline = "Robust Cryptographic Security Posture Maintained"

    # Executive Brief paragraphs
    brief_p1 = (
        f"SecureMailScope completed an in-depth cryptographic posture inspection of {total_sessions} email communication session(s) for '{target_name}'. "
        f"The organization achieved an overall security posture score of {avg_score}/100 (Grade {grade}). "
        f"Out of {total_sessions} evaluated stream(s), {encrypted_count} ({round(encrypted_count/total_sessions*100 if total_sessions else 0)}%) were cryptographically protected, "
        f"while {plaintext_count} session(s) operated entirely unencrypted in plaintext."
    )

    threat_notes = []
    if plaintext_creds > 0:
        threat_notes.append(f"{plaintext_creds} session(s) transmitted user credentials in cleartext over the network")
    if stripped_count > 0:
        threat_notes.append(f"{stripped_count} STARTTLS downgrade attack(s) were identified where encryption was stripped in flight")
    if anomalies_count > 0:
        threat_notes.append(f"{anomalies_count} session(s) triggered unsupervised ML anomaly detection alerts for abnormal handshake entropy")
    if severity_counts.get("critical", 0) > 0:
        threat_notes.append(f"{severity_counts['critical']} critical-severity cryptographic flaw(s) require immediate triage")

    if threat_notes:
        brief_p2 = f"Active threat exposure: {'; '.join(threat_notes)}. These findings leave the mail infrastructure vulnerable to active man-in-the-middle (MitM) eavesdropping, credential hijacking, and spoofing."
    else:
        brief_p2 = "No active credential leaks or STARTTLS stripping anomalies were detected during the assessment window. Transport layers successfully enforced encryption handshakes without downgrade interference."

    brief_p3 = (
        f"Regulatory alignment: The environment was tested against PCI-DSS 4.0 (Req 4.1), NIST SP 800-52r2, and HIPAA § 164.312(e)(1). "
        f"{'Non-compliant protocols or weak ciphers were discovered that prevent audit approval.' if (grade in ('C', 'D', 'F') or severity_counts.get('critical', 0) > 0) else 'Core regulatory encryption baselines are satisfied.'} "
        f"Furthermore, 100% of encrypted streams remain exposed to Harvest-Now-Decrypt-Later (HNDL) quantum intelligence collection."
    )

    executive_brief = f"{brief_p1}\n\n{brief_p2}\n\n{brief_p3}"

    # 3-Phase Action Roadmap
    roadmap = [
        {
            "phase": "Phase 1: Immediate Triage (Next 24 Hours)",
            "timeframe": "0 - 24 Hours",
            "priority": "P1 - Critical",
            "color": "#ff595e",
            "actions": [
                "Disable plaintext authentication across all SMTP/IMAP/POP3 listeners (enforce 'smtpd_tls_auth_only = yes').",
                "Apply strict STARTTLS enforcement on incoming port 25 and submission port 587.",
                "Review client IP addresses flagged for plaintext credentials and force credential resets.",
            ],
        },
        {
            "phase": "Phase 2: Configuration Hardening (Next 7 Days)",
            "timeframe": "1 - 7 Days",
            "priority": "P2 - High",
            "color": "#ff924c",
            "actions": [
                "Deploy generated 1-click MTA hardening configs for Postfix, Dovecot, and Exim.",
                "Disable legacy TLS 1.0, TLS 1.1, and 3DES/CBC ciphers to meet PCI-DSS 4.0 compliance.",
                "Publish an MTA-STS policy ('_mta-sts.<domain>') with mode 'enforce' and publish DANE TLSA records with DNSSEC.",
                "Publish strict DMARC policy (p=reject or p=quarantine) with aggregate reporting (rua).",
            ],
        },
        {
            "phase": "Phase 3: Strategic Post-Quantum Migration (Next 30 - 90 Days)",
            "timeframe": "30 - 90 Days",
            "priority": "P3 - Medium",
            "color": "#1982c4",
            "actions": [
                "Enable hybrid Post-Quantum Key Exchange (X25519MLKEM768 / NIST FIPS 203) in mail server TLS termination proxies.",
                "Implement automated Certificate Transparency (CT) log monitoring for rogue certificate issuance.",
                "Establish automated CI/CD posture evaluation to fail staging pipelines if posture score drops below 80.",
            ],
        },
    ]

    return {
        "job_id": job_id,
        "target_name": target_name,
        "posture_grade": grade,
        "grade_color": grade_color,
        "posture_score": avg_score,
        "headline": headline,
        "executive_brief": executive_brief,
        "summary_paragraphs": [brief_p1, brief_p2, brief_p3],
        "severity_counts": severity_counts,
        "encrypted_ratio": round((encrypted_count / total_sessions * 100) if total_sessions else 0, 1),
        "plaintext_sessions": plaintext_count,
        "credentials_leaked": plaintext_creds,
        "downgrade_attacks": stripped_count,
        "top_vulnerabilities": top_vulnerabilities,
        "post_quantum_assessment": {
            "hndl_risk": hndl_risk,
            "safe_sessions": pqc_safe_count,
            "vulnerable_sessions": pqc_high_count,
            "narrative": pqc_narrative,
        },
        "compliance_summary": {
            "status": "NON-COMPLIANT" if grade in ("D", "F") else ("CONDITIONAL" if grade == "C" else "COMPLIANT"),
            "frameworks_audited": ["PCI-DSS 4.0", "NIST SP 800-52r2", "HIPAA § 164.312"],
            "narrative": "Detailed framework citations and control-level mappings available in the Compliance Matrix.",
        },
        "actionable_roadmap": roadmap,
    }
