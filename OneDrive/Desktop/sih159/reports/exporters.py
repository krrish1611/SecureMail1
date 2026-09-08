"""Report generation for SecureMailScope.

Provides exporters for JSON, HTML (Jinja2), and PDF (reportlab).
"""

from __future__ import annotations

import csv
import html
import json
import os
import datetime as dt
from typing import List

from core.models import Session, Finding, Severity, SEVERITY_NAMES
from core.compliance import evaluate_compliance_all, compliance_report_to_dict

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "generated")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity": SEVERITY_NAMES[f.severity],
        "recommendation": f.recommendation,
        "cwe": f.cwe,
        "cve": f.cve,
    }


def _session_dict(s: Session) -> dict:
    tls = s.tls
    cert = s.certificate
    tls_dict = {}
    if tls:
        tls_dict = {
            "version": tls.version,
            "cipher_suite": tls.cipher_suite,
            "cipher_hex": tls.cipher_hex,
            "key_exchange": tls.key_exchange,
            "key_exchange_group": tls.key_exchange_group,
            "signature_algorithm": tls.signature_algorithm,
            "server_name": tls.server_name,
            "offered_ciphers": tls.offered_ciphers,
            "extensions": tls.extensions,
            "ja3": tls.ja3,
            "ja4": tls.ja4,
            "ja4s": tls.ja4s,
        }
    cert_dict = {}
    if cert:
        cert_dict = {
            "subject": cert.subject,
            "issuer": cert.issuer,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "public_key_algorithm": cert.public_key_algorithm,
            "key_size": cert.key_size,
            "signature_algorithm": cert.signature_algorithm,
            "san": cert.san,
            "self_signed": cert.self_signed,
            "expired": cert.expired,
            "days_to_expiry": cert.days_to_expiry,
            "chain_valid": cert.chain_valid,
            "trusted": cert.trusted,
            "revoked": cert.revoked,
            "revocation_status": cert.revocation_status,
            "revocation_method": cert.revocation_method,
            "ja4x": cert.ja4x,
        }
    dns_dict = {}
    if s.dns_security:
        dns_dict = {
            "domain": s.dns_security.domain,
            "hostname": s.dns_security.hostname,
            "mta_sts_record": s.dns_security.mta_sts_record,
            "mta_sts_valid": s.dns_security.mta_sts_valid,
            "mta_sts_mode": s.dns_security.mta_sts_mode,
            "mta_sts_id": s.dns_security.mta_sts_id,
            "dane_tlsa_records": s.dns_security.dane_tlsa_records,
            "dane_valid": s.dns_security.dane_valid,
            "dane_match_status": s.dns_security.dane_match_status,
            "recommended_mta_sts_dns": s.dns_security.recommended_mta_sts_dns,
            "recommended_mta_sts_policy": s.dns_security.recommended_mta_sts_policy,
        }
    pqc_dict = {}
    if s.pqc:
        pqc_dict = {
            "pqc_status": s.pqc.pqc_status,
            "quantum_safe_kem": s.pqc.quantum_safe_kem,
            "hybrid_key_exchange": s.pqc.hybrid_key_exchange,
            "kem_algorithm": s.pqc.kem_algorithm,
            "classical_algorithm": s.pqc.classical_algorithm,
            "quantum_safe_signature": s.pqc.quantum_safe_signature,
            "signature_scheme": s.pqc.signature_scheme,
            "hndl_risk": s.pqc.hndl_risk,
            "quantum_vulnerability_score": s.pqc.quantum_vulnerability_score,
            "standard_compliance": s.pqc.standard_compliance,
            "remediation_steps": s.pqc.remediation_steps,
        }
    attr_dict = {}
    if s.attribution:
        attr_dict = {
            "client_name": s.attribution.client_name,
            "client_category": s.attribution.client_category,
            "confidence": s.attribution.confidence,
            "matched_fingerprint": s.attribution.matched_fingerprint,
            "is_threat": s.attribution.is_threat,
            "is_automation": s.attribution.is_automation,
            "masquerading_detected": s.attribution.masquerading_detected,
            "masquerading_details": s.attribution.masquerading_details,
            "fingerprint_notes": s.attribution.fingerprint_notes,
        }
    return {
        "session_id": s.id,
        "protocol": s.protocol,
        "server_ip": s.server_ip,
        "server_port": s.server_port,
        "client_ip": s.client_ip,
        "client_port": s.client_port,
        "start_ts": s.start_ts,
        "end_ts": s.end_ts,
        "bytes_c2s": s.bytes_client_to_server,
        "bytes_s2c": s.bytes_server_to_client,
        "packets": s.packets,
        "encrypted": s.encrypted,
        "plaintext": s.plaintext,
        "starttls_requested": s.starttls,
        "starttls_upgraded": s.starttls_upgraded,
        "starttls_stripped": s.starttls_stripped,
        "credentials_plaintext": s.credentials_plaintext,
        "auth_command": s.auth_command_observed,
        "tls": tls_dict,
        "certificate": cert_dict,
        "dns_security": dns_dict,
        "pqc": pqc_dict,
        "attribution": attr_dict,
        "posture_score": s.posture_score,
        "risk_label": s.risk_label,
        "ml_score": s.ml_score,
        "ml_anomaly": s.ml_anomaly,
        "findings": [_finding_dict(f) for f in s.findings],
        "severity_summary": s.severity_count(),
    }



def generate_json(sessions: List[Session], output_path: str = None) -> str:
    """Export all sessions as a JSON report."""
    compliance = evaluate_compliance_all(sessions)
    report = {
        "tool": "SecureMailScope",
        "version": "0.1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "session_count": len(sessions),
        "sessions": [_session_dict(s) for s in sessions],
        "compliance": compliance_report_to_dict(compliance),
    }
    if output_path is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, "report.json")
    else:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return output_path


def generate_html(sessions: List[Session], output_path: str = None) -> str:
    """Export as an HTML report with inline CSS for a professional forensic look."""
    if output_path is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, "report.html")
    else:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#0284c7",
        "info": "#6b7280",
    }
    overall_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    sessions_data = []
    for s in sessions:
        sc = s.severity_count()
        for k, v in sc.items():
            overall_counts[k] += v
        sessions_data.append(_session_dict(s))

    sessions_html = ""
    for sd in sessions_data:
        certs = sd["certificate"]
        tls = sd["tls"]
        dns = sd.get("dns_security")
        tls_block = "".join(f"<b>{k}:</b> {v}<br>" for k, v in tls.items()) if tls else "<i>No TLS detected</i>"
        certs_block = "".join(f"<b>{k}:</b> {v}<br>" for k, v in certs.items()) if certs else "<i>No certificate</i>"
        dns_block = "".join(f"<b>{k}:</b> {v}<br>" for k, v in dns.items() if v) if dns else "<i>No domain heuristics</i>"
        def _finding_row(f):
            color = severity_colors.get(f["severity"], "#6b7280")
            sev = f["severity"].upper()
            return (
                f"<tr><td style='color:{color}; font-weight:bold;'>{sev}</td>"
                f"<td><b>{f['title']}</b><br><small>{f['description']}</small>"
                f"<br><i>Recommendation: {f['recommendation']}</i></td></tr>"
            )

        findings_block = "".join(_finding_row(f) for f in sd["findings"]) or (
            "<tr><td colspan='2' style='text-align:center; color:#6b7280;'>No findings</td></tr>"
        )

        sessions_html += f"""
        <div class='session-card'>
          <h3>Session: {sd['session_id']} ({sd['protocol'].upper()})</h3>
          <div class='detail-grid'>
            <div><b>Server:</b> {sd['server_ip']}:{sd['server_port']}</div>
            <div><b>Client:</b> {sd['client_ip']}:{sd['client_port']}</div>
            <div><b>Encrypted:</b> {sd['encrypted']}</div>
            <div><b>STARTTLS:</b> requested={sd['starttls_requested']} upgraded={sd['starttls_upgraded']} stripped={sd['starttls_stripped']}</div>
            <div><b>Posture Score:</b> {sd['posture_score']}/100 &nbsp;|&nbsp; <b>Risk:</b> {sd['risk_label']}</div>
          </div>
          <div class='tls-block'><h4>TLS Details</h4>{tls_block}</div>
          <div class='cert-block'><h4>Certificate</h4>{certs_block}</div>
          <div class='dns-block' style='background:#111827; padding:12px; border-radius:6px; margin:10px 0;'><h4>MTA-STS & DANE Downgrade Protection</h4>{dns_block}</div>
          <h4>Findings ({len(sd['findings'])})</h4>
          <table class='findings-table'><thead><tr><th>Severity</th><th>Finding</th></tr></thead>
          <tbody>{findings_block}</tbody></table>
        </div>
        """

    counts_badge = "".join(
        f"<span class='badge' style='background:{severity_colors[k]}; color:white; padding:4px 12px; margin:2px; border-radius:12px;'>{v} {k.upper()}</span>"
        for k, v in overall_counts.items()
    )

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'><title>SecureMailScope Forensic Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background:#111827; color:#e5e7eb; margin:0; padding:20px; }}
h1 {{ color:#60a5fa; text-align:center; margin-bottom:5px; }}
h2 {{ color:#93c5fd; text-align:center; margin-top:0; }}
.report-meta {{ text-align:center; color:#9ca3af; margin-bottom:20px; }}
.badge-row {{ text-align:center; margin:20px 0; }}
.session-card {{ background:#1f2937; border:1px solid #374151; border-radius:10px; padding:20px; margin:20px 0; }}
.detail-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin:10px 0; }}
.tls-block, .cert-block {{ background:#111827; padding:12px; border-radius:6px; margin:10px 0; }}
h4 {{ color:#93c5fd; margin-bottom:8px; }}
table {{ width:100%; border-collapse:collapse; margin-top:10px; }}
th {{ text-align:left; color:#60a5fa; border-bottom:1px solid #374151; padding:8px; }}
td {{ padding:8px; border-bottom:1px solid #1f2937; vertical-align:top; }}
footer {{ text-align:center; color:#6b7280; margin-top:40px; font-size:0.85em; }}
</style></head>
<body>
<h1>SecureMailScope</h1>
<h2>Cryptographic Security Posture Assessment</h2>
<div class='report-meta'>Generated: {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Sessions: {len(sessions)}</div>
<div class='badge-row'>{counts_badge}</div>
{sessions_html}
{_generate_compliance_html_section(sessions)}
<footer>SecureMailScope v0.1.0 — AI-Assisted Cryptographic Security Assessment</footer>
</body></html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


try:
    from reportlab.pdfgen import canvas as rl_canvas

    class NumberedCanvas(rl_canvas.Canvas):
        """Two-pass canvas that renders running headers, rules, and page numbers."""
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_page_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_page_decorations(self, page_count: int):
            from reportlab.lib import colors
            from reportlab.lib.units import cm
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))

            # Running header on pages > 1
            if self._pageNumber > 1:
                self.drawString(1.5 * cm, 28.3 * cm, "SecureMailScope — Cryptographic Security Assessment")
                self.setStrokeColor(colors.HexColor("#e2e8f0"))
                self.setLineWidth(0.5)
                self.line(1.5 * cm, 28.1 * cm, 19.5 * cm, 28.1 * cm)

            # Running footer on all pages
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(1.5 * cm, 1.5 * cm, 19.5 * cm, 1.5 * cm)

            self.drawString(1.5 * cm, 1.1 * cm, "CONFIDENTIAL & FORENSIC — Generated by SecureMailScope")
            page_str = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(19.5 * cm, 1.1 * cm, page_str)
            self.restoreState()
except ImportError:
    NumberedCanvas = None


def generate_pdf(sessions: List[Session], output_path: str = None) -> str:
    """Export all sessions and compliance matrix as a comprehensive PDF report."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether, HRFlowable,
        )
    except ImportError:
        raise RuntimeError(
            "ReportLab is required for PDF report generation. Please install reportlab (`pip install reportlab>=4.0.0`)."
        )

    if output_path is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, "report.pdf")
    else:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
    )

    base_styles = getSampleStyleSheet()

    # Typography & styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=base_styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=0,
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#2563eb'),
        spaceAfter=6,
    )
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12,
    )
    section_h1 = ParagraphStyle(
        'SectionH1',
        parent=base_styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True,
    )
    section_h2 = ParagraphStyle(
        'SectionH2',
        parent=base_styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=7,
        spaceAfter=3,
        keepWithNext=True,
    )
    cell_text = ParagraphStyle(
        'CellText',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#0f172a'),
    )
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=cell_text,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1e293b'),
    )
    cell_center = ParagraphStyle(
        'CellCenter',
        parent=cell_text,
        alignment=1,
    )
    cell_center_bold = ParagraphStyle(
        'CellCenterBold',
        parent=cell_bold,
        alignment=1,
    )
    cell_hdr_white = ParagraphStyle(
        'CellHdrWhite',
        parent=cell_center_bold,
        textColor=colors.white,
    )
    cell_hdr_white_left = ParagraphStyle(
        'CellHdrWhiteLeft',
        parent=cell_bold,
        textColor=colors.white,
    )
    kpi_val = ParagraphStyle(
        'KPIVal',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=16,
        alignment=1,
        textColor=colors.HexColor('#0f172a'),
    )
    kpi_lbl = ParagraphStyle(
        'KPILbl',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        alignment=1,
        textColor=colors.HexColor('#64748b'),
    )
    finding_title = ParagraphStyle(
        'FindingTitle',
        parent=base_styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#0f172a'),
    )
    finding_desc = ParagraphStyle(
        'FindingDesc',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=2,
        spaceAfter=2,
    )
    finding_recom = ParagraphStyle(
        'FindingRecom',
        parent=base_styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0369a1'),
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("SecureMailScope", title_style))
    story.append(Paragraph("Cryptographic Security Posture Assessment Report", subtitle_style))
    gen_time = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    story.append(Paragraph(
        f"<b>Generated:</b> {gen_time} &nbsp;|&nbsp; <b>Total Sessions Analyzed:</b> {len(sessions)}",
        meta_style
    ))

    # Overall Statistics
    total = len(sessions)
    encrypted = sum(1 for s in sessions if s.encrypted)
    plaintext = sum(1 for s in sessions if s.plaintext)
    avg_score = (sum(s.posture_score or 0 for s in sessions) / total) if total else 0
    anomalies = sum(1 for s in sessions if s.ml_anomaly)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    proto_counts = {}
    for s in sessions:
        sc = s.severity_count()
        for k, v in sc.items():
            sev_counts[k] += v
        p = (s.protocol or "UNKNOWN").upper()
        proto_counts[p] = proto_counts.get(p, 0) + 1

    # Executive KPI Table (18.0 cm width)
    kpi_data = [
        [
            Paragraph(f"<font color='#0f172a'>{total}</font>", kpi_val),
            Paragraph(f"<font color='#16a34a'>{encrypted}</font>", kpi_val),
            Paragraph(f"<font color='{'#dc2626' if plaintext > 0 else '#16a34a'}'>{plaintext}</font>", kpi_val),
            Paragraph(f"<font color='#2563eb'>{round(avg_score, 1)}/100</font>", kpi_val),
            Paragraph(f"<font color='{'#dc2626' if anomalies > 0 else '#16a34a'}'>{anomalies}</font>", kpi_val),
        ],
        [
            Paragraph("TOTAL SESSIONS", kpi_lbl),
            Paragraph("ENCRYPTED", kpi_lbl),
            Paragraph("PLAINTEXT", kpi_lbl),
            Paragraph("AVG POSTURE SCORE", kpi_lbl),
            Paragraph("ML ANOMALIES", kpi_lbl),
        ]
    ]
    t_kpi = Table(kpi_data, colWidths=[3.6 * cm] * 5)
    t_kpi.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_kpi)
    story.append(Spacer(1, 0.3 * cm))

    # Findings Breakdown Banner Table
    sev_badge_data = [
        [
            Paragraph("<b>CRITICAL</b>", cell_hdr_white),
            Paragraph("<b>HIGH</b>", cell_hdr_white),
            Paragraph("<b>MEDIUM</b>", cell_hdr_white),
            Paragraph("<b>LOW</b>", cell_hdr_white),
            Paragraph("<b>INFO</b>", cell_hdr_white),
            Paragraph("<b>TOTAL FINDINGS</b>", cell_hdr_white),
        ],
        [
            Paragraph(f"<b><font size=10 color='#dc2626'>{sev_counts['critical']}</font></b>", cell_center),
            Paragraph(f"<b><font size=10 color='#ea580c'>{sev_counts['high']}</font></b>", cell_center),
            Paragraph(f"<b><font size=10 color='#d97706'>{sev_counts['medium']}</font></b>", cell_center),
            Paragraph(f"<b><font size=10 color='#0284c7'>{sev_counts['low']}</font></b>", cell_center),
            Paragraph(f"<b><font size=10 color='#64748b'>{sev_counts['info']}</font></b>", cell_center),
            Paragraph(f"<b><font size=10 color='#0f172a'>{sum(sev_counts.values())}</font></b>", cell_center),
        ]
    ]
    t_sev = Table(sev_badge_data, colWidths=[3.0 * cm] * 6)
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('BACKGROUND', (0, 1), (-1, 1), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 0.4 * cm))

    # Protocol breakdown
    proto_str = " &nbsp;|&nbsp; ".join(f"<b>{p}:</b> {count}" for p, count in sorted(proto_counts.items())) if proto_counts else "None"
    story.append(Paragraph(f"<font size=8 color='#475569'><b>Protocol Breakdown:</b> {proto_str}</font>", base_styles['Normal']))
    story.append(Spacer(1, 0.4 * cm))

    # Detailed Sessions Section
    story.append(Paragraph("Detailed Session Forensic Analysis", section_h1))

    if not sessions:
        story.append(Paragraph("<i>No sessions recorded or evaluated.</i>", base_styles['Normal']))
    else:
        for idx, s in enumerate(sessions):
            session_elements = []
            score = s.posture_score or 0
            risk_color = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#d97706",
                "low": "#16a34a",
            }.get(s.risk_label.lower(), "#64748b")

            # Session Header Banner
            anomaly_tag = " &nbsp; <font color='#f87171'><b>[ML ANOMALY DETECTED]</b></font>" if s.ml_anomaly else ""
            header_text = f"<b>Session {html.escape(str(s.id))} ({html.escape(str(s.protocol.upper()))})</b>{anomaly_tag}"
            score_text = f"<b>Score: {score}/100</b> — <font color='{risk_color}'><b>{html.escape(str(s.risk_label.upper()))} RISK</b></font>"

            sess_banner_data = [
                [
                    Paragraph(header_text, ParagraphStyle('SessHdrL', parent=base_styles['Normal'], fontSize=9, leading=12, textColor=colors.white)),
                    Paragraph(score_text, ParagraphStyle('SessHdrR', parent=base_styles['Normal'], fontSize=9, leading=12, alignment=2, textColor=colors.white)),
                ]
            ]
            t_banner = Table(sess_banner_data, colWidths=[10.5 * cm, 7.5 * cm])
            t_banner.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1e293b')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#0f172a')),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            session_elements.append(t_banner)

            # Network Flow & State Table
            cred_text = "<font color='#dc2626'><b>DETECTED (Plaintext Leak)</b></font>" if s.credentials_plaintext else "None detected"
            enc_text = "<font color='#16a34a'><b>Yes (Encrypted)</b></font>" if s.encrypted else "<font color='#dc2626'><b>No (Plaintext)</b></font>"
            starttls_text = f"req={s.starttls} | upgraded={s.starttls_upgraded} | stripped={'<b>YES</b>' if s.starttls_stripped else 'No'}"

            flow_data = [
                [
                    Paragraph("Server Endpoint", cell_bold),
                    Paragraph(f"{html.escape(str(s.server_ip))}:{s.server_port}", cell_text),
                    Paragraph("Client Endpoint", cell_bold),
                    Paragraph(f"{html.escape(str(s.client_ip))}:{s.client_port}", cell_text),
                ],
                [
                    Paragraph("Transport Security", cell_bold),
                    Paragraph(enc_text, cell_text),
                    Paragraph("Plaintext Credentials", cell_bold),
                    Paragraph(cred_text, cell_text),
                ],
                [
                    Paragraph("STARTTLS Negotiation", cell_bold),
                    Paragraph(starttls_text, cell_text),
                    Paragraph("Auth Command", cell_bold),
                    Paragraph(html.escape(str(s.auth_command_observed or 'None')), cell_text),
                ],
                [
                    Paragraph("Packets & Flow", cell_bold),
                    Paragraph(f"{s.packets} packets (C→S: {s.bytes_client_to_server} B, S→C: {s.bytes_server_to_client} B)", cell_text),
                    Paragraph("ML Evaluation", cell_bold),
                    Paragraph(f"Score: {s.ml_score if s.ml_score is not None else 'N/A'} | Anomaly: {'YES' if s.ml_anomaly else 'No'}", cell_text),
                ],
            ]
            t_flow = Table(flow_data, colWidths=[3.2 * cm, 5.8 * cm, 3.2 * cm, 5.8 * cm])
            t_flow.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8fafc')),
                ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            session_elements.append(t_flow)

            # TLS Details Table (if present)
            if s.tls:
                tls = s.tls
                tls_data = [
                    [
                        Paragraph("TLS Version", cell_bold),
                        Paragraph(html.escape(str(tls.version or 'N/A')), cell_text),
                        Paragraph("Negotiated Cipher", cell_bold),
                        Paragraph(html.escape(str(tls.cipher_suite or 'N/A')), cell_text),
                    ],
                    [
                        Paragraph("Cipher Hex Code", cell_bold),
                        Paragraph(html.escape(str(tls.cipher_hex or 'N/A')), cell_text),
                        Paragraph("Server Name (SNI)", cell_bold),
                        Paragraph(html.escape(str(tls.server_name or 'None')), cell_text),
                    ],
                    [
                        Paragraph("Key Exchange / Group", cell_bold),
                        Paragraph(f"{html.escape(str(tls.key_exchange or 'N/A'))} / {html.escape(str(tls.key_exchange_group or 'N/A'))}", cell_text),
                        Paragraph("Signature Algorithm", cell_bold),
                        Paragraph(html.escape(str(tls.signature_algorithm or 'N/A')), cell_text),
                    ],
                    [
                        Paragraph("JA3 Fingerprint", cell_bold),
                        Paragraph(html.escape(str(tls.ja3 or 'N/A')), cell_text),
                        Paragraph("Offered Ciphers Count", cell_bold),
                        Paragraph(f"{len(tls.offered_ciphers) if tls.offered_ciphers else 0} suites", cell_text),
                    ],
                    [
                        Paragraph("JA4 Client FP", cell_bold),
                        Paragraph(html.escape(str(tls.ja4 or 'N/A')), cell_text),
                        Paragraph("JA4S Server FP", cell_bold),
                        Paragraph(html.escape(str(tls.ja4s or 'N/A')), cell_text),
                    ],
                ]
                t_tls = Table(tls_data, colWidths=[3.2 * cm, 5.8 * cm, 3.2 * cm, 5.8 * cm])
                t_tls.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
                    ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f1f5f9')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                session_elements.append(Paragraph("<b>TLS Cryptographic Parameters</b>", section_h2))
                session_elements.append(t_tls)

            # Certificate Details Table (if present)
            if s.certificate:
                c = s.certificate
                exp_text = "<font color='#dc2626'><b>YES (EXPIRED)</b></font>" if c.expired else "No"
                ss_text = "<font color='#dc2626'><b>YES (Self-Signed)</b></font>" if c.self_signed else "No (CA Signed)"
                trust_text = "<font color='#16a34a'><b>Trusted</b></font>" if c.trusted else "<font color='#dc2626'><b>Untrusted / Unverified</b></font>"
                sans_str = ", ".join(c.san[:3]) + (" ..." if len(c.san) > 3 else "") if c.san else "None"

                cert_data = [
                    [
                        Paragraph("Subject DN", cell_bold),
                        Paragraph(html.escape(str(c.subject or 'N/A')), cell_text),
                        Paragraph("Issuer DN", cell_bold),
                        Paragraph(html.escape(str(c.issuer or 'N/A')), cell_text),
                    ],
                    [
                        Paragraph("Validity Period", cell_bold),
                        Paragraph(f"{html.escape(str(c.not_before or 'N/A'))} to {html.escape(str(c.not_after or 'N/A'))}", cell_text),
                        Paragraph("Expiry / Days Left", cell_bold),
                        Paragraph(f"{exp_text} ({c.days_to_expiry if c.days_to_expiry is not None else 'N/A'} days)", cell_text),
                    ],
                    [
                        Paragraph("Public Key / Size", cell_bold),
                        Paragraph(f"{html.escape(str(c.public_key_algorithm or 'N/A'))} ({c.key_size or 'N/A'} bits)", cell_text),
                        Paragraph("Signature Algorithm", cell_bold),
                        Paragraph(html.escape(str(c.signature_algorithm or 'N/A')), cell_text),
                    ],
                    [
                        Paragraph("Trust & Validation", cell_bold),
                        Paragraph(f"{trust_text} | Self-Signed: {ss_text}", cell_text),
                        Paragraph("Revocation Status", cell_bold),
                        Paragraph(f"{html.escape(str(c.revocation_status or 'N/A'))} ({html.escape(str(c.revocation_method or 'None'))})", cell_text),
                    ],
                    [
                        Paragraph("Subject Alt Names (SAN)", cell_bold),
                        Paragraph(html.escape(sans_str), cell_text),
                        Paragraph("Chain Validity", cell_bold),
                        Paragraph("<font color='#16a34a'>Valid</font>" if c.chain_valid else "<font color='#dc2626'>Invalid / Broken</font>", cell_text),
                    ],
                    [
                        Paragraph("JA4X Cert FP", cell_bold),
                        Paragraph(html.escape(str(c.ja4x or 'N/A')), cell_text),
                        Paragraph("", cell_bold),
                        Paragraph("", cell_text),
                    ],
                ]
                t_cert = Table(cert_data, colWidths=[3.2 * cm, 5.8 * cm, 3.2 * cm, 5.8 * cm])
                t_cert.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
                    ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f1f5f9')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                session_elements.append(Paragraph("<b>X.509 Certificate Inspection & Trust</b>", section_h2))
                session_elements.append(t_cert)

            # Downgrade Protection (MTA-STS & DANE) Table
            if s.dns_security and s.dns_security.domain:
                dns = s.dns_security
                mta_text = "<font color='#16a34a'><b>Enforced</b></font>" if dns.mta_sts_mode == "enforce" else ("<font color='#ca8a04'>Testing</font>" if dns.mta_sts_mode == "testing" else "<font color='#dc2626'>Not Published</font>")
                dane_text = "<font color='#16a34a'><b>Validated</b></font>" if dns.dane_valid else ("<font color='#dc2626'>Mismatch</font>" if dns.dane_match_status == "mismatch" else "<font color='#64748b'>Not Published</font>")
                dns_data = [
                    [
                        Paragraph("Mail Domain", cell_bold),
                        Paragraph(html.escape(str(dns.domain or 'N/A')), cell_text),
                        Paragraph("Mail Hostname", cell_bold),
                        Paragraph(html.escape(str(dns.hostname or 'N/A')), cell_text),
                    ],
                    [
                        Paragraph("MTA-STS Status", cell_bold),
                        Paragraph(f"{mta_text} (id={html.escape(str(dns.mta_sts_id or 'none'))})", cell_text),
                        Paragraph("DANE TLSA Status", cell_bold),
                        Paragraph(dane_text, cell_text),
                    ],
                ]
                t_dns = Table(dns_data, colWidths=[3.2 * cm, 5.8 * cm, 3.2 * cm, 5.8 * cm])
                t_dns.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
                    ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f1f5f9')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                session_elements.append(Paragraph("<b>MTA-STS & DANE Downgrade Protection (RFC 8461 / 7672)</b>", section_h2))
                session_elements.append(t_dns)

            # Findings Section
            session_elements.append(Paragraph(f"<b>Security Findings ({len(s.findings)})</b>", section_h2))
            if s.findings:
                sev_badge_colors = {
                    "critical": "#dc2626",
                    "high": "#ea580c",
                    "medium": "#d97706",
                    "low": "#0284c7",
                    "info": "#64748b",
                }
                finding_rows = []
                for f in s.findings:
                    sev_name = SEVERITY_NAMES[f.severity].lower()
                    b_color = sev_badge_colors.get(sev_name, "#64748b")
                    cwe_tag = f" &nbsp; <font color='#475569'><b>[{html.escape(str(f.cwe))}]</b></font>" if f.cwe else ""
                    cve_tag = f" &nbsp; <font color='#475569'><b>[{html.escape(str(f.cve))}]</b></font>" if f.cve else ""

                    f_details = [
                        Paragraph(f"<b>{html.escape(str(f.title))}</b>{cwe_tag}{cve_tag}", finding_title),
                        Paragraph(html.escape(str(f.description)), finding_desc),
                        Paragraph(f"<b>Recommendation:</b> {html.escape(str(f.recommendation))}", finding_recom),
                    ]

                    finding_rows.append([
                        Paragraph(f"<font color='{b_color}'><b>[{sev_name.upper()}]</b></font><br/><font size=6.5 color='#64748b'>{html.escape(str(f.category))}</font>", cell_center),
                        f_details,
                    ])

                t_findings = Table(finding_rows, colWidths=[2.2 * cm, 15.8 * cm])
                t_findings.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                session_elements.append(t_findings)
            else:
                session_elements.append(Paragraph("<i>No vulnerabilities or security posture findings identified for this session.</i>", base_styles['Normal']))

            story.append(KeepTogether(session_elements[:3]))
            for elem in session_elements[3:]:
                story.append(elem)

            if idx < len(sessions) - 1:
                story.append(Spacer(1, 0.4 * cm))
                story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8, spaceBefore=8))

    # Regulatory Compliance Section
    _generate_compliance_pdf_section(
        sessions=sessions,
        story=story,
        base_styles=base_styles,
        section_h1=section_h1,
        section_h2=section_h2,
        cell_text=cell_text,
        cell_bold=cell_bold,
        cell_center=cell_center,
        cell_center_bold=cell_center_bold,
        cell_hdr_white=cell_hdr_white,
        cell_hdr_white_left=cell_hdr_white_left,
    )

    if NumberedCanvas is not None:
        doc.build(story, canvasmaker=NumberedCanvas)
    else:
        doc.build(story)

    return output_path


def _generate_compliance_html_section(sessions: List[Session]) -> str:
    """Generate an HTML compliance matrix section."""
    report = evaluate_compliance_all(sessions)
    data = compliance_report_to_dict(report)

    verdict_colors = {
        "COMPLIANT": "#22c55e",
        "NON-COMPLIANT": "#ef4444",
        "N/A": "#6b7280",
    }
    status_colors = {
        "PASS": "#22c55e",
        "FAIL": "#ef4444",
        "N/A": "#6b7280",
    }

    # Framework summary cards
    fw_cards = ""
    for fw in data["frameworks"]:
        color = verdict_colors.get(fw["verdict"], "#6b7280")
        fw_cards += f"""
        <div style='background:#1f2937; border:1px solid #374151; border-radius:10px;
                    padding:16px; text-align:center; min-width:200px;'>
          <div style='font-size:14px; color:#93c5fd; font-weight:bold;'>{fw["framework"]}</div>
          <div style='font-size:24px; font-weight:bold; color:{color}; margin:8px 0;'>{fw["verdict"]}</div>
          <div style='font-size:12px; color:#9ca3af;'>
            <span style='color:#22c55e;'>✓ {fw["passed"]} passed</span> ·
            <span style='color:#ef4444;'>✗ {fw["failed"]} failed</span> ·
            <span style='color:#6b7280;'>— {fw["na"]} N/A</span>
          </div>
        </div>"""

    # Controls table
    rows = ""
    for ctrl in data["controls_summary"]:
        cells = ""
        for fw_name in ("PCI-DSS 4.0", "NIST 800-52r2", "HIPAA"):
            fw_data = ctrl["frameworks"].get(fw_name, {"status": "N/A", "citation": ""})
            # Handle both dict and Pydantic model
            if isinstance(fw_data, dict):
                st = fw_data.get("status", "N/A")
                cit = fw_data.get("citation", "")
            else:
                st = getattr(fw_data, "status", "N/A")
                cit = getattr(fw_data, "citation", "")
            color = status_colors.get(st, "#6b7280")
            icon = "✓" if st == "PASS" else "✗" if st == "FAIL" else "—"
            cells += f"<td style='text-align:center;'><span style='color:{color}; font-weight:bold;'>{icon} {st}</span><br><small style='color:#6b7280;'>{cit}</small></td>"
        rows += f"<tr><td><b>{ctrl['control_id']}</b></td><td>{ctrl['control_name']}</td>{cells}</tr>"

    return f"""
    <div style='margin:30px 0;'>
      <h2 style='color:#93c5fd; text-align:center;'>Compliance Matrix</h2>
      <div style='display:flex; gap:16px; justify-content:center; flex-wrap:wrap; margin:20px 0;'>
        {fw_cards}
      </div>
      <table style='width:100%; border-collapse:collapse; margin-top:20px;'>
        <thead>
          <tr>
            <th style='text-align:left; color:#60a5fa; border-bottom:1px solid #374151; padding:8px;'>ID</th>
            <th style='text-align:left; color:#60a5fa; border-bottom:1px solid #374151; padding:8px;'>Control</th>
            <th style='text-align:center; color:#60a5fa; border-bottom:1px solid #374151; padding:8px;'>PCI-DSS 4.0</th>
            <th style='text-align:center; color:#60a5fa; border-bottom:1px solid #374151; padding:8px;'>NIST 800-52r2</th>
            <th style='text-align:center; color:#60a5fa; border-bottom:1px solid #374151; padding:8px;'>HIPAA</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def _generate_compliance_pdf_section(sessions: List[Session], story: list, base_styles,
                                     section_h1, section_h2, cell_text, cell_bold,
                                     cell_center, cell_center_bold, cell_hdr_white,
                                     cell_hdr_white_left, **kwargs):
    """Append the Regulatory Compliance Matrix page to the PDF story."""
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, PageBreak

    report = evaluate_compliance_all(sessions)
    data = compliance_report_to_dict(report)

    story.append(PageBreak())
    story.append(Paragraph("Regulatory Compliance Matrix", section_h1))
    story.append(Paragraph(
        "Automated compliance evaluation across industry cybersecurity and data protection standards.",
        base_styles['Normal']
    ))
    story.append(Spacer(1, 0.3 * cm))

    # Framework Summaries Table
    fw_header = [
        Paragraph("<b>Cybersecurity Framework</b>", cell_hdr_white_left),
        Paragraph("<b>Overall Verdict</b>", cell_hdr_white),
        Paragraph("<b>Passed</b>", cell_hdr_white),
        Paragraph("<b>Failed</b>", cell_hdr_white),
        Paragraph("<b>N/A Controls</b>", cell_hdr_white),
    ]
    fw_rows = [fw_header]
    for fw in data["frameworks"]:
        v = fw["verdict"]
        v_color = "#16a34a" if v == "COMPLIANT" else "#dc2626" if v == "NON-COMPLIANT" else "#64748b"
        fw_rows.append([
            Paragraph(f"<b>{html.escape(str(fw['framework']))}</b>", cell_text),
            Paragraph(f"<b><font color='{v_color}'>{html.escape(str(v))}</font></b>", cell_center),
            Paragraph(f"<font color='#16a34a'><b>{fw['passed']}</b> passed</font>", cell_center),
            Paragraph(f"<font color='#dc2626'><b>{fw['failed']}</b> failed</font>", cell_center),
            Paragraph(f"<font color='#64748b'>{fw['na']} N/A</font>", cell_center),
        ])

    t_fw = Table(fw_rows, colWidths=[4.8 * cm, 3.6 * cm, 3.2 * cm, 3.2 * cm, 3.2 * cm])
    t_fw.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_fw)
    story.append(Spacer(1, 0.4 * cm))

    # Controls Table
    story.append(Paragraph("<b>Detailed Control-by-Control Audit Summary</b>", section_h2))
    ctrl_header = [
        Paragraph("<b>ID</b>", cell_hdr_white),
        Paragraph("<b>Security Control Requirement</b>", cell_hdr_white_left),
        Paragraph("<b>PCI-DSS 4.0</b>", cell_hdr_white),
        Paragraph("<b>NIST 800-52r2</b>", cell_hdr_white),
        Paragraph("<b>HIPAA</b>", cell_hdr_white),
    ]
    ctrl_rows = [ctrl_header]
    for ctrl in data["controls_summary"]:
        row = [
            Paragraph(f"<b>{html.escape(str(ctrl['control_id']))}</b>", cell_center),
            Paragraph(html.escape(str(ctrl["control_name"])), cell_text),
        ]
        for fw_name in ("PCI-DSS 4.0", "NIST 800-52r2", "HIPAA"):
            fw_data = ctrl["frameworks"].get(fw_name, {"status": "N/A", "citation": ""})
            if isinstance(fw_data, dict):
                st = fw_data.get("status", "N/A")
                cit = fw_data.get("citation", "")
            else:
                st = getattr(fw_data, "status", "N/A")
                cit = getattr(fw_data, "citation", "")

            color = "#16a34a" if st == "PASS" else "#dc2626" if st == "FAIL" else "#64748b"
            icon = "✓ " if st == "PASS" else "✗ " if st == "FAIL" else "— "
            cit_html = f"<br/><font size=6 color='#64748b'>{html.escape(str(cit))}</font>" if cit else ""
            row.append(Paragraph(f"<b><font color='{color}'>{icon}{st}</font></b>{cit_html}", cell_center))
        ctrl_rows.append(row)

    t_ctrl = Table(ctrl_rows, colWidths=[1.6 * cm, 6.8 * cm, 3.2 * cm, 3.2 * cm, 3.2 * cm])
    t_ctrl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_ctrl)


def generate_csv(sessions: List[Session], output_path: str = None) -> str:
    """Export all sessions to a structured CSV format for spreadsheet auditing."""
    if output_path is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, "report.csv")
    else:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Session ID", "Protocol", "Server IP", "Server Port", 
            "Client IP", "Client Port", "Encrypted", "STARTTLS Status",
            "Plaintext Credentials", "JA3", "JA4", "JA4S", "JA4X",
            "MTA-STS Status", "DANE Status", "Posture Score", "Risk Label", "Findings"
        ])
        
        for s in sessions:
            starttls_status = f"Req:{s.starttls}|Upg:{s.starttls_upgraded}|Str:{s.starttls_stripped}"
            ja3 = (s.tls.ja3 if s.tls else "") or ""
            ja4 = (s.tls.ja4 if s.tls else "") or ""
            ja4s = (s.tls.ja4s if s.tls else "") or ""
            ja4x = (s.certificate.ja4x if s.certificate else "") or ""
            mta_sts = s.dns_security.mta_sts_mode if s.dns_security else "not_evaluated"
            dane = s.dns_security.dane_match_status if s.dns_security else "not_evaluated"
            
            # Format findings into a single readable string
            findings_list = []
            for f_item in s.findings:
                sev_name = SEVERITY_NAMES.get(f_item.severity, str(f_item.severity)).upper()
                cwe_tag = f" [CWE-{f_item.cwe}]" if f_item.cwe else ""
                finding_str = f"[{f_item.id}] {f_item.title} ({sev_name}){cwe_tag} - {f_item.recommendation}"
                findings_list.append(finding_str)
            findings_str = "\n".join(findings_list)
            
            writer.writerow([
                s.id,
                s.protocol,
                s.server_ip,
                s.server_port,
                s.client_ip,
                s.client_port,
                s.encrypted,
                starttls_status,
                s.credentials_plaintext,
                ja3,
                ja4,
                ja4s,
                ja4x,
                mta_sts,
                dane,
                s.posture_score,
                s.risk_label,
                findings_str
            ])
            
    return output_path

