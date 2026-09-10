"""Automated Server Hardening & Remediation Playbook Generator.

Consolidates forensic findings across mail sessions and produces actionable,
production-grade remediation playbooks for email system administrators:
- Prioritized task checklist with estimated completion time (e.g. 15m, 30m) and risk impact.
- Exact daemon-specific configuration snippets:
  * Postfix (SMTP server & client: /etc/postfix/main.cf)
  * Dovecot (IMAP/POP3 server: /etc/dovecot/conf.d/10-ssl.conf)
  * Exim4 (SMTP server: /etc/exim4/exim4.conf)
  * Sendmail (/etc/mail/sendmail.mc)
- Syntax validation & verification commands (postfix check, dovecot -n, etc.)
- Safe pre-flight backup and emergency rollback commands.
- Exports to structured JSON and multi-page professional PDF report.
"""

from __future__ import annotations

import datetime as dt
import os
from typing import Any, Dict, List, Optional

from core.models import Session, Finding, Severity, SEVERITY_NAMES
from reports.hardening import generate_hardening_package, HardeningPackage

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "generated")


def generate_playbook_data(
    sessions: List[Session],
    target_name: str = "Mail Infrastructure",
    job_id: str = "assessment",
) -> Dict[str, Any]:
    """Compile structured remediation playbook from sessions."""
    total_sessions = len(sessions)
    all_findings: Dict[str, Dict[str, Any]] = {}
    total_time_mins = 0

    for s in sessions:
        for f in s.findings:
            if f.id not in all_findings:
                # Estimate fix time based on finding category
                time_mins = 15
                priority = "P2 - High"
                impact = "High Risk"
                if "creds" in f.id or "strip" in f.id:
                    time_mins = 10
                    priority = "P1 - Critical"
                    impact = "Critical Risk"
                elif "tls.10" in f.id or "tls.11" in f.id or "tls.ssl3" in f.id:
                    time_mins = 15
                    priority = "P1 - Critical"
                    impact = "High Risk"
                elif "cipher" in f.id:
                    time_mins = 15
                    priority = "P2 - High"
                    impact = "Medium Risk"
                elif "dane" in f.id or "mta_sts" in f.id:
                    time_mins = 30
                    priority = "P2 - High"
                    impact = "Medium Risk"
                elif "pqc" in f.id:
                    time_mins = 45
                    priority = "P3 - Strategic"
                    impact = "Low (Future Proofing)"

                total_time_mins += time_mins

                all_findings[f.id] = {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": SEVERITY_NAMES.get(f.severity, "info"),
                    "severity_level": int(f.severity),
                    "recommendation": f.recommendation,
                    "cwe": f.cwe,
                    "time_mins": time_mins,
                    "priority": priority,
                    "impact": impact,
                    "occurrences": 1,
                }
            else:
                all_findings[f.id]["occurrences"] += 1

    # Sort tasks by severity desc, occurrences desc
    tasks = sorted(
        all_findings.values(),
        key=lambda x: (x["severity_level"], x["occurrences"]),
        reverse=True
    )

    # Generate representative server hardening configs
    sample_session = sessions[0] if sessions else Session(id="demo_session")
    hardening_pkg = generate_hardening_package(sample_session)

    daemon_guides = {
        "postfix": {
            "daemon_name": "Postfix (SMTP)",
            "target_file": "/etc/postfix/main.cf",
            "backup_cmd": "cp /etc/postfix/main.cf /etc/postfix/main.cf.bak.$(date +%F_%T)",
            "syntax_check_cmd": "postfix check",
            "reload_cmd": "systemctl reload postfix",
            "rollback_cmd": "cp /etc/postfix/main.cf.bak.* /etc/postfix/main.cf && systemctl reload postfix",
            "config_text": hardening_pkg.snippets.get("postfix").config_text if "postfix" in hardening_pkg.snippets else "",
            "explanation": "Enforces TLS 1.2+ minimum, restricts ciphers to AEAD suites, mandates encryption before AUTH, and enables DANE validation.",
        },
        "dovecot": {
            "daemon_name": "Dovecot (IMAP/POP3)",
            "target_file": "/etc/dovecot/conf.d/10-ssl.conf",
            "backup_cmd": "cp /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf.bak.$(date +%F_%T)",
            "syntax_check_cmd": "dovecot -n",
            "reload_cmd": "systemctl reload dovecot",
            "rollback_cmd": "cp /etc/dovecot/conf.d/10-ssl.conf.bak.* /etc/dovecot/conf.d/10-ssl.conf && systemctl reload dovecot",
            "config_text": hardening_pkg.snippets.get("dovecot").config_text if "dovecot" in hardening_pkg.snippets else "",
            "explanation": "Requires mandatory SSL ('ssl = required'), blocks plaintext authentication over unencrypted channels, and disables CBC ciphers.",
        },
        "exim": {
            "daemon_name": "Exim4 (SMTP)",
            "target_file": "/etc/exim4/exim4.conf.localmacros",
            "backup_cmd": "cp /etc/exim4/exim4.conf.localmacros /etc/exim4/exim4.conf.localmacros.bak.$(date +%F_%T)",
            "syntax_check_cmd": "exim -bV",
            "reload_cmd": "systemctl restart exim4",
            "rollback_cmd": "cp /etc/exim4/exim4.conf.localmacros.bak.* /etc/exim4/exim4.conf.localmacros && systemctl restart exim4",
            "config_text": hardening_pkg.snippets.get("exim").config_text if "exim" in hardening_pkg.snippets else "",
            "explanation": "Restricts OpenSSL cipherlist to modern GCM suites and mandates STARTTLS before AUTH.",
        },
        "sendmail": {
            "daemon_name": "Sendmail",
            "target_file": "/etc/mail/sendmail.mc",
            "backup_cmd": "cp /etc/mail/sendmail.mc /etc/mail/sendmail.mc.bak.$(date +%F_%T)",
            "syntax_check_cmd": "make -C /etc/mail",
            "reload_cmd": "systemctl restart sendmail",
            "rollback_cmd": "cp /etc/mail/sendmail.mc.bak.* /etc/mail/sendmail.mc && make -C /etc/mail && systemctl restart sendmail",
            "config_text": hardening_pkg.snippets.get("sendmail").config_text if "sendmail" in hardening_pkg.snippets else "",
            "explanation": "Enforces strict ServerSSLOptions (disabling SSLv2/v3/TLSv1) and applies secure cipher lists.",
        },
    }

    hours = total_time_mins // 60
    mins = total_time_mins % 60
    time_str = f"{hours}h {mins}m" if hours > 0 else f"{mins} mins"

    return {
        "job_id": job_id,
        "target_name": target_name,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total_sessions": total_sessions,
        "total_tasks": len(tasks),
        "estimated_total_time": time_str,
        "tasks": tasks,
        "daemon_guides": daemon_guides,
    }


def generate_playbook_pdf(
    sessions: List[Session],
    target_name: str = "Mail Infrastructure",
    job_id: str = "assessment",
    output_path: Optional[str] = None,
) -> str:
    """Generate professional PDF remediation playbook."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, KeepTogether, HRFlowable, Preformatted
        )
        from reportlab.pdfgen import canvas as rl_canvas
    except ImportError:
        raise RuntimeError("ReportLab is required for PDF generation. Install reportlab>=4.0.0.")

    if output_path is None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, f"remediation_playbook_{job_id}.pdf")
    else:
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    playbook = generate_playbook_data(sessions, target_name=target_name, job_id=job_id)

    class PlaybookNumberedCanvas(rl_canvas.Canvas):
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
                self.draw_decorations(num_pages)
                super().showPage()
            super().save()

        def draw_decorations(self, page_count: int):
            self.saveState()
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#475569"))
            if self._pageNumber > 1:
                self.drawString(1.5 * cm, 28.3 * cm, "SecureMailScope — Automated Remediation Playbook")
                self.setStrokeColor(colors.HexColor("#cbd5e1"))
                self.setLineWidth(0.5)
                self.line(1.5 * cm, 28.1 * cm, 19.5 * cm, 28.1 * cm)

            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(1.5 * cm, 1.5 * cm, 19.5 * cm, 1.5 * cm)

            self.setFont("Helvetica", 8)
            self.drawString(1.5 * cm, 1.1 * cm, "STRICTLY CONFIDENTIAL — Technical Remediation Specification")
            self.drawRightString(19.5 * cm, 1.1 * cm, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=2.2 * cm,
        bottomMargin=2.2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "PlaybookTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "PlaybookSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )
    h2_style = ParagraphStyle(
        "PlaybookH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f766e"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "PlaybookBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    code_style = ParagraphStyle(
        "PlaybookCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # Title Banner
    story.append(Paragraph("SecureMailScope — Technical Remediation Playbook", title_style))
    story.append(Paragraph(
        f"<b>Target:</b> {playbook['target_name']} &nbsp;|&nbsp; <b>Job ID:</b> {playbook['job_id']} &nbsp;|&nbsp; "
        f"<b>Date:</b> {playbook['generated_at'][:10]} &nbsp;|&nbsp; <b>Estimated Effort:</b> {playbook['estimated_total_time']}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f766e"), spaceAfter=14))

    # Executive Overview
    story.append(Paragraph("1. Executive Action Plan & Task Prioritization", h2_style))
    story.append(Paragraph(
        f"This remediation playbook addresses {playbook['total_tasks']} distinct cryptographic vulnerability categories discovered during traffic inspection. "
        f"Total estimated engineering time is <b>{playbook['estimated_total_time']}</b>. Remediations are prioritized by threat severity to mitigate plaintext exposure first.",
        body_style
    ))
    story.append(Spacer(1, 8))

    # Tasks Table
    table_data = [
        [
            Paragraph("<b>Priority</b>", body_style),
            Paragraph("<b>Vulnerability / Task</b>", body_style),
            Paragraph("<b>Est. Time</b>", body_style),
            Paragraph("<b>Impact Level</b>", body_style),
        ]
    ]

    sev_color_map = {
        "critical": colors.HexColor("#fee2e2"),
        "high": colors.HexColor("#ffedd5"),
        "medium": colors.HexColor("#fef9c3"),
        "low": colors.HexColor("#e0f2fe"),
    }

    for t in playbook["tasks"][:10]:
        table_data.append([
            Paragraph(f"<b>{t['priority']}</b>", body_style),
            Paragraph(f"<b>{t['title']}</b><br/><font size=7.5 color='#475569'>{t['recommendation']}</font>", body_style),
            Paragraph(f"{t['time_mins']} mins", body_style),
            Paragraph(t["impact"], body_style),
        ])

    task_table = Table(table_data, colWidths=[3.2 * cm, 8.5 * cm, 2.2 * cm, 3.1 * cm])
    task_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 1.0, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(task_table)
    story.append(Spacer(1, 14))

    # Section 2: Daemon Step-by-Step Guides
    story.append(Paragraph("2. Daemon-Specific Hardening Configurations", h2_style))
    story.append(Paragraph(
        "Apply the hardened configuration blocks below to replace insecure defaults. Each section includes pre-flight backup, configuration file destination, syntax validation, and safe reload commands.",
        body_style
    ))
    story.append(Spacer(1, 10))

    for daemon_key in ["postfix", "dovecot", "exim"]:
        g = playbook["daemon_guides"][daemon_key]
        daemon_story = []
        daemon_story.append(Paragraph(f"<b>{g['daemon_name']} — Target: {g['target_file']}</b>", h2_style))
        daemon_story.append(Paragraph(f"<i>{g['explanation']}</i>", body_style))
        daemon_story.append(Spacer(1, 4))

        # Commands table
        cmds = [
            [Paragraph("<b>Step</b>", body_style), Paragraph("<b>Command</b>", body_style)],
            [Paragraph("1. Pre-flight Backup", body_style), Paragraph(f"<code>{g['backup_cmd']}</code>", code_style)],
            [Paragraph("2. Apply Config", body_style), Paragraph(f"Edit <code>{g['target_file']}</code> with the snippet below", body_style)],
            [Paragraph("3. Syntax Test", body_style), Paragraph(f"<code>{g['syntax_check_cmd']}</code>", code_style)],
            [Paragraph("4. Reload Service", body_style), Paragraph(f"<code>{g['reload_cmd']}</code>", code_style)],
            [Paragraph("Emergency Rollback", body_style), Paragraph(f"<code>{g['rollback_cmd']}</code>", code_style)],
        ]
        cmd_table = Table(cmds, colWidths=[3.5 * cm, 13.5 * cm])
        cmd_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        daemon_story.append(cmd_table)
        daemon_story.append(Spacer(1, 6))

        # Config snippet box (truncated preview if long)
        snippet_preview = g["config_text"][:800] + ("\n... [truncated for print, see dashboard for full text]" if len(g["config_text"]) > 800 else "")
        daemon_story.append(Preformatted(snippet_preview, code_style))
        daemon_story.append(Spacer(1, 10))

        story.append(KeepTogether(daemon_story))

    # Section 3: Post-Quantum & Verification
    story.append(Paragraph("3. Verification & Compliance Sign-Off", h2_style))
    story.append(Paragraph(
        "After applying configurations and reloading mail services, re-run SecureMailScope against the server using the Live Sniffer or PCAP upload. "
        "Verify that Posture Score increases to <b>85+ (Grade A)</b>, plaintext credentials drop to zero, and the Compliance Matrix passes all PCI-DSS and NIST controls.",
        body_style
    ))

    doc.build(story, canvasmaker=PlaybookNumberedCanvas)
    return output_path
