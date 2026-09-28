"""Multi-Channel SIEM, Slack, and Discord Webhook Alerting Engine.

Dispatches structured, cryptographically-rich security alerts to:
- Slack (Block Kit interactive notifications)
- Discord (Rich Embeds with severity colorization)
- SIEM / Syslog / Splunk HEC (Structured JSON for SIEM ingestion)

Triggers immediately when critical security events (STARTTLS stripping, plaintext
credentials, revoked certificates, JA4 masquerading) are discovered.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from .models import Session, Finding, Severity, SEVERITY_NAMES

logger = logging.getLogger(__name__)


# Color codes for Discord Embeds
DISCORD_SEVERITY_COLORS = {
    Severity.CRITICAL: 0xD32F2F,  # Red
    Severity.HIGH: 0xF57C00,      # Orange
    Severity.MEDIUM: 0xFBC02D,    # Amber
    Severity.LOW: 0x388E3C,       # Green
    Severity.INFO: 0x1976D2,      # Blue
}


class WebhookDispatcher:
    """Dispatches security alert notifications to Slack, Discord, or SIEM endpoints."""

    def __init__(
        self,
        default_url: Optional[str] = None,
        provider: str = "slack",  # slack | discord | siem
        min_severity: Severity = Severity.HIGH,
        enabled: bool = True,
        dry_run: bool = False,
    ):
        self.default_url = default_url
        self.provider = provider.lower()
        self.min_severity = min_severity
        self.enabled = enabled
        self.dry_run = dry_run
        self.sent_alerts: List[Dict[str, Any]] = []

    def format_slack(self, session: Session, findings: List[Finding]) -> Dict[str, Any]:
        """Format an alert payload for Slack using Block Kit."""
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        header_text = f"🚨 SecureMailScope Cryptographic Alert: {session.id}"
        if crit_count > 0:
            header_text = f"🚨 CRITICAL SECURITY ALERT: {session.id}"

        finding_lines = []
        for f in findings[:5]:  # Top 5 findings
            sev_icon = "🔴" if f.severity == Severity.CRITICAL else "🟠"
            cwe_str = f" ({f.cwe})" if f.cwe else ""
            finding_lines.append(f"{sev_icon} *[{f.id}]* {f.title}{cwe_str}\n>{f.recommendation}")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Protocol:*\n`{session.protocol.upper() if session.protocol else 'UNKNOWN'}`"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n*{session.risk_label.upper()}* ({session.posture_score or 0}/100)"},
                    {"type": "mrkdwn", "text": f"*Endpoints:*\n`{session.client_ip}:{session.client_port}` ➔ `{session.server_ip}:{session.server_port}`"},
                    {"type": "mrkdwn", "text": f"*TLS Version:*\n`{session.tls.version if session.tls else 'None / Plaintext'}`"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Priority Findings:*\n" + ("\n".join(finding_lines) if finding_lines else "No findings meeting threshold."),
                },
            },
        ]

        # Add JA4 fingerprint section if available
        if session.tls and session.tls.ja4:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"🔐 *Client JA4 Fingerprint:* `{session.tls.ja4}`"},
                ],
            })

        return {"blocks": blocks}

    def format_discord(self, session: Session, findings: List[Finding]) -> Dict[str, Any]:
        """Format an alert payload for Discord using Rich Embeds."""
        highest_sev = max((f.severity for f in findings), default=Severity.INFO)
        color = DISCORD_SEVERITY_COLORS.get(highest_sev, 0x1976D2)

        fields = [
            {"name": "Session ID", "value": f"`{session.id}`", "inline": True},
            {"name": "Protocol", "value": session.protocol.upper() if session.protocol else "UNKNOWN", "inline": True},
            {"name": "Posture Score", "value": f"{session.posture_score or 0}/100 ({session.risk_label.upper()})", "inline": True},
            {"name": "Client", "value": f"`{session.client_ip}:{session.client_port}`", "inline": True},
            {"name": "Server", "value": f"`{session.server_ip}:{session.server_port}`", "inline": True},
            {"name": "TLS Version", "value": session.tls.version if (session.tls and session.tls.version) else "Plaintext", "inline": True},
        ]

        if session.tls and session.tls.ja4:
            fields.append({"name": "Client JA4", "value": f"`{session.tls.ja4}`", "inline": False})

        finding_desc = []
        for f in findings[:5]:
            finding_desc.append(f"• **[{SEVERITY_NAMES[f.severity].upper()}] {f.title}**\n  {f.description}")

        embed = {
            "title": f"🚨 SecureMailScope Alert - {session.id}",
            "description": "\n\n".join(finding_desc) if finding_desc else "No severe findings.",
            "color": color,
            "fields": fields,
            "footer": {"text": "SecureMailScope Cryptographic Security Monitoring"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        return {"embeds": [embed]}

    def format_siem(self, session: Session, findings: List[Finding]) -> Dict[str, Any]:
        """Format an alert payload for SIEM / Splunk / Elastic ingestion."""
        return {
            "event_type": "securemailscope_crypto_alert",
            "timestamp": time.time(),
            "session_id": session.id,
            "protocol": session.protocol,
            "client_ip": session.client_ip,
            "client_port": session.client_port,
            "server_ip": session.server_ip,
            "server_port": session.server_port,
            "tls_version": session.tls.version if session.tls else None,
            "cipher_suite": session.tls.cipher_suite if session.tls else None,
            "ja4_client": session.tls.ja4 if session.tls else None,
            "posture_score": session.posture_score,
            "risk_label": session.risk_label,
            "findings_count": len(findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": SEVERITY_NAMES[f.severity],
                    "cwe": f.cwe,
                    "cve": f.cve,
                    "recommendation": f.recommendation,
                }
                for f in findings
            ],
        }

    def dispatch(
        self,
        session: Session,
        url: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate session findings and dispatch notification if threshold is met."""
        target_url = url or self.default_url
        target_provider = (provider or self.provider).lower()

        # Filter findings matching or exceeding min_severity
        qualifying_findings = [f for f in session.findings if f.severity >= self.min_severity]
        if not qualifying_findings:
            return {
                "dispatched": False,
                "reason": f"No findings meet minimum severity threshold ({SEVERITY_NAMES[self.min_severity]})",
                "findings_count": 0,
            }

        # Build payload according to provider
        if target_provider == "discord":
            payload = self.format_discord(session, qualifying_findings)
        elif target_provider == "siem":
            payload = self.format_siem(session, qualifying_findings)
        else:
            payload = self.format_slack(session, qualifying_findings)

        record = {
            "session_id": session.id,
            "provider": target_provider,
            "url": target_url,
            "payload": payload,
            "timestamp": time.time(),
            "findings_count": len(qualifying_findings),
        }

        if self.dry_run or not target_url:
            record["dispatched"] = True
            record["mode"] = "dry_run"
            self.sent_alerts.append(record)
            return record

        # Perform HTTP POST
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                target_url,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "SecureMailScope-Alerting/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                status_code = resp.status
                record["dispatched"] = (200 <= status_code < 300)
                record["status_code"] = status_code
        except Exception as e:
            logger.warning(f"Webhook dispatch failed to {target_url}: {e}")
            record["dispatched"] = False
            record["error"] = str(e)

        self.sent_alerts.append(record)
        return record
