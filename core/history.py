"""SQLite-backed Historical Trend & Posture Persistence for SecureMailScope.

Persists scan summaries and session artifacts to SQLite (output/history.db):
- Stores timeline of PCAP analyses, live domain probes, and packet sniffing jobs.
- Tracks cryptographic posture progression and security improvements over time.
- Enables reloading past assessments without re-uploading original capture files.
- Provides time-series aggregations for interactive Recharts trend visualizations.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_DB_DIR = os.path.join(os.path.dirname(__file__), "..", "output")

def _resolve_db_dir() -> str:
    d = _DEFAULT_DB_DIR
    try:
        os.makedirs(d, exist_ok=True)
        test_file = os.path.join(d, ".test_write")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return d
    except OSError:
        fallback = os.path.join("/tmp", "securemailscope_output")
        os.makedirs(fallback, exist_ok=True)
        return fallback

DB_DIR = _resolve_db_dir()
DB_PATH = os.path.join(DB_DIR, "history.db")


def _get_connection() -> sqlite3.Connection:
    """Ensure database directory exists and return SQLite connection."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database schema if not already present."""
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                target_name TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                session_count INTEGER NOT NULL,
                avg_posture_score REAL NOT NULL,
                risk_label TEXT NOT NULL,
                encrypted_sessions INTEGER NOT NULL,
                plaintext_sessions INTEGER NOT NULL,
                critical_findings INTEGER NOT NULL,
                high_findings INTEGER NOT NULL,
                medium_findings INTEGER NOT NULL,
                low_findings INTEGER NOT NULL,
                hndl_risk TEXT NOT NULL,
                compliance_verdict TEXT NOT NULL,
                data_json TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)")
        conn.commit()


def save_scan(
    job_id: str,
    target_name: str,
    scan_type: str,
    sessions: List[Any],
    overall: Optional[Any] = None,
    compliance: Optional[Any] = None,
    email_auth: Optional[Any] = None,
) -> None:
    """Persist an analysis scan to the history database."""
    init_db()

    total = len(sessions)
    encrypted = sum(1 for s in sessions if getattr(s, "encrypted", False))
    plaintext = sum(1 for s in sessions if getattr(s, "plaintext", False))
    scores = [getattr(s, "posture_score", 0.0) for s in sessions if getattr(s, "posture_score", None) is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    if avg_score >= 85:
        risk_label = "low"
    elif avg_score >= 70:
        risk_label = "medium"
    elif avg_score >= 40:
        risk_label = "high"
    else:
        risk_label = "critical"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in sessions:
        sc = s.severity_count() if hasattr(s, "severity_count") else {}
        for k in counts.keys():
            counts[k] += sc.get(k, 0)

    # Post-quantum risk determination
    pqc_crit = any(getattr(s, "pqc", None) and getattr(s.pqc, "hndl_risk", "") in ("HIGH", "CRITICAL") for s in sessions)
    hndl_risk = "HIGH" if pqc_crit else "LOW"

    compliance_verdict = "COMPLIANT" if (risk_label in ("low", "medium") and counts["critical"] == 0) else "NON-COMPLIANT"

    # Serialize sessions for rehydration
    sessions_data = []
    for s in sessions:
        if hasattr(s, "to_dict"):
            sessions_data.append(s.to_dict())
        elif hasattr(s, "__dict__"):
            # Fallback simple serialization
            sessions_data.append({
                "id": getattr(s, "id", ""),
                "protocol": getattr(s, "protocol", "unknown"),
                "server_ip": getattr(s, "server_ip", ""),
                "server_port": getattr(s, "server_port", 0),
                "client_ip": getattr(s, "client_ip", ""),
                "client_port": getattr(s, "client_port", 0),
                "encrypted": getattr(s, "encrypted", False),
                "plaintext": getattr(s, "plaintext", False),
                "starttls": getattr(s, "starttls", False),
                "starttls_stripped": getattr(s, "starttls_stripped", False),
                "posture_score": getattr(s, "posture_score", 0.0),
                "risk_label": getattr(s, "risk_label", "unknown"),
                "finding_count": len(getattr(s, "findings", [])),
                "severity_summary": s.severity_count() if hasattr(s, "severity_count") else {},
            })

    overall_dict = overall.model_dump() if hasattr(overall, "model_dump") else (overall.dict() if hasattr(overall, "dict") else (overall if isinstance(overall, dict) else {}))

    payload = {
        "job_id": job_id,
        "target_name": target_name,
        "scan_type": scan_type,
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "session_count": total,
        "avg_posture_score": avg_score,
        "risk_label": risk_label,
        "counts": counts,
        "overall": overall_dict,
        "sessions": sessions_data,
        "compliance": compliance,
        "email_auth": email_auth,
    }

    with _get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO scans (
                id, timestamp, target_name, scan_type,
                session_count, avg_posture_score, risk_label,
                encrypted_sessions, plaintext_sessions,
                critical_findings, high_findings, medium_findings, low_findings,
                hndl_risk, compliance_verdict, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job_id,
            payload["timestamp"],
            target_name,
            scan_type,
            total,
            avg_score,
            risk_label,
            encrypted,
            plaintext,
            counts["critical"],
            counts["high"],
            counts["medium"],
            counts["low"],
            hndl_risk,
            compliance_verdict,
            json.dumps(payload),
        ))
        conn.commit()


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve list of past scans ordered by timestamp descending."""
    init_db()
    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, target_name, scan_type,
                   session_count, avg_posture_score, risk_label,
                   encrypted_sessions, plaintext_sessions,
                   critical_findings, high_findings, medium_findings, low_findings,
                   hndl_risk, compliance_verdict
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_scan(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full scan details and payload for a given job ID."""
    init_db()
    with _get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        try:
            res["payload"] = json.loads(res["data_json"])
        except Exception:
            res["payload"] = {}
        return res


def delete_scan(job_id: str) -> bool:
    """Delete a scan from history by job ID."""
    init_db()
    with _get_connection() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (job_id,))
        conn.commit()
        return cur.rowcount > 0


def clear_history() -> bool:
    """Clear all historical scans."""
    init_db()
    with _get_connection() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
        return True


def get_trends() -> Dict[str, Any]:
    """Calculate time-series trends and posture progression across past scans."""
    init_db()
    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, target_name, scan_type,
                   session_count, avg_posture_score, risk_label,
                   encrypted_sessions, plaintext_sessions,
                   critical_findings, high_findings, medium_findings
            FROM scans
            ORDER BY timestamp ASC
        """).fetchall()

    points = []
    for r in rows:
        d = dict(r)
        total = d["session_count"] or 1
        enc_ratio = round((d["encrypted_sessions"] / total) * 100, 1)
        # Formatted short date e.g. "Sep 10 14:25"
        try:
            ts_dt = dt.datetime.fromisoformat(d["timestamp"])
            date_label = ts_dt.strftime("%b %d, %H:%M")
        except Exception:
            date_label = d["timestamp"][:16]

        points.append({
            "job_id": d["id"],
            "timestamp": d["timestamp"],
            "date_label": date_label,
            "target": d["target_name"],
            "scan_type": d["scan_type"],
            "posture_score": d["avg_posture_score"],
            "encrypted_ratio": enc_ratio,
            "critical_findings": d["critical_findings"],
            "high_findings": d["high_findings"],
            "medium_findings": d["medium_findings"],
        })

    # Summary metrics
    total_scans = len(points)
    avg_score = round(sum(p["posture_score"] for p in points) / total_scans, 1) if total_scans else 0.0
    total_critical = sum(p["critical_findings"] for p in points)

    return {
        "total_scans": total_scans,
        "overall_avg_score": avg_score,
        "total_critical_detected": total_critical,
        "points": points,
    }
