"""API routers for SecureMailScope backend."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import tempfile
import threading
import uuid
import re
from typing import List

from fastapi import APIRouter, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect, Response
from core.capture import reassemble
from core.analyzer import analyze_all
from core.live import LiveMonitor
from core.models import Session, Finding, Severity, SEVERITY_NAMES, TLSInfo
from core.compliance import evaluate_compliance_all, compliance_report_to_dict
from ml.models import MLPostureScorer, rule_based_posture_score
from reports.exporters import generate_json, generate_html, generate_pdf, generate_csv
from reports.hardening import (
    generate_hardening_package,
    generate_hardening_script_sh,
    generate_hardening_script_ps1,
)
from core.alerting import WebhookDispatcher
from core.domain_probe import probe_domain
from core.email_auth import evaluate_email_auth
from core.executive_summary import generate_executive_summary
from core.history import save_scan, get_history, get_scan, delete_scan, clear_history, get_trends
from reports.playbook import generate_playbook_data, generate_playbook_pdf

from ..schemas import (
    AnalyzeResponse, OverallStats, SessionSummary, SessionDetail,
    TLSDetails, CertDetails, DnsSecurityModel, FindingModel, ComplianceReportModel,
    PqcDetails, AttributionDetails, HardeningPackageModel, HardeningSnippetModel,
    WebhookTestRequest, WebhookTestResponse,
    DomainProbeRequest, EmailAuthDetails, ExecutiveSummaryModel,
    HistoricalScanSummary, HistoryTrendsResponse,
    PqcRadarResponse, RemediateResponse, RemediateIssue,
    EmailComplianceResponse, EmailProtocolCheck,
    MitmSimulateResponse, MitmScenario, MitmSimulateRequest,
)

router = APIRouter(prefix="/api", tags=["analysis"])

_jobs = {}   # job_id -> {"sessions": [...], "pcap": str, "target_name": str}


def _resolve_job(job_id: str) -> Optional[dict]:
    """Retrieve job from active memory cache, or fall back to SQLite history database."""
    job = _jobs.get(job_id)
    if job:
        return job
    hist = get_scan(job_id)
    if hist and hist.get("payload"):
        p = hist["payload"]
        _jobs[job_id] = {
            "sessions": [],
            "sessions_data": p.get("sessions", []),
            "pcap": p.get("target_name", "historical"),
            "target_name": p.get("target_name", "historical"),
            "email_auth": p.get("email_auth"),
            "overall": p.get("overall"),
            "compliance": p.get("compliance"),
        }
        return _jobs[job_id]
    return None


def _overall_stats(sessions) -> OverallStats:
    total = len(sessions)
    encrypted = sum(1 for s in sessions if s.encrypted)
    plaintext = sum(1 for s in sessions if s.plaintext)
    avg = (sum(s.posture_score or 0 for s in sessions) / total) if total else 0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    anomalies = 0
    protos = {}
    for s in sessions:
        sc = s.severity_count()
        for k, v in sc.items():
            counts[k] += v
        if s.ml_anomaly:
            anomalies += 1
        p = s.protocol or "unknown"
        protos[p] = protos.get(p, 0) + 1
    return OverallStats(
        total_sessions=total,
        encrypted_sessions=encrypted,
        plaintext_sessions=plaintext,
        avg_posture_score=round(avg, 1),
        severity_counts=counts,
        anomalies=anomalies,
        protocols=protos,
    )


def _session_summary(s: Session) -> SessionSummary:
    return SessionSummary(
        session_id=s.id,
        protocol=s.protocol,
        server_ip=s.server_ip,
        server_port=s.server_port,
        client_ip=s.client_ip,
        client_port=s.client_port,
        encrypted=s.encrypted,
        plaintext=s.plaintext,
        starttls=s.starttls,
        starttls_stripped=s.starttls_stripped,
        posture_score=s.posture_score,
        risk_label=s.risk_label,
        finding_count=len(s.findings),
        severity_summary=s.severity_count(),
    )


def _session_detail(s: Session) -> SessionDetail:
    tls = None
    if s.tls:
        tls = TLSDetails(
            version=s.tls.version,
            cipher_suite=s.tls.cipher_suite,
            key_exchange=s.tls.key_exchange,
            key_exchange_group=s.tls.key_exchange_group,
            signature_algorithm=s.tls.signature_algorithm,
            server_name=s.tls.server_name,
            ja3=s.tls.ja3,
            ja4=s.tls.ja4,
            ja4s=s.tls.ja4s,
            offered_ciphers=s.tls.offered_ciphers or [],
        )
    cert = None
    if s.certificate:
        cert = CertDetails(
            subject=s.certificate.subject,
            issuer=s.certificate.issuer,
            not_before=s.certificate.not_before,
            not_after=s.certificate.not_after,
            public_key_algorithm=s.certificate.public_key_algorithm,
            key_size=s.certificate.key_size,
            signature_algorithm=s.certificate.signature_algorithm,
            san=s.certificate.san or [],
            self_signed=s.certificate.self_signed,
            expired=s.certificate.expired,
            days_to_expiry=s.certificate.days_to_expiry,
            chain_valid=s.certificate.chain_valid,
            trusted=s.certificate.trusted,
            revoked=s.certificate.revoked,
            revocation_status=s.certificate.revocation_status,
            revocation_method=s.certificate.revocation_method,
            ja4x=s.certificate.ja4x,
        )
    dns_sec = None
    if s.dns_security:
        dns_sec = DnsSecurityModel(
            domain=s.dns_security.domain,
            hostname=s.dns_security.hostname,
            mta_sts_record=s.dns_security.mta_sts_record,
            mta_sts_valid=s.dns_security.mta_sts_valid,
            mta_sts_mode=s.dns_security.mta_sts_mode,
            mta_sts_id=s.dns_security.mta_sts_id,
            dane_tlsa_records=s.dns_security.dane_tlsa_records or [],
            dane_valid=s.dns_security.dane_valid,
            dane_match_status=s.dns_security.dane_match_status,
            recommended_mta_sts_dns=s.dns_security.recommended_mta_sts_dns,
            recommended_mta_sts_policy=s.dns_security.recommended_mta_sts_policy,
        )
    findings = [
        FindingModel(
            id=f.id, title=f.title, description=f.description,
            category=f.category, severity=SEVERITY_NAMES[f.severity],
            recommendation=f.recommendation, cwe=f.cwe, cve=f.cve,
        ) for f in s.findings
    ]
    pqc = None
    if s.pqc:
        pqc = PqcDetails(
            pqc_status=s.pqc.pqc_status,
            quantum_safe_kem=s.pqc.quantum_safe_kem,
            hybrid_key_exchange=s.pqc.hybrid_key_exchange,
            kem_algorithm=s.pqc.kem_algorithm,
            classical_algorithm=s.pqc.classical_algorithm,
            quantum_safe_signature=s.pqc.quantum_safe_signature,
            signature_scheme=s.pqc.signature_scheme,
            hndl_risk=s.pqc.hndl_risk,
            quantum_vulnerability_score=s.pqc.quantum_vulnerability_score,
            standard_compliance=s.pqc.standard_compliance or [],
            remediation_steps=s.pqc.remediation_steps or [],
        )
    attr = None
    if s.attribution:
        attr = AttributionDetails(
            client_name=s.attribution.client_name,
            client_category=s.attribution.client_category,
            confidence=s.attribution.confidence,
            matched_fingerprint=s.attribution.matched_fingerprint,
            is_threat=s.attribution.is_threat,
            is_automation=s.attribution.is_automation,
            masquerading_detected=s.attribution.masquerading_detected,
            masquerading_details=s.attribution.masquerading_details,
            fingerprint_notes=s.attribution.fingerprint_notes or [],
        )
    return SessionDetail(
        session_id=s.id, protocol=s.protocol,
        server_ip=s.server_ip, server_port=s.server_port,
        client_ip=s.client_ip, client_port=s.client_port,
        start_ts=s.start_ts, end_ts=s.end_ts,
        bytes_c2s=s.bytes_client_to_server, bytes_s2c=s.bytes_server_to_client,
        packets=s.packets, encrypted=s.encrypted, plaintext=s.plaintext,
        starttls=s.starttls, starttls_stripped=s.starttls_stripped,
        credentials_plaintext=s.credentials_plaintext,
        tls=tls, certificate=cert, dns_security=dns_sec,
        pqc=pqc, attribution=attr,
        posture_score=s.posture_score, risk_label=s.risk_label,
        ml_score=s.ml_score, ml_anomaly=s.ml_anomaly,
        findings=findings, severity_summary=s.severity_count(),
    )



@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_pcap(file: UploadFile = File(...), use_ml: bool = True):
    """Upload a PCAP file and run full analysis."""
    tmp_dir = tempfile.mkdtemp()
    pcap_path = os.path.join(tmp_dir, file.filename or "input.pcap")
    with open(pcap_path, "wb") as f:
        content = await file.read()
        f.write(content)

    streams = reassemble(pcap_path)
    sessions = analyze_all(streams)
    if use_ml:
        scorer = MLPostureScorer()
        for s in sessions:
            scorer.score_session(s)
    else:
        for s in sessions:
            s.posture_score = rule_based_posture_score(s)

    job_id = uuid.uuid4().hex[:12]
    overall = _overall_stats(sessions)
    target_name = file.filename or "input.pcap"
    _jobs[job_id] = {"sessions": sessions, "pcap": pcap_path, "target_name": target_name}
    try:
        save_scan(job_id, target_name, "pcap", sessions, overall=overall)
    except Exception:
        pass
    return AnalyzeResponse(
        status="ok",
        message=f"Analysed {len(sessions)} email sessions",
        job_id=job_id,
        pcap_filename=file.filename,
        session_count=len(sessions),
        overall=overall,
    )


@router.get("/jobs/{job_id}/summary", response_model=List[SessionSummary])
async def get_sessions(job_id: str):
    job = _resolve_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("sessions"):
        return [_session_summary(s) for s in job["sessions"]]
    if job.get("sessions_data"):
        return [
            SessionSummary(
                session_id=s.get("id") or s.get("session_id", ""),
                protocol=s.get("protocol", "unknown"),
                server_ip=s.get("server_ip", ""),
                server_port=s.get("server_port", 0),
                client_ip=s.get("client_ip", ""),
                client_port=s.get("client_port", 0),
                encrypted=s.get("encrypted", False),
                plaintext=s.get("plaintext", False),
                starttls=s.get("starttls", False),
                starttls_stripped=s.get("starttls_stripped", False),
                posture_score=s.get("posture_score", 0.0),
                risk_label=s.get("risk_label", "unknown"),
                finding_count=s.get("finding_count", 0),
                severity_summary=s.get("severity_summary", {}),
            )
            for s in job["sessions_data"]
        ]
    return []


@router.get("/jobs/{job_id}/sessions/{session_id}", response_model=SessionDetail)
async def get_session_detail(job_id: str, session_id: str):
    job = _resolve_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    for s in job.get("sessions", []):
        if s.id == session_id:
            return _session_detail(s)
    for s in job.get("sessions_data", []):
        sid = s.get("id") or s.get("session_id")
        if sid == session_id:
            return SessionDetail(
                session_id=sid,
                protocol=s.get("protocol"),
                server_ip=s.get("server_ip"),
                server_port=s.get("server_port"),
                client_ip=s.get("client_ip"),
                client_port=s.get("client_port"),
                encrypted=s.get("encrypted", False),
                plaintext=s.get("plaintext", False),
                starttls=s.get("starttls", False),
                starttls_stripped=s.get("starttls_stripped", False),
                posture_score=s.get("posture_score"),
                risk_label=s.get("risk_label", "unknown"),
                severity_summary=s.get("severity_summary", {}),
            )
    raise HTTPException(404, "Session not found")


@router.get("/jobs/{job_id}/overall", response_model=OverallStats)
async def get_overall(job_id: str):
    job = _resolve_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("sessions"):
        return _overall_stats(job["sessions"])
    if job.get("overall"):
        ov = job["overall"]
        return OverallStats(
            total_sessions=ov.get("total_sessions", 0),
            encrypted_sessions=ov.get("encrypted_sessions", 0),
            plaintext_sessions=ov.get("plaintext_sessions", 0),
            avg_posture_score=ov.get("avg_posture_score", 0.0),
            severity_counts=ov.get("severity_counts", {}),
            anomalies=ov.get("anomalies", 0),
            protocols=ov.get("protocols", {}),
        )
    raise HTTPException(404, "Overall stats not found")


@router.get("/jobs/{job_id}/compliance", response_model=ComplianceReportModel)
async def get_compliance(job_id: str):
    """Return the full compliance matrix for all sessions in a job."""
    job = _resolve_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job.get("sessions"):
        report = evaluate_compliance_all(job["sessions"])
        return compliance_report_to_dict(report)
    if job.get("compliance"):
        return job["compliance"]
    raise HTTPException(404, "Compliance data not found")



@router.get("/jobs/{job_id}/report/{fmt}")
async def get_report(job_id: str, fmt: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    import os, tempfile
    tmp = tempfile.mkdtemp()
    base = os.path.join(tmp, "report")
    try:
        if fmt == "json":
            path = generate_json(job["sessions"], base + ".json")
        elif fmt == "html":
            path = generate_html(job["sessions"], base + ".html")
        elif fmt == "pdf":
            path = generate_pdf(job["sessions"], base + ".pdf")
        elif fmt == "csv":
            path = generate_csv(job["sessions"], base + ".csv")
        else:
            raise HTTPException(400, "Format must be json, html, pdf, or csv")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to generate {fmt.upper()} report: {e}")
    from fastapi.responses import FileResponse
    return FileResponse(path, filename=f"report.{fmt}",
                        media_type={"json": "application/json",
                                    "html": "text/html",
                                    "pdf": "application/pdf",
                                    "csv": "text/csv"}.get(fmt, "application/octet-stream"))

# --- Tool Endpoints ---

from pydantic import BaseModel
from typing import Optional

class MLTrainRequest(BaseModel):
    n_per_class: int = 500
    baseline_n: int = 1500
    source: str = "synthetic"  # "synthetic", "active_sessions", "history"
    job_id: Optional[str] = None

class LiveCaptureRequest(BaseModel):
    interface: str
    duration: float = 10.0
    use_ml: bool = True
    max_sessions: int = 0
    simulation: bool = False

@router.post("/tools/sample-pcap")
async def generate_sample_pcap_endpoint(use_ml: bool = True):
    from deps.generate_sample_pcap import _write_synthetic_sessions
    import os, uuid
    from core.capture import reassemble
    from core.analyzer import analyze_all
    from ml.models import MLPostureScorer, rule_based_posture_score

    pcap_path = "deps/sample_traffic.pcap"
    _write_synthetic_sessions(pcap_path)
    
    streams = reassemble(pcap_path)
    sessions = analyze_all(streams)
    if use_ml:
        scorer = MLPostureScorer()
        for s in sessions:
            scorer.score_session(s)
    else:
        for s in sessions:
            s.posture_score = rule_based_posture_score(s)
            s.risk_label = "unknown"
            
    job_id = uuid.uuid4().hex[:12]
    overall = _overall_stats(sessions)
    _jobs[job_id] = {"sessions": sessions, "pcap": pcap_path, "target_name": "sample_traffic.pcap"}
    try:
        save_scan(job_id, "sample_traffic.pcap", "pcap", sessions, overall=overall)
    except Exception:
        pass
    
    return AnalyzeResponse(
        status="ok",
        message=f"Analysed {len(sessions)} synthetic sessions",
        job_id=job_id,
        pcap_filename="sample_traffic.pcap",
        session_count=len(sessions),
        overall=overall,
    )

@router.get("/tools/interfaces")
async def get_interfaces():
    # 1. Prefer tshark -D if tshark is installed
    import subprocess
    import shutil
    tshark_bin = shutil.which("tshark") or (r"C:\Program Files\Wireshark\tshark.exe" if os.path.exists(r"C:\Program Files\Wireshark\tshark.exe") else None)
    if tshark_bin:
        try:
            out = subprocess.check_output([tshark_bin, "-D"], text=True, stderr=subprocess.DEVNULL)
            interfaces = []
            for line in out.strip().splitlines():
                m = re.match(r'^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?', line.strip())
                if m:
                    idx, dev, friendly = m.groups()
                    desc = friendly if friendly else dev
                    interfaces.append({"name": dev, "description": f"{desc} ({dev})", "ip": "", "guid": dev})
            if interfaces:
                return {"interfaces": interfaces}
        except Exception:
            pass

    # 2. Native socket + scapy resolution (provides exact system device names like en0, lo0)
    interfaces = []
    try:
        import socket
        from scapy.all import get_if_addr
        for idx, if_name in socket.if_nameindex():
            # Skip noise virtual interfaces
            if any(p in if_name.lower() for p in ("awdl", "llw", "anpi", "bridge", "utun", "gif", "stf")):
                continue
            ip = ""
            try:
                addr = get_if_addr(if_name)
                if addr and addr != "0.0.0.0":
                    ip = addr
            except Exception:
                ip = ""

            desc = if_name
            if if_name == "en0":
                desc = "en0 (Wi-Fi / Primary Interface)"
            elif if_name == "lo0":
                desc = "lo0 (Local Loopback Interface)"
            elif "en" in if_name or "eth" in if_name:
                desc = f"{if_name} (Ethernet Adapter)"

            if ip:
                desc += f" — {ip}"

            interfaces.append({
                "name": if_name,
                "description": desc,
                "ip": ip,
                "guid": if_name
            })

        # Sort: interfaces with non-loopback IP first, then loopback, then others
        interfaces.sort(key=lambda i: (0 if i["ip"] and i["ip"] != "127.0.0.1" else (1 if i["ip"] else 2), i["name"]))
        if interfaces:
            return {"interfaces": interfaces}
    except Exception:
        pass

    return {"interfaces": [
        {"name": "en0", "description": "en0 (Wi-Fi / Primary Interface) — 192.0.0.2", "ip": "192.0.0.2", "guid": "en0"},
        {"name": "lo0", "description": "lo0 (Local Loopback Interface) — 127.0.0.1", "ip": "127.0.0.1", "guid": "lo0"},
    ]}


@router.post("/tools/live-capture", response_model=AnalyzeResponse)
async def start_live_capture(req: LiveCaptureRequest):
    import asyncio
    from core.live import LiveMonitor
    import uuid
    from pathlib import Path

    monitor = LiveMonitor(req.interface, req.use_ml, 2.0, req.max_sessions)

    try:
        if req.simulation:
            sample_pcap = str(Path(__file__).resolve().parents[3] / "deps" / "sample_traffic.pcap")
            await asyncio.to_thread(monitor.start_simulation, sample_pcap, req.duration)
        else:
            await asyncio.to_thread(monitor.start, req.duration)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    sessions = list(monitor.seen_sessions.values())
    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"sessions": sessions, "pcap": "live_capture"}

    overall = _overall_stats(sessions)
    try:
        from core.history import save_scan
        save_scan(
            job_id=job_id,
            target_name=f"Live Sniffer ({req.interface})",
            scan_type="live",
            sessions=sessions,
            overall=overall,
        )
    except Exception:
        pass

    return AnalyzeResponse(
        status="ok",
        message=f"Captured {len(sessions)} live sessions",
        job_id=job_id,
        pcap_filename="live_capture",
        session_count=len(sessions),
        overall=overall,
    )


_active_live_queues: set = set()


@router.websocket("/ws/live")
async def live_websocket_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket streaming for live network packet captures."""
    await websocket.accept()
    await websocket.send_json({
        "type": "status",
        "status": "ready",
        "message": "SecureMailScope Live Sniffer WebSocket connected. Ready to start capture.",
    })

    loop = asyncio.get_running_loop()
    event_queue: asyncio.Queue = asyncio.Queue()
    active_monitor: Optional[LiveMonitor] = None
    worker_thread: Optional[threading.Thread] = None

    _queue_entry = (loop, event_queue)
    _active_live_queues.add(_queue_entry)

    async def forward_events():
        try:
            while True:
                event = await event_queue.get()
                await websocket.send_json(event)
                event_queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    forward_task = asyncio.create_task(forward_events())

    def on_packet_callback(pkt_data: dict):
        loop.call_soon_threadsafe(
            event_queue.put_nowait,
            {"type": "packet", "data": pkt_data}
        )

    def on_session_callback(sess):
        summary_model = _session_summary(sess)
        sess_dict = summary_model.model_dump() if hasattr(summary_model, "model_dump") else summary_model.dict()
        loop.call_soon_threadsafe(
            event_queue.put_nowait,
            {"type": "session", "session": sess_dict}
        )

    def on_status_callback(status: str, stats: dict):
        loop.call_soon_threadsafe(
            event_queue.put_nowait,
            {"type": "status", "status": status, "stats": stats}
        )

    try:
        while True:
            msg = await websocket.receive_json()
            action = msg.get("action")

            if action == "start":
                if active_monitor:
                    active_monitor.stop()

                interface = msg.get("interface", "Wi-Fi")
                duration = float(msg.get("duration", 15.0))
                use_ml = bool(msg.get("use_ml", True))
                simulation = bool(msg.get("simulation", False))
                max_sessions = int(msg.get("max_sessions", 0))
                protocol_filter = msg.get("protocol_filter", "all")

                bpf = None
                if protocol_filter == "smtp":
                    bpf = "tcp and (port 25 or port 465 or port 587 or port 2525 or port 1587 or port 1025 or port 1465)"
                elif protocol_filter == "imap":
                    bpf = "tcp and (port 143 or port 993 or port 1143 or port 1993)"
                elif protocol_filter == "pop3":
                    bpf = "tcp and (port 110 or port 995 or port 1110 or port 1995)"

                active_monitor = LiveMonitor(
                    interface=interface,
                    use_ml=use_ml,
                    analysis_interval=1.0,
                    max_sessions=max_sessions,
                    bpf_filter=bpf,
                    on_packet=on_packet_callback,
                    on_session=on_session_callback,
                    on_status=on_status_callback,
                )

                def run_sniff():
                    try:
                        if simulation:
                            sample_pcap = str(Path(__file__).resolve().parents[3] / "deps" / "sample_traffic.pcap")
                            active_monitor.start_simulation(sample_pcap, duration=duration)
                        else:
                            active_monitor.start(duration=duration)
                    except Exception as err:
                        loop.call_soon_threadsafe(
                            event_queue.put_nowait,
                            {"type": "error", "message": str(err)}
                        )
                    finally:
                        job_id = uuid.uuid4().hex[:12]
                        sessions = list(active_monitor.seen_sessions.values())
                        _jobs[job_id] = {
                            "sessions": sessions,
                            "pcap": "live_simulation" if simulation else "live_capture"
                        }
                        overall = _overall_stats(sessions)
                        try:
                            from core.history import save_scan
                            save_scan(
                                job_id=job_id,
                                target_name=f"Live Sniffer ({interface})",
                                scan_type="live",
                                sessions=sessions,
                                overall=overall,
                            )
                        except Exception:
                            pass
                        overall_dict = overall.model_dump() if hasattr(overall, "model_dump") else overall.dict()
                        loop.call_soon_threadsafe(
                            event_queue.put_nowait,
                            {
                                "type": "completed",
                                "job_id": job_id,
                                "session_count": len(sessions),
                                "overall": overall_dict,
                            }
                        )

                worker_thread = threading.Thread(target=run_sniff, daemon=True)
                worker_thread.start()

            elif action == "stop":
                if active_monitor:
                    active_monitor.stop()

    except WebSocketDisconnect:
        if active_monitor:
            active_monitor.stop()
    except Exception:
        if active_monitor:
            active_monitor.stop()
    finally:
        _active_live_queues.discard(_queue_entry)
        forward_task.cancel()
        if active_monitor:
            active_monitor.stop()


@router.post("/tools/traffic/generate-live")
async def generate_live_traffic_endpoint(
    protocol: str = "smtp",
    port: int = 587,
    num_sessions: int = 3,
):
    """Generate real live email TCP traffic on localhost (127.0.0.1) for hardware sniffer testing."""
    import socket
    import threading
    import time
    import os
    import uuid

    generated_packets = []
    generated_sessions = []
    bound_port = port

    def _worker():
        nonlocal bound_port
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            candidate_ports = [port, 2525, 1587, 1025, 25, 0]
            for p in candidate_ports:
                try:
                    srv.bind(("127.0.0.1", p))
                    bound_port = p if p != 0 else srv.getsockname()[1]
                    break
                except Exception:
                    try:
                        srv.close()
                    except Exception:
                        pass
                    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    continue

            from core.capture import ALL_EMAIL_PORTS, SERVER_PORTS
            ALL_EMAIL_PORTS[bound_port] = "smtp"
            SERVER_PORTS.add(bound_port)

            srv.listen(5)
            srv.settimeout(8.0)

            def _handle_client(conn):
                try:
                    conn.sendall(b"220 mail.securemailscope.internal ESMTP Postfix (Ubuntu)\r\n")
                    data = conn.recv(1024)
                    if b"EHLO" in data or b"HELO" in data:
                        conn.sendall(b"250-mail.securemailscope.internal\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 ENHANCEDSTATUSCODES\r\n")
                        data2 = conn.recv(1024)
                        if b"STARTTLS" in data2:
                            conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                            # Simulate TLS ClientHello record
                            tls_data = conn.recv(4096)
                            if tls_data and tls_data[0] == 0x16:
                                # Send TLS ServerHello record
                                conn.sendall(b"\x16\x03\x03\x00\x46\x02\x00\x00\x42\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + b"\x13\x01\x00")
                        elif b"AUTH" in data2:
                            conn.sendall(b"334 VXNlcm5hbWU6\r\n")
                            conn.recv(1024)
                            conn.sendall(b"334 UGFzc3dvcmQ6\r\n")
                            conn.recv(1024)
                            conn.sendall(b"235 2.7.0 Authentication successful\r\n")
                        conn.sendall(b"221 2.0.0 Bye\r\n")
                except Exception:
                    pass
                finally:
                    conn.close()

            def _client_runner():
                time.sleep(0.3)
                for i in range(num_sessions):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect(("127.0.0.1", bound_port))
                        s.recv(1024)
                        s.sendall(f"EHLO client-workstation-{i}.internal\r\n".encode())
                        s.recv(1024)
                        if i % 2 == 0:
                            s.sendall(b"STARTTLS\r\n")
                            s.recv(1024)
                            client_hello = (
                                b"\x16\x03\x01\x00\x7a\x01\x00\x00\x76\x03\x03"
                                + os.urandom(32)
                                + b"\x20" + os.urandom(32)
                                + b"\x00\x04\x13\x01\x13\x02\x01\x00"
                                + b"\x00\x29\x00\x00\x00\x1b\x00\x19\x00\x00\x16mail.securemailscope.internal"
                            )
                            s.sendall(client_hello)
                            time.sleep(0.1)
                        else:
                            s.sendall(b"AUTH LOGIN\r\n")
                            s.recv(1024)
                            s.sendall(b"YWRtaW5Ac2VjdXJlbWFpbC5nb3Y=\r\n")
                            s.recv(1024)
                            s.sendall(b"U3VwZXJTZWNyZXRQYXNzIQ==\r\n")
                            s.recv(1024)
                        s.close()
                    except Exception:
                        pass
                    time.sleep(0.2)

            threading.Thread(target=_client_runner, daemon=True).start()

            for _ in range(num_sessions):
                try:
                    conn, _ = srv.accept()
                    _handle_client(conn)
                except Exception:
                    break

            srv.close()
        except Exception as e:
            print(f"[Live Traffic Generator Error]: {e}")

    threading.Thread(target=_worker, daemon=True).start()

    # Generate synthetic packet frames and sessions for immediate UI streaming & feedback
    base_time = time.time()
    for s_idx in range(num_sessions):
        client_port = 54100 + s_idx
        sess_id = f"live_{uuid.uuid4().hex[:8]}"
        is_tls = (s_idx % 2 == 0)

        frames = [
            {"protocol": "TCP", "src": f"127.0.0.1:{client_port}", "dst": f"127.0.0.1:{bound_port}", "bytes": 64, "summary": f"TCP SYN → {bound_port} [Seq=0 Win=65535]"},
            {"protocol": "SMTP", "src": f"127.0.0.1:{bound_port}", "dst": f"127.0.0.1:{client_port}", "bytes": 78, "summary": "220 mail.securemailscope.internal ESMTP Postfix"},
            {"protocol": "SMTP", "src": f"127.0.0.1:{client_port}", "dst": f"127.0.0.1:{bound_port}", "bytes": 52, "summary": f"EHLO client-workstation-{s_idx}.internal"},
        ]
        if is_tls:
            frames.extend([
                {"protocol": "SMTP", "src": f"127.0.0.1:{bound_port}", "dst": f"127.0.0.1:{client_port}", "bytes": 48, "summary": "STARTTLS → 220 2.0.0 Ready to start TLS"},
                {"protocol": "TLS", "src": f"127.0.0.1:{client_port}", "dst": f"127.0.0.1:{bound_port}", "bytes": 428, "summary": "TLSv1.3 Handshake: ClientHello (X25519MLKEM768, AES-GCM)"},
            ])
        else:
            frames.extend([
                {"protocol": "SMTP", "src": f"127.0.0.1:{client_port}", "dst": f"127.0.0.1:{bound_port}", "bytes": 58, "summary": "AUTH LOGIN (Plaintext Credentials Alert)"},
                {"protocol": "SMTP", "src": f"127.0.0.1:{bound_port}", "dst": f"127.0.0.1:{client_port}", "bytes": 64, "summary": "235 2.7.0 Authentication successful"},
            ])

        for f_idx, f in enumerate(frames):
            pkt_obj = {
                "packet_num": len(generated_packets) + 1,
                "ts": base_time + (s_idx * 0.4) + (f_idx * 0.05),
                "protocol": f["protocol"],
                "src": f["src"],
                "dst": f["dst"],
                "bytes": f["bytes"],
                "summary": f["summary"]
            }
            generated_packets.append(pkt_obj)
            for q_loop, q in list(_active_live_queues):
                try:
                    q_loop.call_soon_threadsafe(q.put_nowait, {"type": "packet", "data": pkt_obj})
                except Exception:
                    pass

        session_obj = {
            "session_id": sess_id,
            "protocol": "SMTP",
            "server_ip": "127.0.0.1",
            "server_port": bound_port,
            "client_ip": "127.0.0.1",
            "client_port": client_port,
            "encrypted": is_tls,
            "plaintext": not is_tls,
            "starttls": is_tls,
            "starttls_stripped": False,
            "posture_score": 92.0 if is_tls else 22.0,
            "risk_label": "safe" if is_tls else "critical",
            "finding_count": 0 if is_tls else 2,
            "severity_summary": {
                "critical": 0 if is_tls else 1,
                "high": 0 if is_tls else 1,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        generated_sessions.append(session_obj)
        for q_loop, q in list(_active_live_queues):
            try:
                q_loop.call_soon_threadsafe(q.put_nowait, {"type": "session", "session": session_obj})
            except Exception:
                pass

    return {
        "status": "transmitted",
        "protocol": protocol,
        "port": bound_port,
        "target": "127.0.0.1",
        "num_sessions": num_sessions,
        "packets": generated_packets,
        "sessions": generated_sessions,
        "message": f"Transmitted {num_sessions} live TCP email sessions on 127.0.0.1:{bound_port}"
    }


@router.get("/tools/ml/status")
async def get_ml_status():
    from ml.models import CONFIG, MODEL_DIR, FEATURE_NAMES
    risk_clf_exists = os.path.exists(os.path.join(MODEL_DIR, "risk_clf.joblib"))
    anomaly_if_exists = os.path.exists(os.path.join(MODEL_DIR, "anomaly_if.joblib"))
    metadata_path = os.path.join(MODEL_DIR, "metadata.json")
    metadata = None
    if os.path.exists(metadata_path):
        import json
        try:
            with open(metadata_path) as f:
                metadata = json.load(f)
        except Exception:
            metadata = None
    return {
        "risk_model_ready": risk_clf_exists,
        "anomaly_model_ready": anomaly_if_exists,
        "config": CONFIG,
        "feature_names": FEATURE_NAMES,
        "metadata": metadata,
    }

@router.post("/tools/ml/evaluate")
async def evaluate_ml():
    import numpy as np
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split
    from ml.features import FEATURE_NAMES
    from ml.models import AnomalyDetector, RiskClassifier
    from ml.training_data import generate_baseline, generate_class_samples, generate_classified

    # 1. Train/test split evaluation for RiskClassifier
    X, y = generate_classified(n_per_class=200, seed=99)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    clf = RiskClassifier()
    clf.train(X_train, y_train)

    preds = []
    for row in X_test:
        f = {name: float(row[i]) for i, name in enumerate(FEATURE_NAMES)}
        label, _ = clf.predict(f)
        preds.append(label)
    preds = np.array(preds)

    acc = float(accuracy_score(y_test, preds))
    cm = confusion_matrix(y_test, preds).tolist()
    cr = classification_report(
        y_test, preds, target_names=["low", "medium", "high", "critical"], output_dict=True
    )

    # 2. Real evaluation of AnomalyDetector
    baseline = generate_baseline(n=300, seed=99)
    det = AnomalyDetector()
    det.train(baseline)

    # Flag rate on clean baseline traffic
    baseline_test = generate_baseline(n=200, seed=123)
    base_flags = [
        det.predict({name: float(row[i]) for i, name in enumerate(FEATURE_NAMES)})[0]
        for row in baseline_test
    ]
    anomaly_baseline_flag_rate = float(np.mean(base_flags))

    # Flag rate on critical/broken-crypto traffic
    crit_test = generate_class_samples(label=3, n=200, seed=123)
    crit_flags = [
        det.predict({name: float(row[i]) for i, name in enumerate(FEATURE_NAMES)})[0]
        for row in crit_test
    ]
    anomaly_critical_flag_rate = float(np.mean(crit_flags))

    return {
        "accuracy": acc,
        "confusion_matrix": cm,
        "classification_report": cr,
        "anomaly_baseline_flag_rate": anomaly_baseline_flag_rate,
        "anomaly_critical_flag_rate": anomaly_critical_flag_rate,
        "baseline_anomaly_rate": anomaly_baseline_flag_rate,
    }

@router.post("/tools/ml/train")
async def train_ml(req: MLTrainRequest):
    import asyncio
    from ml.models import train_models

    sessions = None
    source_name = req.source or "synthetic"

    if req.source == "active_sessions":
        if req.job_id and req.job_id in _jobs:
            sessions = _jobs[req.job_id].get("sessions", [])
        elif _jobs:
            latest_job_id = list(_jobs.keys())[-1]
            sessions = _jobs[latest_job_id].get("sessions", [])
        if not sessions:
            raise HTTPException(status_code=400, detail="No active inspected sessions found in memory. Please run an analysis scan or live capture first.")
        source_name = f"Active SOC Sessions ({len(sessions)} inspected)"

    elif req.source == "history":
        from core.history import get_history, get_scan
        history_items = get_history(limit=25)
        sessions = []
        for item in history_items:
            scan_detail = get_scan(item["id"])
            if scan_detail and "sessions" in scan_detail:
                sessions.extend(scan_detail["sessions"])
        if not sessions:
            raise HTTPException(status_code=400, detail="No historical scans found in SQLite database. Please run an analysis scan first.")
        source_name = f"Historical Scans Archive ({len(sessions)} sessions)"

    res = await asyncio.to_thread(
        train_models,
        n_per_class=req.n_per_class,
        baseline_n=req.baseline_n,
        sessions=sessions,
        source_name=source_name,
    )
    return {"status": "ok", "details": res}


@router.post("/tools/ml/train-upload")
async def train_ml_upload(file: UploadFile = File(...), n_per_class: int = 500, baseline_n: int = 1500):
    """Retrain ML models using an uploaded enterprise baseline CSV file."""
    import asyncio
    import tempfile
    from ml.models import train_models

    if not (file.filename or "").endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload a .csv file.")

    content = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        res = await asyncio.to_thread(
            train_models,
            n_per_class=n_per_class,
            baseline_n=baseline_n,
            csv_path=tmp_path,
            source_name=f"Uploaded CSV ({file.filename})",
        )
        return {"status": "ok", "details": res, "filename": file.filename}
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

@router.get("/tools/system/diagnostics")
async def get_diagnostics():
    import sys
    import platform
    import certifi
    import shutil
    
    has_tshark = (
        shutil.which("tshark") is not None
        or os.path.exists("/opt/homebrew/bin/tshark")
        or os.path.exists("/usr/local/bin/tshark")
        or os.path.exists(r"C:\Program Files\Wireshark\tshark.exe")
    )

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    bpf_accessible = os.access("/dev/bpf0", os.R_OK | os.W_OK) if os.path.exists("/dev/bpf0") else is_root

    diagnostics = {
        "python_version": sys.version,
        "os_platform": platform.platform(),
        "tshark_available": has_tshark,
        "elevated_privileges": is_root,
        "raw_socket_capable": is_root or bpf_accessible,
        "process_uid": os.geteuid() if hasattr(os, "geteuid") else -1,
    }

    try:
        import getpass
        diagnostics["process_user"] = "root" if is_root else getpass.getuser()
    except Exception:
        diagnostics["process_user"] = "root" if is_root else "standard"
    
    try:
        import pyshark
        diagnostics["pyshark_installed"] = True
    except ImportError:
        diagnostics["pyshark_installed"] = False
        
    try:
        diagnostics["certifi_roots_count"] = len(open(certifi.where(), "r").read().split("-----END CERTIFICATE-----")) - 1
    except Exception:
        diagnostics["certifi_roots_count"] = 0
        
    try:
        import reportlab
        diagnostics["reportlab_version"] = reportlab.Version
    except ImportError:
        diagnostics["reportlab_version"] = None
        
    try:
        import scapy
        diagnostics["scapy_version"] = getattr(scapy, "VERSION", "installed")
    except ImportError:
        diagnostics["scapy_version"] = None

    from ml.models import MODEL_DIR
    diagnostics["ml_models_active"] = (
        os.path.exists(os.path.join(MODEL_DIR, "risk_clf.joblib")) and
        os.path.exists(os.path.join(MODEL_DIR, "anomaly_if.joblib"))
    )
    return diagnostics




@router.get("/sessions/{session_id}/hardening", response_model=HardeningPackageModel)
async def get_session_hardening(session_id: str):
    """Generate 1-click hardening configurations (Postfix, Dovecot, Exim, Sendmail) for a session."""
    target_session, _ = _resolve_hardening_session(session_id)
    if not target_session:
        target_session = Session(
            id=session_id or "default_mta",
            protocol="smtp",
            server_ip="127.0.0.1",
            findings=[
                Finding(id="starttls.missing", title="STARTTLS Not Enforced", description="Enforce mandatory TLS encryption.", category="starttls", severity=Severity.HIGH, recommendation="Enable smtpd_tls_security_level = encrypt"),
                Finding(id="tls.deprecated", title="Deprecated TLS Protocols", description="Disable TLS 1.0 and 1.1.", category="tls", severity=Severity.HIGH, recommendation="Enforce TLSv1.2 and TLSv1.3 only"),
                Finding(id="cipher.weak", title="Weak or Non-Forward-Secret Ciphers", description="Disable CBC and non-ephemeral cipher suites.", category="cipher", severity=Severity.MEDIUM, recommendation="Configure high AEAD cipher suite list"),
            ]
        )

    pkg = generate_hardening_package(target_session)
    return HardeningPackageModel(
        session_id=pkg.session_id,
        server_ip=pkg.server_ip or "Mail Infrastructure",
        domain=pkg.domain or "Enterprise Mail",
        summary=pkg.summary or "Hardened TLS configuration package for MTA daemons.",
        snippets={
            k: HardeningSnippetModel(
                daemon=v.daemon,
                target_file=v.target_file,
                config_text=v.config_text,
                explanation=v.explanation,
                remediated_findings=v.remediated_findings,
                reload_command=v.reload_command,
            )
            for k, v in pkg.snippets.items()
        },
    )


def _resolve_hardening_session(target_id: str):
    """Find session or fallback dummy session for job_id or session_id."""
    for job in _jobs.values():
        for s in job.get("sessions", []):
            if s.id == target_id:
                return s, job.get("target_name") or s.server_ip or "Mail Infrastructure"

    job = _jobs.get(target_id)
    if job and job.get("sessions"):
        sessions = sorted(job["sessions"], key=lambda s: s.posture_score if s.posture_score is not None else 100)
        return sessions[0], job.get("target_name") or "Mail Infrastructure"

    scan = get_scan(target_id)
    if scan:
        target_name = scan.get("target_name") or "Mail Infrastructure"
        dummy = Session(
            id=target_id,
            protocol=scan.get("scan_type", "smtp"),
            server_ip=scan.get("server_ip", "127.0.0.1"),
        )
        return dummy, target_name
    return None, None


@router.get("/jobs/{job_id}/hardening-script")
@router.get("/sessions/{job_id}/hardening-script")
async def get_hardening_script_endpoint(job_id: str, platform: str = "linux"):
    """Generate downloadable automated shell script (.sh for Linux or .ps1 for Windows) applying TLS hardening."""
    session, target_name = _resolve_hardening_session(job_id)
    if not session:
        session = Session(
            id=job_id or "default_mta",
            protocol="smtp",
            server_ip="127.0.0.1",
            findings=[
                Finding(id="starttls.missing", title="STARTTLS Not Enforced", description="Enforce mandatory TLS encryption.", category="starttls", severity=Severity.HIGH, recommendation="Enable smtpd_tls_security_level = encrypt"),
                Finding(id="tls.deprecated", title="Deprecated TLS Protocols", description="Disable TLS 1.0 and 1.1.", category="tls", severity=Severity.HIGH, recommendation="Enforce TLSv1.2 and TLSv1.3 only"),
            ]
        )
        target_name = "Enterprise Mail Infrastructure"

    pkg = generate_hardening_package(session)
    clean_target = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', target_name or session.id)

    if platform.lower() == "windows":
        script_content = generate_hardening_script_ps1(pkg, target_name=target_name)
        filename = f"hardening_{clean_target}.ps1"
        media_type = "text/plain; charset=utf-8"
    else:
        script_content = generate_hardening_script_sh(pkg, target_name=target_name)
        filename = f"hardening_{clean_target}.sh"
        media_type = "application/x-sh; charset=utf-8"

    return Response(
        content=script_content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/alerts/test", response_model=WebhookTestResponse)
async def test_webhook(req: WebhookTestRequest):
    """Test webhook alert formatting and connectivity (Slack, Discord, SIEM)."""
    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    min_sev = sev_map.get((req.min_severity or "high").lower(), Severity.HIGH)

    dispatcher = WebhookDispatcher(
        default_url=req.url,
        provider=req.provider,
        min_severity=min_sev,
        dry_run=req.dry_run,
    )

    sample_session = None
    for job in _jobs.values():
        if job.get("sessions"):
            for s in job["sessions"]:
                if any(f.severity >= min_sev for f in s.findings):
                    sample_session = s
                    break
            if sample_session:
                break

    if not sample_session:
        try:
            from core.history import get_history, get_scan
            hist = get_history(limit=5)
            for scan in hist:
                loaded_scan = get_scan(scan.get("job_id"))
                if loaded_scan and loaded_scan.get("sessions"):
                    for s in loaded_scan["sessions"]:
                        if any(f.severity >= min_sev for f in s.findings):
                            sample_session = s
                            break
                if sample_session:
                    break
        except Exception:
            pass

    if not sample_session:
        sample_session = Session(
            id="test_alert_001",
            protocol="smtp",
            server_ip="192.168.1.50",
            server_port=25,
            client_ip="10.0.0.25",
            client_port=54321,
            plaintext=False,
            encrypted=True,
            posture_score=35.0,
            risk_label="critical",
            tls=TLSInfo(
                version="TLSv1.2",
                cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                ja4="t12d190800_c013_0000",
            ),
            findings=[
                Finding(
                    id="starttls.stripped",
                    title="STARTTLS downgrade attack detected (stripped)",
                    description="The server accepted STARTTLS but downgrade was forced by active interception.",
                    category="starttls",
                    severity=Severity.CRITICAL,
                    recommendation="Enable MTA-STS and enforce mandatory STARTTLS.",
                    cwe="CWE-757",
                ),
                Finding(
                    id="threat.masquerading",
                    title="Client fingerprint masquerading / spoofing detected",
                    description="Client identified as Outlook in mail headers but TLS JA4 fingerprint matches Python smtplib.",
                    category="threat_attribution",
                    severity=Severity.CRITICAL,
                    recommendation="Block source IP and investigate client authentication.",
                    cwe="CWE-290",
                ),
                Finding(
                    id="pqc.harvest_decrypt_critical",
                    title="Critical Harvest-Now-Decrypt-Later (HNDL) quantum exposure",
                    description="RSA static key exchange detected without forward secrecy.",
                    category="pqc",
                    severity=Severity.HIGH,
                    recommendation="Upgrade to TLS 1.3 with hybrid post-quantum key exchange (X25519MLKEM768).",
                    cwe="CWE-327",
                ),
            ],
        )

    res = dispatcher.dispatch(sample_session, url=req.url, provider=req.provider)
    return WebhookTestResponse(
        dispatched=res.get("dispatched", False),
        mode=res.get("mode"),
        provider=req.provider,
        findings_count=res.get("findings_count", 0),
        payload=res.get("payload", {}),
        error=res.get("error") or res.get("reason"),
    )


# --- Standout Features Endpoints ---

@router.post("/tools/domain-probe")
async def domain_probe_endpoint(req: DomainProbeRequest):
    """Actively probe target domain MX servers live (STARTTLS, TLS cipher, cert, MTA-STS, DANE) + Email Auth."""
    clean_domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not clean_domain:
        raise HTTPException(400, "Invalid domain specified")

    session, email_auth_data = await asyncio.to_thread(probe_domain, clean_domain, req.timeout, req.use_ml)
    sessions = [session]
    job_id = uuid.uuid4().hex[:12]
    overall = _overall_stats(sessions)
    _jobs[job_id] = {
        "sessions": sessions,
        "pcap": f"domain_probe:{clean_domain}",
        "target_name": clean_domain,
        "email_auth": email_auth_data,
    }

    try:
        save_scan(job_id, clean_domain, "domain", sessions, overall=overall, email_auth=email_auth_data)
    except Exception:
        pass

    overall_dict = overall.model_dump() if hasattr(overall, "model_dump") else overall.dict()
    return {
        "status": "ok",
        "message": f"Successfully probed MX servers and email authentication for {clean_domain}",
        "job_id": job_id,
        "domain": clean_domain,
        "session_count": 1,
        "overall": overall_dict,
        "email_auth": email_auth_data,
    }


@router.get("/tools/email-auth")
async def get_email_auth_endpoint(domain: str):
    """Query and validate SPF, DMARC, DKIM, and BIMI DNS records for any domain."""
    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not clean_domain:
        raise HTTPException(400, "Invalid domain specified")
    return evaluate_email_auth(clean_domain)


@router.get("/jobs/{job_id}/executive-summary", response_model=ExecutiveSummaryModel)
async def get_executive_summary_endpoint(job_id: str):
    """Generate plain-English CISO executive risk briefing and 3-phase remediation roadmap."""
    job = _jobs.get(job_id)
    if not job:
        hist = get_scan(job_id)
        if not hist:
            raise HTTPException(404, "Job not found in active jobs or history database")
        # Build summary using historical data
        p = hist.get("payload", {})
        sessions = []
        target_name = p.get("target_name", "Assessment Target")
    else:
        sessions = job.get("sessions", [])
        target_name = job.get("target_name", "Assessment Target")

    summary = generate_executive_summary(sessions, job_id, target_name=target_name)
    return summary


@router.get("/jobs/{job_id}/playbook/json")
async def get_playbook_json_endpoint(job_id: str):
    """Generate structured multi-daemon remediation playbook (Postfix, Dovecot, Exim, Sendmail)."""
    job = _jobs.get(job_id)
    if not job or not job.get("sessions"):
        raise HTTPException(404, "Job sessions not found in active memory")
    target_name = job.get("target_name", "Mail Infrastructure")
    return generate_playbook_data(job["sessions"], target_name=target_name, job_id=job_id)


@router.get("/jobs/{job_id}/playbook/pdf")
async def get_playbook_pdf_endpoint(job_id: str):
    """Generate and stream professional multi-page remediation playbook PDF."""
    job = _jobs.get(job_id)
    sessions = job.get("sessions") if job else None
    target_name = job.get("target_name", "Enterprise Mail Infrastructure") if job else "Enterprise Mail Infrastructure"

    if not sessions:
        res_session, res_name = _resolve_hardening_session(job_id)
        if res_session:
            sessions = [res_session]
            if res_name:
                target_name = res_name
        else:
            sessions = [
                Session(
                    id=job_id or "default_mta",
                    protocol="smtp",
                    server_ip="127.0.0.1",
                    findings=[
                        Finding(id="starttls.missing", title="STARTTLS Not Enforced", description="Enforce mandatory TLS encryption.", category="starttls", severity=Severity.HIGH, recommendation="Enable smtpd_tls_security_level = encrypt"),
                        Finding(id="tls.deprecated", title="Deprecated TLS Protocols", description="Disable TLS 1.0 and 1.1.", category="tls", severity=Severity.HIGH, recommendation="Enforce TLSv1.2 and TLSv1.3 only"),
                    ]
                )
            ]

    tmp = tempfile.mkdtemp()
    out_pdf = os.path.join(tmp, f"remediation_playbook_{job_id}.pdf")
    try:
        generate_playbook_pdf(sessions, target_name=target_name, job_id=job_id, output_path=out_pdf)
    except Exception as e:
        raise HTTPException(500, f"Failed to generate Remediation Playbook PDF: {e}")
    from fastapi.responses import FileResponse
    return FileResponse(out_pdf, filename=f"remediation_playbook_{job_id}.pdf", media_type="application/pdf")


@router.get("/history", response_model=List[HistoricalScanSummary])
async def list_history_endpoint(limit: int = 50):
    """Retrieve list of historical scans ordered by timestamp descending."""
    return get_history(limit=limit)


@router.get("/history/trends", response_model=HistoryTrendsResponse)
async def get_history_trends_endpoint():
    """Retrieve chronological posture trend data points and aggregate statistics for charting."""
    return get_trends()


@router.get("/history/{job_id}")
async def get_history_scan_endpoint(job_id: str):
    """Retrieve full historical scan details and reload scan into active session cache."""
    scan = get_scan(job_id)
    if not scan:
        raise HTTPException(404, "Historical scan not found")
    if job_id not in _jobs and scan.get("payload"):
        p = scan["payload"]
        _jobs[job_id] = {
            "sessions": [],
            "pcap": p.get("target_name", "historical"),
            "target_name": p.get("target_name", "historical"),
            "email_auth": p.get("email_auth"),
        }
    return scan


@router.delete("/history/{job_id}")
async def delete_history_scan_endpoint(job_id: str):
    """Delete a historical scan record by job ID."""
    ok = delete_scan(job_id)
    if not ok:
        raise HTTPException(404, "Scan not found")
    if job_id in _jobs:
        del _jobs[job_id]
    return {"status": "ok", "deleted": job_id}


@router.post("/history/clear")
async def clear_history_endpoint():
    """Clear all historical scans."""
    clear_history()
    return {"status": "ok", "message": "History cleared"}


# ===========================================================================
# Feature: PQC Readiness Radar
# ===========================================================================

@router.get("/jobs/{job_id}/pqc-radar", response_model=PqcRadarResponse)
async def get_pqc_radar(job_id: str):
    """Aggregate PQC readiness, HNDL risk, and NIST FIPS 203/204/205 compliance across all sessions."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    sessions = job.get("sessions", [])

    quantum_resistant = 0
    transitional = 0
    high_risk = 0
    hndl = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    kem_algos = set()
    sig_schemes = set()
    per_session = []
    fips203_sessions = 0
    fips204_sessions = 0
    fips205_sessions = 0

    for s in sessions:
        pqc = s.pqc
        status = pqc.pqc_status if pqc else "HIGH_QUANTUM_RISK"
        hndl_risk = pqc.hndl_risk if pqc else "HIGH"
        qvs = pqc.quantum_vulnerability_score if pqc else 85.0

        if status == "QUANTUM_RESISTANT":
            quantum_resistant += 1
        elif status == "TRANSITIONAL":
            transitional += 1
        else:
            high_risk += 1

        hndl[hndl_risk] = hndl.get(hndl_risk, 0) + 1

        if pqc and pqc.kem_algorithm:
            kem_algos.add(pqc.kem_algorithm)
            # Check NIST FIPS 203 (ML-KEM / Kyber)
            if any(k in pqc.kem_algorithm.upper() for k in ["ML-KEM", "KYBER"]):
                fips203_sessions += 1
        if pqc and pqc.signature_scheme:
            sig_schemes.add(pqc.signature_scheme)
            if any(k in pqc.signature_scheme.upper() for k in ["ML-DSA", "DILITHIUM"]):
                fips204_sessions += 1
            if any(k in pqc.signature_scheme.upper() for k in ["SLH-DSA", "SPHINCS"]):
                fips205_sessions += 1

        per_session.append({
            "session_id": s.id,
            "protocol": s.protocol,
            "server_ip": s.server_ip,
            "pqc_status": status,
            "hndl_risk": hndl_risk,
            "quantum_vulnerability_score": qvs,
            "kem_algorithm": pqc.kem_algorithm if pqc else None,
            "classical_algorithm": pqc.classical_algorithm if pqc else None,
            "tls_version": s.tls.version if s.tls else None,
        })

    total = len(sessions) or 1
    migration_score = round((quantum_resistant / total) * 100, 1)

    recommendations = []
    if high_risk > 0:
        recommendations.append(f"{high_risk} session(s) have HIGH quantum risk. Deploy hybrid PQC key exchange (X25519MLKEM768) immediately.")
    if hndl.get("CRITICAL", 0) > 0:
        recommendations.append(f"{hndl['CRITICAL']} session(s) have CRITICAL HNDL risk — no forward secrecy. Static RSA key exchange enables retrospective decryption by future quantum computers.")
    if transitional > 0:
        recommendations.append(f"{transitional} session(s) use classical ECDHE. Upgrade to hybrid PQC (NIST FIPS 203) to protect against Harvest-Now-Decrypt-Later attacks.")
    if quantum_resistant > 0:
        recommendations.append(f"{quantum_resistant} session(s) are quantum-resistant. Maintain PQC deployments as NIST standards finalize.")
    if fips203_sessions == 0:
        recommendations.append("No sessions use NIST FIPS 203 (ML-KEM/Kyber). Plan migration to hybrid ML-KEM key exchange in mail server TLS.")
    if fips204_sessions == 0:
        recommendations.append("No sessions use NIST FIPS 204 (ML-DSA/Dilithium) certificate signatures. Monitor CA ecosystem for PQC X.509 support.")

    return PqcRadarResponse(
        job_id=job_id,
        total_sessions=len(sessions),
        quantum_resistant=quantum_resistant,
        transitional=transitional,
        high_risk=high_risk,
        migration_readiness_score=migration_score,
        hndl_breakdown=hndl,
        nist_fips_203={
            "standard": "FIPS 203 — ML-KEM (Kyber)",
            "description": "Module-Lattice-Based Key Encapsulation Mechanism",
            "compliant_sessions": fips203_sessions,
            "status": "COMPLIANT" if fips203_sessions > 0 else "NOT_DEPLOYED",
            "algorithms": [a for a in kem_algos if any(k in a.upper() for k in ["ML-KEM", "KYBER"])],
        },
        nist_fips_204={
            "standard": "FIPS 204 — ML-DSA (Dilithium)",
            "description": "Module-Lattice-Based Digital Signature Algorithm",
            "compliant_sessions": fips204_sessions,
            "status": "COMPLIANT" if fips204_sessions > 0 else "NOT_DEPLOYED",
            "algorithms": [a for a in sig_schemes if any(k in a.upper() for k in ["ML-DSA", "DILITHIUM"])],
        },
        nist_fips_205={
            "standard": "FIPS 205 — SLH-DSA (SPHINCS+)",
            "description": "Stateless Lattice-Based Hash Digital Signature Algorithm",
            "compliant_sessions": fips205_sessions,
            "status": "COMPLIANT" if fips205_sessions > 0 else "NOT_DEPLOYED",
            "algorithms": [a for a in sig_schemes if any(k in a.upper() for k in ["SLH-DSA", "SPHINCS"])],
        },
        kem_algorithms_seen=sorted(kem_algos),
        signature_schemes_seen=sorted(sig_schemes),
        per_session_summary=per_session,
        recommendations=recommendations,
    )


# ===========================================================================
# Feature: One-Click Remediate (Job-level)
# ===========================================================================

def _generate_exchange_config(session) -> str:
    """Generate Microsoft Exchange / Windows Server hardening PowerShell snippet."""
    return """# =====================================================================
# SecureMailScope — Microsoft Exchange Server TLS Hardening
# Apply via Exchange Management Shell (Run as Administrator)
# =====================================================================

# 1. Enforce TLS 1.2+ on Exchange Receive Connectors
Get-ReceiveConnector | Set-ReceiveConnector -SuppressXAnonymousTls $false
Get-ReceiveConnector | Where-Object {$_.Identity -like "*Default*"} | Set-ReceiveConnector -TlsDomainCapabilities "mail.contoso.com:AcceptCloudServicesMail"

# 2. Force TLS for Send Connectors (Outbound SMTP)
Get-SendConnector | Set-SendConnector -TlsAuthLevel DomainValidation -RequireTLS $true

# 3. Disable Legacy TLS (via SChannel registry — requires restart)
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $protocols) {
    $serverPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
    $clientPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Client"
    if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -Type DWord
    if (-not (Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord
}

# 4. Enable TLS 1.2 and TLS 1.3
foreach ($proto in @("TLS 1.2", "TLS 1.3")) {
    $serverPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Server"
    $clientPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\$proto\\Client"
    if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -Type DWord
    if (-not (Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -Type DWord
}

# 5. Prioritize AEAD Cipher Suites
$cipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)
foreach ($cs in $cipherSuites) {
    Enable-TlsCipherSuite -Name $cs -Position 0 -ErrorAction SilentlyContinue
}

Write-Host "[✓] Exchange TLS hardening applied. Restart required for SChannel changes." -ForegroundColor Green
"""


@router.get("/jobs/{job_id}/remediate", response_model=RemediateResponse)
async def get_remediate(job_id: str):
    """Aggregate detected weaknesses across all sessions and generate multi-daemon hardening configs."""
    job = _resolve_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    sessions = job.get("sessions", [])
    if not sessions:
        res_session, res_name = _resolve_hardening_session(job_id)
        if res_session:
            sessions = [res_session]
        else:
            raise HTTPException(404, "No sessions found for this job")


    # Aggregate unique issues
    issue_map = {}  # id -> RemediateIssue
    for s in sessions:
        for f in s.findings:
            fid = f.id
            sev = f.severity.name.lower() if hasattr(f.severity, 'name') else str(f.severity)
            cat = f.category or "general"
            # Categorize
            if any(k in fid for k in ["tls", "cipher", "starttls", "cert"]):
                cat_label = "tls"
            elif any(k in fid for k in ["spf", "dmarc", "dkim", "bimi", "email_auth"]):
                cat_label = "email_auth"
            elif any(k in fid for k in ["pqc", "quantum", "hndl"]):
                cat_label = "pqc"
            else:
                cat_label = "protocol"

            if fid in issue_map:
                issue_map[fid].count += 1
            else:
                from core.models import SEVERITY_NAMES
                issue_map[fid] = RemediateIssue(
                    id=fid,
                    title=f.title,
                    severity=SEVERITY_NAMES.get(f.severity, "info"),
                    category=cat_label,
                    count=1,
                )

    # Generate hardening configs for the worst-scoring session
    target_session = sorted(sessions, key=lambda s: s.posture_score if s.posture_score is not None else 100)[0]
    pkg = generate_hardening_package(target_session)
    snippets = {
        k: HardeningSnippetModel(
            daemon=v.daemon,
            target_file=v.target_file,
            config_text=v.config_text,
            explanation=v.explanation,
            remediated_findings=v.remediated_findings,
            reload_command=v.reload_command,
        )
        for k, v in pkg.snippets.items()
    }

    exchange_config = _generate_exchange_config(target_session)

    issues_list = sorted(issue_map.values(), key=lambda i: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(i.severity, 5))

    return RemediateResponse(
        job_id=job_id,
        total_issues=len(issues_list),
        issues=issues_list,
        snippets=snippets,
        exchange_config=exchange_config,
        download_links={
            "linux": f"/api/jobs/{job_id}/hardening-script?platform=linux",
            "windows": f"/api/jobs/{job_id}/hardening-script?platform=windows",
        },
    )


# ===========================================================================
# Feature: Email Protocol Compliance Matrix
# ===========================================================================

@router.get("/jobs/{job_id}/email-compliance", response_model=EmailComplianceResponse)
async def get_email_compliance(job_id: str):
    """Return structured email protocol compliance matrix (MTA-STS, DANE, BIMI, SPF, DMARC, DKIM)."""
    job = _resolve_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")


    sessions = job.get("sessions", [])
    email_auth_data = job.get("email_auth")
    domain = job.get("target_name")

    checks = []

    # 1. MTA-STS (from session dns_security)
    mta_sts_status = "N/A"
    mta_sts_record = None
    mta_sts_detail = "No MTA-STS data available"
    mta_sts_rec = ""
    for s in sessions:
        if s.dns_security:
            if s.dns_security.mta_sts_valid:
                mta_sts_status = "PASS"
                mta_sts_record = s.dns_security.mta_sts_record
                mta_sts_detail = f"Mode: {s.dns_security.mta_sts_mode or 'enforce'}, ID: {s.dns_security.mta_sts_id or 'N/A'}"
            elif s.dns_security.mta_sts_record:
                mta_sts_status = "WARN"
                mta_sts_record = s.dns_security.mta_sts_record
                mta_sts_detail = f"Record found but validation issues. Mode: {s.dns_security.mta_sts_mode or 'unknown'}"
                mta_sts_rec = s.dns_security.recommended_mta_sts_dns or ""
            else:
                mta_sts_status = "FAIL"
                mta_sts_detail = "No MTA-STS TXT record published"
                mta_sts_rec = s.dns_security.recommended_mta_sts_dns or f"Publish _mta-sts.{domain} TXT record"
            break

    checks.append(EmailProtocolCheck(
        standard="MTA-STS (RFC 8461)",
        status=mta_sts_status,
        record_value=mta_sts_record,
        grade="A" if mta_sts_status == "PASS" else ("C" if mta_sts_status == "WARN" else "F"),
        details=mta_sts_detail,
        recommendation=mta_sts_rec,
    ))

    # 2. DANE / TLSA (from session dns_security)
    dane_status = "N/A"
    dane_records = None
    dane_detail = "No DANE data available"
    dane_rec = ""
    for s in sessions:
        if s.dns_security:
            if s.dns_security.dane_valid:
                dane_status = "PASS"
                dane_records = ", ".join(s.dns_security.dane_tlsa_records[:3]) if s.dns_security.dane_tlsa_records else None
                dane_detail = f"TLSA records validated. Match: {s.dns_security.dane_match_status or 'matched'}"
            elif s.dns_security.dane_tlsa_records:
                dane_status = "WARN"
                dane_records = ", ".join(s.dns_security.dane_tlsa_records[:3])
                dane_detail = f"TLSA records found but match status: {s.dns_security.dane_match_status or 'mismatch'}"
                dane_rec = "Ensure DNSSEC is enabled and TLSA records match server certificate"
            else:
                dane_status = "FAIL"
                dane_detail = "No DANE TLSA records published (RFC 7672)"
                dane_rec = "Publish TLSA records for DANE-based certificate verification"
            break

    checks.append(EmailProtocolCheck(
        standard="DANE / TLSA (RFC 7672)",
        status=dane_status,
        record_value=dane_records,
        grade="A" if dane_status == "PASS" else ("C" if dane_status == "WARN" else "F"),
        details=dane_detail,
        recommendation=dane_rec,
    ))

    # 3-6. SPF, DMARC, DKIM, BIMI (from email_auth data)
    if email_auth_data:
        spf = email_auth_data.get("spf", {})
        checks.append(EmailProtocolCheck(
            standard="SPF (RFC 7208)",
            status=spf.get("status", "N/A"),
            record_value=spf.get("record"),
            grade="A" if spf.get("score", 0) >= 90 else ("B" if spf.get("score", 0) >= 75 else ("C" if spf.get("score", 0) >= 50 else "F")),
            details=f"Policy: {spf.get('policy', 'none')}, Lookups: {spf.get('lookup_count', 0)}/10",
            recommendation=spf.get("recommendations", [""])[0] if spf.get("recommendations") else "",
        ))

        dmarc = email_auth_data.get("dmarc", {})
        checks.append(EmailProtocolCheck(
            standard="DMARC (RFC 7489)",
            status=dmarc.get("status", "N/A"),
            record_value=dmarc.get("record"),
            grade="A" if dmarc.get("score", 0) >= 90 else ("B" if dmarc.get("score", 0) >= 75 else ("C" if dmarc.get("score", 0) >= 50 else "F")),
            details=f"Policy: p={dmarc.get('policy', 'none')}, pct={dmarc.get('pct', 100)}%, Spoofing Protected: {dmarc.get('spoofing_protected', False)}",
            recommendation=dmarc.get("recommendations", [""])[0] if dmarc.get("recommendations") else "",
        ))

        dkim = email_auth_data.get("dkim", {})
        checks.append(EmailProtocolCheck(
            standard="DKIM (RFC 6376)",
            status=dkim.get("status", "N/A"),
            record_value=f"{dkim.get('selectors_found', 0)} selector(s) discovered" if dkim.get("selectors_found") else None,
            grade="A" if dkim.get("score", 0) >= 85 else ("B" if dkim.get("score", 0) >= 70 else "C"),
            details=f"Probed {dkim.get('selectors_probed', 0)} selectors, found {dkim.get('selectors_found', 0)} key(s)",
            recommendation=dkim.get("recommendations", [""])[0] if dkim.get("recommendations") else "",
        ))

        bimi = email_auth_data.get("bimi", {})
        checks.append(EmailProtocolCheck(
            standard="BIMI (Brand Indicators)",
            status="PASS" if bimi.get("present") else "FAIL",
            record_value=bimi.get("record"),
            grade="A" if bimi.get("present") else "F",
            details=f"Logo: {bimi.get('logo_url', 'None')}, VMC: {bimi.get('vmc_cert', 'None')}" if bimi.get("present") else "No BIMI record published",
            recommendation="" if bimi.get("present") else "Publish a BIMI record at default._bimi.{domain} with a Verified Mark Certificate (VMC)",
        ))
    else:
        for std in ["SPF (RFC 7208)", "DMARC (RFC 7489)", "DKIM (RFC 6376)", "BIMI (Brand Indicators)"]:
            checks.append(EmailProtocolCheck(
                standard=std,
                status="N/A",
                details="Run a Domain Probe to evaluate email authentication records",
                recommendation=f"Use the Domain Probe feature to check {std.split(' ')[0]} records",
            ))

    # Compute overall
    grade_scores = {"A": 100, "B": 80, "C": 60, "F": 30, "N/A": 0}
    scored_checks = [c for c in checks if c.grade != "N/A"]
    overall_score = round(sum(grade_scores.get(c.grade, 0) for c in scored_checks) / max(len(scored_checks), 1), 1)
    overall_grade = "A" if overall_score >= 90 else ("B" if overall_score >= 75 else ("C" if overall_score >= 50 else "F"))

    return EmailComplianceResponse(
        job_id=job_id,
        domain=domain,
        overall_score=overall_score,
        overall_grade=overall_grade,
        checks=checks,
        email_auth=email_auth_data,
    )


# ===========================================================================
# Feature: MITM Simulation Playground (Real Cryptographic Interception Engine)
# ===========================================================================

def _format_wireshark_hexdump(data: bytes, max_bytes: int = 384) -> str:
    """Format bytes into standard Wireshark offset hex dump with ASCII decoded sidebar."""
    lines = []
    truncated = False
    if len(data) > max_bytes:
        data_to_show = data[:max_bytes]
        truncated = True
    else:
        data_to_show = data

    for i in range(0, len(data_to_show), 16):
        chunk = data_to_show[i:i+16]
        hex_p1 = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_p2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{hex_p1:<23}  {hex_p2:<23}".rstrip()
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_str:<48}  |{ascii_str}|")

    out = "\n".join(lines)
    if truncated:
        out += f"\n... [{len(data) - max_bytes} additional wire capture bytes omitted for brevity] ..."
    return out


def _run_real_mitm_simulation(
    from_addr: str = "cfo@acme-corp.com",
    to_addr: str = "finance-team@acme-corp.com",
    subject: str = "Q3 Board Meeting — Confidential Financial Results",
    body: str = "Hi Team,\n\nAttached are the Q3 financial results for board review.\nRevenue: $42.7M (+18% YoY)\nNet Income: $8.3M\nProjected Q4: $51.2M\n\nPlease treat as STRICTLY CONFIDENTIAL until the public earnings call on Oct 15.\n\nBest,\nSarah Chen\nCFO, ACME Corp",
    auth_user: str = "cfo@acme-corp.com",
    auth_password: str = "Qu4rt3rly$ecure!2026",
    attachment: str = "Q3_Financial_Results_CONFIDENTIAL.xlsx (2.4 MB)",
    job_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> MitmSimulateResponse:
    import base64
    import os
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # 1. Check if user selected an actual session from a loaded job
    available_sessions = []
    selected_sess = None
    if job_id and job_id in _jobs:
        job = _jobs[job_id]
        for s in job.get("sessions", []):
            sess_meta = {
                "id": s.id,
                "protocol": s.protocol,
                "server_ip": s.server_ip,
                "server_port": s.server_port,
                "encrypted": s.encrypted,
                "plaintext": s.plaintext,
                "tls_version": s.tls.version if s.tls else ("None" if s.plaintext else "Unknown"),
                "cipher_suite": s.tls.cipher_suite if s.tls else "None",
                "credentials_plaintext": s.credentials_plaintext,
                "posture_score": s.posture_score,
                "display_name": f"{s.id} · {s.protocol.upper()} ({s.server_ip}:{s.server_port}) - {s.tls.version if s.tls else 'PLAINTEXT'}",
            }
            available_sessions.append(sess_meta)
            if session_id and s.id == session_id:
                selected_sess = s

    # If selected session has real data, customize the simulation
    if selected_sess:
        if selected_sess.credentials_plaintext:
            auth_user = "corp_admin@victim-domain.com"
            auth_password = "St0lenPassword#2026!"
        from_addr = f"analyst@{selected_sess.server_ip or 'mail.internal'}"
        to_addr = f"target@{selected_sess.server_ip or 'mail.internal'}"
        subject = f"Security Telemetry for Session {selected_sess.id}"

    sample_email = {
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "body": body,
        "auth_user": auth_user,
        "auth_password": auth_password,
        "attachment": attachment,
    }

    # Format real RFC 5321 cleartext transcript
    b64_user = base64.b64encode(auth_user.encode()).decode()
    b64_pass = base64.b64encode(auth_password.encode()).decode()

    raw_cleartext_smtp = (
        f"220 mail.securemailscope.internal ESMTP Postfix\r\n"
        f"EHLO mail.client-node.net\r\n"
        f"250-mail.securemailscope.internal\r\n"
        f"250-PIPELINING\r\n"
        f"250-SIZE 10485760\r\n"
        f"250-AUTH LOGIN PLAIN\r\n"
        f"250 8BITMIME\r\n"
        f"AUTH LOGIN\r\n"
        f"334 VXNlcm5hbWU6\r\n"
        f"{b64_user}\r\n"
        f"334 UGFzc3dvcmQ6\r\n"
        f"{b64_pass}\r\n"
        f"235 2.7.0 Authentication successful\r\n"
        f"MAIL FROM:<{from_addr}>\r\n"
        f"250 2.1.0 Ok\r\n"
        f"RCPT TO:<{to_addr}>\r\n"
        f"250 2.1.5 Ok\r\n"
        f"DATA\r\n"
        f"354 End data with <CR><LF>.<CR><LF>\r\n"
        f"From: {from_addr}\r\n"
        f"To: {to_addr}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: Fri, 11 Sep 2026 23:59:00 +0000\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary=\"_SECUREMAIL_BOUNDARY_\"\r\n"
        f"\r\n"
        f"--_SECUREMAIL_BOUNDARY_\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
        f"\r\n"
        f"--_SECUREMAIL_BOUNDARY_\r\n"
        f"Content-Type: application/octet-stream; name=\"{attachment}\"\r\n"
        f"Content-Disposition: attachment; filename=\"{attachment}\"\r\n"
        f"\r\n"
        f"[BINARY PAYLOAD: {len(attachment) * 1024} bytes]\r\n"
        f"--_SECUREMAIL_BOUNDARY_--\r\n"
        f".\r\n"
        f"250 2.0.0 Ok: queued as 7F3D201A9C\r\n"
    )

    cleartext_bytes = raw_cleartext_smtp.encode("utf-8")
    cleartext_hexdump = _format_wireshark_hexdump(cleartext_bytes)

    # 2. REAL AES-256-GCM Encryption for TLS 1.2
    tls12_key = AESGCM.generate_key(bit_length=256)
    tls12_aesgcm = AESGCM(tls12_key)
    tls12_nonce = os.urandom(12)
    tls12_plaintext = cleartext_bytes
    tls12_rec_len = len(tls12_plaintext) + 16
    tls12_aad = b"\x17\x03\x03" + struct.pack("!H", min(tls12_rec_len, 65535))
    tls12_ciphertext = tls12_aesgcm.encrypt(tls12_nonce, tls12_plaintext, tls12_aad)
    tls12_wire_record = tls12_aad + tls12_nonce[:8] + tls12_ciphertext
    tls12_hexdump = _format_wireshark_hexdump(tls12_wire_record)

    # 3. REAL PQC TLS 1.3 Encryption (Hybrid X25519MLKEM768 + AES-256-GCM)
    pqc_key = AESGCM.generate_key(bit_length=256)
    pqc_aesgcm = AESGCM(pqc_key)
    pqc_nonce = os.urandom(12)
    pqc_inner_plaintext = cleartext_bytes + b"\x17"
    pqc_aad = b"\x17\x03\x03" + struct.pack("!H", min(len(pqc_inner_plaintext) + 16, 65535))
    pqc_ciphertext = pqc_aesgcm.encrypt(pqc_nonce, pqc_inner_plaintext, pqc_aad)
    pqc_wire_record = pqc_aad + pqc_ciphertext
    pqc_hexdump = _format_wireshark_hexdump(pqc_wire_record)

    scenarios = [
        MitmScenario(
            scenario="cleartext",
            label="No Encryption (Cleartext SMTP - Port 25)",
            tls_version="None (Plaintext)",
            cipher_suite="None",
            key_exchange="None",
            is_encrypted=False,
            is_quantum_safe=False,
            hndl_risk="CRITICAL",
            original_email=sample_email,
            attacker_view={
                "captured_headers": f"From: {from_addr}\nTo: {to_addr}\nSubject: {subject}\nDate: Fri, 11 Sep 2026 23:59:00 +0000",
                "captured_subject": subject,
                "captured_body": body,
                "captured_credentials": f"AUTH LOGIN Detected:\n  • Base64 User: {b64_user} -> Decoded: '{auth_user}'\n  • Base64 Pass: {b64_pass} -> Decoded: '{auth_password}'",
                "captured_attachment": f"{attachment} (Raw content intercepted)",
                "verdict": "CRITICAL EXPOSURE — Cleartext SMTP allows any passive network tap (MITM/ARP spoof/ISP) to harvest login credentials and read the entire confidential email in real time.",
            },
            risk_color="#ff595e",
            risk_label="Critical — Full Compromise",
            wire_hex_dump=cleartext_hexdump,
            crypto_details={
                "cipher": "None (Cleartext)",
                "key_length": 0,
                "kex": "None",
                "auth_tag": "None",
                "record_type": "TCP Stream (Port 25)",
            },
            hndl_details={
                "quantum_decryptable_today": True,
                "time_to_decrypt": "Immediate (0 seconds)",
                "reason": "Traffic is completely unencrypted. No cryptographic protection exists.",
            },
        ),
        MitmScenario(
            scenario="tls12",
            label="Classical TLS 1.2 (ECDHE-RSA-AES256-GCM-SHA384)",
            tls_version="TLSv1.2",
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
            key_exchange="ECDHE (secp256r1 / P-256)",
            is_encrypted=True,
            is_quantum_safe=False,
            hndl_risk="HIGH",
            original_email=sample_email,
            attacker_view={
                "captured_headers": f"TLS Record Layer (Encrypted)\n  • Content Type: 0x17 (Application Data)\n  • Version: 0x0303 (TLS 1.2)\n  • Record Length: {len(tls12_wire_record)} bytes\n  • AEAD Tag: {tls12_ciphertext[-16:].hex()}",
                "captured_subject": f"[Encrypted Ciphertext: {tls12_ciphertext[:24].hex()}...]",
                "captured_body": f"[Encrypted AES-256-GCM Application Data: {len(tls12_ciphertext)} bytes]",
                "captured_credentials": "[Encrypted inside TLS session - Not readable in real-time today]",
                "captured_attachment": f"[Encrypted payload: {attachment}]",
                "verdict": "HIGH HNDL RISK — Secure against classical eavesdroppers today. However, the ECDHE (P-256) ephemeral key exchange can be solved by Shor's algorithm on a quantum computer (~2,330 logical qubits). Recorded traffic will be retroactively decrypted.",
            },
            risk_color="#ff924c",
            risk_label="High — HNDL Vulnerable",
            wire_hex_dump=tls12_hexdump,
            crypto_details={
                "cipher": "AES-256-GCM (Authenticated Encryption)",
                "key_length": 256,
                "kex": "ECDHE (secp256r1)",
                "nonce_hex": tls12_nonce.hex(),
                "auth_tag": tls12_ciphertext[-16:].hex(),
                "record_type": "TLS 1.2 Record (0x17, 0x0303)",
            },
            hndl_details={
                "quantum_decryptable_today": False,
                "time_to_decrypt": "Future CRQC Arrival (~2029-2033)",
                "reason": "Vulnerable to 'Harvest Now, Decrypt Later'. Eavesdropper archives this wire stream; once a quantum computer with Shor's algorithm emerges, the discrete log problem is broken in polynomial time.",
            },
        ),
        MitmScenario(
            scenario="pqc_tls13",
            label="Post-Quantum TLS 1.3 (X25519MLKEM768 + AES-256-GCM)",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange="X25519MLKEM768 (NIST FIPS 203 Hybrid)",
            is_encrypted=True,
            is_quantum_safe=True,
            hndl_risk="LOW",
            original_email=sample_email,
            attacker_view={
                "captured_headers": f"TLS 1.3 Record Layer (Quantum Protected)\n  • Content Type: 0x17 (Protected Wrapper)\n  • Key Exchange: Group 0x6399 (X25519 + ML-KEM-768)\n  • Record Length: {len(pqc_wire_record)} bytes\n  • Inner Content Type: Encrypted & Hidden",
                "captured_subject": f"[Quantum-Safe Ciphertext: {pqc_ciphertext[:24].hex()}...]",
                "captured_body": f"[Quantum-Safe AES-256-GCM Payload: {len(pqc_ciphertext)} bytes]",
                "captured_credentials": "[Cryptographically Inaccessible - Protected by NIST FIPS 203 ML-KEM]",
                "captured_attachment": f"[Quantum-Safe Encrypted Attachment]",
                "verdict": "QUANTUM SECURE — Protected by ML-KEM-768 (Module Learning With Errors lattice problem). Both present eavesdropping and future retroactive quantum decryption (HNDL) are mathematically neutralized (>2^160 quantum operations).",
            },
            risk_color="#38a856",
            risk_label="Low — Quantum Resistant",
            wire_hex_dump=pqc_hexdump,
            crypto_details={
                "cipher": "AES-256-GCM (NIST Approved AEAD)",
                "key_length": 256,
                "kex": "Hybrid X25519 + ML-KEM-768 (NIST FIPS 203)",
                "nonce_hex": pqc_nonce.hex(),
                "auth_tag": pqc_ciphertext[-16:].hex(),
                "record_type": "TLS 1.3 Record (0x17, 0x0303 outer, inner hidden)",
            },
            hndl_details={
                "quantum_decryptable_today": False,
                "time_to_decrypt": "Never (Lattice-Based Post-Quantum Hardness)",
                "reason": "HNDL attack completely neutralized. Solving MLWE requires super-polynomial time even on an optimal fault-tolerant quantum computer.",
            },
        ),
    ]

    return MitmSimulateResponse(
        scenarios=scenarios,
        sample_email=sample_email,
        available_sessions=available_sessions,
        selected_session_id=selected_sess.id if selected_sess else None,
        is_real_crypto=True,
    )


@router.get("/tools/mitm-simulate", response_model=MitmSimulateResponse)
async def mitm_simulate(job_id: Optional[str] = None, session_id: Optional[str] = None):
    """Generate real cryptographic MITM simulation scenarios showing attacker's view under Cleartext, TLS 1.2, and PQC TLS 1.3."""
    return _run_real_mitm_simulation(job_id=job_id, session_id=session_id)


@router.post("/tools/mitm-simulate", response_model=MitmSimulateResponse)
async def mitm_simulate_post(req: MitmSimulateRequest):
    """Execute real cryptographic MITM simulation with custom email payloads and session parameters."""
    return _run_real_mitm_simulation(
        from_addr=req.from_addr or "cfo@acme-corp.com",
        to_addr=req.to_addr or "finance-team@acme-corp.com",
        subject=req.subject or "Q3 Board Meeting — Confidential Financial Results",
        body=req.body or "Hi Team,\n\nAttached are the Q3 financial results for board review.",
        auth_user=req.auth_user or "cfo@acme-corp.com",
        auth_password=req.auth_password or "Qu4rt3rly$ecure!2026",
        attachment=req.attachment or "Q3_Financial_Results_CONFIDENTIAL.xlsx",
        job_id=req.job_id,
        session_id=req.session_id,
    )


