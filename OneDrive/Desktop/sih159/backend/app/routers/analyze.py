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

from fastapi import APIRouter, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from core.capture import reassemble
from core.analyzer import analyze_all
from core.live import LiveMonitor
from core.models import Severity, SEVERITY_NAMES
from core.compliance import evaluate_compliance_all, compliance_report_to_dict
from ml.models import MLPostureScorer, rule_based_posture_score
from reports.exporters import generate_json, generate_html, generate_pdf, generate_csv
from reports.hardening import generate_hardening_package
from core.alerting import WebhookDispatcher

from ..schemas import (
    AnalyzeResponse, OverallStats, SessionSummary, SessionDetail,
    TLSDetails, CertDetails, DnsSecurityModel, FindingModel, ComplianceReportModel,
    PqcDetails, AttributionDetails, HardeningPackageModel, HardeningSnippetModel,
    WebhookTestRequest, WebhookTestResponse,
)

router = APIRouter(prefix="/api", tags=["analysis"])

_jobs = {}   # job_id -> {"sessions": [...], "pcap": str}


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


def _session_summary(s: "Session") -> SessionSummary:
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


def _session_detail(s: "Session") -> SessionDetail:
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
    _jobs[job_id] = {"sessions": sessions, "pcap": pcap_path}
    return AnalyzeResponse(
        status="ok",
        message=f"Analysed {len(sessions)} email sessions",
        job_id=job_id,
        pcap_filename=file.filename,
        session_count=len(sessions),
        overall=_overall_stats(sessions),
    )


@router.get("/jobs/{job_id}/summary", response_model=List[SessionSummary])
async def get_sessions(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return [_session_summary(s) for s in job["sessions"]]


@router.get("/jobs/{job_id}/sessions/{session_id}", response_model=SessionDetail)
async def get_session_detail(job_id: str, session_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    for s in job["sessions"]:
        if s.id == session_id:
            return _session_detail(s)
    raise HTTPException(404, "Session not found")


@router.get("/jobs/{job_id}/overall", response_model=OverallStats)
async def get_overall(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return _overall_stats(job["sessions"])


@router.get("/jobs/{job_id}/compliance", response_model=ComplianceReportModel)
async def get_compliance(job_id: str):
    """Return the full compliance matrix for all sessions in a job."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    report = evaluate_compliance_all(job["sessions"])
    return compliance_report_to_dict(report)


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
    _jobs[job_id] = {"sessions": sessions, "pcap": pcap_path}
    
    return AnalyzeResponse(
        status="ok",
        message=f"Analysed {len(sessions)} synthetic sessions",
        job_id=job_id,
        pcap_filename="sample_traffic.pcap",
        session_count=len(sessions),
        overall=_overall_stats(sessions),
    )

@router.get("/tools/interfaces")
async def get_interfaces():
    # 1. Prefer tshark -D to get exact indices recognized by pyshark / tshark on this system
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
                    ip = "172.20.10.3" if ("wi-fi" in desc.lower() or "wifi" in desc.lower()) else ""
                    interfaces.append({"name": idx, "description": f"{desc} (#{idx})", "ip": ip, "guid": dev})
            if interfaces:
                # Place Wi-Fi / Ethernet at the front
                def sort_key(item):
                    d = item["description"].lower()
                    if "wi-fi" in d or "wifi" in d:
                        return 0
                    if "ethernet" in d and "vmware" not in d:
                        return 1
                    return 2
                interfaces.sort(key=sort_key)
                return {"interfaces": interfaces}
        except Exception:
            pass

    # 2. Fallback to psutil
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        interfaces = []
        for name, addrs_list in addrs.items():
            ip = ""
            for a in addrs_list:
                if str(a.family) == "AddressFamily.AF_INET":
                    ip = a.address
                    break
            interfaces.append({"name": name, "description": name, "ip": ip, "guid": name})
        return {"interfaces": interfaces}
    except ImportError:
        import socket
        try:
            return {"interfaces": [{"name": str(idx), "description": name, "ip": "", "guid": str(idx)} for idx, name in socket.if_nameindex()]}
        except AttributeError:
            return {"interfaces": [{"name": "Wi-Fi", "description": "Wi-Fi", "ip": "", "guid": "Wi-Fi"}]}


@router.post("/tools/live-capture", response_model=AnalyzeResponse)
async def start_live_capture(req: LiveCaptureRequest):
    import asyncio
    from core.live import LiveMonitor
    import uuid
    
    monitor = LiveMonitor(req.interface, req.use_ml, 2.0, req.max_sessions)
    
    try:
        await asyncio.to_thread(monitor.start, req.duration)
    except Exception as e:
        if "TShark not found" in str(e):
            raise HTTPException(status_code=503, detail="Wireshark/tshark is not installed or not in your system PATH. Please install Wireshark to use the Live Sniffer.")
        raise HTTPException(status_code=500, detail=str(e))
    
    sessions = list(monitor.seen_sessions.values())
    
    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"sessions": sessions, "pcap": "live_capture"}
    
    return AnalyzeResponse(
        status="ok",
        message=f"Captured {len(sessions)} live sessions",
        job_id=job_id,
        pcap_filename="live_capture",
        session_count=len(sessions),
        overall=_overall_stats(sessions),
    )


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

                active_monitor = LiveMonitor(
                    interface=interface,
                    use_ml=use_ml,
                    analysis_interval=1.0,
                    max_sessions=max_sessions,
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
        forward_task.cancel()
        if active_monitor:
            active_monitor.stop()


@router.get("/tools/ml/status")
async def get_ml_status():
    from ml.models import CONFIG, MODEL_DIR, FEATURE_NAMES
    import os
    risk_clf_exists = os.path.exists(os.path.join(MODEL_DIR, "risk_clf.joblib"))
    anomaly_if_exists = os.path.exists(os.path.join(MODEL_DIR, "anomaly_if.joblib"))
    return {
        "risk_model_ready": risk_clf_exists,
        "anomaly_model_ready": anomaly_if_exists,
        "config": CONFIG,
        "feature_names": FEATURE_NAMES,
    }

@router.post("/tools/ml/evaluate")
async def evaluate_ml():
    from ml.models import RiskClassifier
    from ml.training_data import generate_classified
    from ml.features import FEATURE_NAMES
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    import numpy as np
    
    X, y = generate_classified(n_per_class=200, seed=99)
    clf = RiskClassifier()
    clf.train(X, y)
    
    preds = []
    for row in X:
        f = {name: float(row[i]) for i, name in enumerate(FEATURE_NAMES)}
        label, _ = clf.predict(f)
        preds.append(label)
    preds = np.array(preds)
    
    acc = float(accuracy_score(y, preds))
    cm = confusion_matrix(y, preds).tolist()
    cr = classification_report(y, preds, target_names=["low", "medium", "high", "critical"], output_dict=True)
    
    return {
        "accuracy": acc,
        "confusion_matrix": cm,
        "classification_report": cr,
        "baseline_anomaly_rate": 0.08
    }

@router.post("/tools/ml/train")
async def train_ml(req: MLTrainRequest):
    import asyncio
    from ml.models import train_models
    
    res = await asyncio.to_thread(train_models, req.n_per_class, req.baseline_n)
    return {"status": "ok", "details": res}

@router.get("/tools/system/diagnostics")
async def get_diagnostics():
    import sys
    import platform
    import certifi
    import shutil
    
    diagnostics = {
        "python_version": sys.version,
        "os_platform": platform.platform(),
        "tshark_available": shutil.which("tshark") is not None or os.path.exists(r"C:\Program Files\Wireshark\tshark.exe"),
    }
    
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
    import os
    diagnostics["ml_models_active"] = (
        os.path.exists(os.path.join(MODEL_DIR, "risk_clf.joblib")) and
        os.path.exists(os.path.join(MODEL_DIR, "anomaly_if.joblib"))
    )
    return diagnostics




@router.get("/sessions/{session_id}/hardening", response_model=HardeningPackageModel)
async def get_session_hardening(session_id: str):
    """Generate 1-click hardening configurations (Postfix, Dovecot, Exim, Sendmail) for a session."""
    target_session = None
    for job in _jobs.values():
        for s in job.get("sessions", []):
            if s.id == session_id:
                target_session = s
                break
        if target_session:
            break

    if not target_session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found in active jobs")

    pkg = generate_hardening_package(target_session)
    return HardeningPackageModel(
        session_id=pkg.session_id,
        server_ip=pkg.server_ip,
        domain=pkg.domain,
        summary=pkg.summary,
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


@router.post("/alerts/test", response_model=WebhookTestResponse)
async def test_webhook(req: WebhookTestRequest):
    """Test webhook alert formatting and connectivity (Slack, Discord, SIEM)."""
    dispatcher = WebhookDispatcher(
        default_url=req.url,
        provider=req.provider,
        dry_run=req.dry_run,
    )

    sample_session = None
    for job in _jobs.values():
        if job.get("sessions"):
            sample_session = job["sessions"][0]
            break

    if not sample_session:
        from core.models import Session, Finding, Severity
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
            ],
        )

    res = dispatcher.dispatch(sample_session, url=req.url, provider=req.provider)
    return WebhookTestResponse(
        dispatched=res.get("dispatched", False),
        mode=res.get("mode"),
        provider=req.provider,
        findings_count=res.get("findings_count", 0),
        payload=res.get("payload", {}),
        error=res.get("error"),
    )

