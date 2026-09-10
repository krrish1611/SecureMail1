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
from core.models import Session, Finding, Severity, SEVERITY_NAMES
from core.compliance import evaluate_compliance_all, compliance_report_to_dict
from ml.models import MLPostureScorer, rule_based_posture_score
from reports.exporters import generate_json, generate_html, generate_pdf, generate_csv
from reports.hardening import generate_hardening_package
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
)

router = APIRouter(prefix="/api", tags=["analysis"])

_jobs = {}   # job_id -> {"sessions": [...], "pcap": str, "target_name": str}


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
                protocol_filter = msg.get("protocol_filter", "all")

                bpf = None
                if protocol_filter == "smtp":
                    bpf = "tcp and (port 25 or port 465 or port 587)"
                elif protocol_filter == "imap":
                    bpf = "tcp and (port 143 or port 993)"
                elif protocol_filter == "pop3":
                    bpf = "tcp and (port 110 or port 995)"

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
        forward_task.cancel()
        if active_monitor:
            active_monitor.stop()


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
    if not job or not job.get("sessions"):
        raise HTTPException(404, "Job sessions not found in active memory")
    target_name = job.get("target_name", "Mail Infrastructure")
    tmp = tempfile.mkdtemp()
    out_pdf = os.path.join(tmp, f"remediation_playbook_{job_id}.pdf")
    try:
        generate_playbook_pdf(job["sessions"], target_name=target_name, job_id=job_id, output_path=out_pdf)
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

