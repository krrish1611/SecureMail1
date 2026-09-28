#!/usr/bin/env python3
"""SecureMailScope CLI entry point.

Usage:
    python cli.py <pcap_file> [--json OUTPUT] [--html OUTPUT] [--pdf OUTPUT]
    python cli.py <pcap_file> --dashboard
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.capture import reassemble
from core.analyzer import analyze_all
from ml.models import MLPostureScorer
from reports.exporters import generate_json, generate_html, generate_pdf, generate_csv, REPORTS_DIR


def print_banner():
    print(r"""
    ____                               __             __  ____
   / __ \____ _____  ____ _____ ______/ /____  _____/ /_/ __ \____ _____  ___  ____
  / / / / __ `/ __ \/ __ `/ __ `/ ___/ __/ _ \/ ___/ __/ / / / __ `/ __ \/ _ \/ __/
 / /_/ / /_/ / / / / /_/ / / / (__  ) /_/  __/ /__/ /_/ /_/ / /_/ / / / /  __/ /
/_____/\__,_/_/ /_/\__,_/_/ /_/____/\__/\___/\___/\__/\____/\__,_/_/ /_/\___/_/
    """)


def print_summary(sessions):
    total = len(sessions)
    crit = sum(1 for s in sessions for f in s.findings if f.severity.value >= 4)
    high = sum(1 for s in sessions for f in s.findings if f.severity.value == 3)
    med = sum(1 for s in sessions for f in s.findings if f.severity.value == 2)
    avg = (sum(s.posture_score or 0 for s in sessions) / total) if total else 0
    encrypted = sum(1 for s in sessions if s.encrypted)
    anomalies = sum(1 for s in sessions if s.ml_anomaly)
    print(f"\n{'='*60}")
    print(f"  ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"  Sessions analysed : {total}")
    print(f"  Encrypted sessions: {encrypted}/{total}")
    print(f"  Critical findings : {crit}")
    print(f"  High findings     : {high}")
    print(f"  Medium findings   : {med}")
    print(f"  Anomalies (ML)    : {anomalies}")
    print(f"  Average posture   : {avg:.1f}/100")
    print(f"{'='*60}\n")


def print_compliance_summary(sessions):
    from core.compliance import evaluate_compliance_all
    report = evaluate_compliance_all(sessions)
    print(f"\n{'='*60}")
    print(f"  COMPLIANCE MATRIX")
    print(f"{'='*60}")
    for fw in report.frameworks:
        if fw.verdict == "COMPLIANT":
            icon = "[PASS]"
        elif fw.verdict == "NON-COMPLIANT":
            icon = "[FAIL]"
        else:
            icon = "[ -- ]"
        print(f"  {icon} {fw.framework:<16s}  {fw.verdict:<16s}  "
              f"(pass={fw.passed} fail={fw.failed} n/a={fw.na})")
    print(f"{'='*60}")

    # Print control-level detail
    from core.compliance import CONTROLS
    print(f"\n  {'ID':<5s} {'Control':<45s} {'PCI-DSS':<10s} {'NIST':<10s} {'HIPAA':<10s}")
    print(f"  {'-'*5} {'-'*45} {'-'*10} {'-'*10} {'-'*10}")
    for ctrl in CONTROLS:
        # Aggregate across sessions for this control
        checks_for_ctrl = [c for c in report.checks if c.control_id == ctrl["id"]]
        fw_statuses = {}
        for fw_name in ("PCI-DSS 4.0", "NIST 800-52r2", "HIPAA"):
            fw_c = [c for c in checks_for_ctrl if c.framework == fw_name]
            has_fail = any(c.status == "FAIL" for c in fw_c)
            all_na = all(c.status == "N/A" for c in fw_c)
            if all_na:
                fw_statuses[fw_name] = "N/A"
            elif has_fail:
                fw_statuses[fw_name] = "FAIL"
            else:
                fw_statuses[fw_name] = "PASS"
        pci = fw_statuses.get("PCI-DSS 4.0", "N/A")
        nist = fw_statuses.get("NIST 800-52r2", "N/A")
        hipaa = fw_statuses.get("HIPAA", "N/A")
        print(f"  {ctrl['id']:<5s} {ctrl['name']:<45s} {pci:<10s} {nist:<10s} {hipaa:<10s}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="SecureMailScope — AI-Assisted Cryptographic Security Posture Assessment"
    )
    parser.add_argument("pcap", nargs="?", help="Path to the input PCAP/PCAPNG file")
    parser.add_argument("--live", action="store_true",
                        help="Run live monitoring on a network interface instead of a PCAP")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface for live capture (e.g. eth0)")
    parser.add_argument("--duration", type=float, default=None,
                        help="Stop live capture after N seconds")
    parser.add_argument("--json", dest="json_out", nargs="?", const=True,
                        help="Output JSON report (default: <pcap>_report.json)")
    parser.add_argument("--html", dest="html_out", nargs="?", const=True,
                        help="Output HTML report (default: <pcap>_report.html)")
    parser.add_argument("--pdf", dest="pdf_out", nargs="?", const=True,
                        help="Output PDF report (default: <pcap>_report.pdf)")
    parser.add_argument("--csv", dest="csv_out", nargs="?", const=True,
                        help="Output CSV report (default: <pcap>_report.csv)")
    parser.add_argument("--no-ml", action="store_true",
                        help="Skip ML scoring (rule-based only)")
    parser.add_argument("--max-sessions", type=int, default=0,
                        help="Maximum number of sessions to analyse (0=all)")
    parser.add_argument("--pretty", action="store_true", default=True,
                        help="Pretty-print JSON to stdout")
    args = parser.parse_args()

    print_banner()

    # ---- Live capture mode ----
    if args.live:
        from core.live import LiveMonitor
        interface = args.interface or "eth0"
        if args.pcap:
            print("[!] Ignoring positional PCAP argument (live mode is active).")
        monitor = LiveMonitor(interface, use_ml=not args.no_ml,
                              analysis_interval=2.0, max_sessions=args.max_sessions)
        monitor.start(duration=args.duration)
        sys.exit(0)

    if not args.pcap:
        print("[ERROR] Provide a PCAP file path, or use --live for live capture.",
              file=sys.stderr)
        parser.print_usage(file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.pcap):
        print(f"[ERROR] File not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading PCAP: {args.pcap}")
    t0 = time.time()
    streams = reassemble(args.pcap)
    t_load = time.time() - t0
    print(f"[*] Reassembled {len(streams)} TCP streams in {t_load:.2f}s")

    max_s = args.max_sessions if args.max_sessions > 0 else None
    sessions = analyze_all(streams, max_sessions=max_s)
    print(f"[*] Identified {len(sessions)} email sessions")

    if not sessions:
        print("[!] No SMTP/IMAP/POP3 sessions found. Nothing to analyse.")
        sys.exit(0)

    # ML scoring
    if not args.no_ml:
        print("[*] Running ML risk scoring...")
        scorer = MLPostureScorer()
        for s in sessions:
            scorer.score_session(s)
        print("[*] ML scoring complete.")
    else:
        # Rule-based scoring only
        from ml.models import rule_based_posture_score
        for s in sessions:
            s.posture_score = rule_based_posture_score(s)
            s.risk_label = "unknown"
        print("[*] Rule-based scoring only (--no-ml).")

    print_summary(sessions)
    print_compliance_summary(sessions)

    # Output paths
    base = Path(args.pcap).stem
    json_path = args.json_out if isinstance(args.json_out, str) else f"{base}_report.json"
    html_path = args.html_out if isinstance(args.html_out, str) else f"{base}_report.html"
    pdf_path = args.pdf_out if isinstance(args.pdf_out, str) else f"{base}_report.pdf"
    csv_path = args.csv_out if isinstance(args.csv_out, str) else f"{base}_report.csv"

    jpath = generate_json(sessions, json_path)
    hpath = generate_html(sessions, html_path)
    print(f"[+] JSON report: {jpath}")
    print(f"[+] HTML report: {hpath}")

    if args.csv_out:
        cpath = generate_csv(sessions, csv_path)
        print(f"[+] CSV report:  {cpath}")

    if args.pdf_out or True:
        try:
            ppath = generate_pdf(sessions, pdf_path)
            print(f"[+] PDF report:  {ppath}")
        except Exception as e:
            print(f"[!] PDF generation failed: {e}", file=sys.stderr)

    # Print top findings
    all_findings = []
    for s in sessions:
        for f in s.findings:
            all_findings.append((f.severity.value, f, s.id))
    all_findings.sort(key=lambda x: x[0], reverse=True)
    if all_findings:
        print("\n--- TOP FINDINGS ---")
        for sev, f, sid in all_findings[:10]:
            from core.models import SEVERITY_NAMES
            print(f"  [{SEVERITY_NAMES[f.severity].upper()}] (session {sid}) {f.title}")
            print(f"         {f.description}")
            print()


if __name__ == "__main__":
    main()
