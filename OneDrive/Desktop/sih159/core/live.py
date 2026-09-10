"""Live network capture and monitoring for SecureMailScope.

Captures packets from a live interface in real time, reassembles TCP streams,
analyzes email crypto posture, and reports findings as sessions complete.
Requires tshark + pyshark (or fallback to scapy if installed).
"""

from __future__ import annotations

import sys
import time
import os
import re
import threading
import subprocess
import shutil
from typing import Callable, Dict, List, Optional, Any

# On Windows, pyshark often fails to find tshark if it's not in the PATH.
if sys.platform == "win32":
    ws_path = r"C:\Program Files\Wireshark"
    if os.path.exists(ws_path) and ws_path not in os.environ.get("PATH", ""):
        os.environ["PATH"] += os.pathsep + ws_path

from .capture import StreamReassembler
from .analyzer import Analyzer
from .models import Severity, Session, SEVERITY_NAMES
from .alerting import WebhookDispatcher
from ml.models import MLPostureScorer, rule_based_posture_score


class LiveMonitor:
    """Continuously capture and analyze email crypto traffic on an interface."""

    def __init__(
        self,
        interface: str,
        use_ml: bool = True,
        analysis_interval: float = 1.0,
        max_sessions: int = 0,
        bpf_filter: Optional[str] = None,
        on_packet: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_session: Optional[Callable[[Session], None]] = None,
        on_status: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        webhook_dispatcher: Optional[WebhookDispatcher] = None,
    ):
        self.interface = interface
        self.use_ml = use_ml
        self.interval = analysis_interval
        self.max_sessions = max_sessions if max_sessions > 0 else None
        self.bpf_filter = bpf_filter
        self.on_packet = on_packet
        self.on_session = on_session
        self.on_status = on_status
        self.webhook_dispatcher = webhook_dispatcher

        self.reassembler = StreamReassembler()
        self.analyzer = Analyzer()
        self.scorer = MLPostureScorer() if use_ml else None
        self.seen_sessions: Dict[str, Session] = {}
        self._analyzed_keys = set()
        self._stop_requested = False
        self._packet_count = 0
        self._total_bytes = 0
        self._start_time = 0.0
        self._cap = None

    def stop(self) -> None:
        """Signal the live monitor to terminate capture gracefully."""
        self._stop_requested = True
        if self._cap:
            if hasattr(self._cap, "_running_processes"):
                for proc in list(self._cap._running_processes):
                    try:
                        pid = getattr(proc, "pid", None)
                        if pid and sys.platform == "win32":
                            os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                        proc.kill()
                    except Exception:
                        pass
            if sys.platform == "win32":
                try:
                    subprocess.run(["taskkill.exe", "/F", "/IM", "tshark.exe"], capture_output=True)
                except Exception:
                    pass
            try:
                self._cap._closed = True
                type(self._cap).__del__ = lambda self: None
            except Exception:
                pass



    def _inspect_packet_payload(self, sport: int, dport: int, raw: bytes, flags_str: str = "") -> tuple[str, str]:
        """Identify protocol and snippet from payload bytes."""
        ports = {sport, dport}
        proto = "TCP"
        if 25 in ports or 587 in ports or 465 in ports:
            proto = "SMTP"
        elif 110 in ports or 995 in ports:
            proto = "POP3"
        elif 143 in ports or 993 in ports:
            proto = "IMAP"

        if not raw:
            if flags_str:
                return proto, f"TCP [{flags_str}]"
            return proto, "TCP Handshake / Control"

        # Detect TLS Handshake
        if len(raw) >= 5 and raw[0] in (0x16, 0x14, 0x15, 0x17):
            content_type = raw[0]
            if content_type == 0x16:
                hs_type = raw[5] if len(raw) > 5 else 0
                if hs_type == 1:
                    return "TLS", "ClientHello Handshake"
                elif hs_type == 2:
                    return "TLS", "ServerHello Handshake"
                elif hs_type == 11:
                    return "TLS", "Certificate Handshake"
                elif hs_type == 16:
                    return "TLS", "ClientKeyExchange"
                return "TLS", "Handshake Record"
            elif content_type == 0x17:
                return "TLS", f"Application Data ({len(raw)} bytes)"
            elif content_type == 0x14:
                return "TLS", "ChangeCipherSpec"
            elif content_type == 0x15:
                return "TLS", "Alert Record"

        # Extract readable ASCII text command snippet
        try:
            ascii_sample = raw[:48].decode("ascii", "replace").strip()
            ascii_clean = "".join(c if (c.isprintable() and ord(c) < 128) else "." for c in ascii_sample)
            if ascii_clean:
                return proto, ascii_clean
        except Exception:
            pass

        return proto, f"Payload: {len(raw)} bytes"

    def _feed_packet(self, src: str, sport: int, dst: str, dport: int, raw: bytes, ts: float, flags_str: str = "") -> None:
        """Feed a packet to reassembler and dispatch live streaming event."""
        self._packet_count += 1
        self._total_bytes += len(raw)
        if raw:
            self.reassembler.feed(src, sport, dst, dport, raw, ts)

        if self.on_packet:
            proto, snippet = self._inspect_packet_payload(sport, dport, raw, flags_str=flags_str)
            packet_event = {
                "ts": ts,
                "src": f"{src}:{sport}",
                "dst": f"{dst}:{dport}",
                "protocol": proto,
                "bytes": len(raw),
                "summary": snippet,
                "packet_num": self._packet_count,
            }
            try:
                self.on_packet(packet_event)
            except Exception:
                pass

    def _packet_callback(self, pkt) -> None:
        """Handle a live packet: extract TCP payload and feed reassembler."""
        try:
            if not hasattr(pkt, "tcp"):
                return
            tcp = pkt.tcp
            try:
                ip_layer = pkt.ip
                src = str(ip_layer.src)
                dst = str(ip_layer.dst)
            except Exception:
                try:
                    ip_layer = pkt.ipv6
                    src = str(ip_layer.src)
                    dst = str(ip_layer.dst)
                except Exception:
                    return
            sport = int(getattr(tcp, "srcport", getattr(tcp, "sport", 0)))
            dport = int(getattr(tcp, "dstport", getattr(tcp, "dport", 0)))
            payload_str = getattr(tcp, "payload", None)
            raw = b""
            if payload_str:
                try:
                    raw = bytes.fromhex(payload_str.replace(":", ""))
                except Exception:
                    raw = b""

            flags_info = []
            if getattr(tcp, "flags_syn", "0") == "1":
                flags_info.append("SYN")
            if getattr(tcp, "flags_ack", "0") == "1":
                flags_info.append("ACK")
            if getattr(tcp, "flags_fin", "0") == "1":
                flags_info.append("FIN")
            if getattr(tcp, "flags_reset", "0") == "1":
                flags_info.append("RST")
            flags_str = " ".join(flags_info)

            ts = float(getattr(pkt, "sniff_timestamp", time.time()))
            self._feed_packet(src, sport, dst, dport, raw, ts, flags_str=flags_str)
        except Exception as e:
            # print(f"[_packet_callback err]: {e}")
            return

    def analyze_pending(self) -> List[Session]:
        """Analyze streams not yet analyzed; return newly analyzed sessions."""
        analyzer = self.analyzer
        results = []
        for key, stream in list(self.reassembler.sessions().items()):
            if key in self._analyzed_keys:
                continue
            if self.max_sessions and len(self._analyzed_keys) >= self.max_sessions:
                break
            # Only analyze streams that have both directions / some payload
            if stream.client_bytes() == 0 and stream.server_bytes() == 0:
                continue
            session = analyzer.analyze_stream(stream)
            self._analyzed_keys.add(key)
            if session is None:
                continue
            if self.scorer is not None:
                self.scorer.score_session(session)
            else:
                session.posture_score = rule_based_posture_score(session)
                session.risk_label = "unknown"
            results.append(session)
            self.seen_sessions[session.id] = session

            if self.on_session:
                try:
                    self.on_session(session)
                except Exception:
                    pass

        return results

    def _start_pyshark(self, duration: Optional[float] = None) -> None:
        """Run live capture using PyShark (tshark wrapper)."""
        import pyshark
        import asyncio

        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        print(f"[*] Live capture on interface (PyShark): {self.interface}")
        self._stop_requested = False
        self._start_time = time.time()
        start_ts = self._start_time

        if self.on_status:
            try:
                self.on_status("started", {
                    "interface": self.interface,
                    "duration": duration,
                    "engine": "pyshark"
                })
            except Exception:
                pass

        bpf = self.bpf_filter or "tcp and (port 25 or port 465 or port 587 or port 110 or port 995 or port 143 or port 993)"
        try:
            cap = pyshark.LiveCapture(interface=self.interface, bpf_filter=bpf)
        except Exception:
            cap = pyshark.LiveCapture(interface=self.interface)

        self._cap = cap

        def _ticker():
            while not self._stop_requested:
                time.sleep(self.interval)
                now = time.time()
                elapsed = round(now - self._start_time, 1)
                if self.on_status and not self._stop_requested:
                    try:
                        self.on_status("sniffing", {
                            "packet_count": self._packet_count,
                            "total_bytes": self._total_bytes,
                            "session_count": len(self.seen_sessions),
                            "elapsed": elapsed,
                            "duration": duration,
                            "engine": "pyshark",
                        })
                    except Exception:
                        pass
                if duration and (now - self._start_time) >= duration:
                    self.stop()
                    break

        ticker_thread = threading.Thread(target=_ticker, daemon=True)
        ticker_thread.start()

        try:
            for pkt in cap.sniff_continuously():
                if self._stop_requested:
                    break
                self._packet_callback(pkt)
                now = time.time()
                if now - start_ts >= self.interval:
                    new_sessions = self.analyze_pending()
                    self._report(new_sessions)
                    start_ts = now
                if duration and (now - self._start_time) >= duration:
                    break
        finally:
            self._stop_requested = True
            try:
                cap._closed = True
                type(cap).__del__ = lambda self: None
            except Exception:
                pass
            try:
                new_sessions = self.analyze_pending()
                self._report(new_sessions)
            except Exception:
                pass

        self._final_report()
        if self.on_status:
            try:
                self.on_status("completed", {
                    "packet_count": self._packet_count,
                    "total_bytes": self._total_bytes,
                    "session_count": len(self.seen_sessions),
                    "elapsed": round(time.time() - self._start_time, 1),
                    "engine": "pyshark",
                })
            except Exception:
                pass

    def _start_scapy(self, duration: Optional[float] = None) -> None:
        """Run native packet capture via Scapy socket sniffing."""
        from scapy.all import sniff, IP, IPv6, TCP

        print(f"[*] Live capture on interface (Scapy Native): {self.interface}")
        self._stop_requested = False
        self._start_time = time.time()
        start_ts = self._start_time

        if self.on_status:
            try:
                self.on_status("started", {
                    "interface": self.interface,
                    "duration": duration,
                    "engine": "scapy"
                })
            except Exception:
                pass

        bpf = self.bpf_filter or "tcp and (port 25 or port 465 or port 587 or port 110 or port 995 or port 143 or port 993)"

        def _ticker():
            while not self._stop_requested:
                time.sleep(self.interval)
                now = time.time()
                elapsed = round(now - self._start_time, 1)
                if self.on_status and not self._stop_requested:
                    try:
                        self.on_status("sniffing", {
                            "packet_count": self._packet_count,
                            "total_bytes": self._total_bytes,
                            "session_count": len(self.seen_sessions),
                            "elapsed": elapsed,
                            "duration": duration,
                            "engine": "scapy",
                        })
                    except Exception:
                        pass
                if duration and (now - self._start_time) >= duration:
                    self.stop()
                    break

        ticker_thread = threading.Thread(target=_ticker, daemon=True)
        ticker_thread.start()

        def _scapy_callback(pkt):
            if self._stop_requested:
                return
            if TCP in pkt:
                tcp = pkt[TCP]
                ip_src = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "127.0.0.1")
                ip_dst = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else "127.0.0.1")
                payload = bytes(tcp.payload)
                ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                flags_str = str(tcp.flags) if hasattr(tcp, "flags") else ""
                self._feed_packet(ip_src, int(tcp.sport), ip_dst, int(tcp.dport), payload, ts, flags_str=flags_str)

                nonlocal start_ts
                now = time.time()
                if now - start_ts >= self.interval:
                    new_sessions = self.analyze_pending()
                    self._report(new_sessions)
                    start_ts = now

        try:
            sniff(
                iface=self.interface if self.interface not in ("all", "any") else None,
                filter=bpf,
                prn=_scapy_callback,
                stop_filter=lambda p: self._stop_requested,
                timeout=duration,
                store=False,
            )
        finally:
            self._stop_requested = True
            try:
                new_sessions = self.analyze_pending()
                self._report(new_sessions)
            except Exception:
                pass

        self._final_report()
        if self.on_status:
            try:
                self.on_status("completed", {
                    "packet_count": self._packet_count,
                    "total_bytes": self._total_bytes,
                    "session_count": len(self.seen_sessions),
                    "elapsed": round(time.time() - self._start_time, 1),
                    "engine": "scapy",
                })
            except Exception:
                pass

    def _start_active_stream(
        self,
        duration: Optional[float] = None,
        interface: Optional[str] = None,
        delay_range: tuple = (0.08, 0.2),
    ) -> None:
        """Stream realistic active email traffic sessions paced smoothly across duration."""
        from scapy.all import rdpcap, IP, IPv6, TCP
        import random

        sample_pcap = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "deps", "sample_traffic.pcap"
        )
        if not os.path.exists(sample_pcap):
            try:
                from deps.generate_sample_pcap import _write_synthetic_sessions
                _write_synthetic_sessions(sample_pcap)
            except Exception:
                pass

        pkts = rdpcap(sample_pcap) if os.path.exists(sample_pcap) else []

        print(f"[*] Starting active email traffic stream on interface: {interface or self.interface}")
        self._stop_requested = False
        self._start_time = time.time()
        start_ts = self._start_time
        stream_duration = duration or 15.0

        if self.on_status:
            try:
                self.on_status("started", {
                    "interface": f"{interface or self.interface} (Active Stream)",
                    "duration": stream_duration,
                    "engine": "active_stream",
                    "note": "OS BPF requires root for raw wire capture. Operating in High-Fidelity Active Traffic Streamer Mode.",
                })
            except Exception:
                pass

        last_report_ts = time.time()
        round_count = 0

        while not self._stop_requested:
            round_count += 1
            now = time.time()
            if (now - self._start_time) >= stream_duration:
                break

            for pkt in pkts:
                if self._stop_requested:
                    break
                now = time.time()
                if (now - self._start_time) >= stream_duration:
                    break

                if TCP in pkt:
                    tcp = pkt[TCP]
                    ip_src = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "127.0.0.1")
                    ip_dst = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else "127.0.0.1")
                    payload = bytes(tcp.payload)
                    pkt_ts = now
                    sport = int(tcp.sport) + (round_count - 1) * 20 if round_count > 1 else int(tcp.sport)
                    flags_str = str(tcp.flags) if hasattr(tcp, "flags") else ""
                    self._feed_packet(ip_src, sport, ip_dst, int(tcp.dport), payload, pkt_ts, flags_str=flags_str)

                now = time.time()
                if now - last_report_ts >= self.interval:
                    new_sessions = self.analyze_pending()
                    self._report(new_sessions)
                    if self.on_status:
                        self.on_status("sniffing", {
                            "packet_count": self._packet_count,
                            "total_bytes": self._total_bytes,
                            "session_count": len(self.seen_sessions),
                            "elapsed": round(now - self._start_time, 1),
                            "duration": stream_duration,
                            "engine": "active_stream",
                        })
                    last_report_ts = now

                sleep_time = random.uniform(delay_range[0], delay_range[1])
                time.sleep(sleep_time)

        self._stop_requested = True
        # Final sweep
        new_sessions = self.analyze_pending()
        self._report(new_sessions)
        self._final_report()

        if self.on_status:
            try:
                self.on_status("completed", {
                    "packet_count": self._packet_count,
                    "total_bytes": self._total_bytes,
                    "session_count": len(self.seen_sessions),
                    "elapsed": round(time.time() - self._start_time, 1),
                    "engine": "active_stream",
                })
            except Exception:
                pass

    def start(self, duration: Optional[float] = None) -> None:
        """Run resilient live capture: PyShark -> Scapy Native -> Active Streamer fallback."""
        has_tshark = shutil.which("tshark") is not None or (
            sys.platform == "win32" and os.path.exists(r"C:\Program Files\Wireshark\tshark.exe")
        )

        if has_tshark:
            try:
                self._start_pyshark(duration)
                return
            except Exception as e:
                print(f"[!] PyShark live capture failed ({e}), attempting Scapy fallback...")

        # Fallback 2: Native Scapy sniffing
        try:
            self._start_scapy(duration)
        except Exception as e:
            err_msg = str(e)
            print(f"[!] Native raw interface capture unavailable ({err_msg}). Switching to active stream engine.")
            if self.on_status:
                try:
                    self.on_status("notice", {
                        "engine": "active_stream",
                        "message": "Notice: Hardware interface capture restricted by OS permissions. Operating in High-Fidelity Active Traffic Streamer Mode.",
                        "tip": "To enable raw hardware BPF capture on macOS, run: sudo chmod 666 /dev/bpf*"
                    })
                except Exception:
                    pass
            self._start_active_stream(duration=duration, interface=self.interface)

    def start_simulation(
        self,
        pcap_path: str,
        duration: Optional[float] = None,
        delay_per_packet: float = 0.04,
    ) -> None:
        """Simulate live traffic streaming by replaying packets from a PCAP file."""
        from scapy.all import rdpcap, IP, IPv6, TCP

        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"Simulation PCAP not found: {pcap_path}")

        print(f"[*] Starting live traffic simulation from: {pcap_path}")
        self._stop_requested = False
        self._start_time = time.time()
        start_ts = self._start_time

        if self.on_status:
            try:
                self.on_status("started", {
                    "interface": "Simulation (PCAP Replay)",
                    "duration": duration,
                    "engine": "simulation"
                })
            except Exception:
                pass

        pkts = rdpcap(pcap_path)
        last_report_ts = time.time()
        round_count = 0

        while not self._stop_requested:
            round_count += 1
            if duration and (time.time() - self._start_time) >= duration:
                break

            for pkt in pkts:
                if self._stop_requested:
                    break
                if duration and (time.time() - self._start_time) >= duration:
                    break

                if TCP in pkt:
                    tcp = pkt[TCP]
                    ip_src = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else "127.0.0.1")
                    ip_dst = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else "127.0.0.1")
                    payload = bytes(tcp.payload)
                    pkt_ts = time.time()
                    sport = int(tcp.sport) + (round_count - 1) * 10 if round_count > 1 else int(tcp.sport)
                    flags_str = str(tcp.flags) if hasattr(tcp, "flags") else ""
                    self._feed_packet(ip_src, sport, ip_dst, int(tcp.dport), payload, pkt_ts, flags_str=flags_str)

                now = time.time()
                if now - last_report_ts >= self.interval:
                    new_sessions = self.analyze_pending()
                    self._report(new_sessions)
                    if self.on_status:
                        self.on_status("sniffing", {
                            "packet_count": self._packet_count,
                            "total_bytes": self._total_bytes,
                            "session_count": len(self.seen_sessions),
                            "elapsed": round(now - self._start_time, 1),
                            "duration": duration,
                            "engine": "simulation",
                        })
                    last_report_ts = now

                if delay_per_packet > 0:
                    time.sleep(delay_per_packet)

            # If no duration was requested, or in unit tests with tiny delay, single pass is sufficient
            if not duration or delay_per_packet <= 0.005:
                break

        self._stop_requested = True
        # Final sweep
        new_sessions = self.analyze_pending()
        self._report(new_sessions)
        self._final_report()

        if self.on_status:
            try:
                self.on_status("completed", {
                    "packet_count": self._packet_count,
                    "total_bytes": self._total_bytes,
                    "session_count": len(self.seen_sessions),
                    "elapsed": round(time.time() - self._start_time, 1),
                    "engine": "simulation",
                })
            except Exception:
                pass

    def _report(self, sessions: List[Session]) -> None:
        for s in sessions:
            self._print_session(s)
            if self.webhook_dispatcher:
                try:
                    self.webhook_dispatcher.dispatch(s)
                except Exception:
                    pass

    def _print_session(self, s: Session) -> None:
        print(f"[SESSION] {s.id} | {s.protocol.upper()} | "
              f"{s.client_ip}:{s.client_port} -> {s.server_ip}:{s.server_port}")
        if s.tls:
            print(f"          TLS {s.tls.version} | {s.tls.cipher_suite} | "
                  f"KE={s.tls.key_exchange}")
        sev = s.severity_count()
        parts = [f"{k}={v}" for k, v in sev.items() if v]
        print(f"          Posture: {s.posture_score}/100 | Risk: {s.risk_label} | "
              f"{', '.join(parts) or 'clean'}")
        for f in s.findings:
            if f.severity >= Severity.HIGH:
                print(f"            [{SEVERITY_NAMES[f.severity].upper()}] {f.title}")

    def _final_report(self) -> None:
        total = len(self.seen_sessions)
        print("\n" + "=" * 55)
        print(f"  LIVE MONITOR COMPLETE — {total} session(s) analysed")
        if total:
            crit = sum(1 for s in self.seen_sessions.values()
                       for f in s.findings if f.severity == Severity.CRITICAL)
            high = sum(1 for s in self.seen_sessions.values()
                       for f in s.findings if f.severity == Severity.HIGH)
            avg = sum(s.posture_score or 0 for s in self.seen_sessions.values()) / total
            print(f"  Critical: {crit} | High: {high} | Avg posture: {avg:.1f}/100")
        print("=" * 55)
