"""Packet capture loading and TCP stream reassembly.

Uses dpkt for fast PCAP/PCAPNG parsing with graceful fallback to scapy if
dpkt is not available. Streams are keyed by a 4-tuple and reassembled in
TCP sequence-number order, with retransmission deduplication. An email-
candidate filter excludes non-email traffic before expensive analysis.
"""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

try:
    import dpkt
    HAVE_DPKT = True
except Exception:  # pragma: no cover
    HAVE_DPKT = False

# Re-use protocol payload signatures from core.protocols (single source of truth).
from .protocols import ALL_EMAIL_PATTERNS

CounterKey = Tuple[str, int, str, int]

# Email service ports — maps port number to canonical protocol name.
# Replaces the former SERVER_PORTS set while remaining backward-compatible:
# anywhere that previously tested `port in SERVER_PORTS` can now test
# `port in EMAIL_PORTS`.
EMAIL_PORTS: Dict[int, str] = {
    25:  "smtp",
    465: "smtps",
    587: "submission",
    110: "pop3",
    995: "pop3s",
    143: "imap",
    993: "imaps",
}

# Standard unprivileged alternative/developer email ports:
ALT_EMAIL_PORTS: Dict[int, str] = {
    1025: "smtp",
    1587: "submission",
    2525: "smtp",
    1465: "smtps",
    1110: "pop3",
    1995: "pop3s",
    1143: "imap",
    1993: "imaps",
}

ALL_EMAIL_PORTS: Dict[int, str] = {**EMAIL_PORTS, **ALT_EMAIL_PORTS}

# Backward-compatible alias — keep existing call-sites (e.g. normalize_key)
# working without changes.
SERVER_PORTS: Set[int] = set(EMAIL_PORTS.keys())

# Pre-compiled matchers for payload-based email candidate detection.
_EMAIL_CANDIDATE_RES: List[re.Pattern[bytes]] = [re.compile(p) for p in ALL_EMAIL_PATTERNS]


def is_email_candidate(payload: bytes, sport: int, dport: int) -> bool:
    """Return True if the packet belongs to a likely email conversation.

    Checks port membership first (fast path), then falls back to payload
    pattern matching against known email protocol signatures so that email
    traffic on non-standard ports is still captured.
    """
    if sport in ALL_EMAIL_PORTS or dport in ALL_EMAIL_PORTS:
        return True
    if payload:
        # Only inspect the first 512 bytes for performance.
        sample = payload[:512]
        for pat in _EMAIL_CANDIDATE_RES:
            if pat.search(sample):
                return True
    return False


# ---------------------------------------------------------------------------
# Sequence-number-aware segment buffer
# ---------------------------------------------------------------------------

@dataclass
class _Segment:
    """A single TCP segment for one direction of a stream."""
    seq: int
    data: bytes


class _DirectionBuffer:
    """Collects TCP segments for one direction and reassembles them in
    sequence-number order with retransmission deduplication.
    """

    __slots__ = ("_segments", "_seen")

    def __init__(self) -> None:
        self._segments: List[_Segment] = []
        # Track (seq, length) pairs to skip exact-duplicate retransmissions.
        self._seen: Set[Tuple[int, int]] = set()

    def add(self, seq: int, data: bytes) -> None:
        """Record a segment.  Exact duplicates (same seq + length) are dropped."""
        key = (seq, len(data))
        if key in self._seen:
            return  # retransmission — skip
        self._seen.add(key)
        self._segments.append(_Segment(seq=seq, data=data))

    def reassemble(self) -> bytearray:
        """Return the reassembled byte stream in sequence-number order."""
        if not self._segments:
            return bytearray()
        # Sort by sequence number; ties broken by arrival order (stable sort).
        self._segments.sort(key=lambda s: s.seq)
        out = bytearray()
        for seg in self._segments:
            out += seg.data
        return out


# ---------------------------------------------------------------------------
# Stream dataclass
# ---------------------------------------------------------------------------

@dataclass
class Stream:
    """A bidirectional TCP stream.

    key convention: (server_ip, server_port, client_ip, client_port).
    """

    key: CounterKey
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_data: bytearray = field(default_factory=bytearray)
    server_data: bytearray = field(default_factory=bytearray)
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    packets: int = 0
    complete: bool = False

    def client_bytes(self) -> int:
        return len(self.client_data)

    def server_bytes(self) -> int:
        return len(self.server_data)


def normalize_key(lip: str, lport: int, rip: str, rport: int) -> CounterKey:
    """Return canonical key = (server, client).

    The endpoint on a well-known service port is treated as the server.
    """
    if lport in SERVER_PORTS or (rport not in SERVER_PORTS and lport < rport):
        return (lip, lport, rip, rport)
    return (rip, rport, lip, lport)


# ---------------------------------------------------------------------------
# Sequence-aware StreamReassembler
# ---------------------------------------------------------------------------

class StreamReassembler:
    """Reassembles TCP segments into directional byte streams.

    Segments are buffered per-direction and ordered by TCP sequence number
    at finalization time.  Exact-duplicate retransmissions are dropped.
    """

    def __init__(self) -> None:
        self.streams: Dict[CounterKey, Stream] = {}
        self._bufs: Dict[CounterKey, Tuple[_DirectionBuffer, _DirectionBuffer]] = {}
        # Track which streams had FIN or RST observed.
        self._fin_rst: Dict[CounterKey, bool] = {}

    def feed(self, ip: str, sport: int, dip: str, dport: int,
             payload: bytes, ts: float, seq: int = 0,
             fin: bool = False, rst: bool = False) -> None:
        if not ip or not dip:
            return
        # Allow packets with no payload but FIN/RST flags for completeness tracking.
        if not payload and not fin and not rst:
            return

        key = normalize_key(ip, sport, dip, dport)
        stream = self.streams.get(key)
        if stream is None:
            stream = Stream(
                key=key,
                server_ip=key[0],
                server_port=key[1],
                client_ip=key[2],
                client_port=key[3],
            )
            self.streams[key] = stream
            self._bufs[key] = (_DirectionBuffer(), _DirectionBuffer())

        stream.packets += 1
        if stream.start_ts is None or ts < stream.start_ts:
            stream.start_ts = ts
        if stream.end_ts is None or ts > stream.end_ts:
            stream.end_ts = ts

        if fin or rst:
            self._fin_rst[key] = True

        if payload:
            is_client = (ip, sport) == (key[2], key[3])
            client_buf, server_buf = self._bufs[key]
            if is_client:
                client_buf.add(seq, payload)
            else:
                server_buf.add(seq, payload)

    def finalize(self) -> None:
        """Reassemble all buffered segments into Stream.client_data / server_data
        in sequence-number order and set the `complete` flag.
        """
        for key, stream in self.streams.items():
            bufs = self._bufs.get(key)
            if bufs:
                client_buf, server_buf = bufs
                stream.client_data = client_buf.reassemble()
                stream.server_data = server_buf.reassemble()
            stream.complete = self._fin_rst.get(key, False)

    def sessions(self) -> Dict[CounterKey, Stream]:
        self.finalize()
        return self.streams


# ---------------------------------------------------------------------------
# Packet extraction helpers
# ---------------------------------------------------------------------------

def _fmt_ip(raw: bytes, v6: bool) -> str:
    try:
        if v6:
            return socket.inet_ntop(socket.AF_INET6, raw)
        return socket.inet_ntop(socket.AF_INET, raw)
    except Exception:
        return raw.hex()


def _ip_packets(ip, ts) -> Iterator[Tuple]:
    """Extract TCP payload tuples from a parsed dpkt IP object.

    Yields (src, sport, dst, dport, payload, ts, seq, fin, rst).
    """
    if not hasattr(ip, "p"):
        return
    proto = ip.p
    if proto == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        v6 = isinstance(ip, dpkt.ip6.IP6) if hasattr(dpkt, "ip6") else False
        src = _fmt_ip(ip.src, v6)
        dst = _fmt_ip(ip.dst, v6)
        sport = getattr(tcp, "sport", 0)
        dport = getattr(tcp, "dport", 0)
        payload = bytes(tcp.data) if hasattr(tcp, "data") else b""
        seq = getattr(tcp, "seq", 0)
        flags = getattr(tcp, "flags", 0)
        fin = bool(flags & dpkt.tcp.TH_FIN)
        rst = bool(flags & dpkt.tcp.TH_RST)
        yield (src, sport, dst, dport, payload, ts, seq, fin, rst)


def iter_packets(pcap_path: str, timeout: int = 120) -> Iterator[Tuple]:
    """Yield (src_ip, sport, dst_ip, dport, payload, ts, seq, fin, rst)
    tuples from a pcap.  Now includes TCP sequence number and FIN/RST flags.
    """
    t0 = time.time()
    if HAVE_DPKT:
        try:
            with open(pcap_path, "rb") as f:
                try:
                    reader = dpkt.pcap.Reader(f)
                except Exception:
                    f.seek(0)
                    reader = dpkt.pcapng.Reader(f)
                for ts, buf in reader:
                    if time.time() - t0 > timeout:
                        break
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue
                    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                        yield from _ip_packets(eth.data, ts)
                    elif eth.type == dpkt.ethernet.ETH_TYPE_IPV6:
                        yield from _ip_packets(eth.data, ts)
            return
        except Exception:
            # fall through to scapy
            pass
    yield from _scapy_iter(pcap_path)


def _scapy_iter(pcap_path: str) -> Iterator[Tuple]:
    """Fallback packet iterator using scapy.

    Yields the same 9-tuple as iter_packets so reassemble() is backend-agnostic.
    """
    try:
        from scapy.all import IP, TCP, rdpcap
    except Exception:
        return
    for p in rdpcap(pcap_path):
        ts = float(getattr(p, "time", 0.0))
        if IP in p and p.haslayer("TCP"):
            ip = p[IP]
            tcp = p["TCP"]
            payload = bytes(tcp.payload)
            seq = getattr(tcp, "seq", 0)
            flags = getattr(tcp, "flags", 0)
            # scapy flags: FIN=0x01, RST=0x04
            fin = bool(flags & 0x01)
            rst = bool(flags & 0x04)
            yield (ip.src, tcp.sport, ip.dst, tcp.dport,
                   payload, ts, seq, fin, rst)


# ---------------------------------------------------------------------------
# Top-level reassembly entry point
# ---------------------------------------------------------------------------

def reassemble(pcap_path: str) -> Dict[CounterKey, Stream]:
    """Load a pcap and return reassembled email-candidate streams.

    Non-email TCP traffic is excluded before full stream reassembly so
    that downstream analysis cost (TLS parsing, DNS lookups, rule engine)
    is bounded to relevant traffic only.
    """
    reassembler = StreamReassembler()

    # Track which 4-tuple keys have been classified as email candidates
    # so that subsequent packets on the same stream are always included
    # even if an individual packet's payload doesn't match a signature.
    candidate_keys: Set[CounterKey] = set()

    for src, sport, dst, dport, payload, ts, seq, fin, rst in iter_packets(pcap_path):
        key = normalize_key(src, sport, dst, dport)

        if key not in candidate_keys:
            # First time seeing this stream — decide if it's email-related.
            if not is_email_candidate(payload, sport, dport):
                # Not a candidate and no payload match — skip for now.
                # Note: if a later packet on this same 4-tuple *does* match,
                # we'll pick it up then (though earlier packets will be lost;
                # this is acceptable for mid-stream joins on non-standard ports).
                continue
            candidate_keys.add(key)

        # Feed the packet (including empty-payload FIN/RST for completeness).
        if payload or fin or rst:
            reassembler.feed(src, sport, dst, dport, payload, ts,
                             seq=seq, fin=fin, rst=rst)

    return reassembler.sessions()
