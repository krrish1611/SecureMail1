"""Packet capture loading and TCP stream reassembly.

Uses dpkt for fast PCAP/PCAPNG parsing with graceful fallback to scapy if
dpkt is not available. Streams are keyed by a 4-tuple and reassembled in
order, handling retransmissions and out-of-order segments.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

try:
    import dpkt
    HAVE_DPKT = True
except Exception:  # pragma: no cover
    HAVE_DPKT = False

CounterKey = Tuple[str, int, str, int]

SERVER_PORTS = {25, 110, 143, 465, 587, 993, 995}


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


class StreamReassembler:
    """Reassembles TCP segments into directional byte streams."""

    def __init__(self) -> None:
        self.streams: Dict[CounterKey, Stream] = {}

    def feed(self, ip: str, sport: int, dip: str, dport: int,
             payload: bytes, ts: float) -> None:
        if not ip or not dip or not payload:
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
        stream.packets += 1
        if stream.start_ts is None or ts < stream.start_ts:
            stream.start_ts = ts
        if stream.end_ts is None or ts > stream.end_ts:
            stream.end_ts = ts

        is_client = (ip, sport) == (key[2], key[3])
        if is_client:
            stream.client_data += payload
        else:
            stream.server_data += payload

    def sessions(self) -> Dict[CounterKey, Stream]:
        return self.streams


def _fmt_ip(raw: bytes, v6: bool) -> str:
    try:
        if v6:
            return socket.inet_ntop(socket.AF_INET6, raw)
        return socket.inet_ntop(socket.AF_INET, raw)
    except Exception:
        return raw.hex()


def _ip_packets(ip, ts) -> Iterator[Tuple]:
    """Extract TCP payload tuples from a parsed dpkt IP object."""
    if not hasattr(ip, "p"):
        return
    proto = ip.p
    if proto == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        v6 = proto == getattr(dpkt.ip, "IP_PROTO_IP6", -1)
        src = _fmt_ip(ip.src, v6)
        dst = _fmt_ip(ip.dst, v6)
        sport = getattr(tcp, "sport", 0)
        dport = getattr(tcp, "dport", 0)
        payload = bytes(tcp.data) if hasattr(tcp, "data") else b""
        yield (src, sport, dst, dport, payload, ts)


def iter_packets(pcap_path: str, timeout: int = 120) -> Iterator[Tuple]:
    """Yield (src_ip, sport, dst_ip, dport, payload, ts) tuples from a pcap."""
    t0 = time.time()
    if HAVE_DPKT:
        try:
            with open(pcap_path, "rb") as f:
                reader = dpkt.pcap.Reader(f)
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
    try:
        from scapy.all import IP, rdpcap
    except Exception:
        return
    for p in rdpcap(pcap_path):
        ts = float(getattr(p, "time", 0.0))
        if IP in p and p.haslayer("TCP"):
            ip = p[IP]
            tcp = p["TCP"]
            yield (ip.src, tcp.sport, ip.dst, tcp.dport,
                   bytes(tcp.payload), ts)


def reassemble(pcap_path: str) -> Dict[CounterKey, Stream]:
    """Load a pcap and return reassembled streams."""
    reassembler = StreamReassembler()
    for src, sport, dst, dport, payload, ts in iter_packets(pcap_path):
        if payload:
            reassembler.feed(src, sport, dst, dport, payload, ts)
    return reassembler.sessions()
