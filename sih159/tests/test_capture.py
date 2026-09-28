"""Unit tests for PCAP email-candidate filtering and TCP reassembly.

Covers:
  - Port-based email candidate detection
  - Payload-signature-based detection on non-standard ports
  - Out-of-order TCP segment reordering
  - Retransmission / duplicate segment deduplication
  - Non-email traffic exclusion from reassembly
  - Empty pcap handling
  - Stream completeness flagging (FIN/RST)
  - Integration with generate_sample_pcap (existing 4-session expectation)
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.capture import (
    EMAIL_PORTS,
    HAVE_DPKT,
    SERVER_PORTS,
    Stream,
    StreamReassembler,
    _DirectionBuffer,
    is_email_candidate,
    normalize_key,
    reassemble,
)


# ---------------------------------------------------------------------------
# is_email_candidate
# ---------------------------------------------------------------------------

class TestIsEmailCandidate:
    """Tests for the port + payload candidate filter."""

    def test_smtp_port_25(self):
        assert is_email_candidate(b"", 12345, 25) is True

    def test_smtp_port_465(self):
        assert is_email_candidate(b"", 12345, 465) is True

    def test_smtp_port_587(self):
        assert is_email_candidate(b"", 12345, 587) is True

    def test_imap_port_143(self):
        assert is_email_candidate(b"", 12345, 143) is True

    def test_imap_port_993(self):
        assert is_email_candidate(b"", 12345, 993) is True

    def test_pop3_port_110(self):
        assert is_email_candidate(b"", 12345, 110) is True

    def test_pop3_port_995(self):
        assert is_email_candidate(b"", 12345, 995) is True

    def test_source_port_is_email(self):
        """Email port as source should also match (server responding)."""
        assert is_email_candidate(b"", 25, 54321) is True

    def test_http_port_not_candidate(self):
        assert is_email_candidate(b"", 12345, 80) is False

    def test_http_port_with_http_payload(self):
        assert is_email_candidate(b"HTTP/1.1 200 OK\r\n", 12345, 80) is False

    def test_nonstandard_port_with_smtp_banner(self):
        """Email on a non-standard port detected via payload signature."""
        assert is_email_candidate(b"220 mail.example.com ESMTP\r\n", 12345, 8025) is True

    def test_nonstandard_port_with_imap_banner(self):
        assert is_email_candidate(b"* OK IMAP4rev1 ready\r\n", 12345, 9143) is True

    def test_nonstandard_port_with_pop3_banner(self):
        assert is_email_candidate(b"+OK POP3 server ready\r\n", 12345, 9110) is True

    def test_nonstandard_port_with_ehlo(self):
        assert is_email_candidate(b"EHLO client.local\r\n", 12345, 8025) is True

    def test_empty_payload_nonstandard_port(self):
        assert is_email_candidate(b"", 12345, 8025) is False

    def test_random_binary_nonstandard_port(self):
        assert is_email_candidate(b"\x00\x01\x02\x03\xff\xfe", 12345, 8025) is False


# ---------------------------------------------------------------------------
# EMAIL_PORTS / SERVER_PORTS backward compatibility
# ---------------------------------------------------------------------------

class TestEmailPorts:
    def test_email_ports_is_superset_of_server_ports(self):
        """SERVER_PORTS must equal set(EMAIL_PORTS.keys()) for backward compat."""
        assert SERVER_PORTS == set(EMAIL_PORTS.keys())

    def test_all_standard_email_ports_present(self):
        expected = {25, 465, 587, 110, 995, 143, 993}
        assert expected == set(EMAIL_PORTS.keys())


# ---------------------------------------------------------------------------
# _DirectionBuffer — sequence-number ordering & dedup
# ---------------------------------------------------------------------------

class TestDirectionBuffer:
    def test_in_order_segments(self):
        buf = _DirectionBuffer()
        buf.add(100, b"Hello")
        buf.add(105, b" World")
        result = buf.reassemble()
        assert result == bytearray(b"Hello World")

    def test_out_of_order_segments(self):
        buf = _DirectionBuffer()
        buf.add(105, b" World")
        buf.add(100, b"Hello")
        result = buf.reassemble()
        assert result == bytearray(b"Hello World")

    def test_retransmission_dedup(self):
        """Exact duplicate (same seq + same length) should be dropped."""
        buf = _DirectionBuffer()
        buf.add(100, b"Hello")
        buf.add(100, b"Hello")  # retransmission
        buf.add(105, b" World")
        result = buf.reassemble()
        assert result == bytearray(b"Hello World")

    def test_empty_buffer(self):
        buf = _DirectionBuffer()
        assert buf.reassemble() == bytearray()

    def test_single_segment(self):
        buf = _DirectionBuffer()
        buf.add(0, b"Only")
        assert buf.reassemble() == bytearray(b"Only")

    def test_many_out_of_order_segments(self):
        """Three segments arriving in reverse order."""
        buf = _DirectionBuffer()
        buf.add(200, b"CCC")
        buf.add(100, b"AAA")
        buf.add(150, b"BBB")
        result = buf.reassemble()
        assert result == bytearray(b"AAABBBCCC")


# ---------------------------------------------------------------------------
# StreamReassembler — integration
# ---------------------------------------------------------------------------

class TestStreamReassembler:
    def test_basic_reassembly_with_seq(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"220 OK\r\n", 1.0, seq=100)
        r.feed("10.0.0.2", 5000, "10.0.0.1", 25, b"EHLO x\r\n", 1.1, seq=200)
        streams = r.sessions()
        assert len(streams) == 1
        s = list(streams.values())[0]
        assert b"220 OK\r\n" in bytes(s.server_data)
        assert b"EHLO x\r\n" in bytes(s.client_data)

    def test_out_of_order_server_data(self):
        r = StreamReassembler()
        # Server sends two segments out of order
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"World", 1.1, seq=105)
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"Hello", 1.0, seq=100)
        streams = r.sessions()
        s = list(streams.values())[0]
        assert bytes(s.server_data) == b"HelloWorld"

    def test_duplicate_segment_dropped(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"Data", 1.0, seq=100)
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"Data", 1.1, seq=100)  # retransmit
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"More", 1.2, seq=104)
        streams = r.sessions()
        s = list(streams.values())[0]
        assert bytes(s.server_data) == b"DataMore"

    def test_fin_marks_complete(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"Data", 1.0, seq=100)
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"", 1.1, seq=104, fin=True)
        streams = r.sessions()
        s = list(streams.values())[0]
        assert s.complete is True

    def test_rst_marks_complete(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"Data", 1.0, seq=100)
        r.feed("10.0.0.2", 5000, "10.0.0.1", 25, b"", 1.1, seq=200, rst=True)
        streams = r.sessions()
        s = list(streams.values())[0]
        assert s.complete is True

    def test_no_fin_rst_incomplete(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"Data", 1.0, seq=100)
        streams = r.sessions()
        s = list(streams.values())[0]
        assert s.complete is False

    def test_empty_payload_no_flags_ignored(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"", 1.0, seq=100)
        streams = r.sessions()
        assert len(streams) == 0

    def test_packet_count_and_timestamps(self):
        r = StreamReassembler()
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"A", 10.0, seq=1)
        r.feed("10.0.0.2", 5000, "10.0.0.1", 25, b"B", 11.0, seq=1)
        r.feed("10.0.0.1", 25, "10.0.0.2", 5000, b"C", 12.0, seq=2)
        streams = r.sessions()
        s = list(streams.values())[0]
        assert s.packets == 3
        assert s.start_ts == 10.0
        assert s.end_ts == 12.0


# ---------------------------------------------------------------------------
# reassemble() — integration with filtering
# ---------------------------------------------------------------------------

class TestReassembleFiltering:
    def test_sample_pcap_still_produces_four_sessions(self, sample_pcap):
        """Guard rail: existing sample PCAP must still yield 4 sessions."""
        if not os.path.exists(sample_pcap):
            pytest.skip("sample_traffic.pcap not found")
        streams = reassemble(sample_pcap)
        assert len(streams) == 4

    def test_dpkt_is_active(self):
        """dpkt must be the active parser (not silently falling back)."""
        assert HAVE_DPKT is True


# ---------------------------------------------------------------------------
# Synthetic PCAP helpers for mixed-traffic tests
# ---------------------------------------------------------------------------

def _write_pcap_header(f):
    f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))


def _write_pcap_packet(f, ts_sec, ts_usec, packet_bytes):
    f.write(struct.pack("<IIII", int(ts_sec), int(ts_usec),
                        len(packet_bytes), len(packet_bytes)))
    f.write(packet_bytes)


def _ethernet_frame(payload):
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    return dst_mac + src_mac + struct.pack(">H", 0x0800) + payload


def _ip_tcp_segment(src_ip, dst_ip, sport, dport, payload, seq=0, flags=0x18):
    import socket as _socket
    tcp_header = struct.pack(">HHIIBBHHH",
                             sport, dport, seq, 0,
                             5 << 4, flags, 65535, 0, 0)
    tcp_header += payload
    ip_header = struct.pack(">BBHHHBBH4s4s",
                            0x45, 0, 20 + len(tcp_header),
                            1, 0, 64, 6, 0,
                            _socket.inet_aton(src_ip),
                            _socket.inet_aton(dst_ip))
    return ip_header + tcp_header


class TestMixedTrafficFiltering:
    """Tests using synthetic PCAPs with mixed email + non-email traffic."""

    def _write_mixed_pcap(self, path):
        """Write a PCAP with 1 SMTP stream (port 25) and 1 HTTP stream (port 80)."""
        with open(path, "wb") as f:
            _write_pcap_header(f)
            ts = 1700000000.0

            # SMTP stream: server 10.0.0.1:25, client 10.0.0.2:5000
            pkt = _ip_tcp_segment("10.0.0.1", "10.0.0.2", 25, 5000,
                                  b"220 mail.example.com ESMTP\r\n", seq=100)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
            ts += 0.1
            pkt = _ip_tcp_segment("10.0.0.2", "10.0.0.1", 5000, 25,
                                  b"EHLO client\r\n", seq=200)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))

            # HTTP stream: server 10.0.0.3:80, client 10.0.0.4:6000
            ts += 0.1
            pkt = _ip_tcp_segment("10.0.0.4", "10.0.0.3", 6000, 80,
                                  b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", seq=300)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
            ts += 0.1
            pkt = _ip_tcp_segment("10.0.0.3", "10.0.0.4", 80, 6000,
                                  b"HTTP/1.1 200 OK\r\n\r\n", seq=400)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))

    def test_http_traffic_excluded(self, tmp_path):
        """Non-email HTTP traffic must not appear in reassembled streams."""
        pcap_path = str(tmp_path / "mixed.pcap")
        self._write_mixed_pcap(pcap_path)
        streams = reassemble(pcap_path)
        assert len(streams) == 1  # only the SMTP stream
        s = list(streams.values())[0]
        assert s.server_port == 25

    def test_email_on_nonstandard_port_via_payload(self, tmp_path):
        """SMTP banner on a non-standard port (8025) should be detected."""
        pcap_path = str(tmp_path / "nonstandard.pcap")
        with open(pcap_path, "wb") as f:
            _write_pcap_header(f)
            ts = 1700000000.0
            pkt = _ip_tcp_segment("10.0.0.1", "10.0.0.2", 8025, 5000,
                                  b"220 hidden.smtp.com ESMTP\r\n", seq=100)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
        streams = reassemble(pcap_path)
        assert len(streams) == 1

    def test_empty_pcap(self, tmp_path):
        """Empty PCAP (header only) should return zero streams."""
        pcap_path = str(tmp_path / "empty.pcap")
        with open(pcap_path, "wb") as f:
            _write_pcap_header(f)
        streams = reassemble(pcap_path)
        assert len(streams) == 0

    def test_out_of_order_reassembly_via_pcap(self, tmp_path):
        """Segments arriving out of order should be reassembled by seq number."""
        pcap_path = str(tmp_path / "ooo.pcap")
        with open(pcap_path, "wb") as f:
            _write_pcap_header(f)
            ts = 1700000000.0
            # Second segment arrives first in capture
            pkt = _ip_tcp_segment("10.0.0.1", "10.0.0.2", 25, 5000,
                                  b" ESMTP\r\n", seq=104)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
            ts += 0.1
            # First segment arrives second in capture
            pkt = _ip_tcp_segment("10.0.0.1", "10.0.0.2", 25, 5000,
                                  b"220 ", seq=100)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
        streams = reassemble(pcap_path)
        assert len(streams) == 1
        s = list(streams.values())[0]
        # Data must be in seq-number order, not capture order
        assert bytes(s.server_data) == b"220  ESMTP\r\n"

    def test_retransmission_dedup_via_pcap(self, tmp_path):
        """Duplicate segments in PCAP should not appear twice in stream."""
        pcap_path = str(tmp_path / "retransmit.pcap")
        with open(pcap_path, "wb") as f:
            _write_pcap_header(f)
            ts = 1700000000.0
            data = b"220 mail.example.com ESMTP\r\n"
            pkt = _ip_tcp_segment("10.0.0.1", "10.0.0.2", 25, 5000, data, seq=100)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
            ts += 0.05
            # Exact retransmission
            pkt = _ip_tcp_segment("10.0.0.1", "10.0.0.2", 25, 5000, data, seq=100)
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
        streams = reassemble(pcap_path)
        s = list(streams.values())[0]
        assert bytes(s.server_data) == data  # only once, not doubled


class TestNonTcpTraffic:
    """PCAP with no TCP traffic should produce zero streams."""

    def test_udp_only_pcap(self, tmp_path):
        """A pcap with only UDP packets should return empty."""
        pcap_path = str(tmp_path / "udp.pcap")
        with open(pcap_path, "wb") as f:
            _write_pcap_header(f)
            ts = 1700000000.0
            # Build a UDP packet (protocol=17)
            import socket as _socket
            udp_payload = b"DNS query data"
            udp_header = struct.pack(">HHHH", 12345, 53, 8 + len(udp_payload), 0) + udp_payload
            ip_header = struct.pack(">BBHHHBBH4s4s",
                                    0x45, 0, 20 + len(udp_header),
                                    1, 0, 64, 17, 0,  # protocol 17 = UDP
                                    _socket.inet_aton("10.0.0.1"),
                                    _socket.inet_aton("10.0.0.2"))
            pkt = ip_header + udp_header
            _write_pcap_packet(f, ts, 0, _ethernet_frame(pkt))
        streams = reassemble(pcap_path)
        assert len(streams) == 0
