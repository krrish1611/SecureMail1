#!/usr/bin/env python3
"""Generate synthetic PCAP files with various email TLS configurations for testing.

Produces a sample PCAP with:
  - An SMTP+STARTTLS session with RC4 cipher (weak)
  - An IMAP session with TLS 1.0 and no forward secrecy
  - A POP3 session with TLS 1.3 and strong cipher
  - An SMTP session with no STARTTLS (plaintext credentials)

Usage: python generate_sample_pcap.py [output.pcap]
"""

from __future__ import annotations

import os
import struct
import socket
import sys
import time


def _write_pcap_header(f):
    # Global header: magic=0xa1b2c3d4, version 2.4, snaplen=65535, linktype=1 (Ethernet)
    f.write(struct.pack("<IHHiIII",
                        0xa1b2c3d4,  # magic
                        2, 4,          # version
                        0,             # timezone
                        0,             # sigfigs
                        65535,         # snaplen
                        1))            # Ethernet


def _write_pcap_packet(f, ts_sec, ts_usec, packet_bytes):
    """Write a single packet record to the pcap file."""
    f.write(struct.pack("<IIII",
                        int(ts_sec),
                        int(ts_usec),
                        len(packet_bytes),
                        len(packet_bytes)))
    f.write(packet_bytes)


def _ethernet_frame(dst_mac, src_mac, eth_type, payload):
    """Build an Ethernet frame."""
    def mac_bytes(mac):
        return bytes(int(x, 16) for x in mac.split(":"))
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(">H", eth_type) + payload


def _ip_tcp_segment(src_ip, dst_ip, sport, dport, payload, flags=0x02,
                     seq=0, ack=0, window=65535):
    """Build IP header + TCP header + payload (no options)."""
    # TCP header (20 bytes)
    tcp_header = struct.pack(">HHIIBBHHH",
                             sport, dport,
                             seq, ack,
                             5 << 4,  # data offset: 5*4=20 bytes
                             flags, window, 0, 0)  # checksum=0, urgent=0
    tcp_header += payload
    tcp_len = len(tcp_header)
    # IP header (20 bytes, protocol=6/TCP, no options)
    ip_header = struct.pack(">BBHHHBBH4s4s",
                            0x45, 0,             # ver/IHL, DSCP/ECN
                            20 + tcp_len,         # total length
                            0x0001, 0x0000,       # identification, flags+frag
                            64, 6, 0,             # TTL, protocol, checksum (0=calc later)
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))
    return ip_header + tcp_header


def _tls_record(content_type, version, payload):
    """Wrap a handshake payload in a TLS record."""
    return bytes([content_type]) + struct.pack(">HH", version, len(payload)) + payload


def _handshake_msg(htype, body):
    """Wrap body in a TLS handshake message header."""
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def _client_hello(version, random, cipher_suites, sni=None, tls13=False, key_share_group=None):
    """Build a structurally valid ClientHello."""
    body = bytearray()
    body += struct.pack(">H", version)
    body += random
    body += b"\x00"                      # session id len
    body += struct.pack(">H", len(cipher_suites) * 2)
    for c in cipher_suites:
        body += struct.pack(">H", c)
    body += b"\x01\x00"                  # compression methods: [null]
    # extensions
    ext_list = bytearray()
    if sni:
        ec = sni.encode()
        host = b"\x00" + struct.pack(">H", len(ec)) + ec        # name_type + name_len + name
        name_list = struct.pack(">H", len(host)) + host          # server_name_list length prefix
        ext_list += b"\x00\x00" + struct.pack(">H", len(name_list)) + name_list
    if tls13:
        # supported_versions: type 0x0029; data: [len][versions...]
        sv_data = b"\x04" + struct.pack(">HH", 0x0304, 0x0303)
        ext_list += struct.pack(">HH", 0x0029, len(sv_data)) + sv_data
        if key_share_group:
            # key_share: type 0x0033; [2B listlen][ group(2) len(2) keydata ]
            ks = struct.pack(">HH", key_share_group, 32) + b"\x00" * 32
            ext_list += struct.pack(">HH", 0x0033, len(ks) + 2) + struct.pack(">H", len(ks)) + ks
    body += struct.pack(">H", len(ext_list))
    body += ext_list
    hs = _handshake_msg(0x01, bytes(body))
    return _tls_record(0x16, 0x0303, hs)


def _server_hello(version, cipher_suite, tls13=False):
    """Build a structurally valid ServerHello."""
    body = bytearray()
    body += struct.pack(">H", version)
    body += b"\x00" * 32                 # random
    body += b"\x00"                      # session id len
    body += struct.pack(">H", cipher_suite)
    body += b"\x00"                      # compression: null
    ext_list = bytearray()
    if tls13:
        # supported_versions ext: type 0x0029, len 2, version 0x0304
        ext_list += struct.pack(">HHH", 0x0029, 0x0002, 0x0304)
    body += struct.pack(">H", len(ext_list))
    body += ext_list
    hs = _handshake_msg(0x02, bytes(body))
    return _tls_record(0x16, version, hs)


def _tcp_handshake(src_ip, dst_ip, sport, dport, ts):
    """Yield SYN, SYN-ACK, ACK packets and their timestamps."""
    payload = b""
    flags_syn = 0x02
    flags_syn_ack = 0x12
    flags_ack = 0x10
    seq1 = 1000
    seq2 = 2000
    frames = []
    frames.append((_ip_tcp_segment(src_ip, dst_ip, sport, dport, b"", flags=flags_syn, seq=seq1), ts))
    frames.append((_ip_tcp_segment(dst_ip, src_ip, dport, sport, b"", flags=flags_syn_ack, seq=seq2, ack=seq1+1), ts + 0.01))
    frames.append((_ip_tcp_segment(src_ip, dst_ip, sport, dport, b"", flags=flags_ack, seq=seq1+1, ack=seq2+1), ts + 0.02))
    return frames, seq1+1, seq2+1


def _build_smtp_banner(src_ip, dst_ip, sport, dport, ts, banner_bytes):
    flags_psh_ack = 0x18
    frames = []
    seq_c = 1001
    seq_s = 2001
    frames.append((_ip_tcp_segment(src_ip, dst_ip, sport, dport, banner_bytes, flags=flags_psh_ack, seq=seq_s, ack=seq_c), ts))
    return frames, seq_c, seq_s


def _build_data_packet(src_ip, dst_ip, sport, dport, data, seq, ack, ts):
    flags_psh_ack = 0x18
    return (_ip_tcp_segment(src_ip, dst_ip, sport, dport, data, flags=flags_psh_ack, seq=seq, ack=ack), ts)


def _write_synthetic_sessions(output_path: str):
    """
    Create synthetic email sessions with various TLS configurations.

    Session 1: SMTP + STARTTLS with weak RC4 cipher (TLS 1.2)
    Session 2: IMAP over TLS 1.0 with RSA key exchange (no forward secrecy)
    Session 3: POP3 with strong TLS 1.3 and ECDHE
    Session 4: SMTP plaintext with no STARTTLS
    """
    print(f"[*] Generating synthetic PCAP: {output_path}")

    # Session 1: SMTP + STARTTLS (weak: RC4, TLS 1.2)
    # Client IP: 10.0.0.2, Server IP: 10.0.0.1:25
    smtp_banner = b"220 mail.example.com ESMTP\r\n"
    smtp_helo = b"EHLO client.local\r\n"
    smtp_starttls = b"STARTTLS\r\n"
    smtp_starttls_ok = b"220 Ready to start TLS\r\n"
    client_hello_tls12_weak = _client_hello(
        0x0303, b"\x00" * 32,
        [0x0005, 0x000a],  # RC4_128_SHA, 3DES
        sni="mail.example.com",
    )
    server_hello_weak = _server_hello(0x0303, 0x0005)  # RC4_128_SHA

    # Session 2: IMAP over TLS 1.0 with RSA key exchange
    imap_banner = b"* OK IMAP4rev1 Server Ready\r\n"
    imap_tls_client = _client_hello(0x0301, b"\x00" * 32, [0x0035])  # TLS 1.0, AES_256_CBC_SHA
    imap_tls_server = _server_hello(0x0301, 0x0035)

    # Session 3: POP3 with strong TLS 1.3
    pop_banner = b"+OK POP3 server ready\r\n"
    pop_tls_client = _client_hello(0x0303, b"\x00" * 32, [0x1301, 0x1302], tls13=True, key_share_group=0x001d)  # TLS1.3, x25519
    pop_tls_server = _server_hello(0x0303, 0x1301, tls13=True)  # TLS1.3 AES_128_GCM

    # Session 4: SMTP plaintext with AUTH LOGIN (no STARTTLS)
    smtp_banner_no_tls = b"220 mail.example.com ESMTP\r\n"
    smtp_helo_no_tls = b"EHLO client.local\r\n"
    smtp_auth_plaintext = b"AUTH LOGIN\r\n"

    with open(output_path, "wb") as f:
        _write_pcap_header(f)
        ts = 1700000000.0

        # Session 1: SMTP + STARTTLS with weak RC4 (TLS 1.2)
        src, dst = "10.0.0.2", "10.0.0.1"
        sp, dp = 49100, 25
        frames, ack_c, ack_s = _tcp_handshake(src, dst, sp, dp, ts)
        for pkt, t in frames:
            _write_pcap_packet(f, t, int((t % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt))
        ts += 0.05
        # SMTP banner
        banner_pkt = _build_data_packet(dst, src, dp, sp, smtp_banner, ack_s, ack_c, ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, banner_pkt[0]))
        ts += 0.01
        ack_pkt = _ip_tcp_segment(src, dst, sp, dp, b"", flags=0x10, seq=ack_c, ack=ack_s + len(smtp_banner))
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, ack_pkt))
        ts += 0.01
        # EHLO
        pkt = _build_data_packet(src, dst, sp, dp, smtp_helo, ack_c, ack_s + len(smtp_banner), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))
        ack_s2 = ack_s + len(smtp_banner)
        ts += 0.01
        # STARTTLS
        pkt = _build_data_packet(src, dst, sp, dp, smtp_starttls, ack_c + len(smtp_helo), ack_s2, ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))
        ts += 0.01
        # 220 Ready
        pkt = _build_data_packet(dst, src, dp, sp, smtp_starttls_ok, ack_s2, ack_c + len(smtp_helo) + len(smtp_starttls), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))
        ts += 0.01
        # ClientHello (TLS 1.2 weak)
        pkt = _build_data_packet(src, dst, sp, dp, client_hello_tls12_weak,
                                 ack_c + len(smtp_helo) + len(smtp_starttls),
                                 ack_s2 + len(smtp_starttls_ok), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))
        ts += 0.01
        # ServerHello
        pkt = _build_data_packet(dst, src, dp, sp, server_hello_weak,
                                 ack_s2 + len(smtp_starttls_ok),
                                 ack_c + len(smtp_helo) + len(smtp_starttls) + len(client_hello_tls12_weak), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))

        # Session 2: IMAP TLS 1.0 (no FS, static RSA)
        ts += 0.5
        src2, dst2 = "10.0.0.3", "10.0.0.1"
        sp2, dp2 = 49200, 143
        frames, ack_c2, ack_s2 = _tcp_handshake(src2, dst2, sp2, dp2, ts)
        for pkt, t in frames:
            _write_pcap_packet(f, t, int(((t) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt))
        ts += 0.05
        # IMAP banner
        pkt = _build_data_packet(dst2, src2, dp2, sp2, imap_banner, ack_s2, ack_c2, ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))
        ts += 0.01
        # ClientHello TLS 1.0
        pkt = _build_data_packet(src2, dst2, sp2, dp2, imap_tls_client, ack_c2, ack_s2 + len(imap_banner), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))
        ts += 0.01
        # ServerHello TLS 1.0
        pkt = _build_data_packet(dst2, src2, dp2, sp2, imap_tls_server, ack_s2 + len(imap_banner),
                                 ack_c2 + len(imap_tls_client), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))

        # Session 3: POP3 with strong TLS 1.3
        ts += 0.5
        src3, dst3 = "10.0.0.4", "10.0.0.1"
        sp3, dp3 = 49300, 110
        frames, ack_c3, ack_s3 = _tcp_handshake(src3, dst3, sp3, dp3, ts)
        for pkt, t in frames:
            _write_pcap_packet(f, t, int(((t) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt))
        ts += 0.05
        # POP3 banner
        pkt = _build_data_packet(dst3, src3, dp3, sp3, pop_banner, ack_s3, ack_c3, ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))
        ts += 0.01
        # ClientHello TLS 1.3
        pkt = _build_data_packet(src3, dst3, sp3, dp3, pop_tls_client, ack_c3, ack_s3 + len(pop_banner), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))
        ts += 0.01
        # ServerHello
        pkt = _build_data_packet(dst3, src3, dp3, sp3, pop_tls_server, ack_s3 + len(pop_banner),
                                 ack_c3 + len(pop_tls_client), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))

        # Session 4: SMTP plaintext with no STARTTLS (credentials in clear)
        ts += 0.5
        src4, dst4 = "10.0.0.5", "10.0.0.1"
        sp4, dp4 = 49400, 25
        frames, ack_c4, ack_s4 = _tcp_handshake(src4, dst4, sp4, dp4, ts)
        for pkt, t in frames:
            _write_pcap_packet(f, t, int(((t) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt))
        ts += 0.05
        pkt = _build_data_packet(dst4, src4, dp4, sp4, smtp_banner_no_tls, ack_s4, ack_c4, ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", 0x0800, pkt[0]))
        ts += 0.01
        pkt = _build_data_packet(src4, dst4, sp4, dp4, smtp_helo_no_tls, ack_c4, ack_s4 + len(smtp_banner_no_tls), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))
        ts += 0.01
        # AUTH LOGIN in plaintext (no STARTTLS!)
        pkt = _build_data_packet(src4, dst4, sp4, dp4, smtp_auth_plaintext,
                                 ack_c4 + len(smtp_helo_no_tls),
                                 ack_s4 + len(smtp_banner_no_tls), ts)
        _write_pcap_packet(f, ts, int(((ts) % 1) * 1e6), _ethernet_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", 0x0800, pkt[0]))

    print(f"[+] Generated {output_path}")
    print("    Session 1: SMTP+STARTTLS weak (RC4, TLS 1.2)")
    print("    Session 2: IMAP TLS 1.0 (no forward secrecy)")
    print("    Session 3: POP3 TLS 1.3 (strong)")
    print("    Session 4: SMTP plaintext (credentials exposed)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "deps/sample_traffic.pcap"
    _write_synthetic_sessions(out)
