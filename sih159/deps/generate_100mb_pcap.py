#!/usr/bin/env python3
"""Generate a ~100MB synthetic PCAP file with email traffic.

Includes realistic email protocol flows:
1. Decrypted / Plaintext:
   - Plaintext SMTP (EHLO, MAIL FROM, RCPT TO, DATA email transfer, AUTH PLAIN)
   - Plaintext IMAP (LOGIN, SELECT INBOX, FETCH emails)
   - Plaintext POP3 (USER, PASS, STAT, LIST, RETR, QUIT)
2. Encrypted (TLS Handshakes & Encrypted Application Data records):
   - SMTP with STARTTLS transitioning to TLS 1.2 / TLS 1.3
   - IMAPS (port 993) direct TLS Handshake + TLS Application Data
   - POP3S (port 995) direct TLS Handshake + TLS Application Data
   - SMTPS (port 465) direct TLS Handshake + TLS Application Data

Padded with realistic payload blocks to reach exactly ~100MB target size.
"""

import os
import struct
import socket
import sys
import time

TARGET_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


def write_pcap_header(f):
    """Global header: magic=0xa1b2c3d4, version 2.4, snaplen=65535, linktype=1 (Ethernet)"""
    f.write(struct.pack("<IHHiIII",
                        0xa1b2c3d4,
                        2, 4,
                        0, 0,
                        65535,
                        1))


def write_pcap_packet(f, ts_sec, ts_usec, packet_bytes):
    """Write packet header + packet data."""
    length = len(packet_bytes)
    f.write(struct.pack("<IIII", int(ts_sec), int(ts_usec), length, length))
    f.write(packet_bytes)
    return 16 + length


def ethernet_frame(dst_mac, src_mac, eth_type, payload):
    def mac_bytes(mac):
        return bytes(int(x, 16) for x in mac.split(":"))
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(">H", eth_type) + payload


def ip_tcp_segment(src_ip, dst_ip, sport, dport, payload, flags=0x18, seq=1000, ack=1000, window=65535):
    tcp_header = struct.pack(">HHIIBBHHH",
                             sport, dport,
                             seq, ack,
                             5 << 4,
                             flags, window, 0, 0)
    tcp_data = tcp_header + payload
    tcp_len = len(tcp_data)
    ip_header = struct.pack(">BBHHHBBH4s4s",
                            0x45, 0,
                            20 + tcp_len,
                            0x1234, 0x0000,
                            64, 6, 0,
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))
    return ip_header + tcp_data


def tls_record(content_type, version, payload):
    return bytes([content_type]) + struct.pack(">HH", version, len(payload)) + payload


def client_hello(version, cipher_suites, sni=None, tls13=False):
    body = bytearray()
    body += struct.pack(">H", version)
    body += b"\x5a" * 32  # random
    body += b"\x00"        # session id len
    body += struct.pack(">H", len(cipher_suites) * 2)
    for c in cipher_suites:
        body += struct.pack(">H", c)
    body += b"\x01\x00"    # compression methods
    ext_list = bytearray()
    if sni:
        ec = sni.encode()
        host = b"\x00" + struct.pack(">H", len(ec)) + ec
        name_list = struct.pack(">H", len(host)) + host
        ext_list += b"\x00\x00" + struct.pack(">H", len(name_list)) + name_list
    if tls13:
        # supported_versions (0x0029)
        ext_list += struct.pack(">HH", 0x0029, 3) + b"\x02\x03\x04"
    if ext_list:
        body += struct.pack(">H", len(ext_list)) + ext_list
    return tls_record(0x16, version, bytes([0x01]) + len(body).to_bytes(3, "big") + body)


def server_hello(version, cipher_suite, tls13=False):
    body = bytearray()
    body += struct.pack(">H", version)
    body += b"\x3c" * 32
    body += b"\x00"
    body += struct.pack(">H", cipher_suite)
    body += b"\x00"
    ext_list = bytearray()
    if tls13:
        ext_list += struct.pack(">HH", 0x0029, 2) + struct.pack(">H", 0x0304)
    if ext_list:
        body += struct.pack(">H", len(ext_list)) + ext_list
    return tls_record(0x16, version, bytes([0x02]) + len(body).to_bytes(3, "big") + body)


def generate_100mb_pcap(output_path="test_traffic_100mb.pcap"):
    print(f"[*] Creating 100MB PCAP file: {output_path}...")
    start_time = time.time()
    
    mac_srv = "00:50:56:c0:00:01"
    mac_cli = "00:0c:29:ab:cd:ef"
    server_ip = "192.168.1.50"
    client_ip = "192.168.1.120"
    
    total_bytes = 0
    ts = 1710330000.0

    # Decrypted / Plaintext Conversations
    plaintext_smtp_chunks = [
        (True, b"220 mail.corp-secure.local ESMTP Postfix (Ubuntu)\r\n"),
        (False, b"EHLO laptop-worker.corp.internal\r\n"),
        (True, b"250-mail.corp-secure.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"),
        (False, b"AUTH PLAIN AHVzZXJAY29ycC5sb2NhbABQQHNzd29yZDEyMw==\r\n"),
        (True, b"235 2.7.0 Authentication successful\r\n"),
        (False, b"MAIL FROM:<alice.smith@corp-secure.local> BODY=8BITMIME\r\n"),
        (True, b"250 2.1.0 Ok\r\n"),
        (False, b"RCPT TO:<bob.jones@partner-agency.com>\r\n"),
        (True, b"250 2.1.5 Ok\r\n"),
        (False, b"DATA\r\n"),
        (True, b"354 End data with <CR><LF>.<CR><LF>\r\n"),
    ]

    plaintext_imap_chunks = [
        (True, b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE] Dovecot ready.\r\n"),
        (False, b"a001 LOGIN alice.smith SecretPass987!\r\n"),
        (True, b"a001 OK [CAPABILITY IMAP4rev1] Logged in successfully\r\n"),
        (False, b"a002 SELECT INBOX\r\n"),
        (True, b"* 42 EXISTS\r\n* 2 RECENT\r\n* OK [UNSEEN 12] First unseen\r\n* OK [UIDVALIDITY 16892341] UIDs valid\r\na002 OK [READ-WRITE] Select completed\r\n"),
        (False, b"a003 FETCH 42 (BODY[HEADER.FIELDS (SUBJECT FROM DATE)])\r\n"),
        (True, b"* 42 FETCH (BODY[HEADER.FIELDS (SUBJECT FROM DATE)] {112}\r\nSubject: Project Alpha Q3 Quarterly Financial Review\r\nFrom: bob.jones@corp-secure.local\r\nDate: Mon, 12 Sep 2026 10:15:30 +0000\r\n\r\n)\r\na003 OK Fetch completed\r\n"),
        (False, b"a004 LOGOUT\r\n"),
        (True, b"* BYE Logging out\r\na004 OK Logout completed\r\n"),
    ]

    plaintext_pop3_chunks = [
        (True, b"+OK POP3 server ready <1892.17000000@mail.corp-secure.local>\r\n"),
        (False, b"USER charlie.evans@corp-secure.local\r\n"),
        (True, b"+OK send password\r\n"),
        (False, b"PASS CharlieWinter2026$\r\n"),
        (True, b"+OK Mailbox open, 14 messages\r\n"),
        (False, b"STAT\r\n"),
        (True, b"+OK 14 1048576\r\n"),
        (False, b"LIST\r\n"),
        (True, b"+OK 14 messages (1048576 octets)\r\n1 4500\r\n2 12040\r\n3 8920\r\n.\r\n"),
        (False, b"RETR 1\r\n"),
        (True, b"+OK 4500 octets\r\nFrom: admin@corp-secure.local\r\nTo: charlie.evans@corp-secure.local\r\nSubject: Internal Security Advisory - TLS 1.0 Deprecation\r\n\r\nPlease upgrade mail clients to support TLS 1.2+ immediately.\r\n.\r\n"),
        (False, b"QUIT\r\n"),
        (True, b"+OK Bye-bye\r\n"),
    ]

    # Encrypted Handshakes
    # 1. SMTP STARTTLS -> TLS 1.2 (ECDHE-RSA-AES128-GCM-SHA256: 0xc02f)
    smtp_tls_ch = client_hello(0x0303, [0xc02f, 0xc030, 0xcca8], sni="smtp.corp-secure.local")
    smtp_tls_sh = server_hello(0x0303, 0xc02f)

    # 2. IMAPS (993) -> TLS 1.3 (AES-256-GCM-SHA384: 0x1302)
    imaps_tls_ch = client_hello(0x0303, [0x1301, 0x1302, 0x1303], sni="imap.corp-secure.local", tls13=True)
    imaps_tls_sh = server_hello(0x0303, 0x1302, tls13=True)

    # 3. POP3S (995) -> TLS 1.2 (ECDHE-RSA-AES256-GCM-SHA384: 0xc030)
    pop3s_tls_ch = client_hello(0x0303, [0xc030, 0xc02f], sni="pop.corp-secure.local")
    pop3s_tls_sh = server_hello(0x0303, 0xc030)

    # Large payloads
    # Plaintext Email message data chunks (Decrypted email body)
    sample_email_body_template = (
        b"Received: by mail.corp-secure.local (Postfix, from userid 1001)\r\n"
        b"From: alice.smith@corp-secure.local\r\n"
        b"To: bob.jones@partner-agency.com\r\n"
        b"Subject: Confidential Architecture & Vulnerability Audit Report\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=UTF-8\r\n"
        b"\r\n"
        b"Hello Bob,\r\n\r\n"
        b"Attached is the full summary of unencrypted vs encrypted communications observed\r\n"
        b"across the corporate mail relay. Plaintext protocols (port 25, 110, 143) expose\r\n"
        b"user credentials and raw transmission contents over the wire.\r\n"
        b"Payload data filler block: " + (b"A" * 1200) + b"\r\n"
    )

    # Encrypted TLS Application Data record (0x17)
    # 1400 bytes of encrypted ciphertext payload
    tls_app_data_payload = os.urandom(1400)
    encrypted_record = tls_record(0x17, 0x0303, tls_app_data_payload)

    with open(output_path, "wb") as f:
        write_pcap_header(f)
        total_bytes += 24

        def write_pkt(src_i, dst_i, sp, dp, payload, is_server):
            nonlocal total_bytes, ts
            ts += 0.0005
            src_m = mac_srv if is_server else mac_cli
            dst_m = mac_cli if is_server else mac_srv
            ip_tcp = ip_tcp_segment(src_i, dst_i, sp, dp, payload)
            eth = ethernet_frame(dst_m, src_m, 0x0800, ip_tcp)
            written = write_pcap_packet(f, ts, int((ts % 1) * 1e6), eth)
            total_bytes += written

        # Write representative header conversations first:
        # Session 1: Plaintext SMTP
        for is_srv, chunk in plaintext_smtp_chunks:
            write_pkt(server_ip if is_srv else client_ip, client_ip if is_srv else server_ip, 25 if is_srv else 45100, 45100 if is_srv else 25, chunk, is_srv)

        # Session 2: Plaintext IMAP
        for is_srv, chunk in plaintext_imap_chunks:
            write_pkt(server_ip if is_srv else client_ip, client_ip if is_srv else server_ip, 143 if is_srv else 45101, 45101 if is_srv else 143, chunk, is_srv)

        # Session 3: Plaintext POP3
        for is_srv, chunk in plaintext_pop3_chunks:
            write_pkt(server_ip if is_srv else client_ip, client_ip if is_srv else server_ip, 110 if is_srv else 45102, 45102 if is_srv else 110, chunk, is_srv)

        # Session 4: SMTPS / STARTTLS (Port 587) - Handshake
        write_pkt(server_ip, client_ip, 587, 45103, b"220 smtp.corp-secure.local ESMTP Postfix\r\n", True)
        write_pkt(client_ip, server_ip, 45103, 587, b"STARTTLS\r\n", False)
        write_pkt(server_ip, client_ip, 587, 45103, b"220 2.0.0 Ready to start TLS\r\n", True)
        write_pkt(client_ip, server_ip, 45103, 587, smtp_tls_ch, False)
        write_pkt(server_ip, client_ip, 587, 45103, smtp_tls_sh, True)

        # Session 5: IMAPS (Port 993) - Encrypted Handshake
        write_pkt(client_ip, server_ip, 45104, 993, imaps_tls_ch, False)
        write_pkt(server_ip, client_ip, 993, 45104, imaps_tls_sh, True)

        # Session 6: POP3S (Port 995) - Encrypted Handshake
        write_pkt(client_ip, server_ip, 45105, 995, pop3s_tls_ch, False)
        write_pkt(server_ip, client_ip, 995, 45105, pop3s_tls_sh, True)

        # Bulk Generation to hit ~100MB
        # Alternating between decrypted plaintext payloads (SMTP data/IMAP/POP3)
        # and encrypted TLS Application Data (Port 587, 993, 995)
        print("[*] Generating high-volume email traffic streams (mix of encrypted & decrypted)...")
        iteration = 0
        while total_bytes < TARGET_SIZE_BYTES:
            iteration += 1

            # 1. Decrypted SMTP large message transfer
            write_pkt(client_ip, server_ip, 45100, 25, sample_email_body_template, False)
            if total_bytes >= TARGET_SIZE_BYTES:
                break

            # 2. Encrypted TLS Application Data on IMAPS (Port 993)
            write_pkt(server_ip, client_ip, 993, 45104, encrypted_record, True)
            if total_bytes >= TARGET_SIZE_BYTES:
                break

            # 3. Decrypted POP3 email RETR retrieval
            write_pkt(server_ip, client_ip, 110, 45102, sample_email_body_template, True)
            if total_bytes >= TARGET_SIZE_BYTES:
                break

            # 4. Encrypted TLS Application Data on SMTPS (Port 587)
            write_pkt(client_ip, server_ip, 45103, 587, encrypted_record, False)
            if total_bytes >= TARGET_SIZE_BYTES:
                break

            # 5. Encrypted TLS Application Data on POP3S (Port 995)
            write_pkt(server_ip, client_ip, 995, 45105, encrypted_record, True)
            if total_bytes >= TARGET_SIZE_BYTES:
                break

            # 6. Decrypted IMAP mail body fetch
            write_pkt(server_ip, client_ip, 143, 45101, sample_email_body_template, True)

            if iteration % 5000 == 0:
                mb = total_bytes / (1024 * 1024)
                print(f"    Progress: {mb:.1f} MB / 100 MB...")

    final_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    elapsed = time.time() - start_time
    print(f"[+] Successfully generated {output_path} ({final_size_mb:.2f} MB) in {elapsed:.2f}s")


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "email_traffic_100mb.pcap"
    generate_100mb_pcap(out_file)
