"""High-level analysis orchestrator.

Takes a reconstructed Stream and runs the full pipeline:
protocol detection -> STARTTLS analysis -> TLS parsing -> cert extraction
-> rule evaluation -> ML feature prep -> posture scoring.
"""

from __future__ import annotations

import uuid
from typing import Dict, Optional

from .capture import Stream
from .models import Severity, Session, TLSInfo
from .protocols import ProtocolDetector, detect_credentials_plaintext, detect_starttls
from .tls import parse_tls_stream
from .certs import parse_certificate, validate_certificates
from .rules import RuleEngine
from .advisory import evaluate_dns_security


class Analyzer:
    """Runs the full analysis pipeline over a single stream."""

    def __init__(self) -> None:
        self.protocol_detector = ProtocolDetector()
        self.rule_engine = RuleEngine()

    def analyze_stream(self, stream: Stream) -> Optional[Session]:
        """Analyze one stream into a Session with findings."""
        session = Session(
            id=uuid.uuid4().hex[:12],
            client_ip=stream.client_ip,
            client_port=stream.client_port,
            server_ip=stream.server_ip,
            server_port=stream.server_port,
            start_ts=stream.start_ts,
            end_ts=stream.end_ts,
            bytes_client_to_server=stream.client_bytes(),
            bytes_server_to_client=stream.server_bytes(),
            packets=stream.packets,
        )

        server_data = bytes(stream.server_data)
        client_data = bytes(stream.client_data)

        # 1. Protocol detection from banner + client bytes
        protocol = self.protocol_detector.detect(server_data[:2048], client_data[:2048])
        if protocol is None:
            # Guess from well-known ports if banner detection failed
            if stream.server_port in (25, 465, 587):
                protocol = "smtp"
            elif stream.server_port in (143, 993):
                protocol = "imap"
            elif stream.server_port in (110, 995):
                protocol = "pop3"
            else:
                protocol = "unknown"
        session.protocol = protocol

        # 2. STARTTLS detection
        stls = detect_starttls(protocol, server_data, client_data)
        session.starttls = stls["requested"]
        session.starttls_upgraded = stls["upgraded"]
        session.starttls_stripped = stls["stripped"]

        # 3. Determine plaintext window and find TLS handshake bytes
        tls_client_start = stls.get("tls_start_index_client")
        tls_server_start = stls.get("tls_start_index_server")

        # Client data before upgrade is plaintext
        if tls_client_start is None:
            # Find ClientHello (0x16 0x03) in client data
            idx = client_data.find(b"\x16\x03")
            tls_client_start = idx  # may be -1
        if tls_server_start is None:
            idx = server_data.find(b"\x16\x03")
            tls_server_start = idx

        # Plaintext credential detection in pre-TLS window
        pre_window_client = client_data[:tls_client_start] if tls_client_start and tls_client_start >= 0 else client_data
        pre_window_server = server_data[:tls_server_start] if tls_server_start and tls_server_start >= 0 else server_data
        creds_found, auth_cmd = detect_credentials_plaintext(protocol, pre_window_client)
        session.credentials_plaintext = creds_found
        session.auth_command_observed = auth_cmd

        # 4. Determine if any crypto activity happened
        has_handshake = ((tls_client_start is not None and tls_client_start >= 0) or
                         (tls_server_start is not None and tls_server_start >= 0))
        has_server_hello_ctx = tls_server_start is not None and tls_server_start >= 0 and \
            len(server_data) > tls_server_start

        if has_handshake:
            session.encrypted = True
            client_ctx = client_data[tls_client_start:] if tls_client_start and tls_client_start >= 0 else client_data
            server_ctx = server_data[tls_server_start:] if tls_server_start and tls_server_start >= 0 else server_data

            # 5. Parse TLS
            tls = parse_tls_stream(server_ctx, client_ctx)
            session.tls = tls

            # 6. Certificate extraction
            if tls.certificate:
                parsed, leaf, chain_valid, issues = validate_certificates(tls.certificate)
                session.certificate = leaf
                if session.certificate:
                    session.certificate.chain_valid = chain_valid
                    session.certificate.chain_issues = issues
                # skip validation-of-chain delegation here; rules handle it
        else:
            # No TLS.
            session.plaintext = True if not session.starttls_upgraded else False
            if session.starttls and not session.starttls_upgraded:
                session.plaintext = True

        # If STARTTLS upgraded, plaintext flag is False
        if session.starttls_upgraded:
            session.plaintext = False

        # 6b. Evaluate MTA-STS and DANE advisory posture
        session.dns_security = evaluate_dns_security(session, check_online=True)

        # 7. Run rule engine
        self.rule_engine.evaluate_all(session)

        return session


def analyze_all(streams: Dict, max_sessions: int = None) -> list:
    """Analyze all streams into a list of Session objects."""
    analyzer = Analyzer()
    results = []
    count = 0
    for key, stream in streams.items():
        if max_sessions and count >= max_sessions:
            break
        session = analyzer.analyze_stream(stream)
        if session is not None:
            results.append(session)
            count += 1
    return results
