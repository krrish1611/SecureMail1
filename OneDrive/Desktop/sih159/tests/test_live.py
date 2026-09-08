"""Tests for Live Sniffing and WebSocket real-time streaming."""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.live import LiveMonitor
from backend.app.main import app
from fastapi.testclient import TestClient

SAMPLE_PCAP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "deps", "sample_traffic.pcap"
)


def test_live_monitor_init_and_stop():
    """Verify LiveMonitor initialization and stop mechanics."""
    monitor = LiveMonitor(interface="lo", use_ml=False, analysis_interval=0.5)
    assert monitor.interface == "lo"
    assert monitor._stop_requested is False
    monitor.stop()
    assert monitor._stop_requested is True


def test_live_monitor_payload_inspection():
    """Verify protocol identification and summary snippet extraction."""
    monitor = LiveMonitor(interface="lo")

    # TLS ClientHello record (0x16 0x03 0x01 ... 0x01)
    tls_client_hello = bytes([0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c])
    proto, summary = monitor._inspect_packet_payload(49100, 465, tls_client_hello)
    assert proto == "TLS"
    assert "ClientHello" in summary

    # SMTP EHLO command
    smtp_cmd = b"EHLO mail.bank.org\r\n"
    proto, summary = monitor._inspect_packet_payload(49200, 25, smtp_cmd)
    assert proto == "SMTP"
    assert "EHLO mail.bank.org" in summary

    # POP3 command
    pop3_cmd = b"USER alice@corp.com\r\n"
    proto, summary = monitor._inspect_packet_payload(49300, 110, pop3_cmd)
    assert proto == "POP3"
    assert "USER alice" in summary


def test_live_monitor_simulation():
    """Verify live traffic simulation parses packets and emits stream events."""
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample_traffic.pcap not found")

    packets_received = []
    sessions_received = []
    statuses_received = []

    def on_pkt(p):
        packets_received.append(p)

    def on_sess(s):
        sessions_received.append(s)

    def on_stat(status, stats):
        statuses_received.append((status, stats))

    monitor = LiveMonitor(
        interface="simulation",
        use_ml=False,
        analysis_interval=0.1,
        on_packet=on_pkt,
        on_session=on_sess,
        on_status=on_stat,
    )

    monitor.start_simulation(SAMPLE_PCAP, duration=0.8, delay_per_packet=0.005)

    assert len(packets_received) > 0
    p0 = packets_received[0]
    assert "ts" in p0
    assert "src" in p0
    assert "dst" in p0
    assert "protocol" in p0
    assert "summary" in p0

    # Sessions reassembled
    assert len(monitor.seen_sessions) > 0
    assert len(sessions_received) > 0

    # Status notifications
    status_names = [s[0] for s in statuses_received]
    assert "started" in status_names
    assert "completed" in status_names


def test_websocket_live_streaming_endpoint():
    """Verify real-time WebSocket communication, simulation control, and event delivery."""
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample_traffic.pcap not found")

    client = TestClient(app)
    with client.websocket_connect("/api/ws/live") as websocket:
        # Initial greeting message
        init_msg = websocket.receive_json()
        assert init_msg["type"] == "status"
        assert init_msg["status"] == "ready"

        # Start live simulation over WebSocket
        websocket.send_json({
            "action": "start",
            "simulation": True,
            "duration": 1.0,
            "use_ml": False,
        })

        events = []
        start_time = time.time()
        while time.time() - start_time < 3.0:
            try:
                data = websocket.receive_json()
                events.append(data)
                if data.get("type") == "completed":
                    break
            except Exception:
                break

        event_types = [e.get("type") for e in events]
        assert "packet" in event_types or "status" in event_types

        # Verify completed message includes job_id
        completed_events = [e for e in events if e.get("type") == "completed"]
        if completed_events:
            job_id = completed_events[0].get("job_id")
            assert job_id is not None
            # Verify job is queryable via REST
            resp = client.get(f"/api/jobs/{job_id}/summary")
            assert resp.status_code == 200
            assert len(resp.json()) > 0


def test_websocket_stop_control():
    """Verify sending stop command cancels capture gracefully."""
    client = TestClient(app)
    with client.websocket_connect("/api/ws/live") as websocket:
        init_msg = websocket.receive_json()
        assert init_msg["type"] == "status"

        # Start capture with long duration
        websocket.send_json({
            "action": "start",
            "simulation": True,
            "duration": 30.0,
            "use_ml": False,
        })

        # Immediately send stop
        time.sleep(0.2)
        websocket.send_json({"action": "stop"})

        # Wait for completed or stopped
        received_types = set()
        t0 = time.time()
        while time.time() - t0 < 3.0:
            try:
                data = websocket.receive_json()
                received_types.add(data.get("type"))
                if data.get("type") == "completed":
                    break
            except Exception:
                break

        assert "completed" in received_types
