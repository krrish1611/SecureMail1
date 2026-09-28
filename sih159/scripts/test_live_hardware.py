import asyncio
import json
import websockets
import threading
import time
import smtplib

def trigger_traffic():
    time.sleep(2.0)
    print("[TrafficGen] Connecting to smtp.gmail.com:587 over Wi-Fi...")
    try:
        s = smtplib.SMTP("smtp.gmail.com", 587, timeout=6)
        s.ehlo()
        print("[TrafficGen] Sent EHLO, initiating STARTTLS...")
        s.starttls()
        print("[TrafficGen] TLS established, sending QUIT...")
        s.quit()
        print("[TrafficGen] SMTP connection complete!")
    except Exception as e:
        print("[TrafficGen] Traffic err:", e)

async def test_ws():
    uri = "ws://127.0.0.1:8000/api/ws/live"
    async with websockets.connect(uri) as ws:
        init_msg = await ws.recv()
        print("[WS Initial Message]:", init_msg)

        start_payload = {
            "action": "start",
            "interface": "4",
            "duration": 8.0,
            "simulation": False
        }
        await ws.send(json.dumps(start_payload))
        print("[WS Sent]: Start sniffing on interface 4 (Hardware Wi-Fi)")

        t = threading.Thread(target=trigger_traffic)
        t.start()

        packets_received = 0
        statuses = []
        sessions = []
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=12.0)
                data = json.loads(msg)
                event_type = data.get("type")
                if event_type == "packet":
                    packets_received += 1
                    pkt = data.get("data", {}) or data.get("packet", {})
                    proto = pkt.get("protocol")
                    src = pkt.get("src")
                    dst = pkt.get("dst")
                    summary = (pkt.get("summary") or "").encode("ascii", "replace").decode("ascii")
                    print(f"  [LIVE PKT #{packets_received}] {proto} | {src} -> {dst} | {summary}")
                elif event_type == "status":
                    status = data.get("status")
                    statuses.append(status)
                    print(f"  [STATUS] {status}: {data.get('stats')}")
                    if status in ("stopped", "completed"):
                        break
                elif event_type == "session":
                    sess = data.get("session", {})
                    sessions.append(sess)
                    print(f"  [NEW SESSION DETECTED] {sess.get('session_id') or sess.get('id')} | {sess.get('service')} | Posture: {sess.get('posture_score')}")
                elif event_type == "completed":
                    print(f"  [COMPLETED] job_id: {data.get('job_id')}, sessions: {data.get('session_count')}")
                    break
        except asyncio.TimeoutError:
            print("[WS] Timed out waiting for messages")

        t.join(timeout=3)
        print(f"\n[SUMMARY]: Live packets: {packets_received}, Sessions: {len(sessions)}, Statuses: {statuses}")

if __name__ == "__main__":
    asyncio.run(test_ws())
