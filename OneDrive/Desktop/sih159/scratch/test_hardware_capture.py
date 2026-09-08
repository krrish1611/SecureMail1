import asyncio
import websockets
import json
import threading
import time
import smtplib

def send_traffic():
    time.sleep(2.0)
    print("[*] Generating real live email handshake traffic to smtp.gmail.com:587...")
    try:
        s = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        s.ehlo()
        s.starttls()
        s.quit()
        print("[+] Live SMTP STARTTLS session completed successfully!")
    except Exception as e:
        print(f"[!] Traffic generation error: {e}")

threading.Thread(target=send_traffic, daemon=True).start()

async def test_live_sniff():
    uri = "ws://127.0.0.1:8000/api/ws/live"
    async with websockets.connect(uri) as ws:
        # Request hardware capture on interface 4 (Wi-Fi)
        await ws.send(json.dumps({
            "action": "start",
            "interface": "4",
            "duration": 8.0,
            "simulation": False,
        }))
        print("[+] Sniffer started on Hardware Interface #4 (Wi-Fi)")

        packet_count = 0
        session_count = 0

        while True:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
                data = json.loads(msg)
                mtype = data.get("type")

                if mtype == "packet":
                    packet_count += 1
                    pkt = data.get("data", {})
                    print(f"  --> [PACKET #{packet_count}] {pkt.get('proto')} {pkt.get('src')}:{pkt.get('sport')} -> {pkt.get('dst')}:{pkt.get('dport')} | {pkt.get('snippet')}")
                elif mtype == "session":
                    session_count += 1
                    sess = data.get("session", {})
                    print(f"  ==> [SESSION REASSEMBLED] {sess.get('session_id')} | {sess.get('protocol')} | Encrypted: {sess.get('encrypted')} | Posture: {sess.get('posture_score')}")
                elif mtype == "status":
                    status = data.get("status")
                    print(f"  [*] Status: {status} -> {data.get('data')}")
                    if status == "completed":
                        break
                elif mtype == "error":
                    print(f"  [!] Capture error: {data.get('message')}")
                    break
            except asyncio.TimeoutError:
                print("[!] Timeout waiting for further capture packets")
                break

    print(f"\n[SUMMARY] Captured {packet_count} packets and {session_count} reassembled sessions on real hardware.")

asyncio.run(test_live_sniff())
