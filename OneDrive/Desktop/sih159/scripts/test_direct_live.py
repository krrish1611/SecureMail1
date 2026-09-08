import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import time
import threading
import smtplib
from core.live import LiveMonitor

pkts = []
def on_pkt(p):
    pkts.append(p)
    print(f"[Direct LiveMonitor] Pkt #{p.get('packet_num')}: {p.get('protocol')} {p.get('src')} -> {p.get('dst')} | {p.get('summary')}")

def on_stat(s, stats):
    print(f"[Direct LiveMonitor Stat] {s}: {stats}")

def on_sess(sess):
    print(f"[Direct LiveMonitor Sess] {sess.id} {sess.service} Posture: {sess.posture_score}")

mon = LiveMonitor(interface="4", on_packet=on_pkt, on_status=on_stat, on_session=on_sess)

def sender():
    time.sleep(1.5)
    print("[Sender] Sending SMTP...")
    try:
        s = smtplib.SMTP("smtp.gmail.com", 587, timeout=5)
        s.ehlo()
        s.starttls()
        s.quit()
        print("[Sender] Done!")
    except Exception as e:
        print("[Sender] Err:", e)

t = threading.Thread(target=sender)
t.start()

print("Starting LiveMonitor for 6s...")
mon.start(duration=6.0)
t.join()
print(f"Total packets captured by LiveMonitor: {len(pkts)}")
