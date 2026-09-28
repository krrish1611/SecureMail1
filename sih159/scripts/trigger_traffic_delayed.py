import time
import smtplib

print("[Traffic Trigger] Waiting 3 seconds before sending live SMTP traffic...")
time.sleep(3)

print("[Traffic Trigger] Connecting to smtp.gmail.com:587 over live Wi-Fi hardware adapter...")
try:
    s = smtplib.SMTP("smtp.gmail.com", 587, timeout=6)
    s.ehlo()
    print("[Traffic Trigger] Sent EHLO, negotiating STARTTLS...")
    s.starttls()
    print("[Traffic Trigger] TLS established, sending QUIT...")
    s.quit()
    print("[Traffic Trigger] SMTP connection complete!")
except Exception as e:
    print("[Traffic Trigger] Error:", e)
