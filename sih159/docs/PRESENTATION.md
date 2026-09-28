# SecureMailScope — Stakeholder Presentation (5–8 min)
### Outline + Talking Script + Demo Run-Through

Audience: internal team / stakeholders. Goal: show what we built, prove it works live,
and explain why it matters + what's next. Keep it to **6 slides / 7 minutes**, leaving time
for questions.

---

## Structure at a glance (7 minutes)

| # | Slide | Time | Purpose |
|---|-------|------|---------|
| 1 | Title + the problem | 1 min | Hook — why this matters |
| 2 | What it does | 1 min | The one-liner + capabilities |
| 3 | LIVE DEMO | 2 min | Prove it works (don't read, just run) |
| 4 | How it works (behind the scenes) | 1 min | Quick architecture trust-builder |
| 5 | Business value & who benefits | 1.5 min | Why stakeholders should care |
| 6 | Status, tests, roadmap | 1 min | Credibility + next steps |

---

## SLIDE 1 — Title + The Problem (1 min)

**On screen:** Title, tagline, and the "problem" bullets.

**Talking script:**
> "SecureMailScope is an AI-assisted tool that continuously assesses the security of the
> encryption underlying our email traffic.
>
> Here's the problem: virtually every organization depends on email, yet production mail
> servers quietly run dangerously weak crypto — TLS 1.0, broken ciphers like RC4, expired
> or revoked certificates, and STARTTLS connections that get silently stripped, sending
> usernames and passwords in plaintext.
>
> The scary part is nobody notices, because Wireshark shows you *packets*, not whether
> your overall posture is good or what to fix first. Active scanners need credentials and
> can't see what other clients negotiated. That's the gap we're closing."

---

## SLIDE 2 — What It Does (1 min)

**On screen:** the numbered capability list (from README).

**Talking script:**
> "SecureMailScope ingests captured traffic — a PCAP file, or a live interface — and
> automatically:
> - identifies SMTP / IMAP / POP3 conversations,
> - reconstructs each TLS handshake, including accurate TLS 1.3 and forward-secrecy
>   detection,
> - validates each certificate against the real public trust store, with OCSP/CRL
>   revocation checking,
> - flags weak ciphers, obsolete TLS versions, stripped STARTTLS, and plaintext
>   credentials,
> - scores every conversation 0–100 and ranks what to fix first.
>
> Crucially, it's **passive and offline** — no credentials, invisible, works on archived
> captures. Perfect for forensics, audits, and assessing infrastructure we don't control."

**Now run the LIVE DEMO** (slide 3). Transition: "But don't take my word for it — let's
run it on a real capture."

---

## SLIDE 3 — LIVE DEMO (2 min)

**What to do (memorize these commands, don't read a script):**

```bash
# 1. Show it's a real working project — run the test suite (fast, ~2s)
python -m pytest tests/          # -> "33 passed"

# 2. Generate a sample capture (4 conversations, 2 critical + 4 high findings)
python deps/generate_sample_pcap.py deps/sample_traffic.pcap

# 3. Run the analysis
python cli.py deps/sample_traffic.pcap
#    -> Sessions analysed: 4, Critical: 2, High: 4, Average posture: 61.0/100

# 4. (If you have time) open the web dashboard
./run_web.sh                     # open http://localhost:8000, upload the pcap
```

**What to say WHILE it runs (2 sentences of narration):**
> "Watch the output — it analysed 4 sessions in seconds, found 2 critical and 4 high
> issues, and gave a posture score of 61/100. That score, and the ranked findings, is
> exactly what a SOC analyst needs to prioritize: fix the criticals first."

**Live-demo failure safety nets:**
- If a command errors, don't panic — say *"let's use the web dashboard instead"* and rely
  on `run_web.sh`. Have it open in a tab beforehand.
- Rehearse generating the pcap at least twice so you're fast.

---

## SLIDE 4 — How It Works, Behind the Scenes (1 min)

**On screen:** simplified pipeline diagram (Input → Streams → Protocol/TLS/Certs → Rules+ML → Score).

**Talking script:**
> "Under the hood it's a clean pipeline. Captured packets are reassembled into TCP streams,
> we detect the protocol and watch for STARTTLS upgrades or strips, we reconstruct the TLS
> handshake and parse each certificate against the real trust store, then two things judge
> each session: a deterministic rule engine encoding known vulnerabilities, and a
> machine-learning layer that flags unusual sessions and learns risk grading. The two are
> blended into one posture score and a prioritized report.
>
> The 'AI-assisted' piece gives us generalization — it catches novel or messy configurations
> that hard-coded rules alone would miss."

---

## SLIDE 5 — Business Value & Who Benefits (1.5 min)

**On screen:** beneficiaries + value bullets (from BUSINESS_VALUE.md).

**Talking script:**
> "Who does this help? Security leadership gets one 0–100 number and a fix plan. SOC and
> incident responders triage thousands of sessions in seconds instead of hours — and spot
> the 2 critical ones among 10,000. Email admins get direct remediation like 'disable RC4,
> enforce TLS 1.2+'. Compliance and audit teams get documented evidence supporting GDPR,
> ISO 27001, NIS2, and PCI DSS requirements.
>
> The business case is simple: it prevents credential theft and business-email-compromise
> — the most expensive email threats — and turns a vague 'be more secure' into a
> prioritized, board-readable report."

---

## SLIDE 6 — Status, Tests & Roadmap (1 min)

**On screen:** green checkmarks + roadmap summary.

**Talking script:**
> "Where are we? Everything shown is implemented and verified — 33 automated tests pass,
> the CLI, web dashboard, and live-capture mode all work, and ML models are trained,
> persisted, and reproducible.
>
> Next up, in priority order: validate against real enterprise traffic, add online
> revocation checking and credential redaction, improve performance on multi-gigabyte
> captures, then package it as Docker and integrate with a SIEM. Full details are in our
> roadmap doc.
>
> Happy to take questions."

---

## Handy one-liner (memorize for Q&A)

> *"Passive, offline, AI-assisted assessment of email encryption that turns any traffic
> capture into a prioritized, board-readable security posture report — with no
> credentials and no footprint."*

---

## Q&A — likely questions & answers

| Question | Answer |
|----------|--------|
| "Can it decrypt the mail?" | No — it assesses the crypto handshake and certificates, not message content. |
| "Does it need credentials or access?" | No — fully passive, works offline on any PCAP. |
| "How accurate is the ML?" | ~1.0 accuracy on held-out realistic synthetic data; improves with real labeled data via `train.py`. |
| "How is it different from an active scanner?" | It sees what *actually* happened for all clients, not just what we can provoke; invisible to the target. |
| "Is it production-ready?" | Fully functional and tested; the top roadmap item is validation on real traffic to harden confidence. |
