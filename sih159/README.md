# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

A passive network forensics framework that analyzes captured network traffic (PCAP files)
containing SMTP, IMAP, and POP3 communications to automatically assess the cryptographic
security posture of enterprise email infrastructures.

---

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Full technical blueprint — how every module works, data model, threat model, posture math |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Install, dependencies, and how to run (CLI / Web / Live / train) |
| [`docs/BUSINESS_VALUE.md`](docs/BUSINESS_VALUE.md) | Why we built it, who benefits, ground-level use cases, money/risk/compliance value |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What more needs doing — prioritized, week-by-week backlog |

---

## The Problem We Solve

Email is critical for governments, banks, and enterprises. Even where TLS is "in use,"
real mail servers frequently suffer dangerous misconfigurations:

- **Obsolete TLS versions** (TLS 1.0/1.1) vulnerable to downgrade/BEAST attacks
- **Weak cipher suites** (RC4, DES, 3DES) that are broken or brute-forceable
- **Insecure STARTTLS** — STARTTLS merely *announces* encryption; an attacker can strip
  it silently (STRIPTLS) and read plaintext credentials
- **Expired / self-signed / untrusted certificates** — identity cannot be verified
- **No forward secrecy** — a leaked server key later decrypts all past traffic

Existing tools (Wireshark, tcpdump) show *packets* but do not assess the overall
**security posture** or tell a SOC / forensics / incident-response analyst what to fix
first. SecureMailScope automates that assessment.

## What It Does

1. Reassembles complete TCP streams from a PCAP
2. Automatically identifies SMTP, IMAP, and POP3
3. Detects STARTTLS negotiation and upgrades — **and detects STARTTLS stripping attacks**
4. Parses and reconstructs TLS handshakes — accurate TLS 1.3, forward-secrecy,
   and offered-version analysis
5. Extracts and validates X.509 certificates against a real OS trust store
   (chain, expiry, key, signature) with best-effort OCSP/CRL revocation checking
6. Detects weak/deprecated TLS versions, cipher suites, key exchange, and cert issues
7. Runs **rule-based + ML** intelligence:
   - **Isolation Forest** → anomaly detection on unusual TLS sessions
   - **Random Forest** → risk classification (low/medium/high/critical)
8. Produces a **0–100 security posture score** per session
9. Generates prioritized, actionable findings with mitigations
10. Exports **JSON / HTML / PDF** forensic reports and serves an interactive dashboard
11. **Live capture mode** (`--live`) monitors a network interface in real time

## Architecture

```
 PCAP ──► TCP Stream Reassembly ──► Protocol ID (SMTP/IMAP/POP3)
              │
              ▼
      STARTTLS Detection & TLS Handshake Parser
              │
              ▼
      X.509 Certificate Extraction & Validation
              │
              ▼
      Feature Extraction ──► Rule Engine + ML (IsolationForest/RandomForest)
              │
              ▼
      Posture Scoring & Prioritized Findings
              │
   ┌──────────┴───────────┐
   ▼                      ▼
 Reports (JSON/HTML/PDF)   FastAPI + React/Vite Dashboard
```

## Project Layout

```
core/            PCAP loading, stream reassembly, protocol ID, STARTTLS,
                 TLS parsing, cert validation, rule engine, orchestrator,
                 live capture monitoring (live.py)
ml/              feature extraction, risk classifier, anomaly detector, posture
                 scoring, realistic training data (training_data.py), config.yml
reports/         JSON / HTML / PDF exporters
backend/         FastAPI REST API + serves the built frontend
frontend/        React + Vite + Recharts interactive dashboard
deps/            synthetic sample PCAP generator for testing
tests/           pytest suite (pip install pytest, then `python -m pytest`)
.github/         GitHub Actions CI workflow
cli.py           command-line interface
train.py         ML model training CLI
run_web.sh       launch script for the web dashboard
```

## Quick Start

### 1. Install dependencies

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

cd frontend && npm install && npm run build && cd ..
```

### 2. Generate a sample PCAP (with deliberately weak + strong mail traffic)

```bash
python deps/generate_sample_pcap.py deps/sample_traffic.pcap
```

### 3. Run the CLI

```bash
python cli.py deps/sample_traffic.pcap            # full analysis (rules + ML)
python cli.py deps/sample_traffic.pcap --no-ml    # rules only
```

This produces `sample_traffic_report.json`, `.html`, and `.pdf`.

### 3b. Live capture mode (runtime monitoring)

```bash
sudo python cli.py --live -i eth0                 # monitor an interface in real time
sudo python cli.py --live -i eth0 --duration 60   # stop after 60s
```

Requires `tshark` + `pyshark`. Press Ctrl+C to stop; a summary is printed at the end.

### 4. Run the web dashboard

```bash
python -m uvicorn backend.app.main:app --port 8000
# or
./run_web.sh
```

Open http://localhost:8000, upload a `.pcap`, and explore the dashboard.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/analyze` | Upload a PCAP (multipart) and run full analysis |
| GET | `/api/health` | Health check |
| GET | `/api/jobs/{id}/summary` | Session summary list |
| GET | `/api/jobs/{id}/sessions/{sid}` | Detailed session + findings |
| GET | `/api/jobs/{id}/overall` | Aggregate posture stats |
| GET | `/api/jobs/{id}/report/{json\|html\|pdf}` | Download report |

## Notes on the ML component

The **risk classifier** (Random Forest) and **anomaly detector** (Isolation Forest) are
trained on realistic, labelled synthetic feature vectors and anomaly baselines defined in
`ml/training_data.py`. Trained models are persisted to `ml/saved_models/` and reused across
runs, so results are reproducible.

- **Train or retrain:** `python train.py` (synthetic) or `python train.py --csv data.csv`
  for your own labelled data. Add `--eval` for a classification report.
- **Tune scoring:** edit `ml/config.yml` (rule/ML blend weights, per-severity deductions,
  anomaly contamination, model sizes) without touching code.
- Classifier labels are `low / medium / high / critical`; anomaly scores range `-1..+1`.

## Tests & CI

```bash
pip install pytest
python -m pytest tests/     # 33 tests: certs, TLS 1.3, analyzer, ML, exports, protocols
```

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs the suite on Python 3.11/3.12
plus a `compileall` and ML-training smoke test.

## Robustness

The pipeline is fuzz-tested against malformed, truncated, and random handshakes, garbage
DER certificates, empty/missing PCAPs, and non-email streams without crashing; such cases
are handled gracefully (e.g. no TLS info, "no email sessions", "unable to parse certificate").
AUTH LOGIN/PLAIN plaintext-credential detection also covers both standalone and
initial-response (`AUTH LOGIN <base64>`) forms.
