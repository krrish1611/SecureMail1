# SecureMailScope — User Guide (Install, Dependencies & How to Run)

This guide gets you from an empty machine to running the tool in all three modes:
**CLI (offline PCAP)**, **Web Dashboard**, and **Live Capture**. It covers every
dependency, why it's there, and the exact commands.

---

## 1. What You Need (Prerequisites)

| Dependency | Version | Why |
|-----------|---------|-----|
| **Python** | 3.9+ (tested 3.11/3.12/3.14) | Core runtime |
| **Node.js + npm** | 16+ | Build the React frontend |
| **Git** (optional) | any | Version control |
| **tshark** (optional) | any | Only for **live** capture mode |
| **Root/sudo** (optional) | — | Only for **live** capture on a real interface |

> **Live capture** additionally needs `tshark` (`sudo apt install tshark`) and a network
> interface you're allowed to sniff (usually requires sudo).

---

## 2. Install — Step by Step

### 2.1 Get the code
```bash
git clone <your-repo-url> SecureMailScope
cd SecureMailScope
```

### 2.2 Python virtual environment + dependencies
```bash
python3 -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` installs: `dpkt`/`scapy` (PCAP parsing), `cryptography` (X.509 + TLS +
verification + OCSP), `certifi` (trust root bundle), `scikit-learn`/`numpy`/`pandas`
(ML), `fastapi`/`uvicorn`/`python-multipart` (web API), `pyshark` (live capture),
`PyYAML` (config), `joblib` (model persistence), `jinja2`/`reportlab`/`weasyprint`
(HTML/PDF reports), `pytest` (tests).

### 2.3 Build the frontend (only needed for the Web Dashboard)
```bash
cd frontend
npm install
npm run build        # outputs static files to frontend/dist/
cd ..
```
> `npm install` may print a warning that `esbuild`'s postinstall script was blocked. If
> so, run `npm install-scripts approve esbuild` (or `npm rebuild esbuild`) so Vite builds
> correctly — this is a security-hardening feature of newer npm.

### 2.4 Sanity check
```bash
python cli.py --help                    # should print usage
python -m pytest tests/                 # should show "33 passed"
```

---

## 3. Generate a Sample Capture (no network needed)

```bash
python deps/generate_sample_pcap.py deps/sample_traffic.pcap
```
This writes a PCAP containing 4 synthetic conversations:
1. **SMTP + STARTTLS** with weak `RC4` (critical)
2. **IMAP** with TLS 1.0 and no forward secrecy (high)
3. **POP3** with clean TLS 1.3 (no findings)
4. **SMTP** with no STARTTLS (plaintext credentials, critical)

---

## 4. Mode A — CLI (offline PCAP analysis)

| Command | What it does |
|---------|--------------|
| `python cli.py deps/sample_traffic.pcap` | Full analysis (rules + ML) + JSON/HTML/PDF |
| `python cli.py file.pcap --no-ml` | Rules only (faster, fully deterministic) |
| `python cli.py file.pcap --json out.json` | Custom JSON output path |
| `python cli.py file.pcap --html out.html --pdf out.pdf` | Custom report paths |
| `python cli.py file.pcap --max-sessions 2` | Limit to first N sessions |

By default the CLI writes `<pcap>_report.json`, `_report.html`, `_report.pdf`.

Sample output tail:
```
  Sessions analysed : 4
  Critical findings : 2
  High findings     : 4
  Average posture   : 61.0/100
[+] JSON report: sample_traffic_report.json
```

---

## 5. Mode B — Web Dashboard (interactive)

```bash
./run_web.sh
# or manually:
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
Open **http://localhost:8000**, upload a `.pcap`, and browse per-session findings,
severity chips, posture bars, TLS details, and certificate trust/revocation status.

### REST API
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/analyze` | Upload PCAP, run analysis (multipart form) |
| GET | `/api/health` | Health check |
| GET | `/api/jobs/{id}/summary` | Session summary list |
| GET | `/api/jobs/{id}/sessions/{sid}` | Full detail + findings for one session |
| GET | `/api/jobs/{id}/overall` | Aggregate stats (protocols, severity, avg score) |
| GET | `/api/jobs/{id}/report/{json\|html\|pdf}` | Download a report |

---

## 6. Mode C — Live Capture (runtime monitoring)

```bash
sudo python cli.py --live -i eth0                 # watch an interface in real time
sudo python cli.py --live -i eth0 --duration 120  # auto-stop after 2 minutes
sudo python cli.py --live -i wlan0 --no-ml        # rules only, lower CPU
```
- Prints each analyzed email session as it completes, plus a final summary.
- Requires `tshark` + `pyshark`. Use `ip link` / `ifconfig` to find your interface name.

---

## 7. Training the ML Models (Custom / Retraining)

```bash
python train.py                    # train on realistic synthetic data
python train.py --eval             # train + print accuracy/confusion report
python train.py --csv labels.csv   # train on YOUR OWN labelled feature vectors
python train.py --force            # retrain even if models exist
```
Models are saved to `ml/saved_models/` and reused across runs. Scoring knobs live in
`ml/config.yml` (rule/ML blend, per-severity deductions, anomaly contamination, model
size) — edit and re-run without touching code.

---

## 8. Running the Test Suite & CI

```bash
python -m pytest tests/            # 33 tests, ~1–2s
```
Covers: X.509 parsing/chain/revocation, TLS 1.3 forward-secrecy accuracy, the end-to-end
analyzer on the sample PCAP, ML feature extraction & training, all exporters, and protocol
/ plaintext-credential detection. A GitHub Actions workflow (`.github/workflows/ci.yml`)
runs the same suite on Python 3.11 & 3.12.

---

## 9. Project Layout Cheat-Sheet

```
cli.py            command-line interface (PCAP + live)
train.py          ML training CLI
core/             capture, protocols, tls, certs, rules, analyzer, live, models
ml/               features, models, training_data, config.yml
reports/          JSON / HTML / PDF exporters
backend/          FastAPI app + routers
frontend/         React + Vite dashboard
tests/            pytest suite
deps/             sample PCAP generator
docs/             architecture, user guide, business value, roadmap
.github/          CI workflow
```

---

## 10. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: yaml` | `pip install PyYAML` |
| `vite: command not found` on `npm run build` | `npm rebuild esbuild` or re-run `npm install` |
| `Analyze endpoint returns 0 sessions` | Verify the file is a valid pcap (use `file x.pcap`); re-generate the sample |
| Live capture fails | Install `tshark` (`sudo apt install tshark`) and run with `sudo` |
| `CryptographyDeprecationWarning` on startup | Harmless; suppressed. Re-train models with a current `cryptography` if you upgrade |
| Reports don't render PDF | Ensure `weasyprint` deps (often `pango`/`cairo`) are installed on Linux |
| Want faster rule-only run | Add `--no-ml` |

---

## 11. Interpreting a Report (Fast Start)

1. Look at **Average Posture** — a single triage number (aim: ≥ 80).
2. Open **Critical/High** findings first — these are true compromise/readability risks.
3. For each finding, read the **recommendation** (e.g. "disable RC4", "enforce TLS 1.2+",
   "replace revoked cert").
4. Use the **session detail** to see TLS version, cipher, key exchange (forward secrecy),
   and certificate trust/revocation for that specific conversation.
