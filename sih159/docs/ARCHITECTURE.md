# SecureMailScope — Technical Blueprint & Architecture

> "What is it, exactly, and how does it actually work under the hood?"

This document is the full technical blueprint: the problem, the design, how every
component works at ground level, the data model, the threat model, and the decision
rules. It is written so an engineer who has never seen the code can reason about it.

---

## 1. One-Paragraph Summary

SecureMailScope is a **passive, offline cryptographic security-posture assessment tool**
for enterprise email traffic. It ingests captured network traffic (a PCAP file — or a
live network interface), reassembles the raw TCP byte streams, automatically detects
SMTP / IMAP / POP3 conversations, reconstructs the TLS handshakes that happen between
a mail client and a mail server, validates the X.509 certificates presented, and then
scores each conversation from **0–100** while producing a prioritized list of actionable
security findings (`weak cipher`, `no forward secrecy`, `revoked certificate`, `STARTTLS
stripped`, `plaintext credentials`, etc.).

It is **purely passive** — it never connects to the mail server, never needs credentials,
never touches production configuration, and can operate **offline** on archived captures.
This makes it ideal for forensic analysis, incident response, and compliance auditing of
infrastructure the analyst does not control.

---

## 2. Why Passive? The Core Design Constraint

The single most important design decision is that the tool is **passive**:

| Active scanner (e.g. openssl s_client) | Passive analyzer (SecureMailScope) |
|----------------------------------------|-------------------------------------|
| Makes live network connections | Reads packets already on the wire |
| Needs the server's address & port | Infers servers from any capture |
| Can be detected / rate-limited / blocked | Invisible, undetectable |
| Only tests what it can reach | Tests *everything that actually happened* |
| Requires credentials for authenticated flows | Needs none |
| Snapshot in time | Can replay archived traffic months later |

Because it works from what **actually occurred** on the wire (rather than what a single
client can provoke), it can catch issues that an active scanner would miss — for example
a mail server that negotiates `RC4` for *some* clients but not others, or a STARTTLS
strip performed in a real session.

---

## 3. System Architecture

```
                 ┌────────────────────────────────────────────────────┐
   Input         │                                                    │
  ┌─────────┐    │   core/capture.py   StreamReassembler              │
  │ PCAP    │───▶│   ├─ read pcap (dpkt) / fallback scapy             │
  │ / iface │    │   └─ per TCP connection → Stream (client/server)   │
  └─────────┘    └────────────────────────────────────────────────────┘
                              │  Stream objects
                              ▼
                 ┌────────────────────────────────────────────────────┐
                 │   core/protocols.py  ProtocolDetector              │
                 │   ├─ SMTP / IMAP / POP3 banner detection           │
                 │   ├─ STARTTLS detection + **strip detection**      │
                 │   └─ plaintext-credential detection (AUTH LOGIN...) │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼
                 ┌────────────────────────────────────────────────────┐
                 │   core/tls.py   TLS handshake parser (TLS 1.2/1.3) │
                 │   ├─ ClientHello / ServerHello / Certificate       │
                 │   ├─ cipher, version, key exchange, FS, JA3, SNI   │
                 │   └─ offered-versions & key_share (TLS 1.3)        │
                 └────────────────────────────────────────────────────┘
                              │  TLSInfo + raw certs
                              ▼
                 ┌────────────────────────────────────────────────────┐
                 │   core/certs.py  Certificate validation             │
                 │   ├─ parse X.509 (PEM/DER)                          │
                 │   ├─ chain vs OS trust store (x509.verification)    │
                 │   ├─ OCSP + CRL revocation (offline-safe)           │
                 │   └─ expiry / key / signature checks                │
                 └────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────┬─────────────────────────────┐
        ▼                         ▼                             ▼
  core/rules.py             ml/features.py               (posture)
  deterministic rule        numeric feature vectors       score 0..100
  engine → findings         ml/models.py                 = rule + ML blend
                            RandomForest + IsolationForest
                              │
                              ▼
        ┌──────────────────────────┬──────────────────────────────┐
        ▼                          ▼                              ▼
  reports/exporters.py        backend/ (FastAPI)             core/live.py
  JSON / HTML / PDF           + frontend/ React dashboard   live interface monitor
```

---

## 4. Module-by-Module, Ground Level

### 4.1 `core/capture.py` — turning packets into conversations
- **DPKT** decodes link-layer → IP → TCP. If dpkt can't parse a capture, it falls back
  to **scapy**.
- The `StreamReassembler` groups TCP segments by the 4-tuple
  `(server_ip, server_port, client_ip, client_port)`. The endpoint on a well-known mail
  port (`25, 465, 587` SMTP, `110, 995` POP3, `143, 993` IMAP) is treated as the server.
- Each `Stream` accumulates `client_data` / `server_data` byte arrays in order, with
  timestamps. **No TCP-option or reordering** complexity — it appends payloads in arrival
  order, which is sufficient for the offline posture use-case.

### 4.2 `core/protocols.py` — "what protocol is this, and did STARTTLS get stripped?"
- `ProtocolDetector.detect()` reads the server **banner** (`220 ... ESMTP`, `* OK IMAP`,
  `+OK POP3`) and the client greeting; falls back to well-known ports.
- `detect_starttls()` watches for the `STARTTLS` command and the server `220 Ready to
  start TLS` reply, marking:
  - `requested` — client asked for STARTTLS
  - `upgraded` — handshake bytes actually followed
  - `stripped` — STARTTLS was *announced* but the client sent cleartext credentials
    anyway (real-world STRIPTLS indicator)
- `detect_credentials_plaintext()` flags `AUTH LOGIN` / `AUTH PLAIN` (standalone *and*
  initial-response `<base64>` forms), IMAP `LOGIN user pass`, POP3 `USER`/`PASS`.

### 4.3 `core/tls.py` — reading the handshake off the wire
It maintains a small state machine over TLS records (`0x16 = handshake`). From each
`ClientHello`/`ServerHello` it extracts:
- negotiated **version** and **cipher suite** (IANA names, e.g. `TLS_AES_128_GCM_SHA256`)
- **key exchange** — `ECDHE`/`DHE` (ephemeral → forward secrecy) vs `RSA (static)`
- **TLS 1.3 correctness**: TLS 1.3 uses `key_share` extension for the group (in the
  ClientHello) and *always* uses an ephemeral key exchange; the parser now recomputes the
  key exchange after **both** hellos are fed, so forwarded-secrecy detection is accurate
  for TLS 1.3.
- **offered versions** (from the ClientHello `supported_versions` extension) — so we can
  flag a server that *only offers* deprecated versions
- **SNI** (RFC 6066 server_name), **JA3** fingerprint, resumed-session flag.

### 4.4 `core/certs.py` — "can we actually trust this server?"
- Parses each certificate (PEM or DER) into a `CertificateInfo` (subject, issuer, key
  type/size, signature algorithm, SAN, validity, SKI/AKI).
- Builds the chain (`leaf → intermediate → root`) and validates it against a **real OS
  trust store** (Python `certifi` bundle, 121+ roots) using the modern
  `cryptography.x509.verification` API (RFC 5280 path validation).
- Performs **OCSP** (Online Certificate Status Protocol) and parses **CRL** distribution
  points from the certificate's AIA/CRL extensions. OCSP checks are best-effort and
  never block: if offline or no responder, revocation status is `unknown` — it degrades
  gracefully instead of crashing.
- Correctly separates: `self-signed`, `trusted` (chains to a public CA), `revoked`,
  `expired`, `not-yet-valid`, `untrusted`.

### 4.5 `core/rules.py` — deterministic domain knowledge
A rule engine that maps each parsed/session property to a `Finding` with an `id`, a
severity (`critical/high/medium/low/info`), a CWE id, and a concrete remediation.
Examples of the ~25 rules:
- `cipher.rc4` (critical) — RC4 is broken
- `tls.10` / `tls.11` (high) — TLS 1.0/1.1 obsolete
- `tls.keyex.no_fs` (high) — static RSA key exchange, no forward secrecy
- `cert.revoked` (critical), `cert.untrusted` (high), `cert.expired` (high)
- `starttls.stripped` (high) — STARTTLS downgrade
- `starttls.plaintext_creds` (critical) — credentials readable on the wire

### 4.6 `ml/` — learned scoring layered on top of the rules
- `features.py` turns a session into a **17-dimension numeric vector** (encrypted?,
  STARTTLS? stripped?, TLS version rank, cipher strength 0–10, forward secrecy?,
  cert valid?, key size, ...).
- `models.py`:
  - **RandomForestClassifier** → risk label `low/medium/high/critical`
  - **IsolationForest** → anomaly score (flags "this session looks *unusual*" without
    needing labels)
  - **posture score** = weighted blend of the rule-based deduction and the ML component
- `training_data.py` defines **realistic** synthetic population profiles (per risk class)
  and a normal-traffic baseline so the anomaly detector doesn't flag everything.
- `train.py` trains and persists models (saved_models/) via a CLI; `config.yml` tunes the
  scoring without code changes.

### 4.7 `reports/exporters.py`, `backend/`, `frontend/`
- Exporters render JSON/HTML/PDF. The FastAPI backend offers REST endpoints
  (`/api/analyze`, `/jobs/{id}/summary`, ...) and a React/Vite dashboard for browsing
  per-session findings with severity chips and posture bars.

---

## 5. Data Model (key objects)

```
Session
 ├─ id, protocol (smtp/imap/pop3), endpoints, timestamps, byte/packet counts
 ├─ plaintext / encrypted / starttls / starttls_stripped / credentials_plaintext
 ├─ tls: TLSInfo
 │    ├─ version, version_rank, cipher_suite, key_exchange, key_exchange_group
 │    ├─ offered_versions[], offered_ciphers[], extensions[], ja3, server_name
 │    └─ certificate: raw certs
 ├─ certificate: CertificateInfo
 │    ├─ subject, issuer, key algorithm/size, sig algorithm, san, validity
 │    ├─ self_signed, trusted, chain_valid, chain_issues[]
 │    ├─ ocsp_url, crl_urls, revoked, revocation_status, revocation_method
 ├─ findings: Finding[]   (id, title, description, category, severity, cwe, rec)
 └─ posture_score, risk_label, ml_score, ml_anomaly(+score)
```

`Severity` is an `IntEnum` (`INFO=0 … CRITICAL=4`); `SEVERITY_NAMES` maps to
string keys used across the API and reports.

---

## 6. Threat Model — What It Detects

| # | Threat | Rule id | Severity |
|---|--------|---------|----------|
| 1 | RC4 / DES / 3DES cipher negotiated | `cipher.rc4` | critical |
| 2 | TLS 1.0 negotiated (BEAST) | `tls.10` | high |
| 3 | TLS 1.1 negotiated | `tls.11` | high |
| 4 | Server offers only deprecated versions | `tls.weak_offered` | high |
| 5 | CBC+HMAC (non-AEAD) cipher | `tls.cipher.cbc_sha1` | medium |
| 6 | Static RSA key exchange → no forward secrecy | `tls.keyex.no_fs` | high |
| 7 | Weak DH modulus | `tls.keyex.dh_weak` | high |
| 8 | Certificate revoked (key compromised) | `cert.revoked` | critical |
| 9 | Certificate not trusted by a public CA | `cert.untrusted` | high |
| 10 | Expired certificate | `cert.expired` | high |
| 11 | Self-signed certificate | `cert.self_signed` | medium |
| 12 | STARTTLS strip / credentials in cleartext | `starttls.stripped` / `starttls.plaintext_creds` | high / critical |
| 13 | No encryption used at all | `starttls.missing` | high |

The **ML layer** additionally flags anomalous sessions that the hard-coded rules may not
recognize (rule drift / novel configurations).

---

## 7. Posture Score — How the 0–100 Number Is Computed

```
posture = rule_weight * rule_score + ml_weight * ml_component
```
- `rule_score` starts at 100 and deducts points per finding by severity
  (critical −18, high −12, medium −6, low −3, info −1) from `ml/config.yml`.
- `ml_component` = `(1 − clf_confidence) * 80 + healthy_bonus_if_not_anomaly`.
- Defaults: rule 60%, ML 40% — both fully configurable in `ml/config.yml`.

A **100** = perfect modern TLS 1.3, AEAD, forward secrecy, trusted valid cert, no
plaintext credentials. Lower scores carry the critical/high findings first.

---

## 8. What Time-Saving Property Makes This "AI-Assisted"?

The rules encode **known** weaknesses. The ML layer catches the **unknown / statistical**
outliers and learns risk grading from labeled examples. The hybrid means:
- Strong, explainable, deterministic coverage (the rules).
- Generalization to new/messy traffic it hasn't been told about (the ML).
- A single human-readable score for triage, plus drill-down to root cause.

---

## 9. Non-Goals (Explicitly Out of Scope Today)

- Decrypting TLS payloads (no session keys) — it assesses the *handshake & certs*, not
  message content.
- Active vulnerability scanning / exploitation.
- Network interception (it only reads what's captured / given to it).
- Real-time inline blocking (it is analysis-first; enforcement would be a roadmap item).

_See `ROADMAP.md` for expansion ideas._
