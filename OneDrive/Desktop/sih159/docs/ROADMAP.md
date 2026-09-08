# SecureMailScope — Roadmap: What More Needs Doing

A prioritized backlog of the next things to build, fix, and validate, ordered by
impact-to-effort. Items marked **P0** deliver immediate real-world value; **P1** fills
the most common feature gaps; **P2** are longer-term differentiators.

---

## Near-term (P0) — polish what exists

### P0-1. Real-world validation on genuine traffic
- [ ] Obtain real (sanitized / synthetic-but-realistic) enterprise email captures
      (e.g. a few thousand real client→server sessions) and run the full pipeline.
- [ ] Validate posture scores against a known-good and a known-bad mail server as a
      reference benchmark.
- [ ] Fold any misclassified sessions into `ml/training_data.py`.

**Why:** the #1 risk is that the synthetic data doesn't match real fingerprint
distributions. Everything else is built; this proves it.

### P0-2. TLS 1.3 post-handshake & session details
- [ ] Record negotiated `key_share` group on the server side for TLS 1.3 (currently
      inferred from the client hello).
- [ ] Surface **resumption** (`session_ticket`/pre_shared_key) and **cert compression**.
- [ ] Add **key-update** / `EndOfEarlyData` handling so long-lived 1.3 sessions stay sane.

### P0-3. STARTTLS strip — stronger signal
- [ ] Add **opportunistic vs required** model: a session that requested STARTTLS but sent
      credentials before any TLS bytes is a *confirmed* STRIPTLS → currently flagged
      `starttls.plaintext_creds`. Add an explicit `starttls.strip_credential_leak` rule and
      a dedicated high-impact indicator in the UI.

### P0-4. Credential handling hardening
- [ ] Mask/redact base64 credential payloads in reports (don't write passwords to disk).
- [ ] Classify the auth mechanism (LOGIN/PLAIN/CRAM-MD5/XOAUTH2) and flag legacy hashing.

---

## Mid-term (P1) — round out the product

### P1-1. Certificate post-processing
- [ ] **Real OCSP/CRL fetch** behind a `--online` flag (currently best-effort/offline-safe).
- [ ] Add **validity window warnings** (expiring in < 30 days).
- [ ] Add **certificate transparency (CT)** / SCT presence check.
- [ ] Expose SKI/AKI chain-builder verification errors in the UI.

### P1-2. More protocols & transports
- [ ] Add **IMAPS/POP3S** implicit-TLS as first-class (currently detected but prioritize
      STARTTLS clarity).
- [ ] Add **SMTP submission (587)** vs MTA-to-MTA (25) distinction — different posture
      expectations per role.
- [ ] (Stretch) **DNS + MTA-STS / DANE** posture: check whether the peer publishes MTA-STS
      policy / DANE TLSA records, shown as an advisory.

### P1-3. Scale & performance
- [ ] Benchmark analyzor on a large capture (1–10 GB). Profile the hot loops in
      `core/tls.py` / `core/capture.py`; add optional `numpy`-backed fast paths.
- [ ] Add **parallel session analysis** (multiprocessing) with a progress stream for the UI.
- [ ] Add **capture memory limits** / streaming reassembly guardrails to avoid OOM on huge
      captures.

### P1-4. Reproducibility & config
- [ ] Lock pinned versions in `requirements.txt` (currently loose) for reproducible builds.
- [ ] Support `config.yml` for **rule severities** (escalate/de-escalate) and thresholds,
      not just ML weights.

### P1-5. Reports
- [ ] Add **CSV/Excel** export of all findings (auditors love spreadsheets).
- [ ] Add a **trend/changelist** view when comparing two captures.
- [ ] Make PDF report paginate cleanly for large session counts.

---

## Long-term (P2) — differentiators

### P2-1. Enforcement / alignment with real infra
- [ ] Integrate with **MTA-STS** validation and produce "recommended policy" text a mail
      admin can paste into DNS.
- [ ] (Stretch) alerting hook (webhook/email) when live mode crosses a posture threshold.

### P2-2. Deeper ML
- [ ] **JA3/JA4 clustering** to fingerprint unusual client stacks.
- [ ] Time-series **baseline drift** detection per peer over repeated captures.
- [ ] Optional **active verification** (opt-in) for a *single* peer, hybridizing passive +
      active results.

### P2-3. Deployment & packaging
- [ ] **Docker image** (`Dockerfile` + compose) so it runs anywhere.
- [ ] **pip-installable package** (`pip install securemailscope`) exposing `smscope --live`.
- [ ] **SIEM integration** (Splunk/ELK ingestion of findings as events).
- [ ] Optional **SaaS upload endpoint** + multi-tenant dashboard (business-model play).

### P2-4. Broader scope
- [ ] Extend to **web / API / TLS-in-general** posture (generalize beyond email).
- [ ] Add **MTA behavioral fingerprinting** (spoofing indicators) — new threat surface.

---

## Suggested sequence (a realistic 6–8 week plan)

| Week | Focus | Exit criterion |
|------|-------|----------------|
| 1 | P0-1 real traffic validation | Posture scores match a known-good/bad reference |
| 2 | P0-2 TLS 1.3 server details | Correct group shown for 1.3 sessions |
| 3 | P0-3/P0-4 STARTTLS strip + credential redaction | Confirmed STRIPTLS flagged; no plaintext creds written |
| 4 | P1-1 online OCSP/CRL + expiry window | Online revocation works with real CA certs |
| 5 | P1-2 protocol roles + MTA-STS advisory | 587-vs-25 distinguished; MTA-STS advisory shown |
| 6 | P1-3 performance on 1–10 GB capture | Analysis of a 10 GB capture completes without OOM |
| 7 | P1-4 pins + P1-5 CSV/trend reports | Fully reproducible build; auditor-friendly exports |
| 8 | P2-1 Docker + webhook | `docker run` works; live alerts on threshold breach |

---

## Always-open / hygiene

- Keep the `pytest` suite green (33 tests) with every change.
- Keep `ml/saved_models/` reproducible — retrain + commit expected scores when data changes.
- Document every new rule id (they appear in reports, API, and UI).
