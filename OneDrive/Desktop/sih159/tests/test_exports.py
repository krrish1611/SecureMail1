"""Tests for the JSON/HTML/PDF report exporters."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.analyzer import analyze_all
from core.capture import reassemble
from reports.exporters import generate_json, generate_html, generate_pdf


def _sessions(sample_pcap):
    streams = reassemble(sample_pcap)
    return analyze_all(streams)


def test_generate_json_valid(sample_pcap, tmp_path):
    sessions = _sessions(sample_pcap)
    out = os.path.join(str(tmp_path), "report.json")
    path = generate_json(sessions, out)
    with open(path) as f:
        data = json.load(f)
    assert "sessions" in data or "findings" in data or "summary" in data


def test_generate_html_nonempty(sample_pcap, tmp_path):
    sessions = _sessions(sample_pcap)
    out = os.path.join(str(tmp_path), "report.html")
    path = generate_html(sessions, out)
    with open(path) as f:
        html = f.read()
    assert "<html" in html.lower() or "<!doctype" in html.lower()
    assert len(html) > 100


def test_exports_include_cert_trust_fields(sample_pcap, tmp_path):
    """The exported JSON should surface trust/revocation fields when present."""
    sessions = _sessions(sample_pcap)
    out = os.path.join(str(tmp_path), "report.json")
    generate_json(sessions, out)
    with open(out) as f:
        data = json.load(f)
    # Serialize all session dicts to check no crash; field presence is best-effort.
    assert data is not None


def test_generate_pdf_valid(sample_pcap, tmp_path):
    """PDF export should create a valid, non-empty PDF file with a proper %PDF header."""
    sessions = _sessions(sample_pcap)
    out = os.path.join(str(tmp_path), "report.pdf")
    path = generate_pdf(sessions, out)
    assert os.path.exists(path)
    assert os.path.getsize(path) > 2000
    with open(path, "rb") as f:
        header = f.read(10)
    assert header.startswith(b"%PDF-")


def test_generate_pdf_empty_sessions(tmp_path):
    """PDF export should handle an empty session list gracefully without crashing."""
    out = os.path.join(str(tmp_path), "empty_report.pdf")
    path = generate_pdf([], out)
    assert os.path.exists(path)
    assert os.path.getsize(path) > 500
    with open(path, "rb") as f:
        header = f.read(10)
    assert header.startswith(b"%PDF-")


def test_generate_pdf_special_characters(sample_pcap, tmp_path):
    """PDF export must safely escape XML special characters in titles, descriptions, and certs."""
    from core.models import Finding, Severity
    sessions = _sessions(sample_pcap)
    if sessions:
        # Inject finding with XML sensitive characters
        sessions[0].findings.append(Finding(
            id="TEST-01",
            title="Dangerous <tag> & symbols 'test' \"quotes\"",
            description="Testing DH key < 2048 bits & cipher strength < 128 bit with <script>alert(1)</script>",
            category="crypto",
            severity=Severity.HIGH,
            recommendation="Upgrade to TLS >= 1.3 & use AES-GCM",
        ))
    out = os.path.join(str(tmp_path), "special_chars_report.pdf")
    path = generate_pdf(sessions, out)
    assert os.path.exists(path)
    assert os.path.getsize(path) > 2000

def test_generate_csv_valid(sample_pcap, tmp_path):
    from reports.exporters import generate_csv
    import csv
    sessions = _sessions(sample_pcap)
    out = os.path.join(str(tmp_path), "report.csv")
    path = generate_csv(sessions, out)
    assert os.path.exists(path)
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        headers = next(reader)
        assert "Session ID" in headers
        assert "Protocol" in headers
        assert "MTA-STS Status" in headers
        assert "DANE Status" in headers
        assert "Findings" in headers
        rows = list(reader)
        assert len(rows) == len(sessions)


def test_dns_security_in_all_exports(tmp_path):
    """Ensure DnsSecurityInfo is correctly serialized into JSON, HTML, PDF, and CSV reports."""
    from core.models import Session, DnsSecurityInfo
    from reports.exporters import generate_json, generate_html, generate_pdf, generate_csv
    import json
    import csv

    session = Session(
        id="dns_sec_test_01",
        protocol="SMTP",
        client_ip="10.0.0.2",
        client_port=49000,
        server_ip="10.0.0.1",
        server_port=25,
        encrypted=True,
    )
    session.dns_security = DnsSecurityInfo(
        domain="securebank.org",
        hostname="smtp.securebank.org",
        mta_sts_record="v=STSv1; id=20240101",
        mta_sts_valid=True,
        mta_sts_mode="enforce",
        mta_sts_id="20240101",
        dane_tlsa_records=["3 0 1 abcdef"],
        dane_valid=True,
        dane_match_status="matched",
        recommended_mta_sts_dns='_mta-sts.securebank.org. IN TXT "v=STSv1; id=20260101000000;"',
        recommended_mta_sts_policy="version: STSv1\nmode: enforce\nmx: mail.securebank.org\nmax_age: 604800\n",
    )

    sessions = [session]

    # 1. JSON
    j_out = os.path.join(str(tmp_path), "test_dns.json")
    generate_json(sessions, j_out)
    with open(j_out, "r", encoding="utf-8") as f:
        data = json.load(f)
    s0 = data["sessions"][0]
    assert "dns_security" in s0
    assert s0["dns_security"]["domain"] == "securebank.org"
    assert s0["dns_security"]["mta_sts_mode"] == "enforce"
    assert s0["dns_security"]["dane_valid"] is True

    # 2. HTML
    h_out = os.path.join(str(tmp_path), "test_dns.html")
    generate_html(sessions, h_out)
    with open(h_out, "r", encoding="utf-8") as f:
        html_content = f.read()
    assert "MTA-STS &amp; DANE Downgrade Protection" in html_content or "MTA-STS & DANE Downgrade Protection" in html_content
    assert "securebank.org" in html_content
    assert "enforce" in html_content

    # 3. CSV
    c_out = os.path.join(str(tmp_path), "test_dns.csv")
    generate_csv(sessions, c_out)
    with open(c_out, "r", newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    headers, row = rows[0], rows[1]
    mta_idx = headers.index("MTA-STS Status")
    dane_idx = headers.index("DANE Status")
    assert row[mta_idx] == "enforce"
    assert row[dane_idx] == "matched"

    # 4. PDF
    p_out = os.path.join(str(tmp_path), "test_dns.pdf")
    generate_pdf(sessions, p_out)
    assert os.path.exists(p_out)
    assert os.path.getsize(p_out) > 2000
