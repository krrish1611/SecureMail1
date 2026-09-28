"""Tests for regulatory compliance matrix (PCI-DSS 4.0, NIST 800-52r2, HIPAA)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.capture import reassemble
from core.analyzer import analyze_all
from core.compliance import (
    evaluate_compliance,
    evaluate_compliance_all,
    compliance_report_to_dict,
    CONTROLS,
)


def test_compliance_evaluation_all_frameworks(sample_pcap):
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    report = evaluate_compliance_all(sessions)

    assert len(report.frameworks) == 3
    fw_names = {fw.framework for fw in report.frameworks}
    assert fw_names == {"PCI-DSS 4.0", "NIST 800-52r2", "HIPAA"}

    # The sample PCAP has RC4 and plaintext credentials, so frameworks should fail
    for fw in report.frameworks:
        assert fw.verdict == "NON-COMPLIANT"
        assert fw.failed > 0
        assert fw.passed > 0

    assert len(report.per_session) == len(sessions)


def test_compliance_controls_structure():
    assert len(CONTROLS) >= 10
    for ctrl in CONTROLS:
        assert "id" in ctrl
        assert "name" in ctrl
        assert "frameworks" in ctrl
        assert "PCI-DSS 4.0" in ctrl["frameworks"]
        assert "NIST 800-52r2" in ctrl["frameworks"]
        assert "HIPAA" in ctrl["frameworks"]


def test_compliance_report_to_dict(sample_pcap):
    streams = reassemble(sample_pcap)
    sessions = analyze_all(streams)
    report = evaluate_compliance_all(sessions)
    d = compliance_report_to_dict(report)

    assert "frameworks" in d
    assert "controls_summary" in d
    assert "per_session" in d
    assert len(d["frameworks"]) == 3
    assert len(d["controls_summary"]) == len(CONTROLS)
