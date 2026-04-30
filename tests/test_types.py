"""Tests for scanner types."""
import pytest
from scanner.types import Finding, ScanResult


def test_finding_creation():
    f = Finding(
        id="TEST-1",
        rule_id="TEST",
        severity="high",
        category="SAST",
        file_path="/tmp/test.go",
        line=10,
        message="Test finding",
    )
    assert f.id == "TEST-1"
    assert f.severity == "high"


def test_scan_result_creation():
    f = Finding(
        id="TEST-1",
        rule_id="TEST",
        severity="high",
        category="SAST",
        file_path="/tmp/test.go",
        line=10,
        message="Test",
    )
    result = ScanResult(findings=[f], scan_duration_ms=100, scanner_name="test")
    assert len(result.findings) == 1
    assert result.scanner_name == "test"


def test_finding_with_cvss():
    f = Finding(
        id="CVE-1",
        rule_id="CVE-123",
        severity="critical",
        category="CVE",
        file_path="/tmp/go.mod",
        line=0,
        message="Vulnerability",
        cvss=9.8,
    )
    assert f.cvss == 9.8
