"""Tests for filters module."""
import pytest
from scanner.types import Finding
from scanner.utils.filters import filter_by_severity, filter_by_category, deduplicate


def make_finding(severity, category, rule_id="R1", file_path="/tmp/test", line=1):
    return Finding(
        id="T1",
        rule_id=rule_id,
        severity=severity,
        category=category,
        file_path=file_path,
        line=line,
        message="Test",
    )


def test_filter_by_severity():
    findings = [
        make_finding("critical", "SAST"),
        make_finding("low", "SAST"),
        make_finding("high", "SAST"),
    ]
    result = filter_by_severity(findings, "high")
    assert len(result) == 2


def test_filter_by_category():
    findings = [
        make_finding("high", "SAST"),
        make_finding("high", "SECRET"),
        make_finding("critical", "CVE"),
    ]
    result = filter_by_category(findings, "SAST")
    assert len(result) == 1


def test_deduplicate():
    findings = [
        make_finding("high", "SAST", "R1", "/tmp/a", 1),
        make_finding("high", "SAST", "R1", "/tmp/a", 1),
        make_finding("high", "SAST", "R2", "/tmp/b", 2),
    ]
    result = deduplicate(findings)
    assert len(result) == 2
