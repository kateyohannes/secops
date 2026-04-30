"""Integration tests for scanners."""
import pytest
import os
from scanner.scanners.gosec import GosecScanner
from scanner.scanners.semgrep import SemgrepScanner
from scanner.types import Finding, ScanResult


def test_gosec_scanner_init():
    scanner = GosecScanner()
    assert scanner.name == "gosec"


def test_semgrep_scanner_init():
    scanner = SemgrepScanner()
    assert scanner.name == "semgrep"


def test_gosec_tool_available():
    scanner = GosecScanner()
    assert hasattr(scanner, "_tool_available")


def test_semgrep_tool_available():
    scanner = SemgrepScanner()
    assert hasattr(scanner, "_tool_available")
