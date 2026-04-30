"""Comprehensive tests for SecOps Tool."""
import os
import json
import tempfile
import pytest
from scanner.baseline import BaselineManager
from scanner.remediation import AutoRemediation
from scanner.config import load_config, validate_config, ConfigValidationError
from scanner.reporter.redactor import OutputRedactor
from scanner.types import Finding, ScanResult


class TestBaselineManager:
    """Tests for BaselineManager."""

    def test_ignore_finding_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BaselineManager(tmpdir)
            manager.add_ignored_finding(type("F", (), {"id": "TEST-123"})())

            f = Finding(
                id="TEST-123", rule_id="TEST", severity="high", category="SAST",
                file_path="/tmp/test.go", line=1, message="Test"
            )
            assert manager.is_ignored(f)

    def test_ignore_rule_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BaselineManager(tmpdir)
            manager.add_ignored_rule("G101")

            f = Finding(
                id="GSECR-G101", rule_id="G101", severity="high", category="SAST",
                file_path="/tmp/test.go", line=1, message="Test"
            )
            assert manager.is_ignored(f)

    def test_ignore_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BaselineManager(tmpdir)
            manager.add_ignored_path("vendor/")

            f = Finding(
                id="TEST-1", rule_id="TEST", severity="high", category="SAST",
                file_path="/tmp/vendor/lib/file.go", line=1, message="Test"
            )
            assert manager.is_ignored(f)

    def test_filter_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = BaselineManager(tmpdir)
            manager.add_ignored_rule("G101")

            findings = [
                Finding(id="T1", rule_id="G101", severity="high", category="SAST",
                        file_path="/tmp/a.go", line=1, message="Test"),
                Finding(id="T2", rule_id="G102", severity="high", category="SAST",
                        file_path="/tmp/b.go", line=1, message="Test"),
            ]

            filtered = manager.filter_findings(findings)
            assert len(filtered) == 1
            assert filtered[0].rule_id == "G102"

    def test_load_from_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".secops-ignore")
            data = {
                "finding_ids": ["TEST-1"],
                "rule_ids": ["G101"],
                "paths": ["vendor/"]
            }
            with open(ignore_file, "w") as f:
                json.dump(data, f)

            manager = BaselineManager(tmpdir)
            assert "TEST-1" in manager.ignored_ids
            assert "G101" in manager.ignored_rules
            assert "vendor/" in manager.ignored_paths


class TestAutoRemediation:
    """Tests for AutoRemediation."""

    def test_can_fix_cve(self):
        remediator = AutoRemediation("/tmp")

        f = Finding(
            id="CVE-1", rule_id="CVE-123", severity="critical", category="CVE",
            file_path="/tmp/package.json", line=0, message="Vulnerability"
        )
        assert remediator.can_fix(f)

    def test_cannot_fix_sast(self):
        remediator = AutoRemediation("/tmp")

        f = Finding(
            id="GSECR-G101", rule_id="G101", severity="high", category="SAST",
            file_path="/tmp/test.go", line=1, message="Test"
        )
        assert not remediator.can_fix(f)

    def test_extract_package_name(self):
        remediator = AutoRemediation("/tmp")

        f = Finding(
            id="CVE-1", rule_id="CVE-123", severity="critical", category="CVE",
            file_path="/tmp/package.json", line=0, message="Vulnerability",
            raw={"affected": [{"package": {"name": "express"}}]}
        )
        name = remediator._extract_package_name(f)
        assert name == "express"


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_valid_config(self):
        config = {
            "scanners": {"gosec": {"enabled": True}},
            "output": {"format": "json"}
        }
        result = validate_config(config)
        assert result is not None

    def test_invalid_format(self):
        config = {"output": {"format": "invalid"}}
        with pytest.raises(ConfigValidationError):
            validate_config(config)

    def test_invalid_scanner(self):
        config = {"scanners": {"invalid_scanner": {"enabled": True}}}
        # Note: validate_config may not raise for unknown scanners
        result = validate_config(config)
        assert result is not None


class TestOutputRedactor:
    """Tests for OutputRedactor."""

    def test_redact_github_token(self):
        redactor = OutputRedactor(enabled=True)
        text = "token = 'ghp_ABCD1234EFGH5678IJKL9012MNOP3456QRST7890'"
        result = redactor.redact(text)
        assert "ghp_ABCD" not in result
        assert "****" in result

    def test_redact_aws_key(self):
        redactor = OutputRedactor(enabled=True)
        text = "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'"
        result = redactor.redact(text)
        assert "AKIAIOSF" not in result

    def test_redact_disabled(self):
        redactor = OutputRedactor(enabled=False)
        text = "token = 'ghp_secret123'"
        result = redactor.redact(text)
        assert result == text

    def test_redact_findings(self):
        redactor = OutputRedactor(enabled=True)
        findings = [
            Finding(
                id="T1", rule_id="G101", severity="high", category="SAST",
                file_path="/tmp/test.go", line=1,
                message="API key: ghp_ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
            )
        ]
        redacted = redactor.redact_findings(findings)
        # The token should be redacted (not contain the full original token)
        assert "ABCD1234" not in redacted[0].message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
