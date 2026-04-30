"""Secrets detector using gitleaks."""
import json
import subprocess
import time
from typing import List
from scanner.scanners.base import BaseScanner
from scanner.types import Finding, ScanResult


class SecretsScanner(BaseScanner):
    """Detect hardcoded secrets using gitleaks."""
    name = "gitleaks"

    def scan(self, target_path: str, config: dict) -> ScanResult:
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []

        if not self._tool_available("gitleaks"):
            errors.append("gitleaks not found. Install: go install github.com/zricethezav/gitleaks/v8@latest")
            return ScanResult(findings, int((time.time() - start) * 1000), self.name, errors)

        args = ["gitleaks", "dir", "-v", "--report-format", "json", "--report-path", "/dev/stdout", target_path]
        if config.get("config"):
            args += ["--config", config["config"]]

        result = self._run_cmd(args)

        if result.returncode not in (0, 1):
            errors.append("gitleaks failed: " + result.stderr[:300])
        else:
            try:
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for item in data:
                            findings.append(Finding(
                                id="SEC-" + str(item.get("RuleID", "unknown")),
                                rule_id=str(item.get("RuleID", "")),
                                severity=self._map_severity(item.get("Severity", "")),
                                category="SECRET",
                                file_path=str(item.get("File", "")),
                                line=int(item.get("StartLine", 0)),
                                message="Secret detected: " + str(item.get("Description", item.get("RuleID", ""))),
                                remediation=self._get_remediation(
                                str(item.get("RuleID", "")),
                                "Rotate this secret immediately and remove from source code. Use environment variables or a secrets manager."
                            ),
                                raw=item,
                            ))
            except json.JSONDecodeError:
                pass  # gitleaks may output nothing when no secrets found
            except Exception as e:
                errors.append("Error processing gitleaks results: " + str(e))

        duration = int((time.time() - start) * 1000)
        return ScanResult(findings, duration, self.name, errors)

    def _map_severity(self, gitleaks_sev: str) -> str:
        mapping = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}
        return mapping.get(gitleaks_sev, "high")

    def _tool_available(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
