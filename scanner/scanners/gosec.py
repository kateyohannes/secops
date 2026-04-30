"""Go AST scanner using gosec."""
import json
import subprocess
import tempfile
import os
import time
from typing import List
from scanner.scanners.base import BaseScanner
from scanner.types import Finding, ScanResult


class GosecScanner(BaseScanner):
    """Scan Go code for security issues using gosec."""
    name = "gosec"

    def scan(self, target_path: str, config: dict) -> ScanResult:
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []

        if not self._tool_available("gosec"):
            errors.append("gosec not found. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest")
            return ScanResult(findings, int((time.time() - start) * 1000), self.name, errors)

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp.close()

        args = ["gosec", "-fmt=json", "-out", tmp.name, "./..."]
        args += config.get("args", [])
        result = self._run_cmd(args, cwd=target_path)

        if os.path.exists(tmp.name) and os.path.getsize(tmp.name) > 0:
            try:
                with open(tmp.name, "r") as f:
                    data = json.load(f)
                for issue in data.get("Issues", []):
                    severity = self._severity_map(issue.get("severity", ""))
                    rule_id = issue.get("rule_id", "unknown")
                    findings.append(Finding(
                        id="GSECR-" + rule_id,
                        rule_id=rule_id,
                        severity=severity,
                        category="SAST",
                        file_path=issue.get("file", ""),
                        line=int(issue.get("line", 0)),
                        message=issue.get("details", ""),
                        cwe=self._extract_cwe(issue.get("cwe", {})),
                        remediation=self._remediation(rule_id),
                        raw=issue,
                    ))
            except json.JSONDecodeError as e:
                errors.append("Failed to parse gosec output: " + str(e))
            except Exception as e:
                errors.append("Error processing gosec results: " + str(e))
            finally:
                if os.path.exists(tmp.name):
                    os.unlink(tmp.name)
        elif result.returncode not in (0, 1):
            errors.append("gosec failed: " + result.stderr)

        duration = int((time.time() - start) * 1000)
        return ScanResult(findings, duration, self.name, errors)

    def _severity_map(self, gosec_sev: str) -> str:
        mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        return mapping.get(gosec_sev.upper(), "medium")

    def _extract_cwe(self, cwe_obj) -> str:
        if isinstance(cwe_obj, dict):
            return cwe_obj.get("id", "")
        return ""

    def _remediation(self, rule_id: str) -> str:
        tips = {
            "G101": "Avoid hardcoding credentials; use environment variables or a secrets manager.",
            "G102": "Avoid binding services to all interfaces; bind to localhost or specific IPs.",
            "G201": "Use parameterized queries instead of string formatting for SQL queries.",
            "G202": "Use parameterized queries instead of string concatenation for SQL queries.",
            "G204": "Avoid exec.Command with user input; use allowlists for commands.",
            "G401": "Use strong cryptographic hash functions (SHA-256+) instead of MD5/SHA1.",
            "G501": "Replace crypto/md5 with crypto/sha256 or other strong hash.",
        }
        return tips.get(rule_id, "Review this finding and apply secure coding practices.")

    def _tool_available(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
