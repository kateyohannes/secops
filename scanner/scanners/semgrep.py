"""JS/TS AST scanner using semgrep."""
import json
import subprocess
import time
from typing import List
from scanner.scanners.base import BaseScanner
from scanner.types import Finding, ScanResult


class SemgrepScanner(BaseScanner):
    """Scan JS/TS code for security issues using semgrep."""
    name = "semgrep"

    def scan(self, target_path: str, config: dict) -> ScanResult:
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []

        if not self._tool_available("semgrep"):
            errors.append("semgrep not found. Install: pip install semgrep")
            return ScanResult(findings, int((time.time() - start) * 1000), self.name, errors)

        args = ["semgrep", "scan", "--json", "--quiet", "-c", "auto", "."]
        args += config.get("args", [])
        result = self._run_cmd(args, cwd=target_path)

        if result.returncode not in (0, 1):
            errors.append("semgrep failed: " + result.stderr[:300])
        else:
            try:
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    for result_item in data.get("results", []):
                        findings.append(Finding(
                            id="SEMGR-" + str(result_item.get("check_id", "unknown")),
                            rule_id=str(result_item.get("check_id", "")),
                            severity=self._map_severity(result_item.get("extra", {}).get("severity", "")),
                            category="SAST",
                            file_path=str(result_item.get("path", "")),
                            line=result_item.get("start", {}).get("line", 0),
                            message=str(result_item.get("extra", {}).get("message", "")),
                            remediation=str(result_item.get("extra", {}).get("fix", "")),
                            cwe=self._extract_cwe(result_item.get("extra", {}).get("metadata", {})),
                            raw=result_item,
                        ))
            except json.JSONDecodeError:
                errors.append("Failed to parse semgrep JSON output")
            except Exception as e:
                errors.append("Error processing semgrep results: " + str(e))

        duration = int((time.time() - start) * 1000)
        return ScanResult(findings, duration, self.name, errors)

    def _map_severity(self, semgrep_sev: str) -> str:
        mapping = {"ERROR": "critical", "WARNING": "high", "INFO": "medium", "EXPERIMENTAL": "low"}
        return mapping.get(semgrep_sev.upper(), "medium")

    def _extract_cwe(self, metadata: dict) -> str:
        for cwe_info in metadata.get("cwe", []):
            if "CWE-" in cwe_info:
                return cwe_info
        return ""

    def _tool_available(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
