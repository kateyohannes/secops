"""DAST scanner using Nuclei for SecOps Tool."""
import subprocess
import time
from typing import List, Optional
from scanner.scanners.base import BaseScanner
from scanner.types import Finding, ScanResult


class NucleiScanner(BaseScanner):
    """Dynamic Application Security Testing using Nuclei."""

    name = "nuclei"

    def scan(self, target_url: str, config: dict) -> ScanResult:
        """Scan a running application for vulnerabilities."""
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []

        if not self._tool_available("nuclei"):
            errors.append("nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            return ScanResult(findings, int((time.time() - start) * 1000), self.name, errors)

        # Build nuclei command
        args = ["nuclei", "-u", target_url, "-json"]

        # Add custom templates if specified
        if config.get("templates"):
            args += ["-t", config["templates"]]

        # Severity filter
        if config.get("severity"):
            args += ["-severity", config["severity"]]

        # Output format
        args += ["-o", "/dev/stdout"]

        result = self._run_cmd(args)

        if result.returncode not in (0, 1):
            errors.append("nuclei failed: " + result.stderr[:300])
        else:
            try:
                # Parse JSON output line by line
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    import json
                    data = json.loads(line)
                    findings.append(Finding(
                        id="NUCLEI-" + str(data.get("template-id", "unknown")),
                        rule_id=str(data.get("template-id", "")),
                        severity=self._map_severity(data.get("info", {}).get("severity", "")),
                        category="DAST",
                        file_path=target_url,
                        line=0,
                        message=data.get("info", {}).get("name", "Vulnerability detected"),
                        remediation=self._get_remediation(data.get("template-id", "")),
                        cvss=self._extract_cvss(data.get("info", {})),
                        raw=data,
                    ))
            except json.JSONDecodeError:
                pass  # Nuclei may output non-JSON lines
            except Exception as e:
                errors.append("Error processing nuclei results: " + str(e))

        duration = int((time.time() - start) * 1000)
        return ScanResult(findings, duration, self.name, errors)

    def _map_severity(self, severity: str) -> str:
        """Map nuclei severity to internal levels."""
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
        return mapping.get(severity.lower(), "medium")

    def _extract_cvss(self, info: dict) -> Optional[float]:
        """Extract CVSS score from nuclei info."""
        cvss_data = info.get("classification", {}).get("cvss-score")
        if cvss_data:
            try:
                return float(cvss_data)
            except (ValueError, TypeError):
                pass
        return None
