"""CVE scanner using osv-scanner."""
import json
import subprocess
import time
from typing import List, Dict, Optional
from scanner.scanners.base import BaseScanner
from scanner.types import Finding, ScanResult


class CVEScanner(BaseScanner):
    """Scan dependencies for CVEs using osv-scanner."""
    name = "osv-scanner"

    ECOSYSTEM_MAP = {
        "go.mod": "Go",
        "go.sum": "Go",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "requirements.txt": "PyPI",
        "Pipfile.lock": "PyPI",
        "poetry.lock": "PyPI",
        "pom.xml": "Maven",
        "build.gradle": "Maven",
        "Cargo.lock": "crates.io",
        "Gemfile.lock": "RubyGems",
        "composer.lock": "Packagist",
    }

    def scan(self, target_path: str, config: dict) -> ScanResult:
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []

        if not self._tool_available("osv-scanner"):
            errors.append("osv-scanner not found. Install: go install github.com/google/osv-scanner/cmd/osv-scanner@latest")
            return ScanResult(findings, int((time.time() - start) * 1000), self.name, errors)

        args = ["osv-scanner", "scan", "--format=json", target_path]
        result = self._run_cmd(args)

        if result.returncode not in (0, 1):
            errors.append("osv-scanner failed: " + result.stderr[:300])
        else:
            try:
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    findings = self._parse_osv_results(data)
            except json.JSONDecodeError:
                errors.append("Failed to parse osv-scanner JSON output")
            except Exception as e:
                errors.append("Error processing osv-scanner results: " + str(e))

        duration = int((time.time() - start) * 1000)
        return ScanResult(findings, duration, self.name, errors)

    def _parse_osv_results(self, data: dict) -> List[Finding]:
        findings: List[Finding] = []
        results = data.get("results", [])
        for group in results:
            for vuln in group.get("vulnerabilities", []):
                findings.append(Finding(
                    id="CVE-" + str(vuln.get("id", "unknown")),
                    rule_id=str(vuln.get("id", "")),
                    severity=self._map_cvss(vuln.get("severity", "")),
                    category="CVE",
                    file_path=str(group.get("source", {}).get("path", "unknown")),
                    line=0,
                    message=self._build_message(vuln),
                    remediation=self._get_remediation(
                        str(vuln.get("id", "")),
                        self._build_remediation(vuln)
                    ),
                    cwe=self._extract_cwe(vuln),
                    cvss=self._extract_cvss_score(vuln),
                    raw=vuln,
                ))
        return findings

    def _build_message(self, vuln: dict) -> str:
        summary = vuln.get("summary", "")
        details = vuln.get("details", "")
        return summary or details[:200] or "Vulnerability detected"

    def _build_remediation(self, vuln: dict) -> str:
        affected = vuln.get("affected", [])
        if affected:
            pkg = affected[0].get("package", {})
            versions = affected[0].get("versions", [])
            pkg_name = pkg.get("name", "package")
            if versions:
                return "Update " + pkg_name + " to version not in: " + ", ".join(versions[:5])
        return "Update the affected package to a patched version."

    def _map_cvss(self, severity: str) -> str:
        mapping = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}
        return mapping.get(severity.upper(), "medium")

    def _extract_cwe(self, vuln: dict) -> str:
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if "cwe" in url.lower():
                return url
        return ""

    def _extract_cvss_score(self, vuln: dict) -> Optional[float]:
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score = sev.get("score")
                if score:
                    return float(score)
        return None

    def _tool_available(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
