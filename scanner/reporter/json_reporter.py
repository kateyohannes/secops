
import json
from typing import List
from scanner.types import Finding, ScanResult


def render_findings(findings: List[Finding]) -> str:
    data = [_finding_to_dict(f) for f in findings]
    return json.dumps(data, indent=2, default=str)


def render_scan_results(results: List[ScanResult]) -> str:
    data = {
        "findings": [_finding_to_dict(f) for r in results for f in r.findings],
        "scans": [
            {
                "scanner": r.scanner_name,
                "duration_ms": r.scan_duration_ms,
                "findings_count": len(r.findings),
                "errors": r.errors,
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2, default=str)


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "category": f.category,
        "file_path": f.file_path,
        "line": f.line,
        "message": f.message,
        "remediation": f.remediation,
        "cwe": f.cwe,
        "cvss": f.cvss,
    }
