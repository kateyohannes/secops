"""JSON output renderer for SecOps Tool."""
import json
from typing import List
from scanner.types import Finding, ScanResult


def render_scan_results(results: List[ScanResult]) -> str:
    """Render scan results as JSON."""
    output = {
        "scan_results": [],
        "summary": {"total_findings": 0, "by_severity": {}, "by_category": {}},
    }

    for res in results:
        scan_data = {
            "scanner": res.scanner_name,
            "duration_ms": res.scan_duration_ms,
            "findings_count": len(res.findings),
            "errors": res.errors,
            "findings": [_finding_to_dict(f) for f in res.findings],
        }
        output["scan_results"].append(scan_data)
        output["summary"]["total_findings"] += len(res.findings)
        for f in res.findings:
            output["summary"]["by_severity"][f.severity] = (
                output["summary"]["by_severity"].get(f.severity, 0) + 1
            )
            output["summary"]["by_category"][f.category] = (
                output["summary"]["by_category"].get(f.category, 0) + 1
            )

    return json.dumps(output, indent=2, default=str)


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a Finding to a dictionary."""
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "category": finding.category,
        "file_path": finding.file_path,
        "line": finding.line,
        "message": finding.message,
        "remediation": finding.remediation,
        "cwe": finding.cwe,
        "cvss": finding.cvss,
    }
