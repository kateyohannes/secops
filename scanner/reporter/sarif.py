"""SARIF output renderer for SecOps Tool."""
import json
from typing import List
from scanner.types import Finding, ScanResult


def render_sarif(results: List[ScanResult]) -> str:
    """Render scan results as SARIF format."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }

    for res in results:
        rules = {}
        results_list = []

        for f in res.findings:
            rule_id = f.rule_id or "unknown"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.message},
                    "defaultConfiguration": {"level": _sarif_level(f.severity)},
                }

            result = {
                "ruleId": rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
            if f.remediation:
                result["fixes"] = [{"description": {"text": f.remediation}}]
            results_list.append(result)

        run = {
            "tool": {
                "driver": {
                    "name": res.scanner_name,
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results_list,
        }
        sarif["runs"].append(run)

    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    """Map severity to SARIF level."""
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return mapping.get(severity, "warning")
