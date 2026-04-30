
import json
from typing import List
from datetime import datetime, timezone
from scanner.types import Finding, ScanResult

SARIF_VERSION = "2.1.0"
SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def render(results: List[ScanResult], tool_name: str = "secops-tool") -> str:
    rules_map = {}
    results_list = []

    for scan_result in results:
        for f in scan_result.findings:
            rule_id = f.rule_id or f.id
            if rule_id not in rules_map:
                rules_map[rule_id] = _build_rule(f)
            results_list.append(_build_result(f, rule_id))

    sarif = {
        "$schema": SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "0.1.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results_list,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _build_rule(f: Finding) -> dict:
    return {
        "id": f.rule_id or f.id,
        "shortDescription": {"text": f"{f.category} - {f.rule_id}"},
        "fullDescription": {"text": f.message},
        "defaultConfiguration": {"level": _sarif_level(f.severity)},
        "properties": {
            "category": f.category,
            "cwe": f.cwe or "",
        },
    }


def _build_result(f: Finding, rule_id: str) -> dict:
    return {
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
        "properties": {
            "severity": f.severity,
            "category": f.category,
            "remediation": f.remediation or "",
        },
    }


def _sarif_level(severity: str) -> str:
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return mapping.get(severity.lower(), "warning")
