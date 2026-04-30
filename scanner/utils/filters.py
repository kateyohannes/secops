
from typing import List, Optional
from scanner.types import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def filter_by_severity(findings: List[Finding], min_severity: str) -> List[Finding]:
    if not min_severity:
        return findings
    threshold = SEVERITY_ORDER.get(min_severity.lower(), 99)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]


def filter_by_category(findings: List[Finding], categories: List[str]) -> List[Finding]:
    if not categories:
        return findings
    return [f for f in findings if f.category in categories]


def filter_by_file(findings: List[Finding], exclude_patterns: List[str]) -> List[Finding]:
    import fnmatch
    if not exclude_patterns:
        return findings
    filtered = []
    for f in findings:
        excluded = any(fnmatch.fnmatch(f.file_path, p) for p in exclude_patterns)
        if not excluded:
            filtered.append(f)
    return filtered


def deduplicate(findings: List[Finding]) -> List[Finding]:
    seen = set()
    result = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
