"""Utility functions for filtering findings."""
from typing import List
from scanner.types import Finding


def filter_by_severity(findings: List[Finding], min_severity: str) -> List[Finding]:
    """Filter findings by minimum severity level."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_level = order.get(min_severity.lower(), 2)
    return [f for f in findings if order.get(f.severity, 2) <= min_level]


def filter_by_category(findings: List[Finding], category: str) -> List[Finding]:
    """Filter findings by category (SAST, SECRET, CVE)."""
    return [f for f in findings if f.category.upper() == category.upper()]


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on rule_id + file_path + line."""
    seen = set()
    result = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
