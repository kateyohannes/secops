"""Auto-triage heuristics for test/mock files."""
import os
from typing import List
from scanner.types import Finding


# Directories to auto-downgrade
EXCLUDED_DIRS = {"test", "tests", "mock", "mocks", "fixture", "fixtures", "__pycache__", "node_modules", "vendor"}

# File patterns to auto-downgrade
EXCLUDED_FILE_PATTERNS = [
    r'.*_test\.(go|py|js|ts)$',
    r'test_.*\.(go|py|js|ts)$',
    r'.*\.test\.(js|ts)$',
    r'.*\.spec\.(js|ts)$',
    r'.*\.mock\.(js|ts)$',
    r'.*\.fixture\.(js|ts)$',
    r'.*\.(md|txt|rst)$',  # Documentation files
]

# Severity downgrade mapping
DOWNGRADE_MAP = {
    "critical": "low",
    "high": "medium",
    "medium": "low",
    "low": "low",
}


def auto_triage(findings: List[Finding]) -> List[Finding]:
    """
    Automatically downgrade findings in test/mock/documentation files.
    Returns modified findings list with adjusted severities.
    """
    import re

    # Compile patterns
    patterns = [re.compile(p, re.IGNORECASE) for p in EXCLUDED_FILE_PATTERNS]

    triaged = []
    for f in findings:
        modified = Finding(
            id=f.id, rule_id=f.rule_id, severity=f.severity,
            category=f.category, file_path=f.file_path, line=f.line,
            message=f.message, remediation=f.remediation, cwe=f.cwe,
            cvss=f.cvss, raw=f.raw
        )

        # Check if file is in excluded directory
        path_parts = f.file_path.replace("\\", "/").split("/")
        should_downgrade = any(part in EXCLUDED_DIRS for part in path_parts)

        # Check file patterns
        if not should_downgrade:
            for pattern in patterns:
                if pattern.match(os.path.basename(f.file_path)):
                    should_downgrade = True
                    break

        # Check if it's a doc file by extension
        if not should_downgrade:
            ext = os.path.splitext(f.file_path)[1].lower()
            if ext in ('.md', '.txt', '.rst', '.doc', '.docx'):
                should_downgrade = True

        # Apply downgrade
        if should_downgrade:
            modified.severity = DOWNGRADE_MAP.get(f.severity, f.severity)
            # Add note to message
            if "AUTO-TRIAGED" not in modified.message:
                modified.message = "[AUTO-TRIAGED] " + modified.message

        triaged.append(modified)

    return triaged
