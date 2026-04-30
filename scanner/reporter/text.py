"""Text output renderer for SecOps Tool."""
from typing import List, Optional
from scanner.types import Finding, ScanResult


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[92m",
}

RESET = "\033[0m"


def render_text(findings: List[Finding], show_details: bool = False) -> str:
    """Render findings as colored text output."""
    if not findings:
        return "No security issues found."

    lines = []
    lines.append("=" * 60)
    lines.append("SECURITY SCAN RESULTS")
    lines.append("=" * 60)
    lines.append("")

    by_sev = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in ["critical", "high", "medium", "low"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        color = SEVERITY_COLORS.get(sev, "")
        lines.append(f"{color}[{sev.upper()}]{RESET} ({len(items)} findings)")
        lines.append("-" * 40)
        for f in sorted(items, key=lambda x: x.file_path):
            lines.append(f"  {f.file_path}:{f.line} - {f.message}")
            if show_details and f.remediation:
                lines.append(f"    Fix: {f.remediation}")
            if f.cwe:
                lines.append(f"    CWE: {f.cwe}")
        lines.append("")

    lines.append(summary_line(findings))
    return "\n".join(lines)


def summary_line(findings: List[Finding]) -> str:
    """Generate a summary line for findings."""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = []
    for sev in ["critical", "high", "medium", "low"]:
        if counts.get(sev, 0) > 0:
            parts.append(f"{counts[sev]} {sev}")
    return "Summary: " + ", ".join(parts) if parts else "No issues found"


def render_findings(findings: List[Finding]) -> str:
    """Render only findings list as text."""
    return render_text(findings, show_details=False)
