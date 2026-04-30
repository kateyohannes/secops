
from typing import List
from scanner.types import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def render(findings: List[Finding], show_details: bool = False) -> str:
    if not findings:
        return "No findings detected."

    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line))

    lines = []
    lines.append("=" * 60)
    lines.append(f" SECURITY SCAN RESULTS ({len(findings)} findings)")
    lines.append("=" * 60)

    current_file = None
    for f in sorted_findings:
        if f.file_path != current_file:
            current_file = f.file_path
            lines.append(f"\n📁 {f.file_path}")

        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
        lines.append(f"  {sev_icon} [{f.severity.upper()}] {f.rule_id}: {f.message}")
        lines.append(f"      Line {f.line} | Category: {f.category} | ID: {f.id}")
        if f.cwe:
            lines.append(f"      CWE: {f.cwe}")
        if f.cvss:
            lines.append(f"      CVSS: {f.cvss}")
        if show_details and f.remediation:
            lines.append(f"      💡 Fix: {f.remediation}")

    lines.append("\n" + "=" * 60)
    lines.append(summary_line(findings))
    lines.append("=" * 60 + "\n")
    return "\n".join(lines)


def summary_line(findings: List[Finding]) -> str:
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [f"{s.upper()}: {counts.get(s, 0)}" for s in ["critical", "high", "medium", "low"] if counts.get(s)]
    return "Summary: " + " | ".join(parts) if parts else "No findings."
