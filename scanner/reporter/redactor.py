"""Output sanitizer for SecOps Tool - Redacts secrets from output."""
import re
from typing import Dict, List, Tuple, Callable, Any


# Common secret patterns with proper lambda handling
SECRET_PATTERNS: List[Tuple] = [
    # GitHub tokens (ghp_...)
    (re.compile(r'ghp_[a-zA-Z0-9]{30,}'), lambda m: 'ghp_********' + m.group(0)[-4:]),
    # GitHub PAT (github_pat_...)
    (re.compile(r'github_pat_[a-zA-Z0-9_]{70,}'), lambda m: 'github_pat_********' + m.group(0)[-4:]),
    # AWS access keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), lambda m: 'AKIA********' + m.group(0)[-4:]),
    # Slack tokens
    (re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'), lambda m: m.group(0)[:4] + '********' + m.group(0)[-4:]),
    # Generic API keys in common formats
    (re.compile(r'(api[_-]?key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9+/=]{20,})', re.IGNORECASE), 
     lambda m: m.group(1) + '********'),
    # Private key headers
    (re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'), '-----BEGIN *REDACTED*-----'),
    # Generic high-entropy strings (32+ chars of base64-like)
    (re.compile(r'\b[a-zA-Z0-9+/]{32,}={0,2}\b'), '********[entropy_redacted]'),
]


class OutputRedactor:
    """Sanitizes output to prevent secret leakage in logs."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._redacted_count = 0

    def redact(self, text: str) -> str:
        """Redact secrets from text output."""
        if not self.enabled or not text:
            return text

        result = text
        for pattern, replacement in SECRET_PATTERNS:
            if callable(replacement):
                result = pattern.sub(replacement, result)
            else:
                result = pattern.sub(replacement, result)
            # Count replacements (approximate)
            if result != text:
                self._redacted_count += 1

        return result

    def redact_findings(self, findings: list) -> list:
        """Redact secrets from finding messages and file paths."""
        if not self.enabled:
            return findings

        redacted = []
        for f in findings:
            f_copy = Finding(
                id=f.id,
                rule_id=f.rule_id,
                severity=f.severity,
                category=f.category,
                file_path=self.redact(f.file_path),
                line=f.line,
                message=self.redact(f.message),
                remediation=self.redact(f.remediation) if f.remediation else "",
                cwe=f.cwe,
                cvss=f.cvss,
                raw=f.raw,
            )
            # Also redact raw data if it's a dict
            if isinstance(f_copy.raw, dict):
                f_copy.raw = self._redact_dict(f_copy.raw)
            redacted.append(f_copy)

        return redacted

    def _redact_dict(self, data: dict, max_depth: int = 5) -> dict:
        """Recursively redact secrets from dictionary."""
        if max_depth <= 0:
            return data

        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.redact(value)
            elif isinstance(value, dict):
                result[key] = self._redact_dict(value, max_depth - 1)
            elif isinstance(value, list):
                result[key] = [
                    self._redact_dict(item, max_depth - 1) if isinstance(item, dict)
                    else self.redact(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    @property
    def redacted_count(self) -> int:
        """Return number of redactions made."""
        return self._redacted_count


# Import Finding here to avoid circular import
from scanner.types import Finding
