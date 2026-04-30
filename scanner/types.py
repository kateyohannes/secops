
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class Finding:
    id: str
    rule_id: str
    severity: str
    category: str
    file_path: str
    line: int
    message: str
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    raw: Optional[dict] = field(default_factory=dict)


@dataclass
class ScanResult:
    findings: List[Finding]
    scan_duration_ms: int
    scanner_name: str
    errors: List[str] = field(default_factory=list)
