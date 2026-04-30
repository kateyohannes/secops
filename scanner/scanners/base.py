"""Base scanner class for SecOps Tool."""
import subprocess
import os
import yaml
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from scanner.types import Finding, ScanResult


class BaseScanner(ABC):
    """Abstract base class for all scanners."""
    name: str = "base"
    _remediations: Dict[str, str] = {}

    def __init__(self):
        """Initialize scanner and load remediations."""
        self._load_remediations()

    @abstractmethod
    def scan(self, target_path: str, config: dict) -> ScanResult:
        """Run the scanner and return results."""
        pass

    def _load_remediations(self):
        """Load remediation advice from external YAML file."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "configs",
            "remediations.yaml"
        )
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    data = yaml.safe_load(f)
                if data and self.name in data:
                    self._remediations = data[self.name]
            except Exception:
                pass

    def _get_remediation(self, key: str, default: str = "Review this finding and apply secure coding practices.") -> str:
        """Get remediation advice for a finding."""
        return self._remediations.get(key, default)

    def _run_cmd(self, cmd: List[str], cwd: str = None) -> subprocess.CompletedProcess:
        """Execute a command and return the result."""
        return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=300)

    def _tool_available(self, tool: str) -> bool:
        """Check if a tool is available in PATH."""
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
