
import subprocess
from abc import ABC, abstractmethod
from typing import List
from scanner.types import Finding, ScanResult


class BaseScanner(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, target_path: str, config: dict) -> ScanResult:
        pass

    def _run_cmd(self, cmd: List[str], cwd: str = None) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=300)

    def _tool_available(self, tool: str) -> bool:
        try:
            subprocess.run([tool, "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
