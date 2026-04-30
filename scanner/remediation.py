"""Auto-remediation module for SecOps Tool."""
import os
import subprocess
import json
from typing import List, Optional
from scanner.types import Finding, ScanResult


class AutoRemediation:
    """Handles automatic remediation of certain types of findings."""

    def __init__(self, target_path: str):
        self.target_path = target_path

    def can_fix(self, finding: Finding) -> bool:
        """Check if a finding can be automatically fixed."""
        # CVE findings with package updates
        if finding.category == "CVE" and finding.file_path:
            if any(f in finding.file_path for f in ["package.json", "go.mod", "requirements.txt"]):
                return True
        return False

    def fix_finding(self, finding: Finding) -> bool:
        """Attempt to fix a finding. Returns True if successful."""
        if finding.category == "CVE":
            return self._fix_cve(finding)
        return False

    def _fix_cve(self, finding: Finding) -> bool:
        """Fix CVE by updating the affected package."""
        file_path = finding.file_path

        try:
            if "package.json" in file_path:
                return self._fix_npm_package(file_path, finding)
            elif "go.mod" in file_path:
                return self._fix_go_package(file_path, finding)
            elif "requirements.txt" in file_path:
                return self._fix_python_package(file_path, finding)
        except Exception as e:
            print(f"Error fixing {finding.id}: {e}")
        return False

    def _fix_npm_package(self, file_path: str, finding: Finding) -> bool:
        """Update NPM package to fix vulnerability (patch version only)."""
        pkg_name = self._extract_package_name(finding)
        if not pkg_name:
            return False

        # Use npm update which respects semver by default (patch/minor only)
        # Avoid npm install which could do major version upgrades
        result = subprocess.run(
            ["npm", "update", pkg_name, "--save"],
            cwd=os.path.dirname(file_path),
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.returncode == 0

    def _fix_go_package(self, file_path: str, finding: Finding) -> bool:
        """Update Go package to fix vulnerability."""
        pkg_name = self._extract_package_name(finding)
        if not pkg_name:
            return False

        result = subprocess.run(
            ["go", "get", "-u", pkg_name],
            cwd=os.path.dirname(file_path),
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.returncode == 0

    def _fix_python_package(self, file_path: str, finding: Finding) -> bool:
        """Update Python package to fix vulnerability and update requirements.txt."""
        pkg_name = self._extract_package_name(finding)
        if not pkg_name:
            return False

        # Upgrade package with safe upgrade strategy
        result = subprocess.run(
            ["pip", "install", "--upgrade", "--upgrade-strategy", "only-if-needed", pkg_name],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return False

        # Get the new installed version
        show_result = subprocess.run(
            ["pip", "show", pkg_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        if show_result.returncode != 0:
            return True  # Package upgraded but couldn't update requirements.txt

        # Extract version from pip show output
        new_version = None
        for line in show_result.stdout.splitlines():
            if line.startswith("Version:"):
                new_version = line.split(":", 1)[1].strip()
                break

        if not new_version:
            return True

        # Update requirements.txt using native Python (proper approach)
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()

            # Normalize package name for comparison (case-insensitive, treat - and _ as equivalent)
            normalized_pkg = pkg_name.lower().replace("-", "_")

            updated_lines = []
            for line in lines:
                stripped = line.strip()
                # Check if this line is the package we're updating
                if stripped and not stripped.startswith("#"):
                    # Extract package name from requirement (handles ==, >=, ~=, etc.)
                    pkg_part = stripped.split("=")[0].split(">")[0].split("<")[0].strip()
                    if pkg_part.lower().replace("-", "_") == normalized_pkg:
                        # Replace with new version
                        updated_lines.append(f"{pkg_name}=={new_version}\n")
                        continue
                updated_lines.append(line)

            with open(file_path, "w") as f:
                f.writelines(updated_lines)

        except Exception as e:
            print(f"Warning: Failed to update {file_path}: {e}")

        return True

    def _extract_package_name(self, finding: Finding) -> Optional[str]:
        """Extract package name from finding message or rule_id."""
        # Try to get from raw data
        if finding.raw and isinstance(finding.raw, dict):
            affected = finding.raw.get("affected", [])
            if affected:
                return affected[0].get("package", {}).get("name")
        return None

    def fix_all(self, findings: List[Finding]) -> tuple:
        """Attempt to fix all fixable findings. Returns (fixed, failed) counts."""
        fixed = 0
        failed = 0

        for finding in findings:
            if self.can_fix(finding):
                if self.fix_finding(finding):
                    fixed += 1
                else:
                    failed += 1

        return fixed, failed
