"""Baseline/ignore manager for SecOps Tool."""
import os
import json
from typing import Set, Optional
from scanner.types import Finding


class BaselineManager:
    """Manages .secops-ignore file for tracking false positives and accepted risks."""

    IGNORE_FILE = ".secops-ignore"

    def __init__(self, target_path: str):
        self.target_path = target_path
        self.ignore_file = os.path.join(target_path, self.IGNORE_FILE)
        self.ignored_ids: Set[str] = set()
        self.ignored_rules: Set[str] = set()
        self.ignored_paths: Set[str] = set()
        self._load()

    def _load(self):
        """Load ignored findings from .secops-ignore file."""
        if not os.path.exists(self.ignore_file):
            return

        try:
            with open(self.ignore_file, "r") as f:
                data = json.load(f)

            # Support both simple list and structured format
            if isinstance(data, list):
                self.ignored_ids = set(data)
            elif isinstance(data, dict):
                self.ignored_ids = set(data.get("finding_ids", []))
                self.ignored_rules = set(data.get("rule_ids", []))
                self.ignored_paths = set(data.get("paths", []))
        except (json.JSONDecodeError, Exception) as e:
            print(f"Warning: Failed to load {self.ignore_file}: {e}")

    def is_ignored(self, finding: Finding) -> bool:
        """Check if a finding should be ignored."""
        # Check by finding ID
        if finding.id in self.ignored_ids:
            return True

        # Check by rule ID
        if finding.rule_id in self.ignored_rules:
            return True

        # Check by path (supports glob-like matching)
        for ignored_path in self.ignored_paths:
            if ignored_path in finding.file_path or finding.file_path.endswith(ignored_path):
                return True

        return False

    def filter_findings(self, findings: list) -> list:
        """Filter out ignored findings."""
        return [f for f in findings if not self.is_ignored(f)]

    def add_ignored_finding(self, finding: Finding, reason: str = "false positive"):
        """Add a finding to the ignore list."""
        self.ignored_ids.add(finding.id)
        self._save()

    def add_ignored_rule(self, rule_id: str):
        """Ignore all findings from a specific rule."""
        self.ignored_rules.add(rule_id)
        self._save()

    def add_ignored_path(self, path: str):
        """Ignore all findings in a specific path."""
        self.ignored_paths.add(path)
        self._save()

    def _save(self):
        """Save the ignore list to file."""
        data = {
            "finding_ids": sorted(list(self.ignored_ids)),
            "rule_ids": sorted(list(self.ignored_rules)),
            "paths": sorted(list(self.ignored_paths)),
            "comment": "Managed by SecOps Tool. Add reasons in format: 'ID': 'reason'"
        }
        with open(self.ignore_file, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def create_default(target_path: str) -> str:
        """Create a default .secops-ignore file with documentation."""
        ignore_file = os.path.join(target_path, BaselineManager.IGNORE_FILE)
        default_content = {
            "finding_ids": [],
            "rule_ids": [],
            "paths": [],
            "comment": "Add finding IDs, rule IDs, or paths to ignore during scanning",
            "examples": {
                "finding_ids": ["GSECR-G101", "SEMGR-bandit.B105"],
                "rule_ids": ["G101", "bandit.B105"],
                "paths": ["vendor/", "node_modules/", "test/"]
            }
        }
        with open(ignore_file, "w") as f:
            json.dump(default_content, f, indent=2)
        return ignore_file
