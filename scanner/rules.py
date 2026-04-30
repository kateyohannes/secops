"""Custom rules loader for SecOps Tool."""
import os
import tempfile
import shutil
from typing import Optional, Dict, List
import yaml


def load_custom_rules(rules_dir: Optional[str] = None, rules_url: Optional[str] = None) -> List[str]:
    """
    Load custom rules for scanners.
    Returns a list of rule file/directory paths.
    """
    rule_paths = []

    # Load from local directory
    if rules_dir and os.path.exists(rules_dir):
        for root, dirs, files in os.walk(rules_dir):
            for f in files:
                if f.endswith(('.yaml', '.yml', '.json')):
                    rule_paths.append(os.path.join(root, f))

    # Download from URL (e.g., central security team's rules repo)
    if rules_url:
        try:
            import urllib.request
            import zipfile
            import io

            # Handle GitHub zipball URLs
            if "github.com" in rules_url and not rules_url.endswith(".zip"):
                if not rules_url.endswith("/"):
                    rules_url += "/"
                rules_url += "archive/refs/heads/main.zip"

            # Download rules archive
            with tempfile.TemporaryDirectory() as tmpdir:
                zip_path = os.path.join(tmpdir, "rules.zip")
                urllib.request.urlretrieve(rules_url, zip_path)

                # Extract only rule files
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    for member in zip_ref.namelist():
                        if any(member.endswith(ext) for ext in ['.yaml', '.yml', '.json']):
                            # Extract to rules directory
                            extracted = zip_ref.extract(member, tmpdir)
                            rule_paths.append(extracted)

        except Exception as e:
            print(f"Warning: Failed to load rules from URL: {e}")

    return rule_paths


def update_semgrep_config(rule_paths: List[str]) -> Dict[str, Any]:
    """Update semgrep configuration with custom rules."""
    if not rule_paths:
        return {}

    return {
        "semgrep": {
            "enabled": True,
            "args": ["--config"] + rule_paths
        }
    }
