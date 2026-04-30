
import os
import yaml
from typing import Optional


DEFAULT_CONFIG = {
    "scanners": {
        "gosec": {"enabled": True, "args": []},
        "semgrep": {"enabled": True, "args": []},
        "secrets": {"enabled": True, "config": None},
        "cve": {"enabled": True, "ecosystems": ["Go", "npm", "PyPI"]},
    },
    "output": {
        "format": "text",
        "file": None,
        "severity_filter": None,
    },
    "paths": {
        "exclude": ["vendor", "node_modules", ".git", "dist", "build"],
    },
}


def load_config(config_path: Optional[str] = None) -> dict:
    config = DEFAULT_CONFIG.copy()
    paths = [config_path] if config_path else [
        "configs/default.yaml",
        os.path.expanduser("~/.secops.yaml"),
        ".secops.yaml",
    ]
    for p in paths:
        if p and os.path.exists(p):
            with open(p, "r") as f:
                user = yaml.safe_load(f) or {}
            _deep_update(config, user)
            break
    return config


def _deep_update(base: dict, override: dict):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
