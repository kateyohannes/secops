"""Configuration loader for SecOps Tool."""
import os
import yaml
from typing import Optional, List, Dict, Any


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""
    pass


# Try to import pydantic for schema validation
try:
    from pydantic import BaseModel, Field, field_validator
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


if HAS_PYDANTIC:
    class ScannerConfig(BaseModel):
        """Schema for individual scanner configuration."""
        enabled: bool = True
        args: List[str] = Field(default_factory=list)
        config: Optional[str] = None
        ecosystems: List[str] = Field(default_factory=list)

    class OutputConfig(BaseModel):
        """Schema for output configuration."""
        format: str = "text"
        file: Optional[str] = None
        severity_filter: Optional[str] = None

        @field_validator("format")
        @classmethod
        def validate_format(cls, v: str) -> str:
            if v not in ["text", "json", "sarif"]:
                raise ValueError(f"Invalid format: {v}")
            return v

        @field_validator("severity_filter")
        @classmethod
        def validate_severity(cls, v: Optional[str]) -> Optional[str]:
            if v and v not in ["critical", "high", "medium", "low"]:
                raise ValueError(f"Invalid severity: {v}")
            return v

    class PathsConfig(BaseModel):
        """Schema for paths configuration."""
        exclude: List[str] = Field(default_factory=lambda: ["vendor", "node_modules", ".git", "dist", "build"])

    class RemediationConfig(BaseModel):
        """Schema for remediation configuration."""
        enabled: bool = True
        source: str = "configs/remediations.yaml"

    class SecOpsConfig(BaseModel):
        """Main configuration schema."""
        scanners: Dict[str, ScannerConfig] = Field(default_factory=lambda: {
            "gosec": ScannerConfig(),
            "semgrep": ScannerConfig(),
            "secrets": ScannerConfig(),
            "cve": ScannerConfig(),
        })
        output: OutputConfig = Field(default_factory=OutputConfig)
        paths: PathsConfig = Field(default_factory=PathsConfig)
        remediation: RemediationConfig = Field(default_factory=RemediationConfig)


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
    "remediation": {
        "enabled": True,
        "source": "configs/remediations.yaml",
    },
}


def validate_config(config: dict) -> dict:
    """Validate configuration dictionary using pydantic if available."""
    if HAS_PYDANTIC:
        try:
            validated = SecOpsConfig(**config)
            return validated.model_dump()
        except Exception as e:
            raise ConfigValidationError(f"Pydantic validation failed: {e}")
    else:
        # Fallback to basic validation
        errors = []

        if "scanners" in config:
            scanners = config["scanners"]
            if not isinstance(scanners, dict):
                errors.append("'scanners' must be a dictionary")
            else:
                valid_scanners = ["gosec", "semgrep", "secrets", "cve"]
                for name, settings in scanners.items():
                    if name not in valid_scanners:
                        errors.append(f"Unknown scanner: {name}")
                    if not isinstance(settings, dict):
                        errors.append(f"Scanner '{name}' settings must be a dictionary")

        if errors:
            raise ConfigValidationError("Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors))

    return config


def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from file or use defaults."""
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

    # Validate the merged configuration
    try:
        validate_config(config)
    except ConfigValidationError as e:
        import sys
        print(f"Warning: {e}", file=sys.stderr)
        print("Using default configuration.", file=sys.stderr)
        config = DEFAULT_CONFIG.copy()

    return config


def _deep_update(base: dict, override: dict):
    """Recursively update nested dictionaries."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
