"""Tests for config module."""
import pytest
import os
import tempfile
from scanner.config import load_config, DEFAULT_CONFIG


def test_load_default_config():
    config = load_config()
    assert "scanners" in config
    assert "output" in config
    assert config["scanners"]["gosec"]["enabled"] is True


def test_load_custom_config():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("scanners:\n  gosec:\n    enabled: false\n")
        path = f.name
    try:
        config = load_config(path)
        assert config["scanners"]["gosec"]["enabled"] is False
    finally:
        os.unlink(path)
