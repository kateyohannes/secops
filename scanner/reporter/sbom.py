"""SBOM generator for SecOps Tool."""
import subprocess
import os
from typing import Optional


def generate_sbom(target_path: str, output_path: Optional[str] = None, format: str = "cyclonedx-json") -> str:
    """Generate SBOM using cdxgen."""
    if not _tool_available("cdxgen"):
        return "Error: cdxgen not found. Install: npm install -g @cyclonedx/cdxgen"

    args = ["cdxgen", "-t", "auto", "-o", output_path or "sbom.json"]
    if format == "spdx-json":
        args += ["-f", "spdxjson"]
    else:
        args += ["-f", "json"]

    result = subprocess.run(args, capture_output=True, text=True, cwd=target_path, timeout=300)

    if result.returncode != 0:
        return "Error generating SBOM: " + result.stderr[:300]

    if output_path and os.path.exists(output_path):
        return f"SBOM generated: {output_path}"
    elif os.path.exists("sbom.json"):
        with open("sbom.json", "r") as f:
            return f.read()
    return "SBOM generation completed"


def _tool_available(tool: str) -> bool:
    """Check if a tool is available in PATH."""
    try:
        subprocess.run([tool, "--version"], capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
