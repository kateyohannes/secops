
import json
import os
import subprocess
from typing import List, Dict, Optional


def generate_sbom(target_path: str, output_path: Optional[str] = None, fmt: str = "cyclonedx-json") -> str:
    if not _tool_available("cdxgen"):
        return json.dumps({
            "error": "cdxgen not found. Install: npm install -g @cyclonedx/cdxgen",
            "help": "https://github.com/CycloneDX/cdxgen"
        })

    args = ["cdxgen", "-t", "auto", "-o", "/dev/stdout", target_path]
    if fmt == "spdx-json":
        args += ["-f", "spdx"]

    result = subprocess.run(args, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        return json.dumps({"error": "cdxgen failed: " + result.stderr[:300]})

    output = result.stdout
    if output_path:
        with open(output_path, "w") as out:
            out.write(output)

    return output


def parse_sbom_for_cves(sbom_json: str) -> List[Dict]:
    try:
        sbom = json.loads(sbom_json)
        components = sbom.get("components", [])
        vulns = []
        for comp in components:
            if "version" in comp and "name" in comp:
                vulns.append({
                    "name": comp["name"],
                    "version": comp["version"],
                    "purl": comp.get("purl", ""),
                })
        return vulns
    except json.JSONDecodeError:
        return []


def _tool_available(tool: str) -> bool:
    try:
        subprocess.run([tool, "--version"], capture_output=True, timeout=10)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
