# SecOps Tool 🛡️

An enterprise-grade, extensible Security Operations orchestration platform. 

SecOps Tool provides a unified CLI interface to run static analysis (SAST), software composition analysis (SCA/CVE), secrets detection, and dynamic analysis (DAST) across your codebases. It is built for speed, CI/CD pipeline integration, and developer experience.

## ✨ Key Features

* **🏎️ High Performance:** Executes multiple security engines concurrently.
* **🔌 Extensible Architecture:** Drop-in plugin system for adding new scanners (Semgrep, Gosec, Gitleaks, Nuclei, etc.).
* **🤖 Auto-Remediation:** Safely updates vulnerable dependencies automatically (`--fix`).
* **🧠 Stateful Baselines:** Suppress false positives and accepted risks using `.secops-ignore` files.
* **🔄 Differential Scanning:** Only scan files changed in your current Git branch/PR (`--diff`).
* **🛑 CI/CD Ready:** Exit codes designed for pipeline gatekeeping (`--fail-on`).
* **📊 Standardized Reporting:** Exports to beautiful CLI tables, JSON, and Enterprise SARIF formats.
* **🔐 Secure Output:** Automatically redacts high-entropy secrets and API keys from logs.
* **📦 SBOM Generation:** Instantly generate CycloneDX or SPDX Software Bill of Materials.

---

## 🚀 Installation

### Option 1: Docker Compose (Highly Recommended)
The easiest way to run the tool with all dependencies (Python, Go, Node.js, and external scanner binaries) pre-installed.

Place the code you want to scan in a `./scan-target` directory next to the `docker-compose.yml`, then run:
```bash
# Build the image and run a default scan
docker compose up secops

# Run with custom flags (e.g., auto-fix and SARIF output)
docker compose run --rm secops --fix --format=sarif --output=/scan/results.sarif
```

### Option 2: Docker CLI

```bash
# Build the multi-stage Docker image
docker build -t secops-tool .

# Run the tool against your current directory
docker run --rm -v $(pwd):/app secops-tool scan .
```

### Option 3: Local Installation
If you prefer running it natively, install the Python package.

```bash
# Install the CLI tool
pip install -e .

# Verify your host environment has required external binaries (gosec, semgrep, gitleaks, etc.)
secops check_env
```

---

## 📖 Usage Guide

### Basic Scanning

Scan the current directory using default scanners (SAST, Secrets, CVE):
```bash
secops scan .
```

Run specific categories of scanners (e.g., just DAST and Secrets):
```bash
secops scan . --scanners dast,secrets
```

### CI/CD Integration

Fail the build if any `critical` or `high` vulnerabilities are found:
```bash
secops scan . --fail-on high
```

Output results in **SARIF** format (ideal for GitHub Advanced Security or SonarQube ingestion):
```bash
secops scan . --format sarif -o results.sarif
```

### Differential Scanning (Pull Requests)

Only scan files that have changed since the `main` branch (saves massive amount of time in large monorepos):
```bash
secops scan . --diff origin/main
```

### Auto-Remediation (Fixing Issues)

Attempt to automatically bump dependency versions in `package.json`, `go.mod`, or `requirements.txt` to fix identified CVEs safely:
```bash
secops scan . --fix
```

### Generating an SBOM

Generate a CycloneDX JSON Software Bill of Materials for compliance:
```bash
secops sbom . --format cyclonedx-json -o sbom.json
```

---

## 🎯 Baseline Management (Suppressing False Positives)

Tired of the scanner flagging test files or accepted risks? Use the baseline manager to track them in code.

1. **Initialize a baseline file** in your repository:
   ```bash
   secops baseline init .
   ```
2. **Ignore a specific rule** (e.g., G101 for hardcoded credentials in test files):
   ```bash
   secops baseline add . --rule-id G101
   ```
3. **Ignore a specific path** (e.g., vendor directories):
   ```bash
   secops baseline add . --path "vendor/"
   ```
4. **View current baseline**:
   ```bash
   secops baseline show .
   ```

*(Note: The `secops scan` command uses the `.secops-ignore` baseline file by default. You can bypass it with `--no-ignore-baseline`)*.

---

## 🛠️ Architecture & Extensibility

Adding a new scanner to the SecOps Tool is trivial thanks to the dynamic loader. 

1. Create a new Python file in `scanner/scanners/` (e.g., `bandit.py`).
2. Inherit from `BaseScanner` and implement the `scan` method.

```python
from scanner.scanners.base import BaseScanner
from scanner.types import Finding, ScanResult

class BanditScanner(BaseScanner):
    name = "bandit"

    def scan(self, target_path: str, config: dict) -> ScanResult:
        # Run your tool via subprocess and parse its output into Finding objects
        pass
```
The tool will automatically discover your scanner and map it to a category based on its name!

---

## 📝 Audit Logging
For enterprise visibility, the tool supports forwarding execution logs to SIEMs (Splunk, Datadog) or Syslog. Configure this in `configs/audit.yaml`.
