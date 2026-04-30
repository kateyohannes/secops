# SecOps Tool 🛡️

An enterprise-grade, extensible Security Operations tool for modern DevSecOps pipelines.

SecOps Tool provides a unified CLI interface to run **SAST**, **DAST**, **SCA/CVE**, and **Secrets Detection** across your codebases. Built for speed, CI/CD integration, and developer experience.

---

## ✨ Key Features

* **🏎️ High Performance:** Executes multiple security engines concurrently using ThreadPoolExecutor.
* **🔌 Extensible Architecture:** Drop-in plugin system for adding new scanners (Semgrep, Gosec, Gitleaks, Nuclei, etc.).
* **🤖 Auto-Remediation:** Safely updates vulnerable dependencies automatically (`--fix`).
* **🧠 Stateful Baselines:** Suppress false positives and accepted risks using `.secops-ignore` files.
* **🔄 Differential Scanning:** Only scan files changed in your current Git branch/PR (`--diff`).
* **🛑 CI/CD Ready:** Exit codes designed for pipeline gatekeeping (`--fail-on`).
* **📊 Standardized Reporting:** Exports to beautiful CLI output, JSON, SARIF, and CycloneDX SBOM.
* **🔐 Secure Output:** Automatically redacts high-entropy secrets and API keys from logs.
* **📦 SBOM Generation:** Instantly generate CycloneDX or SPDX Software Bill of Materials.
* **🔭 Audit Logging:** SIEM integration via Splunk, Syslog, or file-based logging.

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
# Build and run with all dependencies pre-installed
docker build -t secops-tool .
docker run --rm -v $(pwd):/scan secops-tool scan /scan
```

### Option 2: Local Installation
```bash
pip install -e .
secops scan .
```

---

## 📖 Usage Examples

### Basic Scan
```bash
# Scan current directory with all scanners
secops scan .

# Scan specific path with SAST only
secops scan /path/to/project --scanners=sast

# Scan with secrets and CVE detection
secops scan /path/to/project --scanners=secrets,cve
```

### CI/CD Integration
```bash
# Fail pipeline on critical findings
secops scan . --fail-on=critical --format=sarif --output=results.sarif

# Auto-fix vulnerable dependencies
secops scan . --fix --scanners=cve

# Only scan changed files in PR
secops scan . --diff main
```

### Dynamic Application Security Testing (DAST)
```bash
# Scan running application with Nuclei
secops scan https://staging.example.com --scanners=dast
```

### Baseline Management
```bash
# Initialize baseline file
secops baseline init /path/to/project

# Add finding to ignore list
secops baseline add /path/to/project --finding-id GSECR-G101

# View current baseline
secops baseline show /path/to/project
```

---

## 🔧 Configuration

Create a `configs/audit.yaml` for audit logging:
```yaml
audit:
  enabled: true
  log_file: "/var/log/secops-audit.log"
  splunk_url: "https://splunk.example.com:8088/services/collector/event"
  splunk_token: "your-splunk-token"
```

Create `.secops-ignore` for baseline management:
```json
{
  "finding_ids": ["GSECR-G101"],
  "rule_ids": ["G101"],
  "paths": ["vendor/", "node_modules/"]
}
```

---

## 📦 SBOM Generation
```bash
# Generate CycloneDX JSON SBOM
secops sbom /path/to/project --format=cyclonedx-json --output=sbom.json
```

---

## 🧪 Testing
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=scanner --cov-report=html
```

---

## 📋 Requirements

- Python 3.8+
- External tools (installed automatically in Docker):
  - `gosec` (Go SAST)
  - `semgrep` (JS/TS SAST)
  - `gitleaks` (Secrets detection)
  - `osv-scanner` (CVE scanning)
  - `nuclei` (DAST)
  - `cdxgen` (SBOM generation)

---

## 📄 License

MIT License

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

For enterprise support or custom rule packs, contact the security team.
