# SecOps Tool - Usage Guide

## Overview

SecOps Tool is a Python-based security scanner that integrates multiple security tools:

- **Gosec**: Go SAST (static application security testing)
- **Semgrep**: JS/TS SAST scanning
- **Gitleaks**: Secrets detection (API keys, passwords, tokens)
- **OSV-Scanner**: CVE/vulnerability scanning for dependencies
- **cdxgen**: SBOM (Software Bill of Materials) generation

## Prerequisites

### Install Go (required for gosec, gitleaks, osv-scanner)

```bash
# Linux
wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Verify
go version
```

### Install Python 3.8+

```bash
python3 --version
```

### Install Node.js (optional, for cdxgen/SBOM)

```bash
node --version
npm --version
```

## Installation

### 1. Clone or download the tool

```bash
cd /home/jeo/Development/aleph/ai/build_secops_tool
```

### 2. Install Python dependencies

```bash
pip install click pyyaml
```

### 3. Install security tools

```bash
# Install gosec (Go SAST)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Install gitleaks (secrets detection)
go install github.com/zricethezav/gitleaks/v8@latest
# If that fails, try:
# cd /tmp && git clone https://github.com/gitleaks/gitleaks.git
# cd gitleaks && go build -o ~/go/bin/gitleaks .

# Install osv-scanner (CVE scanning)
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Install semgrep (JS/TS SAST)
pip install semgrep

# Optional: Install cdxgen (for SBOM generation)
npm install -g @cyclonedx/cdxgen

# Add ~/go/bin to PATH
export PATH=$PATH:~/go/bin
```

### 4. Verify installation

```bash
python3 main.py --version

# Check tools
gosec --version
gitleaks version
semgrep --version
osv-scanner --version
```

## Quick Start

### Basic scan of current directory

```bash
python3 main.py scan .
```

### Scan specific directory

```bash
python3 main.py scan /path/to/your/project
```

## CLI Commands

### Scan Command

```bash
python3 main.py scan [OPTIONS] [TARGET]
```

**Options:**

| Option | Description |
|--------|-------------|
| `TARGET` | Directory to scan (default: `.`) |
| `--scanners TEXT` | Comma-separated scanners: sast,secrets,cve |
| `--format TEXT` | Output format: text, json, sarif |
| `--output FILE` | Save output to file |
| `--config FILE` | Path to config file |
| `--severity TEXT` | Min severity: critical, high, medium, low |
| `--show-details/--no-details` | Show remediation details |

### SBOM Command

```bash
python3 main.py sbom [OPTIONS] [TARGET]
```

**Options:**

| Option | Description |
|--------|-------------|
| `TARGET` | Directory to scan (default: `.`) |
| `--format TEXT` | cyclonedx-json, spdx-json |
| `--output FILE` | Save output to file |

## Examples

### 1. Scan Go project for all issues

```bash
python3 main.py scan /path/to/go-project --scanners sast,cve
```

### 2. Scan JS/TS project for secrets and vulnerabilities

```bash
python3 main.py scan /path/to/js-project --scanners sast,secrets
```

### 3. Output results as JSON

```bash
python3 main.py scan . --format json --output results.json
```

### 4. Output results as SARIF (for GitHub Security tab)

```bash
python3 main.py scan . --format sarif --output results.sarif
```

### 5. Filter by severity

```bash
# Show only critical and high findings
python3 main.py scan . --severity high
```

### 6. Show remediation details

```bash
python3 main.py scan . --show-details
```

### 7. Generate SBOM

```bash
python3 main.py sbom . --format cyclonedx-json --output sbom.json
```

## Config File

Create `configs/default.yaml` or `.secops.yaml`:

```yaml
scanners:
  gosec:
    enabled: true
    args: []
  semgrep:
    enabled: true
    args: []
  secrets:
    enabled: true
    config: null  # Path to custom gitleaks config
  cve:
    enabled: true
    ecosystems:
      - Go
      - npm
      - PyPI

output:
  format: text
  file: null
  severity_filter: null

paths:
  exclude:
    - vendor
    - node_modules
    - .git
    - dist
    - build
```

Use custom config:

```bash
python3 main.py scan . --config /path/to/config.yaml
```

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install SecOps Tool
        run: |
          pip install click pyyaml
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          go install github.com/zricethezav/gitleaks/v8@latest
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest
          pip install semgrep
          echo "$HOME/go/bin" >> $GITHUB_PATH

      - name: Run Security Scan
        run: python3 main.py scan . --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security_scan:
  stage: test
  image: python:3.11
  script:
    - pip install click pyaml
    - go install github.com/securego/gosec/v2/cmd/gosec@latest
    - go install github.com/zricethezav/gitleaks/v8@latest
    - pip install semgrep
    - export PATH=$PATH:$HOME/go/bin
    - python3 main.py scan . --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Understanding Output

### Text Output (default)

```
============================================================
 SECURITY SCAN RESULTS (3 findings)
============================================================

📁 /path/to/file.go
  🔴 [HIGH] G201: SQL injection risk
      Line 45 | Category: SAST | ID: GSECR-G201
      CWE: 89

📁 /path/to/secrets.txt
  🔴 [CRITICAL] SEC: AWS API Key detected
      Line 12 | Category: SECRET

============================================================
Summary: CRITICAL: 1 | HIGH: 1 | MEDIUM: 1
============================================================
```

### JSON Output

```json
{
  "findings": [
    {
      "id": "GSECR-G201",
      "rule_id": "G201",
      "severity": "high",
      "category": "SAST",
      "file_path": "/path/to/file.go",
      "line": 45,
      "message": "SQL injection risk",
      "cwe": "89",
      "cvss": null
    }
  ],
  "scans": [...]
}
```

### SARIF Output

Compatible with GitHub Security tab, Azure DevOps, etc.

## Troubleshooting

### "gosec not found"

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
export PATH=$PATH:~/go/bin
```

### "semgrep not found"

```bash
pip install semgrep
```

### "gitleaks not found"

```bash
# Build from source
cd /tmp
git clone https://github.com/gitleaks/gitleaks.git
cd gitleaks
go build -o ~/go/bin/gitleaks .
```

### "osv-scanner not found"

```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### "click not found"

```bash
pip install click
```

## Project Structure

```
build_secops_tool/
├── main.py                    # CLI entry point
├── scanner/
│   ├── __init__.py
│   ├── types.py             # Finding and ScanResult types
│   ├── config.py            # Configuration loader
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py        # Base scanner class
│   │   ├── gosec.py      # Go SAST scanner
│   │   ├── semgrep.py    # JS/TS SAST scanner
│   │   ├── secrets.py    # Secrets detection
│   │   └── cve.py       # CVE scanner
│   ├── reporter/
│   │   ├── __init__.py
│   │   ├── text.py       # Text output
│   │   ├── json_reporter.py  # JSON output
│   │   ├── sarif.py      # SARIF output
│   │   └── sbom.py      # SBOM generation
│   └── utils/
│       ├── __init__.py
│       └── filters.py     # Finding filters
├── configs/
│   └── default.yaml       # Default configuration
└── USAGE.md                # This file
```

## License

MIT License

## Support

For issues and questions:
- Check the tool output for error messages
- Ensure all dependencies are installed
- Verify the target directory exists and is accessible
