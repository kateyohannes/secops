# SecOps Tool

A Python-based security scanner that integrates multiple open-source tools to detect:
- **Hard-coded secrets** (API keys, passwords, tokens)
- **Code vulnerabilities** (OWASP Top 10, SQL injection, XSS, etc.)
- **CVE vulnerabilities** in dependencies via OSV database
- **SBOM generation** (CycloneDX/SPDX formats)

Supports: **Go**, **JavaScript/TypeScript**

---

## Quick Start

### 1. Install Dependencies

```bash
# Python libraries
pip install click pyyaml

# Go tools (requires Go installed)
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Semgrep
pip install semgrep

# Add Go bin to PATH
export PATH=$PATH:~/go/bin
```

### 2. Verify Installation

```bash
python3 main.py --version
gosec --version
semgrep --version
gitleaks version
```

### 3. Run Your First Scan

```bash
cd /home/jeo/Development/aleph/ai/build_secops_tool
python3 main.py scan .
```

---

## Usage

### Basic Scan

```bash
# Scan current directory (all scanners)
python3 main.py scan .

# Scan specific directory
python3 main.py scan /path/to/project
```

### Output Formats

```bash
# Text output (default - human readable)
python3 main.py scan . --format text

# JSON output (machine readable)
python3 main.py scan . --format json --output results.json

# SARIF output (for GitHub Security tab)
python3 main.py scan . --format sarif --output results.sarif
```

### Select Scanners

```bash
# Run only SAST (Go + JS/TS static analysis)
python3 main.py scan . --scanners sast

# Run only secrets detection
python3 main.py scan . --scanners secrets

# Run only CVE scanning
python3 main.py scan . --scanners cve

# Run multiple scanners
python3 main.py scan . --scanners sast,secrets
```

### Filter by Severity

```bash
# Show only critical and high severity findings
python3 main.py scan . --severity high

# Valid values: critical, high, medium, low
```

### Show Remediation Details

```bash
python3 main.py scan . --show-details
```

---

## Examples

### Scan Go Project

```bash
python3 main.py scan /path/to/go-project --scanners sast,cve
```

### Scan JavaScript/TypeScript Project

```bash
python3 main.py scan /path/to/js-project --scanners sast,secrets
```

### Generate SBOM

```bash
# Requires: npm install -g @cyclonedx/cdxgen
python3 main.py sbom . --format cyclonedx-json --output sbom.json
```

---

## CLI Commands

### scan Command

```bash
python3 main.py scan [OPTIONS] [TARGET]
```

| Option | Description |
|--------|-------------|
| `TARGET` | Directory to scan (default: `.`) |
| `--scanners TEXT` | Comma-separated scanners: sast,secrets,cve |
| `--format TEXT` | Output format: text, json, sarif |
| `--output FILE` | Save output to file |
| `--config FILE` | Path to config file |
| `--severity TEXT` | Min severity: critical, high, medium, low |
| `--show-details/--no-details` | Show remediation details |

### sbom Command

```bash
python3 main.py sbom [OPTIONS] [TARGET]
```

| Option | Description |
|--------|-------------|
| `TARGET` | Directory to scan (default: `.`) |
| `--format TEXT` | cyclonedx-json, spdx-json |
| `--output FILE` | Save output to file |

---

## Configuration

Create a `configs/default.yaml` or `.secops.yaml`:

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

---

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
      
      - name: Setup Python
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

---

## Project Structure

```
build_secops_tool/
├── README.md                 # This file
├── main.py                    # CLI entry point
├── scanner/
│   ├── types.py             # Finding and ScanResult types
│   ├── config.py            # Configuration loader
│   ├── scanners/
│   │   ├── base.py        # Base scanner class
│   │   ├── gosec.py      # Go SAST scanner
│   │   ├── semgrep.py    # JS/TS SAST scanner
│   │   ├── secrets.py    # Secrets detection
│   │   └── cve.py       # CVE scanner
│   ├── reporter/
│   │   ├── text.py       # Text output
│   │   ├── json_reporter.py  # JSON output
│   │   ├── sarif.py      # SARIF output
│   │   └── sbom.py      # SBOM generation
│   └── utils/
│       └── filters.py     # Finding filters
└── configs/
    └── default.yaml       # Default configuration
```

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| `gosec not found` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| `semgrep not found` | `pip install semgrep` |
| `gitleaks not found` | `go install github.com/zricethezav/gitleaks/v8@latest` |
| `osv-scanner not found` | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| `click not found` | `pip install click` |
| `osv-scanner failed: No package sources found` | Directory has no dependency files (go.mod, package.json, etc.) |

---

## How It Works

The tool orchestrates specialized scanners behind a unified CLI interface:

| Scanner | Tool | Detections |
|---------|------|-------------|
| **gosec** | Go SAST | Hardcoded creds, SQL injection, command exec, crypto issues |
| **semgrep** | JS/TS SAST | OWASP Top 10, injection flaws, insecure patterns |
| **gitleaks** | Secrets detection | API keys, passwords, tokens, certificates |
| **osv-scanner** | CVE scanning | Vulnerable dependencies via OSV database |
| **cdxgen** | SBOM generation | CycloneDX/SPDX bill of materials |

---

## License

MIT License

---

## Support

- Check the tool output for error messages
- Ensure all dependencies are installed
- Verify the target directory exists and contains code/dependencies
- Open an issue at: https://github.com/your-repo/issues
