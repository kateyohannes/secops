# How to Use SecOps Tool

## Quick Start (3 steps)

### 1. Install Dependencies

```bash
# Install Python libraries
pip install click pyyaml

# Install Go tools (requires Go installed)
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/zricethezav/gitleaks/v8@latest  
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Install Semgrep
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
# Scan current directory
python3 main.py scan .

# Scan specific directory
python3 main.py scan /path/to/project

# Output as JSON
python3 main.py scan . --format json --output results.json

# Output as SARIF (for GitHub Security)
python3 main.py scan . --format sarif --output results.sarif
```

## Common Usage Examples

### Scan Go Project
```bash
python3 main.py scan /go/project --scanners sast,cve
```

### Scan JavaScript/TypeScript Project
```bash
python3 main.py scan /js/project --scanners sast,secrets
```

### Filter by Severity
```bash
# Show only high and critical findings
python3 main.py scan . --severity high
```

### Show Remediation Details
```bash
python3 main.py scan . --show-details
```

### Generate SBOM
```bash
# Requires: npm install -g @cyclonedx/cdxgen
python3 main.py sbom . --format cyclonedx-json --output sbom.json
```

## Output Formats

| Format | Command | Use Case |
|--------|---------|----------|
| text | `--format text` | Terminal output (default) |
| json | `--format json` | Machine-readable, CI integration |
| sarif | `--format sarif` | GitHub/Azure Security tab |

## Scanner Options

| Scanner | Description | Command |
|---------|-------------|---------|
| sast | Go + JS/TS static analysis | `--scanners sast` |
| secrets | API keys, passwords, tokens | `--scanners secrets` |
| cve | Dependency vulnerability scanning | `--scanners cve` |
| all | All scanners | `--scanners sast,secrets,cve` |

## CI/CD Integration

### GitHub Actions (`.github/workflows/security.yml`)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"
      
      - name: Install tools
        run: |
          pip install click pyyaml semgrep
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          go install github.com/zricethezav/gitleaks/v8@latest
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest
          echo "$HOME/go/bin" >> $GITHUB_PATH
      
      - name: Run scan
        run: python3 main.py scan . --format sarif --output results.sarif
      
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Project Structure

```
build_secops_tool/
├── main.py                    # CLI entry point
├── scanner/
│   ├── types.py             # Finding/ScanResult types
│   ├── config.py            # Configuration
│   ├── scanners/
│   │   ├── base.py        # Base scanner class
│   │   ├── gosec.py      # Go SAST
│   │   ├── semgrep.py    # JS/TS SAST
│   │   ├── secrets.py    # Secrets detection
│   │   └── cve.py       # CVE scanning
│   ├── reporter/
│   │   ├── text.py       # Text output
│   │   ├── json_reporter.py  # JSON output
│   │   ├── sarif.py      # SARIF output
│   │   └── sbom.py      # SBOM generation
│   └── utils/
│       └── filters.py     # Finding filters
├── configs/
│   └── default.yaml       # Default config
├── USAGE.md                # Detailed documentation
└── HOW_TO_USE.md            # This file
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| `gosec not found` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| `semgrep not found` | `pip install semgrep` |
| `gitleaks not found` | `go install github.com/zricethezav/gitleaks/v8@latest` |
| `osv-scanner not found` | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| `click not found` | `pip install click` |

## Need Help?

1. Check the full documentation: `cat USAGE.md`
2. Verify all tools are installed: `gosec --version && semgrep --version`
3. Check Python syntax: `python3 -m py_compile main.py`
