# SecOps Tool - Quick Start#

## What is this?

A Python security scanner that detects:
- **Hardcoded secrets** (API keys, passwords)
- **Code vulnerabilities** (SQL injection, XSS, etc.)
- **CVE vulnerabilities** in dependencies

Supports: **Go**, **JavaScript/TypeScript**

## Installation (Copy & Paste)

```bash
# 1. Install Python libraries
pip install click pyyaml

# 2. Install Go (if not installed)
# https://go.dev/doc/install

# 3. Install security tools
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/zricethezav/gitleaks/v8@latest
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# 4. Install Semgrep
pip install semgrep

# 5. Add Go bin to PATH
export PATH=$PATH:~/go/bin
# Add to ~/.bashrc for permanent:
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

## Usage (3 commands to know)

### 1. Scan current directory
```bash
cd /home/jeo/Development/aleph/ai/build_secops_tool
python3 main.py scan .
```

### 2. Scan a specific project
```bash
python3 main.py scan /home/jeo/Development/eagle/cbe/org_clone/CBE-Super-App
```

### 3. Different output formats
```bash
# Text (default - human readable)
python3 main.py scan . --format text

# JSON (machine readable)
python3 main.py scan . --format json --output results.json

# SARIF (for GitHub Security tab)
python3 main.py scan . --format sarif --output results.sarif
```

## Common Options

| Option | Example | Description |
|--------|---------|-------------|
| `--scanners` | `--scanners sast,secrets` | Which scanners to run |
| `--severity` | `--severity high` | Min severity: critical, high, medium, low |
| `--show-details` | `--show-details` | Show remediation advice |
| `--output` | `--output results.json` | Save to file |

## Scanner Types

| Scanner | Detects | Command |
|---------|---------|---------|
| `sast` | Code vulnerabilities in Go/JS/TS | `--scanners sast` |
| `secrets` | Hardcoded passwords, API keys | `--scanners secrets` |
| `cve` | Vulnerable dependencies | `--scanners cve` |
| All (default) | All of the above | `--scanners sast,secrets,cve` |

## Example Output

```bash
$ python3 main.py scan test_code --scanners=sast

============================================================
 SECURITY SCAN RESULTS (1 findings)
============================================================

📁 /path/to/vulnerable.go
  🟢 [LOW] G104: Errors unhandled
      Line 18 | Category: SAST | ID: GSECR-G104
      CWE: 703

============================================================
Summary: LOW: 1
============================================================
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| `gosec not found` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| `semgrep not found` | `pip install semgrep` |
| `gitleaks not found` | `go install github.com/zricethezav/gitleaks/v8@latest` |
| `osv-scanner not found` | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| Command not found | `export PATH=$PATH:~/go/bin` |

## Full Documentation

- `cat USAGE.md` - Complete guide (8KB)
- `cat HOW_TO_USE.md` - Quick reference (4KB)
- `cat QUICKSTART.md` - This file (2KB)
