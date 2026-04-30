"""SecOps Tool - Security scanner for code and dependencies."""
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import click
except ImportError:
    print("Error: click not found. Install with: pip install click")
    sys.exit(1)

from scanner.config import load_config
from scanner.scanners.gosec import GosecScanner
from scanner.scanners.semgrep import SemgrepScanner
from scanner.scanners.secrets import SecretsScanner
from scanner.scanners.cve import CVEScanner
from scanner.reporter import render_text, summary_line
from scanner.reporter import render_findings, render_scan_results
from scanner.reporter import render_sarif, generate_sbom
from scanner.utils.filters import filter_by_severity, filter_by_category, deduplicate


@click.group()
@click.version_option("0.1.0")
def cli():
    """SecOps Tool - Security scanner for code and dependencies."""
    pass


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--scanners", default="sast,secrets,cve", help="Comma-separated list of scanners.")
@click.option("--format", "-f", type=click.Choice(["text", "json", "sarif"]), default="text")
@click.option("--output", "-o", help="Output file path.")
@click.option("--config", "-c", help="Config file path.")
@click.option("--severity", help="Minimum severity filter (critical, high, medium, low).")
@click.option("--show-details/--no-details", default=False, help="Show remediation details.")
def scan(target, scanners, format, output, config, severity, show_details):
    """Scan target directory for security issues."""
    cfg = load_config(config)
    scanner_names = [s.strip() for s in scanners.split(",")]

    results = []
    all_findings = []

    # Build scanner instances
    scanner_instances = []
    scanner_map = {
        "sast": [GosecScanner(), SemgrepScanner()],
        "secrets": [SecretsScanner()],
        "cve": [CVEScanner()],
    }

    for name in scanner_names:
        scanner_instances.extend(scanner_map.get(name, []))

    # Run scanners concurrently
    if scanner_instances:
        click.echo(f"Running {len(scanner_instances)} scanners concurrently...", err=True)
        with ThreadPoolExecutor(max_workers=len(scanner_instances)) as executor:
            future_to_scanner = {
                executor.submit(
                    scanner.scan,
                    os.path.abspath(target),
                    cfg.get("scanners", {}).get(scanner.name, {})
                ): scanner
                for scanner in scanner_instances
            }

            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    result = future.result()
                    results.append(result)
                    all_findings.extend(result.findings)
                    for err in result.errors:
                        click.echo(f"  Warning from {scanner.name}: {err}", err=True)
                    click.echo(f"  {scanner.name} completed", err=True)
                except Exception as e:
                    click.echo(f"  Error in {scanner.name}: {e}", err=True)

    # Apply filters
    if severity:
        all_findings = filter_by_severity(all_findings, severity)
    all_findings = deduplicate(all_findings)

    # Generate output
    if format == "text":
        output_text = render_text(all_findings, show_details)
    elif format == "json":
        output_text = render_scan_results(results)
    elif format == "sarif":
        output_text = render_sarif(results)
    else:
        output_text = render_text(all_findings, show_details)

    if output:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Results written to {output}", err=True)
    else:
        click.echo(output_text)


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["cyclonedx-json", "spdx-json"]), default="cyclonedx-json")
@click.option("--output", "-o", help="Output file path.")
def sbom(target, format, output):
    """Generate Software Bill of Materials (SBOM)."""
    click.echo("Generating SBOM...", err=True)
    result = generate_sbom(os.path.abspath(target), output, format)
    if output:
        click.echo(f"SBOM written to {output}", err=True)
    else:
        click.echo(result)


@cli.command()
def check_env():
    """Check if required security tools are installed."""
    import shutil

    tools = {
        "gosec": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
        "semgrep": "pip install semgrep",
        "gitleaks": "go install github.com/zricethezav/gitleaks/v8@latest",
        "osv-scanner": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        "cdxgen": "npm install -g @cyclonedx/cdxgen",
    }

    click.echo("Checking environment for required tools...\n")
    all_good = True

    for tool, install_cmd in tools.items():
        if shutil.which(tool):
            click.echo(f"  ✓ {tool:15} - Found")
        else:
            click.echo(f"  ✗ {tool:15} - Missing")
            click.echo(f"    Install: {install_cmd}")
            all_good = False

    click.echo("")
    if all_good:
        click.echo("All tools are installed and ready!")
    else:
        click.echo("Some tools are missing. Install them to enable all scanners.")
        click.echo("Tip: Use Docker image to get all tools pre-installed:")
        click.echo("  docker build -t secops .")


if __name__ == "__main__":
    cli()
