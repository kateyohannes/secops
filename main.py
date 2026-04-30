"""SecOps Tool - Security scanner for code and dependencies."""
import sys
import os

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

    scanner_map = {
        "sast": [GosecScanner(), SemgrepScanner()],
        "secrets": [SecretsScanner()],
        "cve": [CVEScanner()],
    }

    for name in scanner_names:
        for scanner in scanner_map.get(name, []):
            click.echo(f"Running {scanner.name} scanner...", err=True)
            result = scanner.scan(os.path.abspath(target), cfg.get("scanners", {}).get(name, {}))
            results.append(result)
            all_findings.extend(result.findings)
            for err in result.errors:
                click.echo(f"  Warning: {err}", err=True)

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


if __name__ == "__main__":
    cli()
