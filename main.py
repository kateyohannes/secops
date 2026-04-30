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
from scanner.scanners.loader import discover_scanners
from scanner.baseline import BaselineManager
from scanner.remediation import AutoRemediation
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
@click.option("--fail-on", default=None, help="Exit with error if findings meet or exceed this severity (for CI/CD).")
@click.option("--ignore-baseline/--no-ignore-baseline", default=True, help="Use .secops-ignore baseline to filter findings.")
@click.option("--fix/--no-fix", default=False, help="Attempt to automatically fix fixable findings (CVE package updates).")
@click.option("--diff", default=None, help="Only scan files changed since this git reference (e.g., main, HEAD~1).")
def scan(target, scanners, format, output, config, severity, show_details, fail_on, ignore_baseline, fix, diff):
    """Scan target directory for security issues."""
    cfg = load_config(config)
    scanner_names = [s.strip() for s in scanners.split(",")]

    results = []
    all_findings = []

    # Dynamically discover and load scanners
    scanner_map = discover_scanners()

    # Build scanner instances based on user selection
    scanner_instances = []
    for name in scanner_names:
        scanner_instances.extend(scanner_map.get(name, []))
        if not scanner_map.get(name):
            click.echo(f"  Warning: No scanners found for category '{name}'", err=True)

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

            failed_scanners = []
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
                    error_msg = f"Scanner {scanner.name} failed: {e}"
                    click.echo(f"  ERROR: {error_msg}", err=True)
                    failed_scanners.append((scanner.name, str(e)))

            # Report any scanner failures
            if failed_scanners:
                click.echo(f"\nWarning: {len(failed_scanners)} scanner(s) failed:", err=True)
                for name, err in failed_scanners:
                    click.echo(f"  - {name}: {err}", err=True)
                click.echo("Scan completed with errors. Results may be incomplete.", err=True)

    # Apply filters
    if severity:
        all_findings = filter_by_severity(all_findings, severity)
    all_findings = deduplicate(all_findings)

    # Apply baseline/ignore file
    if ignore_baseline:
        baseline = BaselineManager(os.path.abspath(target))
        original_count = len(all_findings)
        all_findings = baseline.filter_findings(all_findings)
        ignored_count = original_count - len(all_findings)
        if ignored_count >0:
            click.echo(f"  Ignored {ignored_count} finding(s) from baseline.", err=True)

    # Apply differential scanning (git diff)
    if diff:
        all_findings = _filter_by_git_diff(all_findings, target, diff)
        click.echo(f"  Filtered to findings in changed files (--diff {diff}).", err=True)

    # Apply auto-remediation
    if fix and all_findings:
        remediator = AutoRemediation(os.path.abspath(target))
        fixed, failed = remediator.fix_all(all_findings)
        if fixed > 0:
            click.echo(f"  Auto-fixed {fixed} finding(s).", err=True)
            # Remove fixed findings from the list
            all_findings = [f for f in all_findings if not remediator.can_fix(f)]
        if failed > 0:
            click.echo(f"  Failed to fix {failed} finding(s).", err=True)

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

    # Handle fail-on for CI/CD
    if fail_on and all_findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        fail_level = severity_order.get(fail_on.lower())
        if fail_level is not None:
            for f in all_findings:
                if severity_order.get(f.severity, 3) <= fail_level:
                    click.echo(f"\nFailing due to {fail_on}+ severity finding. Exiting with code 1.", err=True)
                    sys.exit(1)

    # If we had scanner failures, exit with code 1
    if failed_scanners:
        sys.exit(1)


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


@cli.group()
def baseline():
    """Manage baseline/ignore file for persistent findings filtering."""
    pass


@baseline.command("init")
@click.argument("target", default=".", type=click.Path(exists=True))
def baseline_init(target):
    """Create a new .secops-ignore file in the target directory."""
    path = BaselineManager.create_default(target)
    click.echo(f"Created baseline file: {path}")
    click.echo("Edit this file to ignore specific findings, rules, or paths.")


@baseline.command("show")
@click.argument("target", default=".", type=click.Path(exists=True))
def baseline_show(target):
    """Show current baseline/ignore settings."""
    manager = BaselineManager(target)
    click.echo("=== SecOps Baseline (Ignored Items) ===")
    click.echo(f"\nIgnored Finding IDs ({len(manager.ignored_ids)}):")
    for fid in sorted(manager.ignored_ids):
        click.echo(f"  - {fid}")
    click.echo(f"\nIgnored Rule IDs ({len(manager.ignored_rules)}):")
    for rule in sorted(manager.ignored_rules):
        click.echo(f"  - {rule}")
    click.echo(f"\nIgnored Paths ({len(manager.ignored_paths)}):")
    for path in sorted(manager.ignored_paths):
        click.echo(f"  - {path}")


@baseline.command("add")
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--finding-id", help="Finding ID to ignore (e.g., GSECR-G101).")
@click.option("--rule-id", help="Rule ID to ignore (e.g., G101).")
@click.option("--path", help="Path to ignore (e.g., vendor/).")
def baseline_add(target, finding_id, rule_id, path):
    """Add items to the baseline ignore list."""
    manager = BaselineManager(target)
    if finding_id:
        manager.add_ignored_finding(type("F", (), {"id": finding_id})())
        click.echo(f"Ignored finding: {finding_id}")
    if rule_id:
        manager.add_ignored_rule(rule_id)
        click.echo(f"Ignored rule: {rule_id}")
    if path:
        manager.add_ignored_path(path)
        click.echo(f"Ignored path: {path}")
    if not any([finding_id, rule_id, path]):
        click.echo("Please specify --finding-id, --rule-id, or --path")


def _filter_by_git_diff(findings: list, target_path: str, ref: str) -> list:
    """Filter findings to only include files changed since the git reference."""
    import subprocess
    import shutil

    # Check if git is available
    if not shutil.which("git"):
        click.echo("  Warning: git not found in PATH. --diff requires git to be installed.", err=True)
        return findings

    # Check if directory is a git repo
    is_git_repo = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=target_path,
        capture_output=True,
        timeout=10
    )

    if is_git_repo.returncode != 0:
        click.echo("  Warning: Not a git repository. --diff requires a git repo.", err=True)
        return findings

    try:
        # Get list of changed files from git diff
        result = subprocess.run(
            ["git", "diff", "--name-only", ref + "..."],
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            click.echo(f"  Warning: git diff failed: {result.stderr}", err=True)
            return findings

        changed_files = set(line.strip() for line in result.stdout.splitlines() if line.strip())

        if not changed_files:
            click.echo(f"  No files changed since {ref}.", err=True)
            return []

        # Also get untracked/modified files in working directory
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=target_path,
            capture_output=True,
            text=True,
            timeout=30
        )

        if status_result.returncode == 0:
            for line in status_result.stdout.splitlines():
                if len(line) > 3:
                    changed_files.add(line[3:].strip())

        # Filter findings to only include changed files
        filtered = []
        for f in findings:
            # Normalize paths
            finding_path = f.file_path
            if finding_path.startswith(target_path):
                finding_path = finding_path[len(target_path):].lstrip("/")

            if any(changed_file.endswith(finding_path) or finding_path.endswith(changed_file)
                   for changed_file in changed_files):
                filtered.append(f)

        return filtered

    except Exception as e:
        click.echo(f"  Warning: git diff filtering failed: {e}", err=True)
        return findings


if __name__ == "__main__":
    cli()
