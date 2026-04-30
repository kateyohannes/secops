"""SecOps Tool - Security scanner for code and dependencies."""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import click
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError as e:
    print(f"Error: Missing dependency. Install with: pip install click rich")
    print(f"Details: {e}")
    sys.exit(1)

from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.config import load_config
from scanner.scanners.loader import discover_scanners
from scanner.baseline import BaselineManager
from scanner.remediation import AutoRemediation
from scanner.reporter import render_text, summary_line
from scanner.reporter import render_findings, render_scan_results
from scanner.reporter import render_sarif, generate_sbom
from scanner.reporter.redactor import OutputRedactor
from scanner.audit import setup_audit_logging, AuditLogger
from scanner.rules import load_custom_rules, update_semgrep_config
from scanner.triage import auto_triage
from scanner.utils.filters import filter_by_severity, filter_by_category, deduplicate

console = Console()


def _severity_color(severity: str) -> str:
    """Return rich color for severity level."""
    return {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(severity, "white")


def _format_findings_table(findings: list) -> Table:
    """Create a rich table with findings."""
    table = Table(title="Security Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Severity", width=12, justify="center")
    table.add_column("Rule ID", style="cyan", width=25)
    table.add_column("File:Line", style="blue", width=35)
    table.add_column("Message", style="white", no_wrap=False, min_width=40, max_width=60)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda x: (severity_order.get(x.severity, 99), x.file_path))

    for idx, f in enumerate(sorted_findings, 1):
        severity_text = Text(f.severity.upper(), style=_severity_color(f.severity))
        # Show shortened path
        short_path = f.file_path
        if len(short_path) > 32:
            short_path = "..." + short_path[-29:]
        location = f"{short_path}:{f.line}"
        # Truncate message if too long
        message = f.message
        if len(message) > 80:
            message = message[:77] + "..."
        table.add_row(str(idx), severity_text, f.rule_id, location, message)

    return table


def _print_summary(findings: list):
    """Print a beautiful summary panel."""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = len(findings)
    if total == 0:
        console.print(Panel("[bold green]✓ No security issues found![/bold green]", border_style="green"))
        return

    summary_text = Text()
    summary_text.append(f"Total Findings: {total}\n\n", style="bold")

    for sev in ["critical", "high", "medium", "low"]:
        count = counts.get(sev, 0)
        if count > 0:
            summary_text.append(f"  {sev.upper()}: ", style=_severity_color(sev))
            summary_text.append(f"{count}\n", style="white")

    console.print(Panel(summary_text, title="[bold]Scan Summary[/bold]", border_style="blue"))


@click.group()
@click.version_option("0.2.0")
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

    # Initialize audit logger
    audit_logger = setup_audit_logging()
    start_time = time.time()

    results = []
    all_findings = []
    failed_scanners = []

    # Dynamically discover and load scanners
    scanner_map = discover_scanners()

    # Load custom rules if specified
    custom_rules = []
    if cfg.get("rules_dir") or cfg.get("rules_url"):
        custom_rules = load_custom_rules(cfg.get("rules_dir"), cfg.get("rules_url"))
        if custom_rules:
            semgrep_config = update_semgrep_config(custom_rules)
            cfg["scanners"]["semgrep"] = semgrep_config.get("semgrep", {})

    # Build scanner instances based on user selection
    scanner_instances = []
    for name in scanner_names:
        scanner_instances.extend(scanner_map.get(name, []))
        if not scanner_map.get(name):
            console.print(f"[yellow]Warning: No scanners found for category '{name}'[/yellow]")

    # Run scanners concurrently with progress bar
    if scanner_instances:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(scanner_instances))

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
                            console.print(f"  [yellow]Warning from {scanner.name}: {err}[/yellow]")
                        progress.update(task, advance=1, description=f"[green]{scanner.name} completed[/green]")
                    except Exception as e:
                        error_msg = f"Scanner {scanner.name} failed: {e}"
                        console.print(f"  [red]ERROR: {error_msg}[/red]")
                        failed_scanners.append((scanner.name, str(e)))
                        progress.update(task, advance=1, description=f"[red]{scanner.name} failed[/red]")

    # Apply filters
    if severity:
        all_findings = filter_by_severity(all_findings, severity)
    all_findings = deduplicate(all_findings)

    # Apply auto-triage heuristics
    all_findings = auto_triage(all_findings)

    # Apply baseline/ignore file
    if ignore_baseline:
        baseline = BaselineManager(os.path.abspath(target))
        original_count = len(all_findings)
        all_findings = baseline.filter_findings(all_findings)
        ignored_count = original_count - len(all_findings)
        if ignored_count > 0:
            console.print(f"[dim]Ignored {ignored_count} finding(s) from baseline.[/dim]")

    # Apply differential scanning (git diff)
    if diff:
        all_findings = _filter_by_git_diff(all_findings, target, diff)
        console.print(f"[dim]Filtered to findings in changed files (--diff {diff}).[/dim]")

    # Apply auto-remediation
    if fix and all_findings:
        remediator = AutoRemediation(os.path.abspath(target))
        fixed, failed = remediator.fix_all(all_findings)
        if fixed > 0:
            console.print(f"[green]Auto-fixed {fixed} finding(s).[/green]")
            all_findings = [f for f in all_findings if not remediator.can_fix(f)]
        if failed > 0:
            console.print(f"[yellow]Failed to fix {failed} finding(s).[/yellow]")

    # Apply secret redaction to findings
    redactor = OutputRedactor(enabled=True)
    all_findings = redactor.redact_findings(all_findings)

    # Generate output
    if format == "text":
        console.print("\n")
        _print_summary(all_findings)
        if all_findings:
            console.print(_format_findings_table(all_findings))
            if show_details:
                console.print("\n[bold]Remediation Details:[/bold]")
                for f in all_findings:
                    if f.remediation:
                        color = _severity_color(f.severity)
                        console.print(f"  [{color}]{f.rule_id}[/]: {f.remediation}")
        output_text = render_text(all_findings, show_details)
    elif format == "json":
        output_text = render_scan_results(results)
        output_text = redactor.redact(output_text)
    elif format == "sarif":
        output_text = render_sarif(results)
        output_text = redactor.redact(output_text)
    else:
        output_text = render_text(all_findings, show_details)

    if output:
        with open(output, "w") as f:
            f.write(output_text)
        console.print(f"[green]Results written to {output}[/green]")
    elif format != "text":
        console.print(output_text)

    # Handle fail-on for CI/CD
    if fail_on and all_findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        fail_level = severity_order.get(fail_on.lower())
        if fail_level is not None:
            for f in all_findings:
                if severity_order.get(f.severity, 3) <= fail_level:
                    console.print(f"\n[red bold]Failing due to {fail_on}+ severity finding. Exiting with code 1.[/red bold]")
                    # Log before exit
                    duration_ms = int((time.time() - start_time) * 1000)
                    audit_logger.log_scan(
                        target=target,
                        findings_count=len(all_findings),
                        duration_ms=duration_ms,
                        scanners_used=scanner_names,
                        fail_on=fail_on,
                        exit_code=1
                    )
                    sys.exit(1)

    # If we had scanner failures, exit with code 1
    if failed_scanners:
        console.print(f"\n[yellow]{len(failed_scanners)} scanner(s) failed. Exiting with code 1.[/yellow]")
        duration_ms = int((time.time() - start_time) * 1000)
        audit_logger.log_scan(
            target=target,
            findings_count=len(all_findings),
            duration_ms=duration_ms,
            scanners_used=scanner_names,
            fail_on=fail_on,
            exit_code=1
        )
        sys.exit(1)

    # Log successful scan
    duration_ms = int((time.time() - start_time) * 1000)
    audit_logger.log_scan(
        target=target,
        findings_count=len(all_findings),
        duration_ms=duration_ms,
        scanners_used=scanner_names,
        fail_on=fail_on,
        exit_code=0
    )


@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["cyclonedx-json", "spdx-json"]), default="cyclonedx-json")
@click.option("--output", "-o", help="Output file path.")
def sbom(target, format, output):
    """Generate Software Bill of Materials (SBOM)."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating SBOM...", total=1)
        result = generate_sbom(os.path.abspath(target), output, format)
        progress.update(task, advance=1)

    if output:
        console.print(f"[green]SBOM written to {output}[/green]")
    else:
        console.print(result)


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

    console.print(Panel.fit("[bold]Checking environment for required tools...[/bold]", border_style="blue"))
    all_good = True
    table = Table(show_header=False, box=None)
    table.add_column("Status", width=5)
    table.add_column("Tool", style="cyan", width=15)
    table.add_column("Info", style="dim")

    for tool, install_cmd in tools.items():
        if shutil.which(tool):
            table.add_row("[green]✓[/green]", tool, "Found")
        else:
            table.add_row("[red]✗[/red]", tool, f"[dim]Install: {install_cmd}[/dim]")
            all_good = False

    console.print(table)
    console.print()

    if all_good:
        console.print("[bold green]All tools are installed and ready![/bold green]")
    else:
        console.print("[yellow]Some tools are missing. Install them to enable all scanners.[/yellow]")
        console.print("[dim]Tip: Use Docker image to get all tools pre-installed: docker build -t secops .[/dim]")


@cli.group()
def baseline():
    """Manage baseline/ignore file for persistent findings filtering."""
    pass


@baseline.command("init")
@click.argument("target", default=".", type=click.Path(exists=True))
def baseline_init(target):
    """Create a new .secops-ignore file in the target directory."""
    path = BaselineManager.create_default(target)
    console.print(f"[green]Created baseline file: {path}[/green]")
    console.print("[dim]Edit this file to ignore specific findings, rules, or paths.[/dim]")


@baseline.command("show")
@click.argument("target", default=".", type=click.Path(exists=True))
def baseline_show(target):
    """Show current baseline/ignore settings."""
    manager = BaselineManager(target)
    console.print(Panel.fit("[bold]SecOps Baseline (Ignored Items)[/bold]", border_style="blue"))

    if manager.ignored_ids:
        console.print(f"\n[bold]Ignored Finding IDs ({len(manager.ignored_ids)}):[/bold]")
        for fid in sorted(manager.ignored_ids):
            console.print(f"  [dim]-[/dim] {fid}")

    if manager.ignored_rules:
        console.print(f"\n[bold]Ignored Rule IDs ({len(manager.ignored_rules)}):[/bold]")
        for rule in sorted(manager.ignored_rules):
            console.print(f"  [dim]-[/dim] {rule}")

    if manager.ignored_paths:
        console.print(f"\n[bold]Ignored Paths ({len(manager.ignored_paths)}):[/bold]")
        for path in sorted(manager.ignored_paths):
            console.print(f"  [dim]-[/dim] {path}")

    if not manager.ignored_ids and not manager.ignored_rules and not manager.ignored_paths:
        console.print("[dim]No items in baseline. Use 'secops baseline add' to ignore findings.[/dim]")


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
        console.print(f"[green]Ignored finding: {finding_id}[/green]")
    if rule_id:
        manager.add_ignored_rule(rule_id)
        console.print(f"[green]Ignored rule: {rule_id}[/green]")
    if path:
        manager.add_ignored_path(path)
        console.print(f"[green]Ignored path: {path}[/green]")
    if not any([finding_id, rule_id, path]):
        console.print("[yellow]Please specify --finding-id, --rule-id, or --path[/yellow]")


def _filter_by_git_diff(findings: list, target_path: str, ref: str) -> list:
    """Filter findings to only include files changed since the git reference."""
    import subprocess
    import shutil

    # Check if git is available
    if not shutil.which("git"):
        console.print("[yellow]  Warning: git not found in PATH. --diff requires git to be installed.[/yellow]")
        return findings

    # Check if directory is a git repo
    is_git_repo = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=target_path,
        capture_output=True,
        timeout=10
    )

    if is_git_repo.returncode != 0:
        console.print("[yellow]  Warning: Not a git repository. --diff requires a git repo.[/yellow]")
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
            console.print(f"[yellow]  Warning: git diff failed: {result.stderr}[/yellow]")
            return findings

        changed_files = set(line.strip() for line in result.stdout.splitlines() if line.strip())

        if not changed_files:
            console.print(f"[dim]  No files changed since {ref}.[/dim]")
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
            finding_path = f.file_path
            if finding_path.startswith(target_path):
                finding_path = finding_path[len(target_path):].lstrip("/")

            if any(changed_file.endswith(finding_path) or finding_path.endswith(changed_file)
                   for changed_file in changed_files):
                filtered.append(f)

        return filtered

    except Exception as e:
        console.print(f"[yellow]  Warning: git diff filtering failed: {e}[/yellow]")
        return findings


if __name__ == "__main__":
    cli()
