"""SecPipe CLI — DevSecOps pipeline security scanner."""

import sys
from pathlib import Path

import click

from secpipe.models.finding import Finding, Severity
from secpipe.reporter.json_report import generate_json_report
from secpipe.reporter.terminal_report import print_terminal_report
from secpipe.scanner.base import BaseScanner
from secpipe.scanner.secrets import SecretsScanner


def get_all_scanners() -> list[BaseScanner]:
    """Return a list of all available scanner instances."""
    return [
        SecretsScanner(),
    ]


@click.command()
@click.argument("repo_path", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json"]),
    default="terminal",
    help="Output format for scan results.",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    default="LOW",
    help="Minimum severity to report. Findings below this are hidden.",
)
def main(repo_path: str, output_format: str, severity_threshold: str) -> None:
    """Scan a Git repository for security issues.

    REPO_PATH is the path to the repository you want to scan.

    Examples:

        secpipe .

        secpipe /path/to/project --format json

        secpipe . --severity-threshold HIGH
    """
    path = Path(repo_path).resolve()

    # Run all scanners
    scanners = get_all_scanners()
    all_findings: list[Finding] = []

    for scanner in scanners:
        click.echo(f"Running {scanner.name} scanner...")
        findings = scanner.scan(path)
        all_findings.extend(findings)

    # Filter by severity threshold
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    threshold_index = severity_order.index(Severity[severity_threshold])
    filtered = [f for f in all_findings if severity_order.index(f.severity) <= threshold_index]

    # Output results
    if output_format == "json":
        click.echo(generate_json_report(filtered, str(path)))
    else:
        print_terminal_report(filtered, str(path))

    # Exit with error code if findings exist above threshold
    critical_or_high = [f for f in filtered if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical_or_high:
        sys.exit(1)
