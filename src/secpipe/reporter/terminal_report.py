"""Terminal reporter — prints coloured scan results to the console."""

import click

from secpipe.models.finding import Finding, Severity


# Colour mapping for severity levels
SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "yellow",
    Severity.MEDIUM: "cyan",
    Severity.LOW: "white",
}


def print_terminal_report(findings: list[Finding], repo_path: str) -> None:
    """Print a formatted scan report to the terminal.

    Args:
        findings: List of all findings from all scanners.
        repo_path: Path to the scanned repository (for display).
    """
    # Count findings by severity
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity] += 1

    # Print header
    click.echo()
    click.echo(click.style("SecPipe v0.1.0 — Scan Results", bold=True))
    click.echo("=" * 40)
    click.echo(f"Repository: {repo_path}")

    # Print summary
    summary_parts: list[str] = []
    for severity in Severity:
        count = counts[severity]
        colour = SEVERITY_COLOURS[severity]
        summary_parts.append(click.style(f"{count} {severity.value}", fg=colour))
    click.echo(f"Findings:   {', '.join(summary_parts)}")
    click.echo()

    if not findings:
        click.echo(click.style("No security issues found.", fg="green", bold=True))
        return

    # Sort findings by severity (CRITICAL first)
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

    # Print each finding
    for finding in sorted_findings:
        colour = SEVERITY_COLOURS[finding.severity]
        click.echo(
            click.style(
                f"[{finding.severity.value}] {finding.rule_id} — {finding.title}",
                fg=colour,
                bold=True,
            )
        )

        location = f"  File: {finding.file_path}"
        if finding.line_number:
            location += f":{finding.line_number}"
        click.echo(location)

        if finding.evidence:
            click.echo(f"  Evidence: {finding.evidence}")

        click.echo(click.style(f"  Fix:  {finding.remediation}", fg="green"))
        click.echo()
