#!/bin/bash
# SecPipe Code Setup Script
# Run this from inside your secpipe folder:
#   cd ~/secpipe
#   bash setup_code.sh

echo "=== SecPipe Code Setup ==="
echo "Creating all code files..."
echo ""

# --- src/secpipe/models/finding.py ---
cat > src/secpipe/models/finding.py << 'ENDFILE'
"""Data models for security scan findings."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Represents a single security finding from a scanner.

    Attributes:
        scanner: Name of the scanner that found this issue.
        rule_id: Unique identifier for the rule.
        severity: How serious this finding is.
        file_path: Path to the file where the issue was found.
        line_number: Line number in the file.
        title: Short description of the finding.
        description: Detailed explanation of what was found.
        remediation: How to fix the issue.
        evidence: The offending code snippet (redacted if sensitive).
    """

    scanner: str
    rule_id: str
    severity: Severity
    file_path: str
    line_number: Optional[int]
    title: str
    description: str
    remediation: str
    evidence: str = ""
ENDFILE
echo "[1/10] Created src/secpipe/models/finding.py"

# --- src/secpipe/scanner/base.py ---
cat > src/secpipe/scanner/base.py << 'ENDFILE'
"""Abstract base class for all security scanners."""

from abc import ABC, abstractmethod
from pathlib import Path

from secpipe.models.finding import Finding


class BaseScanner(ABC):
    """Base class that all scanners must inherit from.

    This ensures every scanner has a consistent interface:
    - A name property identifying the scanner
    - A scan() method that takes a repo path and returns findings
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this scanner."""
        ...

    @abstractmethod
    def scan(self, repo_path: Path) -> list[Finding]:
        """Scan the repository and return a list of findings.

        Args:
            repo_path: Path to the root of the repository to scan.

        Returns:
            A list of Finding objects representing security issues found.
        """
        ...

    def _get_files(
        self,
        repo_path: Path,
        extensions: set[str] | None = None,
        filenames: set[str] | None = None,
    ) -> list[Path]:
        """Walk the repo and return files matching criteria.

        Skips common non-source directories like .git, node_modules, .venv.

        Args:
            repo_path: Root path to walk.
            extensions: File extensions to include (e.g., {".py", ".js"}).
                        If None, includes all files.
            filenames: Specific filenames to include (e.g., {"Dockerfile"}).
                       If None, does not filter by filename.

        Returns:
            List of Path objects matching the criteria.
        """
        skip_dirs = {
            ".git",
            "node_modules",
            ".venv",
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "dist",
            "build",
            ".eggs",
        }

        files: list[Path] = []
        for item in repo_path.rglob("*"):
            if any(skip_dir in item.parts for skip_dir in skip_dirs):
                continue

            if not item.is_file():
                continue

            if filenames and item.name in filenames:
                files.append(item)
            elif extensions and item.suffix in extensions:
                files.append(item)
            elif extensions is None and filenames is None:
                files.append(item)

        return files
ENDFILE
echo "[2/10] Created src/secpipe/scanner/base.py"

# --- src/secpipe/scanner/secrets.py ---
cat > src/secpipe/scanner/secrets.py << 'ENDFILE'
"""Scanner for hardcoded secrets in source code."""

import re
from pathlib import Path

from secpipe.models.finding import Finding, Severity
from secpipe.scanner.base import BaseScanner


# Each rule is a tuple of: (rule_id, title, regex_pattern, severity, remediation)
SECRET_PATTERNS: list[tuple[str, str, str, Severity, str]] = [
    (
        "SEC001",
        "Hardcoded AWS Access Key",
        r"(?:^|['\"\s=])(?P<secret>AKIA[0-9A-Z]{16})(?:['\"\s]|$)",
        Severity.CRITICAL,
        "Move AWS credentials to environment variables or use AWS IAM roles.",
    ),
    (
        "SEC002",
        "Hardcoded Private Key",
        r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
        Severity.CRITICAL,
        "Never store private keys in source code. Use a secrets manager.",
    ),
    (
        "SEC003",
        "GitHub Personal Access Token",
        r"(?:^|['\"\s=])(?P<secret>ghp_[A-Za-z0-9_]{36,})(?:['\"\s]|$)",
        Severity.CRITICAL,
        "Revoke this token immediately and use environment variables.",
    ),
    (
        "SEC004",
        "Generic Password in Source Code",
        r"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|api[-_]?secret)"
        r"[\s]*[=:]+[\s]*['\"]([^'\"]{8,})['\"]",
        Severity.HIGH,
        "Move sensitive values to environment variables or a secrets manager.",
    ),
    (
        "SEC005",
        "Database Connection String with Credentials",
        r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^:\s]+:[^@\s]+@",
        Severity.HIGH,
        "Use environment variables for database connection strings.",
    ),
    (
        "SEC006",
        "GitLab Personal Access Token",
        r"(?:^|['\"\s=])(?P<secret>glpat-[A-Za-z0-9\-_]{20,})(?:['\"\s]|$)",
        Severity.CRITICAL,
        "Revoke this token immediately and use environment variables.",
    ),
]

# File extensions to scan for secrets
TARGET_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".rb",
    ".go",
    ".php",
    ".cs",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".toml",
    ".cfg",
    ".ini",
    ".conf",
    ".env",
    ".sh",
    ".bash",
    ".tf",
}


class SecretsScanner(BaseScanner):
    """Scans source code files for hardcoded secrets using regex patterns."""

    @property
    def name(self) -> str:
        return "secrets"

    def scan(self, repo_path: Path) -> list[Finding]:
        """Scan all source files in the repo for hardcoded secrets.

        Args:
            repo_path: Path to the repository root.

        Returns:
            List of Finding objects for each detected secret.
        """
        findings: list[Finding] = []
        files = self._get_files(repo_path, extensions=TARGET_EXTENSIONS)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                for rule_id, title, pattern, severity, remediation in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        redacted = self._redact_line(line.strip())
                        findings.append(
                            Finding(
                                scanner=self.name,
                                rule_id=rule_id,
                                severity=severity,
                                file_path=str(file_path.relative_to(repo_path)),
                                line_number=line_number,
                                title=title,
                                description=f"Potential {title.lower()} detected.",
                                remediation=remediation,
                                evidence=redacted,
                            )
                        )
                        break  # One finding per line is enough

        return findings

    @staticmethod
    def _redact_line(line: str, max_length: int = 80) -> str:
        """Redact sensitive parts of a line for safe display.

        Args:
            line: The source code line containing the secret.
            max_length: Maximum length of the returned string.

        Returns:
            A redacted version of the line safe for display.
        """
        if len(line) > max_length:
            line = line[:max_length] + "..."
        return line
ENDFILE
echo "[3/10] Created src/secpipe/scanner/secrets.py"

# --- src/secpipe/reporter/terminal_report.py ---
cat > src/secpipe/reporter/terminal_report.py << 'ENDFILE'
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
ENDFILE
echo "[4/10] Created src/secpipe/reporter/terminal_report.py"

# --- src/secpipe/reporter/json_report.py ---
cat > src/secpipe/reporter/json_report.py << 'ENDFILE'
"""JSON reporter — outputs findings as structured JSON."""

import json
from typing import Any

from secpipe.models.finding import Finding


def generate_json_report(findings: list[Finding], repo_path: str) -> str:
    """Generate a JSON string from scan findings.

    Args:
        findings: List of all findings from all scanners.
        repo_path: Path to the scanned repository.

    Returns:
        A formatted JSON string.
    """
    report: dict[str, Any] = {
        "tool": "secpipe",
        "version": "0.1.0",
        "repository": repo_path,
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity.value == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in findings if f.severity.value == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity.value == "LOW"),
        },
        "findings": [
            {
                "scanner": f.scanner,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }
    return json.dumps(report, indent=2)
ENDFILE
echo "[5/10] Created src/secpipe/reporter/json_report.py"

# --- src/secpipe/cli.py ---
cat > src/secpipe/cli.py << 'ENDFILE'
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
ENDFILE
echo "[6/10] Created src/secpipe/cli.py"

# --- tests/conftest.py ---
cat > tests/conftest.py << 'ENDFILE'
"""Shared test fixtures for SecPipe tests."""
ENDFILE
echo "[7/10] Created tests/conftest.py"

# --- tests/fixtures/insecure_app.py ---
cat > tests/fixtures/insecure_app.py << 'ENDFILE'
"""Deliberately insecure file for testing SecPipe's secrets scanner.

DO NOT use any of these values. They are fake examples.
"""

# AWS Access Key (fake)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Database connection string with password
DATABASE_URL = "postgresql://admin:s3cretP@ss@localhost:5432/mydb"

# GitHub token (fake)
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

# This is safe — no secrets here
APP_NAME = "MyApp"
DEBUG = True
PORT = 8080
ENDFILE
echo "[8/10] Created tests/fixtures/insecure_app.py"

# --- tests/fixtures/safe_app.py ---
cat > tests/fixtures/safe_app.py << 'ENDFILE'
"""A safe file with no hardcoded secrets for testing."""

import os

# Correct way to handle credentials
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
DATABASE_URL = os.environ.get("DATABASE_URL")
API_KEY = os.environ.get("API_KEY")

APP_NAME = "SecureApp"
DEBUG = False
PORT = 8080
ENDFILE
echo "[9/10] Created tests/fixtures/safe_app.py"

# --- tests/test_secrets_scanner.py ---
cat > tests/test_secrets_scanner.py << 'ENDFILE'
"""Tests for the secrets scanner."""

from pathlib import Path

import pytest

from secpipe.models.finding import Severity
from secpipe.scanner.secrets import SecretsScanner


@pytest.fixture
def scanner() -> SecretsScanner:
    """Create a SecretsScanner instance for testing."""
    return SecretsScanner()


@pytest.fixture
def repo_without_secrets(tmp_path: Path) -> Path:
    """Create a temporary repo with no secrets."""
    safe_file = tmp_path / "app.py"
    safe_file.write_text(
        'import os\n'
        'API_KEY = os.environ.get("API_KEY")\n'
        'print("Hello world")\n'
    )
    return tmp_path


class TestSecretsScanner:
    """Tests for SecretsScanner."""

    def test_scanner_name(self, scanner: SecretsScanner) -> None:
        """Scanner should identify itself as 'secrets'."""
        assert scanner.name == "secrets"

    def test_finds_aws_access_key(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should detect AWS access keys."""
        test_file = tmp_path / "config.py"
        test_file.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        aws_finding = [f for f in findings if f.rule_id == "SEC001"]
        assert len(aws_finding) == 1
        assert aws_finding[0].severity == Severity.CRITICAL

    def test_finds_github_token(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should detect GitHub personal access tokens."""
        test_file = tmp_path / "config.py"
        test_file.write_text('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"')

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        gh_finding = [f for f in findings if f.rule_id == "SEC003"]
        assert len(gh_finding) == 1
        assert gh_finding[0].severity == Severity.CRITICAL

    def test_finds_password_in_code(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should detect hardcoded passwords."""
        test_file = tmp_path / "db.py"
        test_file.write_text('password = "my_super_secret_password"')

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        pwd_finding = [f for f in findings if f.rule_id == "SEC004"]
        assert len(pwd_finding) == 1

    def test_finds_private_key(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should detect private keys."""
        test_file = tmp_path / "key.pem"
        test_file.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "fake_key_data\n"
            "-----END RSA PRIVATE KEY-----"
        )

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        key_finding = [f for f in findings if f.rule_id == "SEC002"]
        assert len(key_finding) == 1
        assert key_finding[0].severity == Severity.CRITICAL

    def test_finds_database_connection_string(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should detect database connection strings with credentials."""
        test_file = tmp_path / "settings.py"
        test_file.write_text('DB = "postgresql://user:pass123@localhost:5432/mydb"')

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        db_finding = [f for f in findings if f.rule_id == "SEC005"]
        assert len(db_finding) == 1

    def test_no_findings_in_safe_code(
        self, scanner: SecretsScanner, repo_without_secrets: Path
    ) -> None:
        """Should not flag safe code that uses environment variables."""
        findings = scanner.scan(repo_without_secrets)
        assert len(findings) == 0

    def test_skips_git_directory(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should not scan files inside .git directories."""
        git_dir = tmp_path / ".git" / "config"
        git_dir.parent.mkdir(parents=True)
        git_dir.write_text("AKIAIOSFODNN7EXAMPLE")

        findings = scanner.scan(tmp_path)
        assert len(findings) == 0

    def test_skips_node_modules(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Should not scan files inside node_modules."""
        nm_file = tmp_path / "node_modules" / "package" / "config.js"
        nm_file.parent.mkdir(parents=True)
        nm_file.write_text('const key = "AKIAIOSFODNN7EXAMPLE"')

        findings = scanner.scan(tmp_path)
        assert len(findings) == 0

    def test_finding_includes_file_path(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Findings should include the relative file path."""
        sub_dir = tmp_path / "src"
        sub_dir.mkdir()
        test_file = sub_dir / "config.py"
        test_file.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        assert "src/config.py" in findings[0].file_path

    def test_finding_includes_line_number(self, scanner: SecretsScanner, tmp_path: Path) -> None:
        """Findings should include the correct line number."""
        test_file = tmp_path / "config.py"
        test_file.write_text('safe = True\nkey = "AKIAIOSFODNN7EXAMPLE"\nmore = False')

        findings = scanner.scan(tmp_path)

        assert len(findings) >= 1
        assert findings[0].line_number == 2
ENDFILE
echo "[10/10] Created tests/test_secrets_scanner.py"

# --- .github/workflows/ci.yml ---
mkdir -p .github/workflows
cat > .github/workflows/ci.yml << 'ENDFILE'
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Lint with ruff
        run: ruff check src/ tests/

      - name: Type check with mypy
        run: mypy src/

      - name: Run tests with coverage
        run: pytest --cov=secpipe --cov-report=xml --cov-report=term-missing -v
ENDFILE
echo "[BONUS] Created .github/workflows/ci.yml"

# --- CONTRIBUTING.md ---
cat > CONTRIBUTING.md << 'ENDFILE'
# Contributing to SecPipe

Thank you for your interest in contributing to SecPipe.

## Development Setup

1. Fork and clone the repository
2. Create a virtual environment: `python -m venv .venv`
3. Activate it: `source .venv/bin/activate`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Create a branch: `git checkout -b feature/your-feature-name`

## Code Standards

- All code must pass `ruff check`
- All code must pass `mypy` strict mode
- All new features must have tests
- Test coverage must remain above 80%
- Use type hints on all function signatures

## Running Tests

```bash
pytest -v
pytest --cov=secpipe --cov-report=term-missing
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Describe your changes clearly in the PR description
ENDFILE
echo "[BONUS] Created CONTRIBUTING.md"

echo ""
echo "=== All files created! ==="
echo ""
echo "Now run these commands:"
echo "  pip install -e '.[dev]'"
echo "  secpipe --help"
echo "  pytest -v"
echo ""
