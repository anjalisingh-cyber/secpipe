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
        r"(?i)(?:mongodb|postgre(?:s|sql)|mysql|redis|amqp)://[^:\s]+:[^@\s]+@",
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
    ".pem",
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
