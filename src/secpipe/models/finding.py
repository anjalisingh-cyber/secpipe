"""Data models for security scan findings."""

from dataclasses import dataclass
from enum import Enum


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
    line_number: int | None
    title: str
    description: str
    remediation: str
    evidence: str = ""
