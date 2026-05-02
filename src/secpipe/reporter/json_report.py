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
