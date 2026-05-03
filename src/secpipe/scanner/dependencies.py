"""Scanner for known vulnerabilities in project dependencies."""

import json
import re
from pathlib import Path
from typing import Any

import requests

from secpipe.models.finding import Finding, Severity
from secpipe.scanner.base import BaseScanner

# Map CVSS severity strings from OSV to our Severity enum
SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# OSV.dev API endpoint (free, no API key needed)
OSV_API_URL = "https://api.osv.dev/v1/query"

# Request timeout in seconds
REQUEST_TIMEOUT = 10


def _parse_requirements_txt(file_path: Path) -> list[tuple[str, str]]:
    """Parse a requirements.txt file and extract package names and versions.

    Args:
        file_path: Path to the requirements.txt file.

    Returns:
        List of (package_name, version) tuples.
    """
    packages: list[tuple[str, str]] = []
    content = file_path.read_text(encoding="utf-8", errors="ignore")

    for line in content.splitlines():
        line = line.strip()
        # Skip empty lines, comments, and options
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Match patterns like: package==1.0.0 or package>=1.0.0
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*[=~><!]+\s*([0-9][0-9a-zA-Z\.\-\*]*)", line)
        if match:
            packages.append((match.group(1).strip(), match.group(2).strip()))

    return packages


def _parse_package_json(file_path: Path) -> list[tuple[str, str]]:
    """Parse a package.json file and extract dependency names and versions.

    Args:
        file_path: Path to the package.json file.

    Returns:
        List of (package_name, version) tuples.
    """
    packages: list[tuple[str, str]] = []

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return packages

    for dep_key in ("dependencies", "devDependencies"):
        deps = data.get(dep_key, {})
        if not isinstance(deps, dict):
            continue
        for name, version_str in deps.items():
            # Remove version prefixes like ^, ~, >=
            clean_version = re.sub(r"^[\^~>=<]+", "", str(version_str)).strip()
            if clean_version and clean_version[0].isdigit():
                packages.append((name, clean_version))

    return packages


def _query_osv(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    """Query the OSV.dev API for known vulnerabilities.

    Args:
        ecosystem: The package ecosystem (e.g., "PyPI", "npm").
        package_name: Name of the package.
        version: Version string to check.

    Returns:
        List of vulnerability dictionaries from OSV.
    """
    try:
        response = requests.post(
            OSV_API_URL,
            json={
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem,
                },
                "version": version,
            },
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("vulns", [])
    except (requests.RequestException, json.JSONDecodeError):
        return []


def _get_severity_from_vuln(vuln: dict[str, Any]) -> Severity:
    """Extract severity from an OSV vulnerability record.

    Args:
        vuln: Vulnerability dictionary from OSV.

    Returns:
        The mapped Severity enum value.
    """
    # Try to get severity from database_specific or severity field
    severity_list = vuln.get("severity", [])
    if severity_list:
        for sev in severity_list:
            score = sev.get("score", "")
            # CVSS v3 score ranges
            if score:
                try:
                    cvss = float(score) if isinstance(score, (int, float)) else 0.0
                    if cvss >= 9.0:
                        return Severity.CRITICAL
                    if cvss >= 7.0:
                        return Severity.HIGH
                    if cvss >= 4.0:
                        return Severity.MEDIUM
                    return Severity.LOW
                except (ValueError, TypeError):
                    pass

    # Try database_specific severity
    db_specific = vuln.get("database_specific", {})
    severity_str = db_specific.get("severity", "").upper()
    if severity_str in SEVERITY_MAP:
        return SEVERITY_MAP[severity_str]

    # Default to HIGH for any known vulnerability
    return Severity.HIGH


def _get_fix_version(vuln: dict[str, Any], package_name: str) -> str:
    """Extract the recommended fix version from an OSV vulnerability.

    Args:
        vuln: Vulnerability dictionary from OSV.
        package_name: Name of the package to find fix for.

    Returns:
        String describing the fix version, or a generic message.
    """
    affected_list = vuln.get("affected", [])
    for affected in affected_list:
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            ranges = affected.get("ranges", [])
            for range_info in ranges:
                events = range_info.get("events", [])
                for event in events:
                    fixed = event.get("fixed")
                    if fixed:
                        return fixed
    return "latest"


class DependencyScanner(BaseScanner):
    """Scans dependency files for packages with known vulnerabilities."""

    @property
    def name(self) -> str:
        return "dependencies"

    def scan(self, repo_path: Path) -> list[Finding]:
        """Scan dependency files for known vulnerabilities.

        Checks requirements.txt (Python/PyPI) and package.json (Node/npm)
        against the OSV.dev vulnerability database.

        Args:
            repo_path: Path to the repository root.

        Returns:
            List of Finding objects for each vulnerable dependency.
        """
        findings: list[Finding] = []

        # Scan Python dependencies
        req_files = self._get_files(repo_path, filenames={"requirements.txt"})
        for req_file in req_files:
            packages = _parse_requirements_txt(req_file)
            for pkg_name, pkg_version in packages:
                vulns = _query_osv("PyPI", pkg_name, pkg_version)
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "No description available.")
                    severity = _get_severity_from_vuln(vuln)
                    fix_version = _get_fix_version(vuln, pkg_name)

                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DEP001",
                            severity=severity,
                            file_path=str(req_file.relative_to(repo_path)),
                            line_number=None,
                            title=f"Vulnerable dependency: {pkg_name}=={pkg_version}",
                            description=f"{vuln_id}: {summary}",
                            remediation=f"Upgrade {pkg_name} to version {fix_version} or later.",
                            evidence=f"{pkg_name}=={pkg_version}",
                        )
                    )

        # Scan Node.js dependencies
        pkg_files = self._get_files(repo_path, filenames={"package.json"})
        for pkg_file in pkg_files:
            packages = _parse_package_json(pkg_file)
            for pkg_name, pkg_version in packages:
                vulns = _query_osv("npm", pkg_name, pkg_version)
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "No description available.")
                    severity = _get_severity_from_vuln(vuln)
                    fix_version = _get_fix_version(vuln, pkg_name)

                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DEP002",
                            severity=severity,
                            file_path=str(pkg_file.relative_to(repo_path)),
                            line_number=None,
                            title=f"Vulnerable dependency: {pkg_name}@{pkg_version}",
                            description=f"{vuln_id}: {summary}",
                            remediation=f"Upgrade {pkg_name} to version {fix_version} or later.",
                            evidence=f"{pkg_name}@{pkg_version}",
                        )
                    )

        return findings
