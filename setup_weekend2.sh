#!/bin/bash
# SecPipe Weekend 2 — Dependency Scanner + Dockerfile Scanner
# Run this from inside your secpipe folder:
#   cd ~/secpipe
#   source .venv/bin/activate
#   bash setup_weekend2.sh

echo "=== SecPipe Weekend 2 Setup ==="
echo "Creating dependency scanner, dockerfile scanner, and tests..."
echo ""

# --- src/secpipe/scanner/dependencies.py ---
cat > src/secpipe/scanner/dependencies.py << 'ENDFILE'
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
ENDFILE
echo "[1/6] Created src/secpipe/scanner/dependencies.py"

# --- src/secpipe/scanner/dockerfile.py ---
cat > src/secpipe/scanner/dockerfile.py << 'ENDFILE'
"""Scanner for Dockerfile security misconfigurations."""

import re
from pathlib import Path

from secpipe.models.finding import Finding, Severity
from secpipe.scanner.base import BaseScanner


class DockerfileScanner(BaseScanner):
    """Scans Dockerfiles for common security misconfigurations."""

    @property
    def name(self) -> str:
        return "dockerfile"

    def scan(self, repo_path: Path) -> list[Finding]:
        """Scan all Dockerfiles in the repo for misconfigurations.

        Args:
            repo_path: Path to the repository root.

        Returns:
            List of Finding objects for each detected misconfiguration.
        """
        findings: list[Finding] = []

        # Find all Dockerfiles (Dockerfile, Dockerfile.dev, Dockerfile.prod, etc.)
        docker_files = self._get_files(repo_path, filenames={"Dockerfile"})

        # Also find files matching Dockerfile.* pattern
        for item in repo_path.rglob("Dockerfile.*"):
            skip_dirs = {".git", "node_modules", ".venv", "__pycache__"}
            if any(d in item.parts for d in skip_dirs):
                continue
            if item.is_file() and item not in docker_files:
                docker_files.append(item)

        for dockerfile in docker_files:
            try:
                content = dockerfile.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(dockerfile.relative_to(repo_path))
            lines = content.splitlines()

            findings.extend(self._check_user_root(lines, rel_path))
            findings.extend(self._check_latest_tag(lines, rel_path))
            findings.extend(self._check_add_vs_copy(lines, rel_path))
            findings.extend(self._check_secrets_in_env(lines, rel_path))
            findings.extend(self._check_healthcheck(lines, rel_path))
            findings.extend(self._check_apt_no_pin(lines, rel_path))

        return findings

    def _check_user_root(self, lines: list[str], file_path: str) -> list[Finding]:
        """Check if container runs as root (no USER directive or USER root)."""
        findings: list[Finding] = []
        has_user_directive = False

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("USER"):
                has_user_directive = True
                user_value = stripped[4:].strip()
                if user_value.lower() in ("root", "0"):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DOC001",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            title="Container runs as root user",
                            description="USER directive is set to root. If an attacker compromises the application, they gain root access to the container.",
                            remediation="Create a non-root user and switch to it: RUN useradd -m appuser && USER appuser",
                            evidence=stripped,
                        )
                    )

        if not has_user_directive:
            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id="DOC001",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=None,
                    title="No USER directive — container runs as root",
                    description="No USER directive found. The container will run as root by default, giving attackers full control if they break in.",
                    remediation="Add a non-root user: RUN useradd -m appuser && USER appuser",
                    evidence="",
                )
            )

        return findings

    def _check_latest_tag(self, lines: list[str], file_path: str) -> list[Finding]:
        """Check for unpinned base images (using :latest or no tag)."""
        findings: list[Finding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM"):
                continue

            # Extract the image reference (ignore --platform and AS alias)
            parts = stripped.split()
            image = ""
            for i, part in enumerate(parts):
                if i == 0:
                    continue  # skip FROM
                if part.startswith("--"):
                    continue  # skip flags like --platform
                image = part
                break

            if not image:
                continue

            # Check for :latest or no tag
            if image.endswith(":latest"):
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC002",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        title="Base image uses :latest tag",
                        description="Using :latest means your build could silently pull a different (potentially compromised) image tomorrow.",
                        remediation=f"Pin to a specific version, e.g., {image.replace(':latest', ':3.12-slim')}",
                        evidence=stripped,
                    )
                )
            elif ":" not in image and image.lower() != "scratch":
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC002",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        title="Base image has no version tag",
                        description="No tag specified defaults to :latest. Your build is not reproducible and could pull a compromised image.",
                        remediation=f"Pin to a specific version, e.g., {image}:3.12-slim",
                        evidence=stripped,
                    )
                )

        return findings

    def _check_add_vs_copy(self, lines: list[str], file_path: str) -> list[Finding]:
        """Check for ADD used instead of COPY."""
        findings: list[Finding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("ADD "):
                # ADD is acceptable for tar extraction and URLs in specific cases
                # But generally COPY is safer
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC003",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        title="ADD used instead of COPY",
                        description="ADD can fetch remote URLs and auto-extract archives, which creates supply chain risks. COPY is explicit and safer.",
                        remediation="Replace ADD with COPY unless you specifically need tar extraction.",
                        evidence=stripped,
                    )
                )

        return findings

    def _check_secrets_in_env(self, lines: list[str], file_path: str) -> list[Finding]:
        """Check for secrets passed via ENV or ARG instructions."""
        findings: list[Finding] = []
        secret_patterns = re.compile(
            r"(?i)(password|passwd|secret|token|api_key|apikey|private_key|credential|auth)",
        )

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith(("ENV ", "ARG ")):
                if secret_patterns.search(stripped):
                    instruction = stripped.split()[0].upper()
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DOC004",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            title=f"Secret exposed in {instruction} instruction",
                            description=f"Sensitive value passed via {instruction}. These are visible in the image metadata and layer history.",
                            remediation="Use Docker secrets, BuildKit secret mounts (--mount=type=secret), or runtime environment variables instead.",
                            evidence=stripped[:80] + "..." if len(stripped) > 80 else stripped,
                        )
                    )

        return findings

    def _check_healthcheck(self, lines: list[str], file_path: str) -> list[Finding]:
        """Check if HEALTHCHECK instruction is missing."""
        has_healthcheck = any(
            line.strip().upper().startswith("HEALTHCHECK") for line in lines
        )

        if not has_healthcheck:
            return [
                Finding(
                    scanner=self.name,
                    rule_id="DOC005",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=None,
                    title="No HEALTHCHECK instruction",
                    description="Without HEALTHCHECK, Docker cannot detect if the application inside the container has crashed or become unresponsive.",
                    remediation="Add HEALTHCHECK, e.g.: HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1",
                    evidence="",
                )
            ]
        return []

    def _check_apt_no_pin(self, lines: list[str], file_path: str) -> list[Finding]:
        """Check for apt-get install without version pinning or --no-install-recommends."""
        findings: list[Finding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if "apt-get install" in stripped or "apt install" in stripped:
                if "--no-install-recommends" not in stripped:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DOC006",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            title="apt-get install without --no-install-recommends",
                            description="Installing packages without --no-install-recommends pulls unnecessary dependencies, increasing attack surface and image size.",
                            remediation="Add --no-install-recommends flag: apt-get install --no-install-recommends package-name",
                            evidence=stripped[:80] + "..." if len(stripped) > 80 else stripped,
                        )
                    )

        return findings
ENDFILE
echo "[2/6] Created src/secpipe/scanner/dockerfile.py"

# --- Update src/secpipe/cli.py to include new scanners ---
cat > src/secpipe/cli.py << 'ENDFILE'
"""SecPipe CLI — DevSecOps pipeline security scanner."""

import sys
from pathlib import Path

import click

from secpipe.models.finding import Finding, Severity
from secpipe.reporter.json_report import generate_json_report
from secpipe.reporter.terminal_report import print_terminal_report
from secpipe.scanner.base import BaseScanner
from secpipe.scanner.dependencies import DependencyScanner
from secpipe.scanner.dockerfile import DockerfileScanner
from secpipe.scanner.secrets import SecretsScanner


def get_all_scanners() -> list[BaseScanner]:
    """Return a list of all available scanner instances."""
    return [
        SecretsScanner(),
        DependencyScanner(),
        DockerfileScanner(),
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
echo "[3/6] Created src/secpipe/cli.py (updated with all 3 scanners)"

# --- Test fixtures ---
cat > tests/fixtures/vulnerable_requirements.txt << 'ENDFILE'
flask==2.2.0
requests==2.25.1
django==3.2.0
pyyaml==5.3.1
ENDFILE
echo "[4/6] Created tests/fixtures/vulnerable_requirements.txt"

cat > tests/fixtures/bad_dockerfile << 'ENDFILE'
FROM python:latest
RUN apt-get update && apt-get install curl
ENV API_SECRET=my_super_secret_key
ADD app.tar.gz /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 8080
CMD ["python", "app.py"]
ENDFILE
echo "[5/6] Created tests/fixtures/bad_dockerfile"

# --- tests/test_dockerfile_scanner.py ---
cat > tests/test_dockerfile_scanner.py << 'ENDFILE'
"""Tests for the Dockerfile scanner."""

from pathlib import Path

import pytest

from secpipe.models.finding import Severity
from secpipe.scanner.dockerfile import DockerfileScanner


@pytest.fixture
def scanner() -> DockerfileScanner:
    """Create a DockerfileScanner instance for testing."""
    return DockerfileScanner()


class TestDockerfileScanner:
    """Tests for DockerfileScanner."""

    def test_scanner_name(self, scanner: DockerfileScanner) -> None:
        """Scanner should identify itself as 'dockerfile'."""
        assert scanner.name == "dockerfile"

    def test_detects_no_user_directive(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag Dockerfiles with no USER directive."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nRUN pip install flask\nCMD python app.py\n")

        findings = scanner.scan(tmp_path)

        user_findings = [f for f in findings if f.rule_id == "DOC001"]
        assert len(user_findings) >= 1
        assert user_findings[0].severity == Severity.CRITICAL

    def test_detects_user_root(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag USER root."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nUSER root\nCMD python app.py\n")

        findings = scanner.scan(tmp_path)

        user_findings = [f for f in findings if f.rule_id == "DOC001"]
        assert len(user_findings) >= 1

    def test_detects_latest_tag(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag FROM image:latest."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:latest\nUSER appuser\nCMD python app.py\n")

        findings = scanner.scan(tmp_path)

        tag_findings = [f for f in findings if f.rule_id == "DOC002"]
        assert len(tag_findings) == 1
        assert tag_findings[0].severity == Severity.HIGH

    def test_detects_no_tag(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag FROM image with no tag at all."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python\nUSER appuser\nCMD python app.py\n")

        findings = scanner.scan(tmp_path)

        tag_findings = [f for f in findings if f.rule_id == "DOC002"]
        assert len(tag_findings) == 1

    def test_detects_add_instead_of_copy(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag ADD used instead of COPY."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nADD app.tar.gz /app\nUSER appuser\n")

        findings = scanner.scan(tmp_path)

        add_findings = [f for f in findings if f.rule_id == "DOC003"]
        assert len(add_findings) == 1
        assert add_findings[0].severity == Severity.MEDIUM

    def test_detects_secrets_in_env(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag secrets passed via ENV."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nENV API_SECRET=my_key\nUSER appuser\n")

        findings = scanner.scan(tmp_path)

        env_findings = [f for f in findings if f.rule_id == "DOC004"]
        assert len(env_findings) == 1
        assert env_findings[0].severity == Severity.CRITICAL

    def test_detects_secrets_in_arg(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag secrets passed via ARG."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nARG DB_PASSWORD=secret123\nUSER appuser\n")

        findings = scanner.scan(tmp_path)

        arg_findings = [f for f in findings if f.rule_id == "DOC004"]
        assert len(arg_findings) == 1

    def test_detects_missing_healthcheck(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag missing HEALTHCHECK."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nUSER appuser\nCMD python app.py\n")

        findings = scanner.scan(tmp_path)

        hc_findings = [f for f in findings if f.rule_id == "DOC005"]
        assert len(hc_findings) == 1
        assert hc_findings[0].severity == Severity.LOW

    def test_no_healthcheck_finding_when_present(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should not flag HEALTHCHECK when it exists."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nUSER appuser\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nCMD python app.py\n")

        findings = scanner.scan(tmp_path)

        hc_findings = [f for f in findings if f.rule_id == "DOC005"]
        assert len(hc_findings) == 0

    def test_detects_apt_without_no_install_recommends(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should flag apt-get install without --no-install-recommends."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nRUN apt-get update && apt-get install curl\nUSER appuser\n")

        findings = scanner.scan(tmp_path)

        apt_findings = [f for f in findings if f.rule_id == "DOC006"]
        assert len(apt_findings) == 1

    def test_no_apt_finding_with_no_install_recommends(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should not flag apt-get install with --no-install-recommends."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nRUN apt-get update && apt-get install --no-install-recommends curl\nUSER appuser\n")

        findings = scanner.scan(tmp_path)

        apt_findings = [f for f in findings if f.rule_id == "DOC006"]
        assert len(apt_findings) == 0

    def test_safe_dockerfile(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """A well-configured Dockerfile should have minimal findings."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim\n"
            "RUN apt-get update && apt-get install --no-install-recommends -y curl && rm -rf /var/lib/apt/lists/*\n"
            "RUN useradd -m appuser\n"
            "USER appuser\n"
            "COPY app.py /app/\n"
            "WORKDIR /app\n"
            "HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1\n"
            "CMD [\"python\", \"app.py\"]\n"
        )

        findings = scanner.scan(tmp_path)

        # Should only have low-severity or no findings
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0

    def test_skips_non_dockerfile(self, scanner: DockerfileScanner, tmp_path: Path) -> None:
        """Should not scan non-Dockerfile files."""
        not_docker = tmp_path / "app.py"
        not_docker.write_text("FROM python\nUSER root\n")

        findings = scanner.scan(tmp_path)
        assert len(findings) == 0
ENDFILE
echo "[6/6] Created tests/test_dockerfile_scanner.py"

echo ""
echo "=== All Weekend 2 files created! ==="
echo ""
echo "Now run these commands:"
echo "  ruff check src/ --fix"
echo "  pytest -v"
echo ""
echo "If all tests pass:"
echo "  git add ."
echo "  git commit -m 'feat: add dependency scanner and dockerfile scanner'"
echo "  git push origin main"
echo ""
