#!/bin/bash
# Fix dockerfile.py line length issues
cd ~/secpipe

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
            List of Finding objects for each misconfiguration.
        """
        findings: list[Finding] = []

        docker_files = self._get_files(
            repo_path, filenames={"Dockerfile"}
        )

        for item in repo_path.rglob("Dockerfile.*"):
            skip_dirs = {
                ".git", "node_modules", ".venv", "__pycache__",
            }
            if any(d in item.parts for d in skip_dirs):
                continue
            if item.is_file() and item not in docker_files:
                docker_files.append(item)

        for dockerfile in docker_files:
            try:
                content = dockerfile.read_text(
                    encoding="utf-8", errors="ignore"
                )
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

    def _check_user_root(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        """Check if container runs as root."""
        findings: list[Finding] = []
        has_user_directive = False

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("USER"):
                has_user_directive = True
                user_value = stripped[4:].strip()
                if user_value.lower() in ("root", "0"):
                    desc = (
                        "USER is set to root. Attackers who"
                        " compromise the app gain root access."
                    )
                    fix = (
                        "Create a non-root user: "
                        "RUN useradd -m appuser && USER appuser"
                    )
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DOC001",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            title="Container runs as root user",
                            description=desc,
                            remediation=fix,
                            evidence=stripped,
                        )
                    )

        if not has_user_directive:
            desc = (
                "No USER directive found. The container runs"
                " as root by default."
            )
            fix = (
                "Add a non-root user: "
                "RUN useradd -m appuser && USER appuser"
            )
            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id="DOC001",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=None,
                    title="No USER directive — runs as root",
                    description=desc,
                    remediation=fix,
                    evidence="",
                )
            )

        return findings

    def _check_latest_tag(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        """Check for unpinned base images."""
        findings: list[Finding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM"):
                continue

            parts = stripped.split()
            image = ""
            for i, part in enumerate(parts):
                if i == 0:
                    continue
                if part.startswith("--"):
                    continue
                image = part
                break

            if not image:
                continue

            if image.endswith(":latest"):
                pinned = image.replace(":latest", ":3.12-slim")
                desc = (
                    "Using :latest means builds could pull"
                    " a different or compromised image."
                )
                fix = (
                    "Pin to a specific version, "
                    f"e.g., {pinned}"
                )
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC002",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        title="Base image uses :latest tag",
                        description=desc,
                        remediation=fix,
                        evidence=stripped,
                    )
                )
            elif ":" not in image and image.lower() != "scratch":
                desc = (
                    "No tag defaults to :latest. Build is"
                    " not reproducible."
                )
                fix = f"Pin a version, e.g., {image}:3.12-slim"
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC002",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        title="Base image has no version tag",
                        description=desc,
                        remediation=fix,
                        evidence=stripped,
                    )
                )

        return findings

    def _check_add_vs_copy(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        """Check for ADD used instead of COPY."""
        findings: list[Finding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith("ADD "):
                desc = (
                    "ADD can fetch remote URLs and extract"
                    " archives, creating supply chain risk."
                )
                fix = (
                    "Replace ADD with COPY unless you need"
                    " tar extraction."
                )
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC003",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        title="ADD used instead of COPY",
                        description=desc,
                        remediation=fix,
                        evidence=stripped,
                    )
                )

        return findings

    def _check_secrets_in_env(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        """Check for secrets in ENV or ARG instructions."""
        findings: list[Finding] = []
        secret_patterns = re.compile(
            r"(?i)(password|passwd|secret|token|"
            r"api_key|apikey|private_key|credential|auth)",
        )

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.upper().startswith(("ENV ", "ARG ")):
                if secret_patterns.search(stripped):
                    instruction = stripped.split()[0].upper()
                    desc = (
                        f"Sensitive value in {instruction}."
                        " Visible in image metadata."
                    )
                    fix = (
                        "Use Docker secrets or BuildKit"
                        " secret mounts instead."
                    )
                    ev = stripped[:80]
                    if len(stripped) > 80:
                        ev += "..."
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="DOC004",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            title=f"Secret in {instruction}",
                            description=desc,
                            remediation=fix,
                            evidence=ev,
                        )
                    )

        return findings

    def _check_healthcheck(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        """Check if HEALTHCHECK instruction is missing."""
        has_healthcheck = any(
            line.strip().upper().startswith("HEALTHCHECK")
            for line in lines
        )

        if not has_healthcheck:
            desc = (
                "No HEALTHCHECK. Docker cannot detect if"
                " the app has crashed."
            )
            fix = (
                "Add HEALTHCHECK, e.g.: HEALTHCHECK CMD"
                " curl -f http://localhost/ || exit 1"
            )
            return [
                Finding(
                    scanner=self.name,
                    rule_id="DOC005",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=None,
                    title="No HEALTHCHECK instruction",
                    description=desc,
                    remediation=fix,
                    evidence="",
                )
            ]
        return []

    def _check_apt_no_pin(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        """Check for apt-get install without --no-install-recommends."""
        findings: list[Finding] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if "apt-get install" not in stripped:
                if "apt install" not in stripped:
                    continue
            if "--no-install-recommends" not in stripped:
                desc = (
                    "Missing --no-install-recommends pulls"
                    " unnecessary deps, increasing attack"
                    " surface."
                )
                fix = (
                    "Add --no-install-recommends to"
                    " apt-get install."
                )
                ev = stripped[:80]
                if len(stripped) > 80:
                    ev += "..."
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="DOC006",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        title="apt-get without --no-install-recommends",
                        description=desc,
                        remediation=fix,
                        evidence=ev,
                    )
                )

        return findings
ENDFILE

echo "Fixed dockerfile.py"
echo "Now run: ruff check src/"
