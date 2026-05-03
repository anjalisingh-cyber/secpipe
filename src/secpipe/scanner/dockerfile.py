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
