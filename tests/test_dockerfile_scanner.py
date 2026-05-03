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
