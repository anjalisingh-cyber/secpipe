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
