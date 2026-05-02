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
