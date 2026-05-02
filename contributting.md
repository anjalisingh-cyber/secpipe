# Contributing to SecPipe

Thank you for your interest in contributing to SecPipe.

## Development Setup

1. Fork and clone the repository
2. Create a virtual environment: `python -m venv .venv`
3. Activate it: `source .venv/bin/activate`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Create a branch: `git checkout -b feature/your-feature-name`

## Code Standards

- All code must pass `ruff check`
- All code must pass `mypy` strict mode
- All new features must have tests
- Test coverage must remain above 80%
- Use type hints on all function signatures

## Running Tests

```bash
pytest -v
pytest --cov=secpipe --cov-report=term-missing
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Describe your changes clearly in the PR description