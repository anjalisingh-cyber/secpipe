# SecPipe

**DevSecOps pipeline security scanner** — detects hardcoded secrets, vulnerable dependencies, and Dockerfile misconfigurations in your codebase.

[![CI](https://github.com/anjalisingh-cyber/secpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/anjalisingh-cyber/secpipe/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What It Does

SecPipe scans a Git repository and reports security issues that should be fixed before code reaches production.

| Scanner | What It Detects | Status |
|---------|----------------|--------|
| **Secrets** | AWS keys, API tokens, passwords, private keys, database connection strings | ✅ |
| **Dependencies** | Known CVEs in Python and Node.js packages via OSV.dev | ✅ |
| **Dockerfile** | Running as root, unpinned base images, secrets in ENV, ADD vs COPY | ✅ |
| **IaC (Terraform)** | Coming soon | 🔜 |
| **Git History** | Coming soon | 🔜 |

---

## Installation

```bash
pip install secpipe
```

Or install from source:

```bash
git clone https://github.com/anjalisingh-cyber/secpipe.git
cd secpipe
pip install -e ".[dev]"
```

---

## Quick Start

Scan a repository:

```bash
secpipe /path/to/your/repo
```

Output as JSON:

```bash
secpipe /path/to/your/repo --format json
```

Only show HIGH and CRITICAL findings:

```bash
secpipe /path/to/your/repo --severity-threshold HIGH
```

---

## Sample Output

```
SecPipe v0.1.0 — Scan Results
===============================
Repository: /home/user/my-project
Scanners:   secrets, dependencies, dockerfile
Findings:   2 CRITICAL, 1 HIGH, 0 MEDIUM, 1 LOW

[CRITICAL] SEC001 — Hardcoded AWS Access Key
  File: src/config.py:42
  Fix:  Move AWS credentials to environment variables or use AWS IAM roles.

[CRITICAL] SEC004 — Generic Password in Source Code
  File: src/db.py:8
  Fix:  Move sensitive values to environment variables or a secrets manager.

[HIGH] DEP001 — Known vulnerability in requests==2.25.1 (CVE-2023-32681)
  File: requirements.txt:3
  Fix:  Upgrade to requests>=2.31.0

[LOW] DOC003 — No HEALTHCHECK in Dockerfile
  File: Dockerfile:1
  Fix:  Add HEALTHCHECK instruction for container monitoring.
```

---

## CI/CD Integration

Add SecPipe to your GitHub Actions workflow:

```yaml
- name: Security scan with SecPipe
  run: |
    pip install secpipe
    secpipe . --severity-threshold HIGH
```

SecPipe exits with code 1 if CRITICAL or HIGH findings are detected, which will fail your CI pipeline — preventing insecure code from reaching production.

---

## Architecture

```
CLI (click) → Scanner Registry → [Secrets Scanner]     → Findings → Terminal Report
                                  [Dependency Scanner]              → JSON Report
                                  [Dockerfile Scanner]
                                        ↓
                                  OSV.dev API (CVE data)
```

Each scanner inherits from `BaseScanner` and implements a `scan()` method that returns a list of `Finding` objects. This makes adding new scanners straightforward — implement the interface, register it, done.

---

## Development

```bash
# Clone and install
git clone https://github.com/anjalisingh-cyber/secpipe.git
cd secpipe
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v

# Run tests with coverage
pytest --cov=secpipe --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

---

## Disclaimer

This tool is intended for **authorised security testing and educational purposes only**. Only scan repositories you own or have explicit permission to test. The author is not responsible for misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.