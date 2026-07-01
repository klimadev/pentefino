# Contributing to Pentefino

Thanks for your interest! This doc covers everything you need to contribute effectively.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Code Conventions](#code-conventions)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Adding a Platform](#adding-a-platform)
- [Release Process](#release-process)
- [Getting Help](#getting-help)

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be respectful, constructive, and inclusive.

---

## Quick Start

```bash
# Fork + clone
git clone https://github.com/YOUR_USER/pentefino.git
cd pentefino

# Python deps
pip install -e ".[dev]"
pre-commit install

# External tools (optional — skip if not testing that feature)
npm install -g lighthouse impeccable
go install github.com/tomnomnom/assetfinder@latest

# Browser for screenshots
playwright install chromium

# Smoke test
python3 pentefino.py example.com
```

---

## Development Setup

### Prerequisites

- Python 3.11+
- `pip` (or `pipx` for isolated installs)
- `git`

### Install in editable mode

```bash
pip install -e ".[dev]"
```

This installs all runtime deps plus dev tools (`ruff`, `pre-commit`).

### Configure pre-commit hooks

```bash
pre-commit install
```

Hooks run automatically on `git commit`. To run them manually:

```bash
pre-commit run --all-files
```

### Environment variables

```bash
export GEMINI_API_KEY="your-key-here"  # required for AI features
```

Get a key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

---

## Code Conventions

### Python

- **Python 3.11+** with `async`/`await` throughout
- **ruff** linting: rules `E`, `F`, `W`, `I`; line length **120**
- **Format**: `ruff format .` (double quotes, consistent spacing)

### Style

| Convention | Standard |
|-----------|----------|
| Functions/vars | `snake_case` |
| Constants | `UPPER_CASE` |
| Classes | `PascalCase` (rare — this is a procedural CLI) |
| Type hints | Always use modern syntax: `str \| None`, `list[str]` |
| Imports | stdlib → blank → third-party → blank → local, sorted via `ruff` |
| Lambdas | Use `def` instead of `lambda: ...` assignment |
| Line length | 120 characters max |

### Async patterns

```python
async def scan(target: str, log: LogFn, ai: AiClient | None) -> dict:
    result = await some_io_call()
    return result
```

---

## Commit Messages

We use **conventional commits** for automatic changelog generation.

```
<type>: <short description>

<body> (optional)
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `chore` | Maintenance, deps, config |
| `docs` | Documentation only |
| `refactor` | Code change with no behavior change |
| `test` | Adding or fixing tests |
| `perf` | Performance improvement |
| `ci` | CI/CD workflow changes |
| `style` | Formatting, lint fixes |

### Examples

```
feat: add RDAP lookup fallback when WHOIS fails
fix: handle UnicodeDecodeError in subprocess output
docs: clarify GEMINI_API_KEY requirement in README
refactor: extract DNS resolution to separate module
ci: add macOS to release build matrix
```

---

## Pull Request Process

1. **Create an issue** first for significant changes (or pick an existing one)
2. **Fork** the repo and create a branch: `git checkout -b feat/my-thing`
3. **Make your changes** following the conventions above
4. **Run checks** locally:
   ```bash
   ruff check .
   ruff format --check .
   python3 pentefino.py example.com  # smoke test
   ```
5. **Commit** with a conventional commit message
6. **Push** and open a PR against `master`
7. **Ensure CI passes** — the CI workflow runs on every PR

### PR checklist

- [ ] Code follows conventions (ruff clean)
- [ ] Smoke test passes
- [ ] Commit messages follow conventional commits
- [ ] Documentation updated (README, CLAUDE.md if relevant)
- [ ] No new warnings introduced

---

## Adding a Platform

The plugin system auto-discovers platforms at runtime. No central registry to edit.

### Step-by-step

1. Create `pentefino/platforms/<name>.py`
2. Export a `PLATFORM` dict:

```python
"""My platform scanner."""

async def scan(target: str, log, ai=None) -> dict:
    """Run scan against target."""
    log("Scanning...")
    return {"result": "ok"}

PLATFORM = {
    "name": "my_platform",
    "label": "My Platform",
    "description": "What this platform scans",
    "detect": lambda target: "mysite" in target.lower(),
    "scan": scan,
}
```

3. Test with: `python3 pentefino.py --list-platforms` (should show your platform)

### PLATFORM dict fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `str` | Yes | Machine name (slug) |
| `label` | `str` | Yes | Human-readable name |
| `description` | `str` | Yes | One-line description |
| `detect` | `(str) → bool` | Yes | Auto-detection function |
| `scan` | `(str, log, ai?) → dict` | Yes | Async scan function |

---

## Release Process

Releases are fully automated via GitHub Actions.

```bash
# 1. Bump version, commit, and tag
./scripts/bump.sh 0.3.0

# 2. Push — triggers the Release workflow
git push origin v0.3.0
```

The workflow:
1. Generates changelog from commits (via `git-cliff`)
2. Builds standalone binaries via PyInstaller (Linux, macOS, Windows)
3. Creates a GitHub Release with changelog + binaries attached

See `.github/workflows/release.yml` for details.

---

## Getting Help

- Open an [issue](https://github.com/Klimadev/pentefino/issues) for bugs or feature requests
- Check the [README](README.md) for usage examples
- Review the [CLAUDE.md](CLAUDE.md) for Claude Code integration
