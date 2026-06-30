# Pentefino — Claude Code Guide

## Project

Python CLI: OSINT + recon + performance audit + visual critique scanner for websites & Instagram. Async, plugin-based platforms.

## Commands

```bash
# Run scan
python3 pentefino.py example.com
python3 pentefino.py -v example.com
python3 pentefino.py --platform instagram @user
python3 pentefino.py --list-platforms

# Lint & format (pre-commit runs these automatically)
ruff check .
ruff format --check .
ruff format .

# Pre-commit (installed: hooks run on git commit)
pre-commit run --all-files
```

## Code Conventions

- **Python** 3.11+, async-first (`asyncio`)
- **ruff** linting: `E`, `F`, `W`, `I` rule sets, 120 char line length
- **ruff-format** for auto-formatting
- **Imports**: stdlib → third-party → local, grouped
- **Naming**: `snake_case` for functions/vars, `UPPER` for constants, `PascalCase` for classes (rare here)
- **Strings**: double quotes (ruff default)
- **Type hints**: always use (`str | None`, not `Optional[str]`)
- **No `lambda` assignment** — use `def`; no ambiguous `l` as variable name

## Architecture

```
pentefino.py              ← entry point (argparse + asyncio dispatch)
pentefino/
  __init__.py
  ai.py                   ← Gemini Vision wrapper
  formatter.py            ← terminal output + JSON dump helpers
  runner.py               ← subprocess wrappers (run, sh, curl)
  platforms/
    __init__.py           ← auto-registry (pkgutil discovery of PLATFORM dicts)
    site_generico.py      ← OSINT + DNS + Lighthouse + visual critique
    instagram.py          ← Playwright screenshot + Gemini analysis
```

### Adding a Platform

Create `pentefino/platforms/<name>.py` with a `PLATFORM` dict:
```python
PLATFORM = {
    "name": "my_platform",
    "label": "...",
    "description": "...",
    "detect": lambda target: ...,
    "scan": scan_function,
}
```
Registry auto-discovers it.

## Pre-commit

- `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-json`
- `ruff` (with `--fix`), `ruff-format`
- Runs on `git commit` — install via `pre-commit install`

## CI

GitHub Actions (`.github/workflows/ci.yml`): ruff lint + format check + smoke test on Python 3.11/3.12.

## Environment

- `GEMINI_API_KEY` — required for visual/Instagram AI analysis
- `GEMINI_MODEL` — optional (default: `gemini-3.1-flash-lite`)
- External tools: `playwright`, `lighthouse`, `impeccable`, `assetfinder`, `whatweb`

## Testing

No test framework yet. Smoke test: `python3 pentefino.py example.com` should complete with `CONCLUÍDO` and produce a `report_*/` dir.
