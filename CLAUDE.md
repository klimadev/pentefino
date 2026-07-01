# Pentefino — Claude Code Guide

## Project Identity

Python CLI tool for OSINT recon, performance auditing, and AI-powered visual critique of websites and Instagram profiles. Async-first, plugin-based platform architecture.

**Stack**: Python 3.11+ · `asyncio` · `google-genai` (Gemini) · Playwright · Lighthouse

## Commands

```bash
# ── Scanning ──────────────────────────────────────────
python3 pentefino.py example.com              # Full site scan
python3 pentefino.py -v example.com           # + visual AI critique
python3 pentefino.py --platform instagram @u  # Instagram profile
python3 pentefino.py -P "focus on UX" site    # Custom AI prompt
python3 pentefino.py site1 @user site2        # Batch (parallel)
python3 pentefino.py --list-platforms         # List registered

# ── Lint & Format (pre-commit runs these) ────────────
ruff check .
ruff format --check .
ruff format .

# ── Pre-commit ────────────────────────────────────────
pre-commit run --all-files

# ── Release ───────────────────────────────────────────
./scripts/bump.sh 0.3.0   # bump pyproject.toml + commit + tag
git push origin v0.3.0    # triggers GitHub Release workflow
```

## Code Conventions

- **Python** 3.11+, async-first (`asyncio`, `async def`, `await`)
- **ruff** rules: `E`, `F`, `W`, `I`; line length **120**
- **Imports**: stdlib → third-party → local, blank-line separated
- **Naming**: `snake_case` for functions/vars, `UPPER` for constants, `PascalCase` only for classes (rare)
- **Strings**: double quotes (ruff default)
- **Type hints**: always. Use `str | None` (not `Optional[str]`), `list[str]` (not `List[str]`)
- **No lambda assignment** — use `def`; no ambiguous `l` as variable name (use `ln`, `row`, etc.)
- **Functions**: small, single-responsibility, documented with docstrings where non-obvious

## Architecture

```
pentefino.py                  ← Entry point: argparse + asyncio dispatch
pentefino/
  __init__.py
  ai.py                       ← Gemini Vision wrapper (google-genai SDK)
  formatter.py                ← Terminal color output + JSON dump helpers
  runner.py                   ← Subprocess wrappers (async run, sh, curl)
  platforms/
    __init__.py               ← Auto-registry (pkgutil iter_modules)
    site_generico.py          ← OSINT + DNS + Lighthouse + visual critique
    instagram.py              ← Playwright screenshot + Gemini analysis
.github/workflows/
  ci.yml                      ← lint + format check + smoke test
  release.yml                 ← changelog + PyInstaller build + GitHub Release
scripts/
  bump.sh                     ← Version bump helper (pyproject.toml → tag)
cliff.toml                    ← git-cliff changelog generator config
```

### Flow

```
CLI args → platform detect → scan() → { formatter.print, json.dump }
  site:      RDAP → WHOIS → DNS → whatweb → assetfinder → Lighthouse → impeccable → AI critique
  instagram: Playwright screenshot → Gemini analysis
```

### Adding a Platform

Create `pentefino/platforms/<name>.py`:

```python
PLATFORM = {
    "name": "my_platform",
    "label": "My Platform",
    "description": "Scans ...",
    "detect": lambda target: "keyword" in target.lower(),
    "scan": scan_function,  # async (target, log, ai) → dict
}
```

The registry auto-discovers it via `pkgutil.iter_modules`. No central registration needed.

## Pre-commit

| Hook | Source | Purpose |
|------|--------|---------|
| `trailing-whitespace` | pre-commit-hooks | Trim trailing whitespace |
| `end-of-file-fixer` | pre-commit-hooks | Ensure newline at EOF |
| `check-yaml` | pre-commit-hooks | YAML validity |
| `check-json` | pre-commit-hooks | JSON validity |
| `check-added-large-files` | pre-commit-hooks | Prevent large file commits |
| `ruff` | ruff-pre-commit | Auto-fix lint issues |
| `ruff-format` | ruff-pre-commit | Auto-format |

Install: `pre-commit install`

## CI / CD

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| **CI** (`.github/workflows/ci.yml`) | Push/PR to `master` | ruff lint + format check + smoke test on Python 3.11/3.12 |
| **Release** (`.github/workflows/release.yml`) | Tag push `v*`, manual `workflow_dispatch` | git-cliff changelog → PyInstaller builds (Linux/macOS/Windows) → GitHub Release |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | For AI features | – | Google AI Studio API key |
| `GEMINI_MODEL` | No | `gemini-3.1-flash-lite` | Gemini model for visual analysis |

Without `GEMINI_API_KEY`, non-AI features still work (OSINT, DNS, Lighthouse, impeccable).

### External Tools

| Tool | Purpose | Install |
|------|---------|---------|
| `playwright` | Screenshots | `pip install playwright && playwright install chromium` |
| `lighthouse` | Performance audit | `npm install -g lighthouse` |
| `impeccable` | Design anti-pattern check | `npm install -g impeccable` |
| `assetfinder` | Subdomain enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| `whatweb` | Tech stack detection | `apt install whatweb` or `brew install whatweb` |

## Testing

No test framework yet. Smoke test:

```bash
python3 pentefino.py example.com
```

Expected: scan completes with `CONCLUÍDO` status and produces `report_example.com/` dir.

Before opening a PR, run:

```bash
ruff check .
ruff format --check .
python3 pentefino.py example.com  # quick smoke
```
