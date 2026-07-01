<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/github/v/release/Klimadev/pentefino?include_prereleases&logo=github" alt="Release">
  <img src="https://img.shields.io/github/actions/workflow/status/Klimadev/pentefino/.github/workflows/ci.yml?branch=master&logo=github" alt="CI">
  <img src="https://img.shields.io/github/actions/workflow/status/Klimadev/pentefino/.github/workflows/release.yml?branch=master&logo=github&label=release" alt="Release CD">
  <img src="https://img.shields.io/github/license/Klimadev/pentefino" alt="License">
  <img src="https://img.shields.io/github/repo-size/Klimadev/pentefino" alt="Size">
  <img src="https://img.shields.io/github/last-commit/Klimadev/pentefino?logo=git" alt="Last Commit">
  <img src="https://img.shields.io/badge/OSINT-Recon-blueviolet" alt="OSINT">
</p>

<h1 align="center">🕵️ Pentefino</h1>

<p align="center">
  <strong>OSINT + Recon + Performance Audit + Visual Critique</strong><br>
  One tool to scan websites and Instagram profiles — DNS, domain registration, tech stack, Lighthouse, design review, and AI-powered visual analysis.
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#usage">Usage</a> •
  <a href="#publishing">Publishing</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## Features

| Area | What it does |
|------|-------------|
| **Domain Registration** | RDAP + WHOIS lookup — registrar, dates, contacts |
| **DNS** | A, AAAA, CNAME, MX, NS, SOA, TXT, SPF, DMARC |
| **Subdomain Enumeration** | via `assetfinder` |
| **Tech Stack** | HTTP headers, `whatweb`, Next.js detection |
| **AI-Generated Content Detection** | Scans JS for LLM-generation markers |
| **Performance** | Google Lighthouse (mobile + desktop), Core Web Vitals |
| **Design Anti-patterns** | via `impeccable` (npm) |
| **Visual Critique** | Full-page screenshot + Gemini Vision analysis (layout, colors, typography) |
| **Instagram** | Public profile screenshot + AI content/visual strategy analysis |
| **Batch Scan** | Multiple targets in parallel |

---

## Quick Start

```bash
git clone https://github.com/Klimadev/pentefino.git
cd pentefino
pip install -e .
python3 pentefino.py example.com
```

That runs a full OSINT + DNS + Performance scan. Add `-v` for AI visual critique (requires `GEMINI_API_KEY`).

---

## Installation

### Python package

```bash
pip install google-genai playwright
```

### Browser for screenshots

```bash
playwright install chromium
```

### External tools (optional per feature)

| Tool | For | Install |
|------|-----|---------|
| `lighthouse` | Performance audit | `npm install -g lighthouse` |
| `impeccable` | Design anti-patterns | `npm install -g impeccable` |
| `assetfinder` | Subdomain enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| `whatweb` | Tech stack detection | `apt install whatweb` / `brew install whatweb` |

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes (for AI) | – | Google AI Studio API key |
| `GEMINI_MODEL` | No | `gemini-3.1-flash-lite` | Gemini model for visual analysis |

Get a key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

Without the key, non-AI features (OSINT, DNS, Lighthouse, design check) still work — only visual critique and Instagram analysis are skipped.

---

## Usage

```bash
# Basic site scan
python3 pentefino.py example.com

# With visual critique (requires GEMINI_API_KEY)
python3 pentefino.py -v example.com

# Instagram profile analysis
python3 pentefino.py --platform instagram @username

# With custom AI prompt
python3 pentefino.py -v example.com --prompt "Focus on accessibility issues"

# Batch scan (parallel)
python3 pentefino.py example.com mysite.org @friend

# List available platforms
python3 pentefino.py --list-platforms
```

### Options

| Flag | Description |
|------|-------------|
| `targets` | One or more targets (domain, `@user`, URL) |
| `-v`, `--visual-critique` | Enable visual/AI critique (site) |
| `-p`, `--platform` | Force platform (`site` or `instagram`) |
| `-P`, `--prompt` | Custom AI prompt |
| `--list-platforms` | List registered platforms |

### Platform Auto-Detection

| Input | Detected As |
|-------|------------|
| `example.com` (contains `.`, doesn't start with `@`) | **site** |
| `@username` or `instagram.com/...` | **instagram** |

### Report Output

Each scan creates `report_<target>/`:

| File | Format | Description |
|------|--------|-------------|
| `pentefino_<timestamp>.txt` | Plain text | Human-readable scan report |
| `pentefino_<timestamp>.json` | JSON | Structured data for automation |
| `profile.png` | PNG | Full-page screenshot |
| `subdomains.txt` | Text | Discovered subdomains (site only) |

---

## Example Output

### Site scan

```
╔══════════════════════════════════════════════════╗
║        PENTEFINO — OSINT + RECON + PERF         ║
║        example.com                               ║
╚══════════════════════════════════════════════════╝

═══ [1] REGISTRO DO DOMÍNIO ═══
  Registrar:    RESERVED-Internet Assigned Numbers Authority
  Criação:      1995-08-14T04:00:00Z

═══ [2] DNS ═══
  A:     172.66.147.243
  AAAA:  2606:4700:10::6814:179a
  NS:    hera.ns.cloudflare.com / elliott.ns.cloudflare.com

═══ [4] STACK TECNOLÓGICA ═══
  Título:  Example Domain
  whatweb: cloudflare, HTML5

═══ [6] PERFORMANCE ═══
  ━━━ MOBILE ━━━
    93% ✅ Performance    96% ✅ Acessibilidade
  ━━━ DESKTOP ━━━
    100% ✅ Performance   96% ✅ Acessibilidade

═══ [7] DESIGN CHECK ═══
  ⚠️ Low contrast text (2)
```

### Instagram profile

```
╔══════════════════════════════════════════════════╗
║     PENTEFINO — INSTAGRAM PROFILE ANALYSIS      ║
║     @username                                    ║
╚══════════════════════════════════════════════════╝

🔍 Alvo: https://www.instagram.com/username/
📸 Capturando screenshot... ✅

🤖 Analisando com IA...
  profile_quality: 8/10 ✅
  vibe geral: Clean, professional aesthetic with consistent earth tones
  💡 Sugestões:
    • Add story highlights for product categories
    • Improve bio link strategy with a landing page
```

> AI analysis requires `GEMINI_API_KEY`.

---

## Publishing

Releases are fully automated via GitHub Actions — no local build tools required.

```bash
./scripts/bump.sh 0.3.0    # bump pyproject.toml + commit + tag v0.3.0
git push origin v0.3.0     # triggers Release workflow
```

The workflow:

1. **Changelog** — auto-generated from commits (git-cliff)
2. **Build** — PyInstaller produces standalone binaries for Linux, macOS, Windows
3. **Release** — GitHub Release created with changelog + binaries

Downloads on the [Releases](https://github.com/Klimadev/pentefino/releases) page.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide:

- Setup & conventions
- Commit message format (conventional commits)
- PR checklist
- How to add a new platform

```python
# pentefino/platforms/my_platform.py
PLATFORM = {
    "name": "my_platform",
    "label": "My Platform",
    "description": "What this platform scans",
    "detect": lambda target: "mydomain" in target.lower(),
    "scan": scan_function,
}
```

That's it — the registry discovers it automatically.

---

## License

MIT © [Klimadev](https://github.com/Klimadev)

---

<p align="center">
  <sub>Built with ☕ and curiosity — for security researchers, developers, and the over-engineered-curious.</sub>
</p>
