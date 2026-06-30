<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/github/v/release/Klimadev/pentefino?include_prereleases&logo=github" alt="Release">
  <img src="https://img.shields.io/github/actions/workflow/status/Klimadev/pentefino/.github/workflows/ci.yml?branch=master&logo=github" alt="CI">
  <img src="https://img.shields.io/badge/OSINT-Recon-blueviolet" alt="OSINT">
</p>

<h1 align="center">🕵️ Pentefino</h1>

<p align="center">
  <strong>OSINT + Recon + Performance Audit + Visual Critique</strong><br>
  One tool to scan websites and Instagram profiles — DNS, domain registration, tech stack, Lighthouse, design review, and AI-powered visual analysis.
</p>

---

## ✨ Features

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

## 📦 Installation

```bash
# Python dependencies
pip install google-genai playwright

# Browser for screenshots
playwright install chromium

# Performance & design audit
npm install -g lighthouse impeccable

# Subdomain enumeration
go install github.com/tomnomnom/assetfinder@latest
```

```bash
# Clone & run
git clone https://github.com/Klimadev/pentefino.git
cd pentefino
python3 pentefino.py --help
```

---

## 🔧 Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes (for AI features) | – | Google AI Studio API key |
| `GEMINI_MODEL` | No | `gemini-3.1-flash-lite` | Gemini model for visual analysis |

Get an API key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey).

Without the key, non-AI features (OSINT, DNS, Lighthouse, design check) still work — only visual critique and Instagram analysis are skipped.

---

## 🚀 Usage

```bash
# Basic site scan
python3 pentefino.py example.com

# With visual critique (requires GEMINI_API_KEY)
python3 pentefino.py -v example.com

# Instagram profile analysis
python3 pentefino.py --platform instagram @username

# With custom AI prompt
python3 pentefino.py -v example.com --prompt "Focus on accessibility issues"

# Batch scan
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

---

## 🧩 Platform Auto-Detection

| Input | Detected As |
|-------|------------|
| `example.com` | Contains `.`, doesn't start with `@` → **site** |
| `@username` or `instagram.com/...` | Starts with `@` or contains `instagram.com` → **instagram** |

Adding a new platform is a single file: create `pentefino/platforms/your_platform.py` with a `PLATFORM` dict and it registers automatically.

---

## 📋 Example Output

### Site Scan

```text
╔══════════════════════════════════════════════════╗
║        PENTEFINO — OSINT + RECON + PERF         ║
║        example.com                               ║
║        Tue Jun 30 19:50:41 2026                 ║
╚══════════════════════════════════════════════════╝

═══ [1] REGISTRO DO DOMÍNIO ═══
  Registrar:    RESERVED-Internet Assigned Numbers Authority
  Criação:      1995-08-14T04:00:00Z
  Expiração:    2026-08-13T04:00:00Z

═══ [2] DNS ═══
  A:     172.66.147.243
  AAAA:  2606:4700:10::6814:179a
  NS:    hera.ns.cloudflare.com / elliott.ns.cloudflare.com
  SPF:   ✅ Configurado
  DMARC: ✅ Configurado

═══ [4] STACK TECNOLÓGICA ═══
  Título:  Example Domain
  whatweb: cloudflare, HTML5
  Next.js: ❌

═══ [5] DETECÇÃO DE IA ═══
  - Nenhum padrão detectado

═══ [6] PERFORMANCE ═══
  ━━━ MOBILE ━━━
    93% ✅ Performance    96% ✅ Acessibilidade
    96% ✅ Boas Práticas  80% ⚠️ SEO
    LCP 882ms ✅  TBT 320ms ⚠️  FCP 882ms ✅

  ━━━ DESKTOP ━━━
    100% ✅ Performance   96% ✅ Acessibilidade
    96% ✅ Boas Práticas  80% ⚠️ SEO

═══ [7] DESIGN CHECK ═══
  ⚠️ Line length too long
  ⚠️ Low contrast text (2)
```

### Instagram Profile Analysis

```text
╔══════════════════════════════════════════════════╗
║     PENTEFINO — INSTAGRAM PROFILE ANALYSIS      ║
║     @username                                    ║
║     Tue Jun 30 19:52:32 2026                    ║
╚══════════════════════════════════════════════════╝

🔍 Alvo: https://www.instagram.com/username/
📸 Capturando screenshot... ✅

🤖 Analisando com IA...
  profile_quality: 8/10 ✅
  vibe geral: Clean, professional aesthetic with consistent earth tones
  💡 Sugestões:
    • Add story highlights for product categories
    • Improve bio link strategy with a landing page
    • Increase posting frequency to 4-5x/week
```

> **Note:** AI analysis requires `GEMINI_API_KEY`. Screenshot capture works standalone.

---

## 📁 Report Output

Each scan creates a directory named `report_<target>/` containing:

| File | Format | Description |
|------|--------|-------------|
| `pentefino_<timestamp>.txt` | Plain text | Human-readable scan report |
| `pentefino_<timestamp>.json` | JSON | Structured data for automation |
| `profile.png` | PNG | Full-page screenshot (site & Instagram) |
| `subdomains.txt` | Text | Discovered subdomains (site only) |

---

## 🤝 Contributing

1. Fork the repo
2. Install dev dependencies:
   ```bash
   pip install ruff pre-commit
   pre-commit install
   ```
3. Make your changes
4. Run checks:
   ```bash
   ruff check .
   ruff format --check .
   ```
5. Open a Pull Request

### Adding a Platform

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

## 🚢 Publishing

Releases are fully automated via GitHub Actions — no local build tools required.

```bash
# Bump version, tag, and push — the workflow does the rest
./scripts/bump.sh 0.2.0
git push origin v0.2.0
```

The workflow:

1. **Changelog** — auto-generated from commits via `git-cliff`
2. **Build** — PyInstaller produces standalone binaries for Linux, macOS, and Windows
3. **Release** — GitHub Release created with changelog + binaries attached

Downloads are available on the [Releases](https://github.com/Klimadev/pentefino/releases) page.

---

## 📄 License

MIT © [Klimadev](https://github.com/Klimadev)

---

<p align="center">
  <sub>Built with ☕ and curiosity — for security researchers, developers, and the over-engineered-curious.</sub>
</p>
