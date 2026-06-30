# Pentefino

Ferramenta CLI de OSINT, auditoria de performance e crítica visual de sites e perfis de Instagram com IA.

## Funcionalidades

- **Registro de domínio** — RDAP + WHOIS (registrar, datas, contato)
- **DNS** — A, AAAA, CNAME, MX (com detecção de provedor), NS, SOA, TXT, SPF, DMARC
- **Subdomínios** — enumeração via `assetfinder`
- **Tech stack** — headers HTTP, Next.js detection, `whatweb`
- **Detecção de IA** — varre JS em busca de marcações de geração por IA
- **Performance** — Google Lighthouse (mobile + desktop), Core Web Vitals
- **Design anti-patterns** — `impeccable` (npm)
- **Crítica visual** — screenshot full-page + análise Gemini Vision (layout, cores, tipografia)
- **Instagram** — análise de perfil público com IA (estratégia de conteúdo, identidade visual)
- **Batch scan** — múltiplos targets em paralelo

## Instalação

```bash
pip install google-genai playwright
playwright install chromium
npm install -g lighthouse impeccable

# assetfinder (subdomain enum)
go install github.com/tomnomnom/assetfinder@latest
```

## Uso

```bash
python3 pentefino.py <target> [target2 ...]
python3 pentefino.py -v <target>              # com crítica visual
python3 pentefino.py --platform instagram @perfil
python3 pentefino.py --list-platforms
```

## Configuração

- `GEMINI_API_KEY` — obrigatório (Google AI Studio)
- `GEMINI_MODEL` — opcional (default: `gemini-3.1-flash-lite`)

## Plataformas

| Alvo | Detecta | Módulo |
|------|---------|--------|
| `exemplo.com` | contém `.` e não começa com `@` | `site_generico` |
| `@usuario` ou `instagram.com/...` | começa com `@` ou contém `instagram.com` | `instagram` |

Basta criar um módulo em `pentefino/platforms/` com um `PLATFORM` dict — o registro é automático.

## Licença

MIT
