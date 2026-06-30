"""Platform: Instagram — screenshot + AI analysis of public profiles."""

import re, json
from pathlib import Path
from datetime import datetime, timezone

from pentefino.runner import sh
from pentefino.formatter import R, G, Y, B, N, BO
from pentefino import ai as pentefino_ai


DEFAULT_PROMPT = (
    "You are a senior social-media design critic. "
    "Analyze this Instagram profile screenshot and return a JSON with:\n"
    "  - profile_quality: 1-10 integer\n"
    "  - visual_identity: 'description of branding consistency, colors, vibe'\n"
    "  - content_strategy: 'what the content mix looks like, posting patterns'\n"
    "  - engagement_signals: 'bio link strategy, highlights, story engagement cues'\n"
    "  - improvements: ['list', 'of', 'actionable', 'tips']\n"
    "  - overall_vibe: 'one sentence summary'\n"
    "Return ONLY valid JSON, no markdown."
)


def _extract_username(target: str) -> str:
    """Extract Instagram username from @user, url, or raw text."""
    t = target.strip()
    m = re.search(r'instagram\.com/([^/?&#]+)', t)
    if m:
        return m.group(1)
    return t.lstrip('@').split('/')[0].split('?')[0]


async def scan(target: str, prompt: str | None = None, opts: dict | None = None) -> dict:
    """Screenshot Instagram profile → Gemini AI analysis."""
    opts = opts or {}
    batch = opts.get('batch', False)
    username = _extract_username(target)
    url = f'https://www.instagram.com/{username}/'
    report_dir = Path.cwd() / f'report_instagram_{username}'
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = report_dir / f'instagram_{username}_{ts}.json'
    out_txt = report_dir / f'instagram_{username}_{ts}.txt'

    out_lines = []
    def log(s='', end='\n'):
        if not batch:
            print(s, end=end)
        out_lines.append(re.sub(r'\033\[[0-9;]*m', '', s))

    log(f'{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║     PENTEFINO — INSTAGRAM PROFILE ANALYSIS     ║{N}')
    log(f'{BO}║     @{username}{" "*(44-len(username)-1)}║{N}')
    log(f'{BO}║     {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}             ║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')
    log(f'\n{BO}🔍 Alvo:{N} {url}')

    # Screenshot
    log(f'\n{BO}📸 Capturando screenshot...{N}')
    screenshot_path = report_dir / 'profile.png'
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 390, "height": 844})  # mobile-first
            await page.goto(url, wait_until='networkidle', timeout=45000)
            await page.screenshot(path=str(screenshot_path), full_page=True)
            await browser.close()
        if not screenshot_path.exists() or screenshot_path.stat().st_size == 0:
            raise RuntimeError("Screenshot empty")
        log(f'  {G}✅ Screenshot salvo:{N} {screenshot_path}')
    except Exception as e:
        log(f'  {R}❌ Screenshot falhou:{N} {e}')
        log(f'\n{R}⚠️  Instagram pode estar bloqueando o Playwright. Tente:\n'
            f'  • Rodar de um IP residencial\n'
            f'  • Usar --platform site para análise tradicional{N}')
        results = dict(platform='instagram', username=username, url=url,
                       error=f'screenshot_failed: {e}', timestamp=datetime.now(timezone.utc).isoformat())
        _save_results(results, out_json, out_txt, log)
        log(f'\n{BO}╔{"═"*50}╗{N}')
        log(f'{BO}║  ❌ @{username} FALHOU{" "*35}║{N}')
        log(f'{BO}╚{"═"*50}╝{N}')
        return results

    # AI Analysis
    log(f'\n{BO}🤖 Analisando com IA...{N}')
    active_prompt = prompt or DEFAULT_PROMPT
    try:
        img_bytes = screenshot_path.read_bytes()
        analysis = await pentefino_ai.analyze_image(img_bytes, active_prompt)
        if analysis is None:
            raise RuntimeError("AI returned None")
        log(f'  {G}✅ Análise concluída{N}')
        if analysis.get('profile_quality'):
            pq = analysis['profile_quality']
            log(f'  {BO}Qualidade do perfil:{N} {pq}/10 {"✅" if pq >= 7 else "⚠️" if pq >= 4 else "❌"}')
        if analysis.get('overall_vibe'):
            log(f'  {BO}Vibe geral:{N} {analysis["overall_vibe"]}')
        if analysis.get('improvements'):
            log(f'\n{BO}💡 Sugestões de melhoria:{N}')
            for imp in analysis['improvements']:
                log(f'  • {imp}')
    except Exception as e:
        log(f'  {Y}⚠️ Análise IA falhou: {e}{N}')
        analysis = None

    results = dict(
        platform='instagram', username=username, url=url,
        screenshot=str(screenshot_path),
        ai_analysis=analysis,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    _save_results(results, out_json, out_txt, log)

    log(f'\n{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║  ✅ @{username} CONCLUÍDO{" "*33}║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')
    return results


def _save_results(results: dict, out_json: Path, out_txt: Path, log):
    """Save JSON + TXT reports."""
    out_json.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str))
    log(f'  📄 {out_json}')
    lines = [
        f"Instagram Profile Analysis: @{results.get('username','?')}",
        f"URL: {results.get('url','')}",
        f"Timestamp: {results.get('timestamp','')}",
        f"{'─'*40}",
    ]
    ai = results.get('ai_analysis')
    if ai:
        lines.append('')
        lines.append('AI Analysis:')
        lines.append(json.dumps(ai, ensure_ascii=False, indent=2))
    out_txt.write_text('\n'.join(lines))
    log(f'  📄 {out_txt}')

PLATFORM = {
    "name": "instagram",
    "label": "Instagram",
    "description": "Análise de perfil público do Instagram com IA",
    "detect": lambda t: t.startswith('@') or 'instagram.com' in t.lower(),
    "scan": scan,
}
