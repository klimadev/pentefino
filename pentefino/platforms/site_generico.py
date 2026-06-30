"""Platform: site genérico — OSINT + recon + perf + visual critique.

Extracted from monolith with minimal changes.
"""

import asyncio, json, re, tempfile, shutil
from pathlib import Path
from datetime import datetime, timezone

from pentefino.runner import run, sh, curl, curl_head
from pentefino.formatter import R, G, Y, B, N, BO, print_lighthouse, build_json
from pentefino import ai as pentefino_ai

# ── scan functions ─────────────────────────────────────────────

async def scan_registration(domain: str) -> dict:
    reg_domain = re.sub(r'^www\d?\.', '', domain)
    tld = reg_domain.split('.')[-1]
    if tld in ('com', 'net'):
        rdap_url = f'https://rdap.verisign.com/{tld}/v1/domain/{reg_domain}'
    elif tld == 'org':
        rdap_url = 'https://rdap.publicinterestregistry.org/rdap/domain/' + reg_domain
    else:
        rdap_url = 'https://rdap.org/domain/' + reg_domain

    rdap_raw = await curl(rdap_url)
    rdap = json.loads(rdap_raw) if rdap_raw else {}
    events = {e.get('eventAction', ''): e.get('eventDate', '') for e in rdap.get('events', [])}

    def _vc(role):
        for ent in rdap.get('entities', []):
            if role in ent.get('roles', []):
                va = ent.get('vcardArray', [])
                if len(va) < 2 or not va[1]:
                    continue
                for row in va[1]:
                    if isinstance(row, list) and len(row) > 3 and row[0] == 'fn':
                        return str(row[3])
        return ''
    whois_raw = await sh(f'whois {reg_domain} 2>/dev/null | head -80', 15)
    w = whois_raw.split('\n')
    ws = {}
    for l in w:
        m = re.match(r'^\s*(.*?)\s*:\s*(.*)', l)
        if m:
            ws[m.group(1).strip().lower()] = m.group(2).strip()
    return dict(
        registrar=rdap.get('port43') or rdap.get('name') or ws.get('registrar', ''),
        registrant_name=_vc('registrant') or ws.get('registrant name', ''),
        registrant_org=ws.get('registrant organization', ''),
        registrant_email=ws.get('registrant email', ''),
        registrant_country=ws.get('registrant country', ''),
        creation=events.get('registration') or ws.get('creation date', ''),
        expiration=events.get('expiration') or ws.get('registry expiry date', ''),
    )

async def scan_dns(domain: str) -> dict:
    a, aaaa, mx, ns, txt, cname, soa = await asyncio.gather(
        run('dig', '+short', domain),
        run('dig', '+short', domain, 'aaaa'),
        run('dig', '+short', domain, 'mx'),
        run('dig', '+short', domain, 'ns'),
        run('dig', '+short', domain, 'txt'),
        run('dig', '+short', domain, 'cname'),
        run('dig', domain, 'soa'),
    )
    mx_provider = ''
    mx_lines = [l.strip() for l in mx.split('\n') if l.strip()]
    # strip priority, get domain
    mx_domains = [re.sub(r'^\d+\s+', '', l).rstrip('.') for l in mx_lines[:3]]
    if mx_domains:
        mx_provider = mx_domains[0]
        for kw, label in [('google', 'Google Workspace'), ('outlook', 'Microsoft 365'),
                          ('protect', 'Cloudflare'), ('mailgun', 'Mailgun'),
                          ('sendgrid', 'SendGrid'), ('zoho', 'Zoho')]:
            if kw in mx_domains[0]:
                mx_provider = label
                break
    txt_raw = await run('dig', '+short', domain, 'txt')
    dmarc_raw = await run('dig', '+short', '_dmarc.' + domain, 'txt')
    spf = any('v=spf1' in l for l in txt_raw.split('\n') if l.strip())
    dmarc = any('v=DMARC1' in l for l in dmarc_raw.split('\n') if l.strip())
    return dict(
        a=a.split('\n')[0] if a else '',
        aaaa=aaaa.split('\n')[0] if aaaa else '',
        cname=cname.split('\n')[0] if cname else '',
        soa=soa.split('\n')[0] if soa else '',
        mx_list=mx_lines, mx_provider=mx_provider,
        ns_list=[l.strip().rstrip('.') for l in ns.split('\n') if l.strip()],
        txt_list=[l.strip().strip('"') for l in txt.split('\n') if l.strip()],
        spf=spf, dmarc=dmarc,
    )

async def scan_subdomains(domain: str, report_dir: Path) -> dict:
    out = report_dir / 'subdomains.txt'
    await sh(f'assetfinder {domain} 2>/dev/null | sort -u > {out}', 30)
    count = 0
    if out.exists():
        text = out.read_text().strip()
        count = len([l for l in text.split('\n') if l.strip() and l.strip() != domain])
    return dict(count=count, file=str(out) if count else None)

async def scan_stack(domain: str) -> dict:
    url = f'https://{domain}'
    hdrs_raw = await curl_head(url)
    status_code = ''
    title = ''
    webserver = ''
    nextjs = dict(headers=False, next_data=False, next_static=False)
    cpe = []
    if hdrs_raw:
        m = re.search(r'^HTTP/\d\.\d\s+(\d+)', hdrs_raw, re.M)
        if m:
            status_code = m.group(1)
        mt = re.search(r'<title>(.*?)</title>', hdrs_raw, re.I)
        if mt:
            title = mt.group(1)
        ws = re.search(r'^Server:\s*(.*)', hdrs_raw, re.M)
        if ws:
            webserver = ws.group(1)
        ht = re.search(r'^X-Powered-By:\s*(.*)', hdrs_raw, re.M)
        if ht:
            cpe.append(ht.group(1))
        if re.search(r'^X-NextJs:\s', hdrs_raw, re.M):
            nextjs['headers'] = True
    # second pass: fetch page for next.js detection
    body = await curl(url)
    if body:
        if '__NEXT_DATA__' in body:
            nextjs['next_data'] = True
        if '/_next/static/' in body:
            nextjs['next_static'] = True
        mt = re.search(r'<title>(.*?)</title>', body, re.I)
        if mt:
            title = mt.group(1)
    whatweb = await sh(f'whatweb {url} --no-errors --color=never', 20)
    return dict(status_code=status_code, title=title, webserver=webserver,
                cpe=cpe, nextjs=nextjs, whatweb=whatweb)

async def fetch_html(domain: str) -> str:
    return await curl(f'https://{domain}')

async def scan_ai(domain: str, html: str, tmpdir: Path) -> dict:
    """Detect AI-generated patterns in downloaded JS."""
    js_patterns = [
        (r'/react-dom\.\w+\.js', 'react-dom'),
        (r'/react\.\w+\.js', 'react'),
        (r'next/static', 'next.js'),
        (r'/_buildManifest\.js', 'next.js'),
        (r'/_ssgManifest\.js', 'next.js'),
        (r'/_buildManifest\.js', 'next.js'),
        (r'/_next/static/chunks/\d+-[a-f0-9]+\.js', 'next.js'),
        (r'/assets/js/main\.\w+\.js', 'webpack inject'),
        (r'/static/js/bundle\.js', 'CRA bundle'),
        (r'create-react-app', 'CRA'),
        (r'webpackJsonp', 'webpack'),
        (r'__NUXT__', 'Nuxt'),
        (r'__VUE__', 'Vue'),
        (r'SvelteComponent', 'Svelte'),
        (r'angular\.[a-z]', 'Angular'),
        (r'parcelRequire', 'Parcel'),
    ]
    parsed = []
    for pat, label in js_patterns:
        if re.search(pat, html, re.I):
            parsed.append(label)
    # download JS files and scan for AI patterns
    js_urls = re.findall(r'<script[^>]+src=["\'](https://[^"\']+\.js[^"\']*)["\']', html)
    js_files = []
    for js_url in js_urls[:5]:
        content = await curl(js_url, timeout=10)
        if content:
            f = tmpdir / f'js_{len(js_files)}.js'
            f.write_text(content)
            js_files.append(f)

    ai_patterns = re.compile(
        r'(generated by AI|automatically generated|auto-generated|'
        r'created with assistance from|generated with|'
        r'this code was (written|generated|created) by|'
        r'OpenAI|ChatGPT|GPT-4|Claude|Anthropic|Gemini)',
        re.I,
    )
    async def scan_js(f: Path) -> int:
        text = f.read_text(errors='replace')
        return len(ai_patterns.findall(text))

    async def scan_js_len(f: Path) -> int:
        out = await sh(f'rg -ci "(generated by AI|chatgpt|claude|openai)" "{f}" 2>/dev/null || true', 10)
        if not out:
            return 0
        try:
            return len(json.loads(out))
        except Exception:
            return 0

    total = sum(await asyncio.gather(*[scan_js(f) for f in js_files])) if js_files else 0
    return dict(html_size=len(html), js_count=len(parsed),
                js_downloaded=len(js_files), total_patterns=total)

async def scan_visual(domain: str, tmpdir: Path, log=print) -> dict | None:
    """Full-page screenshot → Gemini Vision → structured design critique."""
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 1280, "height": 720})
            await page.goto(f'https://{domain}', wait_until='networkidle', timeout=30000)
            out = tmpdir / 'screenshot.png'
            await page.screenshot(path=str(out), full_page=True)
            await browser.close()
        if not out.exists() or out.stat().st_size == 0:
            return None
    except Exception as e:
        log(f'  {Y}⚠️ Screenshot failed: {e}{N}')
        return None

    prompt = (
        'You are a senior UI/UX design critic. Analyze this full-page website screenshot.\n'
        'Return ONLY a valid JSON object:\n'
        '{\n'
        '  "design_quality": <1-10 integer>,\n'
        '  "layout": "detailed layout critique — spacing, alignment, visual hierarchy, use of whitespace",\n'
        '  "colors": "color palette critique — contrast, accessibility, brand alignment, visual appeal",\n'
        '  "typography": "font choices, readability, hierarchy, line lengths, sizing",\n'
        '  "consistency": "visual consistency — reusable components, spacing rhythm, brand coherence",\n'
        '  "mobile_friendly": true/false,\n'
        '  "issues_found": <integer count>,\n'
        '  "key_issues": ["specific issue 1", "specific issue 2", ...],\n'
        '  "recommendations": ["specific actionable fix 1", "specific actionable fix 2", ...]\n'
        '}\n'
        'Be honest, critical, and specific. Reference concrete visual elements.'
    )
    try:
        img_bytes = out.read_bytes()
        result = await pentefino_ai.analyze_image(img_bytes, prompt)
        if result:
            # ensure all keys exist for downstream
            for k in ('design_quality', 'layout', 'colors', 'typography', 'consistency',
                      'mobile_friendly', 'issues_found', 'key_issues', 'recommendations'):
                result.setdefault(k, None)
        return result
    except Exception as e:
        log(f'  {Y}⚠️ Visual critique failed: {e}{N}')
        return None

async def scan_perf(domain: str, strategy: str, tmpdir: Path) -> dict:
    out = tmpdir / f'lh_{strategy}.json'
    preset = '--preset=desktop' if strategy == 'desktop' else ''
    await sh(f'npx --yes lighthouse https://{domain} --output json --output-path {out} '
             f'--chrome-flags="--no-sandbox --headless" --quiet {preset}', 120)
    if not out.exists():
        return dict(scores={}, cwv={})
    try:
        data = json.loads(out.read_text())
    except Exception:
        return dict(scores={}, cwv={})

    def gs(c: str) -> int:
        return int(((data.get('categories', {}).get(c, {}) or {}).get('score', 0) or 0) * 100)

    def ga(a: str) -> float:
        return (data.get('audits', {}).get(a, {}) or {}).get('numericValue', 0) or 0

    return dict(
        scores=dict(
            performance=gs('performance'), accessibility=gs('accessibility'),
            best_practices=gs('best-practices'), seo=gs('seo'),
        ),
        cwv=dict(
            lcp_ms=ga('largest-contentful-paint'), cls=ga('cumulative-layout-shift'),
            tbt_ms=ga('total-blocking-time'), fcp_ms=ga('first-contentful-paint'),
            si_ms=ga('speed-index'),
        ),
    )

async def scan_impeccable(domain: str) -> list:
    """Run impeccable design anti-pattern detector."""
    url = f'https://{domain}'
    out = await sh(f'CI=1 npx --yes impeccable detect --json {url} 2>/dev/null', 60)
    if not out:
        return []
    try:
        return json.loads(out)
    except Exception:
        return []

# ── orchestrator ──────────────────────────────────────────────

def _print_summary(r: dict, log):
    """Print executive summary block."""
    log(f'\n{BO}{B}═══════════════════════════════════════════════════{N}')
    log(f'{BO}{B}   📋 RESUMO EXECUTIVO{N}')
    log(f'{BO}{B}═══════════════════════════════════════════════════{N}')
    reg = r.get('registration', {}); dns = r.get('dns', {}); stk = r.get('stack', {})
    subs = r.get('subdomains', {}); perf = r.get('performance', {})
    issues = [0]
    def issue(icon, msg): log(f'  {icon} {msg}'); issues[0] += 1

    log(f'\n  {BO}🏢 Registro{N}')
    log(f'    Titular: {reg.get("registrant_name","N/A")} ({reg.get("registrant_org","N/A")})')
    log(f'    Registrado em: {reg.get("creation","N/A")} | Expira: {reg.get("expiration","N/A")}')
    log(f'\n  {BO}🌐 DNS / Infra{N}')
    log(f'    IP: {dns.get("a","N/A")} | MX: {dns.get("mx_provider","N/A")}')
    log(f'    Hospedagem: {stk.get("webserver","N/A")}')
    if not dns.get('dmarc'): issue(f'{R}❌{N}', f'{BO}DMARC não configurado{N} — vulnerável a spoofing')
    if dns.get('spf'): issue(f'{G}✅{N}', f'{BO}SPF configurado{N}')
    log(f'\n  {BO}🥞 Stack{N}')
    cpe = stk.get('cpe', []); log(f'    {cpe[0] if cpe else "Framework: Não identificado"}')
    log(f'    Subdomínios: {subs.get("count",0)} encontrados')
    log(f'\n  {BO}⚡ Performance (Mobile vs Desktop){N}')
    for mode in ('mobile', 'desktop'):
        p = perf.get(mode, {}).get('scores', {}).get('performance', 0)
        lcp = perf.get(mode, {}).get('cwv', {}).get('lcp_ms', 0)
        if p and p < 90: issue(f'{Y}⚠️{N}', f'{BO}{mode.title()}: Performance {p}%{N} (LCP {lcp/1000:.1f}s)')
    vc = r.get('visual_critique')
    if vc and vc.get('design_quality'):
        dq = vc['design_quality']
        if dq < 5: issue(f'{R}🎨{N}', f'{BO}Design visual: {dq}/10{N} — revisar layout/UI')
        log(f'\n  {BO}🎨 Design Visual{N}')
        log(f'    Qualidade: {dq}/10')
        if vc.get('key_issues'):
            for iss in vc['key_issues'][:3]: log(f'    • {iss}')
    log(f'\n  {BO}🔍 Recomendações:{N}')
    if not dns.get('dmarc'): log(f'    • {R}CRÍTICO{N}: Configure DMARC')
    lcp_m = perf.get('mobile', {}).get('cwv', {}).get('lcp_ms', 0)
    if lcp_m > 2500: log(f'    • {Y}LENTO{N}: LCP mobile alto ({lcp_m:.0f}ms). Otimizar imagens, JS, caching')
    log(f'    • {BO}INFO{N}: {subs.get("count",0)} subdomínios — revisar shadow IT')
    log(f'    • {BO}INFO{N}: Criar relatório contínuo: python3 pentefino.py {r.get("domain","")}')
    log(f'\n{BO}{B}═══════════════════════════════════════════════════{N}')


async def scan(target: str, prompt: str | None = None, opts: dict | None = None) -> dict:
    """Run full site scan. Returns results dict."""
    opts = opts or {}
    visual = opts.get('visual', False)
    batch = opts.get('batch', False)
    domain = re.sub(r'^https?://', '', target).split('/')[0]
    report_dir = Path.cwd() / f'report_{domain}'
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = report_dir / f'pentefino_{ts}.json'
    out_txt = report_dir / f'pentefino_{ts}.txt'
    tmpdir = Path(tempfile.mkdtemp(prefix='scan_'))

    out_lines = []
    def log(s='', end='\n'):
        if not batch:
            print(s, end=end)
        out_lines.append(re.sub(r'\033\[[0-9;]*m', '', s))

    log(f'{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║        PENTEFINO — OSINT + RECON + PERF         ║{N}')
    log(f'{BO}║        {domain}{" "*(44-len(domain))}║{N}')
    log(f'{BO}║        {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}             ║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')

    log(f'\n{BO}🚀 Lançando tarefas paralelas... (Lighthouse roda simultaneamente){N}')
    log('')
    tasks = dict(
        registration=asyncio.create_task(scan_registration(domain), name='reg'),
        dns=asyncio.create_task(scan_dns(domain), name='dns'),
        subdomains=asyncio.create_task(scan_subdomains(domain, report_dir), name='sub'),
        stack=asyncio.create_task(scan_stack(domain), name='stack'),
        html=asyncio.create_task(fetch_html(domain), name='html'),
        perf_mobile=asyncio.create_task(scan_perf(domain, 'mobile', tmpdir), name='lh-m'),
        perf_desktop=asyncio.create_task(scan_perf(domain, 'desktop', tmpdir), name='lh-d'),
        impeccable=asyncio.create_task(scan_impeccable(domain), name='impeccable'),
    )
    if visual:
        tasks['visual'] = asyncio.create_task(scan_visual(domain, tmpdir, log=log), name='vis')
    labels = dict(
        registration='Registro (RDAP + WHOIS)', dns='DNS', subdomains='Subdomínios',
        stack='Stack', html='HTML', perf_mobile='⚡ Performance (Mobile)',
        perf_desktop='⚡ Performance (Desktop)', impeccable='🔍 Design (impeccable)',
    )
    if visual:
        labels['visual'] = '🎨 Crítica Visual'
    for lbl in labels.values():
        log(f'  ⏳ {lbl}')

    # [1] Registration
    log(f'\n{BO}{B}═══ [1] REGISTRO DO DOMÍNIO ═══{N}')
    r = await tasks['registration']
    log(f'  {BO}Registrar:{N}         {r.get("registrar") or "N/A"}')
    log(f'  {BO}Titular:{N}          {r.get("registrant_name") or "N/A"}')
    log(f'  {BO}Organização:{N}       {r.get("registrant_org") or "N/A"}')
    log(f'  {BO}País:{N}              {r.get("registrant_country") or "N/A"}')
    log(f'  {BO}E-mail contato:{N}    {r.get("registrant_email") or "N/A"}')
    log(f'  {BO}Criação:{N}           {r.get("creation") or "N/A"}')
    log(f'  {BO}Expiração:{N}          {r.get("expiration") or "N/A"}')

    # [2] DNS
    log(f'\n{BO}{B}═══ [2] DNS ═══{N}')
    d = await tasks['dns']
    log(f'  {BO}A:{N}     {d.get("a") or "N/A"}')
    log(f'  {BO}AAAA:{N}  {d.get("aaaa") or "N/A"}')
    if d.get('cname'): log(f'  {BO}CNAME:{N}{d["cname"]}')
    if d.get('soa'): log(f'  {BO}SOA:{N}  {d["soa"]}')
    log(f'  {BO}MX:{N}')
    for mx in d.get('mx_list', []): log(f'    {mx}')
    log(f'  {BO}NS:{N}')
    for ns in d.get('ns_list', []): log(f'    {ns}')
    log(f'  {BO}TXT:{N}')
    for tx in d.get('txt_list', [])[:10]: log(f'    {tx}')
    spf_s = f'{G}Configurado{N}' if d.get('spf') else f'{R}Não configurado{N}'
    dmarc_s = f'{G}Configurado{N}' if d.get('dmarc') else f'{R}Não configurado{N}'
    log(f'  {BO}SPF:{N}   {spf_s}')
    log(f'  {BO}DMARC:{N} {dmarc_s}')
    log(f'  {BO}Provedor MX:{N} {d.get("mx_provider")}')

    # [3] Subdomains
    log(f'\n{BO}{B}═══ [3] SUBDOMÍNIOS ═══{N}')
    s = await tasks['subdomains']
    log(f'  {BO}Encontrados:{N} {s.get("count")}')
    if s.get('file'): log(f'  {BO}Arquivo:{N} {s["file"]}')

    # [4] Stack
    log(f'\n{BO}{B}═══ [4] STACK TECNOLÓGICA ═══{N}')
    st = await tasks['stack']
    log(f'  {BO}Status:{N}   {st.get("status_code") or "N/A"}')
    log(f'  {BO}Título:{N}   {st.get("title") or "N/A"}')
    log(f'  {BO}Servidor:{N} {st.get("webserver") or "N/A"}')
    if st.get('cpe'):
        log(f'  {BO}Framework:{N}')
        for fw in st['cpe']: log(f'    ✅ {fw}')
    log(f'  {BO}whatweb:{N}')
    for line in st.get('whatweb', '').split('\n'):
        if line.strip(): log(f'    {line.strip()}')
    log(f'  {BO}Evidências Next.js:{N}')
    nj = st.get('nextjs', {})
    log(f'    {"✅" if nj.get("headers") else "❌"} Headers HTTP')
    log(f'    {"✅" if nj.get("next_data") else "❌"} __NEXT_DATA__')
    log(f'    {"✅" if nj.get("next_static") else "❌"} /_next/static/')

    # [5] AI Detection
    log(f'\n{BO}{B}═══ [5] DETECÇÃO DE IA ═══{N}')
    html = await tasks['html']
    ai = await scan_ai(domain, html, tmpdir)
    log(f'  {BO}HTML:{N} {ai.get("html_size")} bytes')
    log(f'  {BO}JS baixados:{N} {ai.get("js_downloaded")} ({ai.get("js_count")} encontrados)')
    if ai.get('total_patterns'):
        log(f'    {Y}⚠️  {ai["total_patterns"]} padrões IA encontrados{N}')
    else:
        log(f'    - Nenhum padrão detectado')

    # [6] Performance
    log(f'\n{BO}{B}═══ [6] PERFORMANCE ═══{N}')
    perf_m = await tasks['perf_mobile']
    perf_d = await tasks['perf_desktop']
    print_lighthouse(log, 'MOBILE', perf_m)
    print_lighthouse(log, 'DESKTOP', perf_d)

    # [7] Impeccable
    log(f'\n{BO}{B}═══ [7] DESIGN CHECK (impeccable) ═══{N}')
    imp = await tasks['impeccable']
    if imp and len(imp):
        warn = sum(1 for f in imp if f.get('severity') == 'warning')
        adv = sum(1 for f in imp if f.get('severity') == 'advisory')
        log(f'  {BO}Total:{N} {len(imp)} problemas ({warn} warnings, {adv} advisories)')
        by_ap: dict[str, list] = {}
        for f in imp:
            ap = f.get('antipattern') or '?'
            by_ap.setdefault(ap, []).append(f)
        for ap, items in sorted(by_ap.items()):
            name = items[0].get('name', ap)
            sv = items[0].get('severity', 'info')
            ico = '⚠️' if sv == 'warning' else 'ℹ️'
            log(f'  {ico} {name} ({len(items)})')
            if items[0].get('snippet'):
                log(f'      Ex: {items[0]["snippet"]}')
    else:
        log(f'  {G}✅ Nenhum problema de design detectado{N}')

    # [8] Visual Critique
    vis = tasks.get('visual')
    if vis:
        vis = await vis
        log(f'\n{BO}{B}═══ [8] CRÍTICA VISUAL ═══{N}')
        if vis and vis.get('design_quality'):
            dq = vis['design_quality']
            log(f'  {BO}Qualidade de Design:{N} {dq}/10 {"✅" if dq >= 7 else "⚠️" if dq >= 4 else "❌"}')
            if vis.get('layout'): log(f'  {BO}Layout:{N} {vis["layout"]}')
            if vis.get('colors'): log(f'  {BO}Cores:{N} {vis["colors"]}')
            if vis.get('typography'): log(f'  {BO}Tipografia:{N} {vis["typography"]}')
            if vis.get('consistency'): log(f'  {BO}Consistência:{N} {vis["consistency"]}')
            log(f'  {BO}Mobile-friendly:{N} {"✅ Sim" if vis.get("mobile_friendly") else "❌ Não"}')
            if vis.get('key_issues'):
                log(f'  {BO}Problemas:{N}')
                for issue in vis['key_issues']: log(f'    • {issue}')
            if vis.get('recommendations'):
                log(f'  {BO}Recomendações:{N}')
                for rec in vis['recommendations']: log(f'    • {rec}')
        else:
            log(f'  {Y}⚠️ Crítica visual indisponível (falha na captura ou API){N}')

    # [9] Results
    results = dict(
        domain=domain, registration=r, dns=d, subdomains=s, stack=st, ai=ai,
        performance=dict(mobile=perf_m, desktop=perf_d),
        impeccable=imp if imp else None,
        visual_critique=vis if vis else None,
    )
    _print_summary(results, log)

    # [10] Reports
    log(f'\n{BO}{B}═══ [10] REPORT ═══{N}')
    _build_json_custom(results, domain, out_json, log)
    out_txt.write_text('\n'.join(out_lines))
    log(f'  {G}TXT:{N}  {out_txt}')

    shutil.rmtree(tmpdir, ignore_errors=True)

    log(f'\n{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║  ✅ {domain} CONCLUÍDO{" "*34}║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')
    return results


def _build_json_custom(r: dict, domain: str, out_json: Path, log):
    """Build and save JSON report (standalone version for site platform)."""
    reg = r.get('registration', {}); dns = r.get('dns', {}); subs = r.get('subdomains', {})
    stk = r.get('stack', {}); ai = r.get('ai', {}); perf = r.get('performance', {})
    _n = lambda v: v if v else None
    def _s(s): return [_n(l) for l in (s if isinstance(s, list) else s.split('\n')) if l] if s else []
    data = dict(
        scan=dict(domain=domain, timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), tool='pentefino.py'),
        registration=dict(registrar=_n(reg.get('registrar')), registrant_name=_n(reg.get('registrant_name')),
                          registrant_org=_n(reg.get('registrant_org')), registrant_email=_n(reg.get('registrant_email')),
                          registrant_country=_n(reg.get('registrant_country')),
                          creation_date=_n(reg.get('creation')), expiration_date=_n(reg.get('expiration'))),
        dns=dict(a=_s(dns.get('a', '')), aaaa=_s(dns.get('aaaa', '')), cname=_n(dns.get('cname', '')),
                 mx=_s(dns.get('mx_list', [])), ns=_s(dns.get('ns_list', [])), txt=_s(dns.get('txt_list', [])),
                 soa=_n(dns.get('soa', '')), spf=_n(dns.get('spf')), dmarc=_n(dns.get('dmarc')),
                 mx_provider=dns.get('mx_provider')),
        subdomains=dict(count=subs.get('count', 0), file=subs.get('file')),
        stack=dict(raw_cpe=stk.get('cpe', []), webserver=stk.get('webserver', ''), title=stk.get('title', ''),
                   nextjs_proven=any(stk.get('nextjs', {}).values())),
        performance=dict(
            mobile=dict(lh_scores=perf.get('mobile', {}).get('scores'), cwv=perf.get('mobile', {}).get('cwv')),
            desktop=dict(lh_scores=perf.get('desktop', {}).get('scores'), cwv=perf.get('desktop', {}).get('cwv'))),
    )
    vc = r.get('visual_critique')
    if vc:
        data['visual_critique'] = vc
    imp = r.get('impeccable')
    if imp:
        data['impeccable'] = dict(findings=imp, count=len(imp))
    out_json.write_text(json.dumps(data, indent=2))
    log(f'  {G}JSON:{N} {out_json}')

PLATFORM = {
    "name": "site",
    "label": "Site Genérico",
    "description": "OSINT + DNS + performance + visual critique",
    "detect": lambda t: not t.startswith('@') and '.' in t,
    "scan": scan,
}
