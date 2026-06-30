#!/usr/bin/env python3
"""pentefino — async OSINT + recon + perf + visual critique scanner.

Usage: pentefino.py [-v] <domain> [domain2 ...]
   -v, --visual-critique  enable visual design critique (Gemini Vision)
"""
import asyncio, json, os, re, sys, subprocess, tempfile, shutil, argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Optional

R,G,Y,B,N,BO='\033[0;31m','\033[0;32m','\033[0;33m','\033[0;34m','\033[0m','\033[1m'

# ── subprocess helpers ─────────────────────────────────────────────

async def run(*args: str, timeout: int = 30) -> str:
    """Run executable, return stdout (empty on error)."""
    try:
        p = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        o,_ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return o.decode(errors='replace').strip()
    except: return ''

async def sh(cmd: str, timeout: int = 30) -> str:
    """Shell command -> stdout."""
    try:
        p = await asyncio.create_subprocess_shell(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o,_ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return o.decode(errors='replace').strip()
    except: return ''

async def curl(url: str, timeout: int = 15) -> str:
    return await run('curl', '-sL', '--max-time', str(timeout), url, timeout=timeout+5)

async def curl_head(url: str) -> str:
    return await run('curl', '-sI', '--max-time', '10', url, timeout=12)

# ── scan modules ──────────────────────────────────────────────────

async def scan_registration(domain: str) -> dict:
    # RDAP/WHOIS only works on registered domains, not subdomains like www
    reg_domain = re.sub(r'^www\d?\.', '', domain)
    tld = reg_domain.split('.')[-1]
    if tld in ('com','net'):
        rdap_url = f'https://rdap.verisign.com/{tld}/v1/domain/{reg_domain}'
    elif tld == 'org':
        rdap_url = 'https://rdap.publicinterestregistry.org/rdap/domain/' + reg_domain
    else:
        rdap_url = 'https://rdap.org/domain/' + reg_domain

    rdap_raw = await curl(rdap_url)
    rdap = json.loads(rdap_raw) if rdap_raw else {}
    events = {e.get('eventAction',''): e.get('eventDate','') for e in rdap.get('events', [])}

    # extract fields from vcardArray for a given role
    def _vc(role):
        for ent in rdap.get('entities', []):
            if role in ent.get('roles', []):
                va = ent.get('vcardArray', [])
                if len(va) < 2 or not va[1]: continue
                for row in va[1]:
                    if isinstance(row, list) and len(row) > 3 and row[0] == 'fn':
                        return row[3]
        return ''

    rdap_registrar = _vc('registrar')
    rdap_name = _vc('registrant')
    rdap_org = ''
    rdap_email = ''
    rdap_country = ''

    # fallback: scan all vcard properties in all entities
    if not any([rdap_registrar, rdap_name]):
        for ent in rdap.get('entities', []):
            va = ent.get('vcardArray', [])
            if len(va) < 2 or not va[1]: continue
            for row in va[1]:
                if not isinstance(row, list) or len(row) < 4: continue
                key, val = row[0], row[3]
                if key == 'fn' and not rdap_registrar and not rdap_name:
                    rdap_registrar = rdap_name = val
                elif key == 'org' and not rdap_org:
                    rdap_org = val
                elif key == 'email' and not rdap_email:
                    rdap_email = val

    whois_raw = await sh('timeout 15 whois ' + reg_domain, 20)
    def wg(patterns: list) -> str:
        for p in patterns:
            m = re.search(rf'{p}:\s*(.*)', whois_raw, re.I | re.M)
            if m:
                v = m.group(1).strip().strip('"')
                if v and v not in ('REDACTED FOR PRIVACY', 'PRIVACY', 'Whois Privacy'):
                    return v
        return ''

    return dict(
        registrar=rdap_registrar or wg(['Registrar', 'Sponsoring Registrar', 'Registrar Name']),
        registrant_name=rdap_name or wg(['Registrant Name', 'Registrant:', 'Registrant']),
        registrant_org=rdap_org or wg(['Registrant Organization', 'Organization:', 'Org:', 'Registrant Organiz']),
        registrant_email=rdap_email or wg(['Registrant Email', 'Registrant E-mail', 'Email:', 'E-mail:', 'Registrant E-mail:']),
        registrant_country=wg(['Registrant Country', 'Country:', 'Country Code:', 'Registrant Country Code']),
        creation=events.get('registration', '') or wg(['Creation Date', 'Created Date', 'Created On']),
        expiration=events.get('expiration', '') or wg(['Registry Expiry Date', 'Expiration Date', 'Expires On', 'Expiry Date']),
    )

async def scan_dns(domain: str) -> dict:
    a_raw = await run('dig','+short','A',domain, timeout=10)
    a4 = await run('dig','+short','AAAA',domain, timeout=10)
    mx = await run('dig','+short','MX',domain, timeout=10)
    ns = await run('dig','+short','NS',domain, timeout=10)
    tx = await run('dig','+short','TXT',domain, timeout=10)
    dm = await run('dig','+short','TXT',f'_dmarc.{domain}', timeout=10)
    soa = await run('dig','+short','SOA',domain, timeout=10)
    cname_raw = await run('dig','+short','CNAME',domain, timeout=10)

    # A record may include CNAME target as first line
    a_lines = [l for l in a_raw.split('\n') if l] if a_raw else []
    cname = cname_raw.strip() if cname_raw else ''
    a_list = [l for l in a_lines if l and not l.endswith('.')] if not cname else a_lines
    if cname and not a_list:
        a_list = [l for l in a_lines if l != cname]
    if not cname and a_lines and any(l.endswith('.') for l in a_lines):
        cname = a_lines[0]
        a_list = a_lines[1:]

    mx_l = [l for l in mx.split('\n') if l] if mx else []
    ns_l = [l for l in ns.split('\n') if l] if ns else []
    tx_l = [l.strip('"') for l in tx.split('\n') if l] if tx else []
    spf = next((t for t in tx_l if 'v=spf1' in t.lower()), '')
    soa_str = soa.strip() if soa else ''

    mx_j = ' '.join(mx_l).lower()
    prov = 'outro'
    if 'google.com' in mx_j: prov = 'Google Workspace'
    elif 'outlook' in mx_j or 'microsoft' in mx_j: prov = 'Microsoft 365'
    elif 'cloudflare' in mx_j: prov = 'Cloudflare'
    elif 'zoho' in mx_j: prov = 'Zoho'
    elif 'protonmail' in mx_j or 'proton.me' in mx_j: prov = 'ProtonMail'

    return dict(a='\n'.join(a_list) if a_list else '', aaaa=a4 or '', cname=cname if cname else '',
                mx_list=mx_l, ns_list=ns_l, txt_list=tx_l, soa=soa_str,
                spf=spf, dmarc=dm.strip('"') if dm else '', mx_provider=prov)

async def scan_subdomains(domain: str, report_dir: Path) -> dict:
    out = report_dir / f'subdomains_{domain}.txt'
    await sh(f'subfinder -d {domain} -silent -o {out}', 60)
    count = len(out.read_text().splitlines()) if out.exists() else 0
    return dict(count=count, file=str(out) if out.exists() else '')

async def scan_stack(domain: str) -> dict:
    url = f'https://{domain}'
    httpx_raw = await sh(f'httpx -u {url} -silent -sc -server -td -title -follow-redirects -json', 20)
    h = {}
    for line in httpx_raw.split('\n'):
        if line.strip():
            try: h = json.loads(line); break
            except: continue

    res = dict(status_code=str(h.get('status_code','')), title=h.get('title',''),
               webserver=h.get('webserver',''),
               cpe=[f'{p["product"]} ({p.get("vendor","")})' for p in h.get('cpe',[]) if p.get('product')],
               whatweb=await sh(f'whatweb {url} --no-errors --color=never', 20))

    hdrs = await curl_head(url)
    body = await curl(url)
    res['nextjs'] = dict(
        headers=bool(re.search(r'x-nextjs-|x-vercel', hdrs, re.I)),
        next_data='__NEXT_DATA__' in body,
        next_static=bool(re.search(r'/_next/static/[^"\']+', body)))
    return res

async def fetch_html(domain: str) -> str:
    body = await curl(f'https://{domain}')
    if not body: body = await curl(f'https://www.{domain}')
    return body

async def scan_ai(domain: str, html: str, tmpdir: Path) -> dict:
    if not html:
        return dict(html_size=0, js_count=0, js_downloaded=0, total_patterns=0)
    js_urls = re.findall(r'src="([^"]+\.js[^"]*)"', html)
    parsed = []
    for u in js_urls:
        if u.startswith('http'): parsed.append(u)
        elif u.startswith('/'): parsed.append(f'https://{domain}{u}')
        else: parsed.append(f'https://{domain}/{u}')

    js_dir = tmpdir / 'js'; js_dir.mkdir(parents=True, exist_ok=True)
    dl = [run('curl','-sL','--max-time','10',url,'-o',str(js_dir / f'{i}.js'), timeout=12)
          for i, url in enumerate(parsed[:20])]
    if dl: await asyncio.gather(*dl)

    js_files = [f for f in sorted(js_dir.glob('*.js')) if f.stat().st_size > 0]
    async def scan_js(p: Path) -> int:
        if p.stat().st_size > 2_097_152: return 0
        out = await sh(f'npx --yes impeccable detect --json {p}', 30)
        if not out: return 0
        try: return len(json.loads(out))
        except: return 0
    total = sum(await asyncio.gather(*[scan_js(f) for f in js_files])) if js_files else 0
    return dict(html_size=len(html), js_count=len(parsed), js_downloaded=len(js_files), total_patterns=total)

async def scan_perf(domain: str, strategy: str, tmpdir: Path) -> dict:
    out = tmpdir / f'lh_{strategy}.json'
    preset = '--preset=desktop' if strategy == 'desktop' else ''
    await sh(f'npx --yes lighthouse https://{domain} --output json --output-path {out} '
             f'--chrome-flags="--no-sandbox --headless" --quiet {preset}', 120)
    if not out.exists(): return dict(scores={}, cwv={})
    try: data = json.loads(out.read_text())
    except: return dict(scores={}, cwv={})
    def gs(c: str) -> int: return int(((data.get('categories',{}).get(c,{}) or {}).get('score',0) or 0)*100)
    def ga(a: str) -> float: return (data.get('audits',{}).get(a,{}) or {}).get('numericValue',0) or 0
    return dict(scores=dict(performance=gs('performance'), accessibility=gs('accessibility'),
                            best_practices=gs('best-practices'), seo=gs('seo')),
                cwv=dict(lcp_ms=ga('largest-contentful-paint'), cls=ga('cumulative-layout-shift'),
                         tbt_ms=ga('total-blocking-time'), fcp_ms=ga('first-contentful-paint'),
                         si_ms=ga('speed-index')))

# ── visual critique (optional) ───────────────────────────────────

async def scan_visual(domain: str, tmpdir: Path, log: Any = print) -> dict | None:
    """Full-page screenshot → Gemini Vision → structured design critique.
    Returns None if screenshot or API call fails.
    """
    from google import genai
    from google.genai import types

    # take full-page screenshot with Playwright (headless, cross-platform)
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

    # send to Gemini Vision API
    try:
        client = genai.Client(api_key='GEMINI_API_KEY_EM_ENV_VAR')
        prompt = (
            'You are a senior UI/UX design critic. Analyze this full-page website screenshot.\n'
            'Return ONLY a valid JSON object (no markdown, no code fences):\n'
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
        img_bytes = out.read_bytes()
        response = client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=[prompt, types.Part.from_bytes(data=img_bytes, mime_type='image/png')],
        )
        text = response.text.strip()
        # strip possible markdown fences
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        return json.loads(text)
    except Exception as e:
        log(f'  {Y}⚠️ Visual critique failed: {e}{N}')
        return None

async def scan_impeccable(domain: str) -> list:
    """Run impeccable design anti-pattern detector. Returns list of findings."""
    url = f'https://{domain}'
    out = await sh(f'CI=1 npx --yes impeccable detect --json {url} 2>/dev/null', 60)
    if not out: return []
    try: return json.loads(out)
    except: return []

# ── output helpers ────────────────────────────────────────────────

def _print_lh(log, label: str, data: dict):
    sc = data.get('scores',{}); cw = data.get('cwv',{})
    if not sc: return log(f'  {BO}━━━ {label} (sem dados) ━━━{N}')
    p,a,bp,seo = sc.get('performance',0),sc.get('accessibility',0),sc.get('best_practices',0),sc.get('seo',0)
    lcp,cls,tbt,fcp,si = cw.get('lcp_ms',0),cw.get('cls',0),cw.get('tbt_ms',0),cw.get('fcp_ms',0),cw.get('si_ms',0)
    def c(v): return G if v>=90 else Y if v>=50 else R
    def e(v): return '✅' if v>=90 else '⚠️' if v>=50 else '❌'
    def we(v,ok,warn): return '✅' if v<ok else '⚠️' if v<warn else '❌'
    log(f'\n  {BO}━━━ {label} ━━━{N}')
    log(f'  {BO}Scores:{N}')
    log(f'    {c(p)}{p}%{N} {e(p)} Performance')
    log(f'    {c(a)}{a}%{N} {e(a)} Acessibilidade')
    log(f'    {c(bp)}{bp}%{N} {e(bp)} Boas Práticas')
    log(f'    {c(seo)}{seo}%{N} {e(seo)} SEO')
    log(f'\n  {BO}Core Web Vitals (lab):{N}')
    log(f'    LCP {we(lcp,2500,4000)} — {lcp/1000:.1f}s (ideal < 2.5s)')
    log(f'    CLS {we(cls,0.1,0.25)} — {cls:.2f} (ideal < 0.1)')
    log(f'    TBT {we(tbt,200,600)} — {tbt:.0f}ms (ideal < 200ms)')
    log(f'    FCP — {fcp/1000:.1f}s')
    log(f'    Speed Index — {si/1000:.1f}s')

def _print_summary(r: dict, log):
    log(f'\n{BO}{B}═══════════════════════════════════════════════════{N}')
    log(f'{BO}{B}   📋 RESUMO EXECUTIVO{N}')
    log(f'{BO}{B}═══════════════════════════════════════════════════{N}')
    reg = r.get('registration',{}); dns = r.get('dns',{}); stk = r.get('stack',{})
    subs = r.get('subdomains',{}); perf = r.get('performance',{})
    issues = [0]
    def issue(icon, msg): log(f'  {icon} {msg}'); issues[0]+=1

    log(f'\n  {BO}🏢 Registro{N}')
    log(f'    Titular: {reg.get("registrant_name","N/A")} ({reg.get("registrant_org","N/A")})')
    log(f'    Registrado em: {reg.get("creation","N/A")} | Expira: {reg.get("expiration","N/A")}')
    log(f'\n  {BO}🌐 DNS / Infra{N}')
    log(f'    IP: {dns.get("a","N/A")} | MX: {dns.get("mx_provider","N/A")}')
    log(f'    Hospedagem: {stk.get("webserver","N/A")}')
    if not dns.get('dmarc'): issue(f'{R}❌{N}',f'{BO}DMARC não configurado{N} — vulnerável a spoofing')
    if dns.get('spf'): issue(f'{G}✅{N}',f'{BO}SPF configurado{N}')
    log(f'\n  {BO}🥞 Stack{N}')
    cpe = stk.get('cpe',[]); log(f'    {cpe[0] if cpe else "Framework: Não identificado"}')
    log(f'    Subdomínios: {subs.get("count",0)} encontrados')
    log(f'\n  {BO}⚡ Performance (Mobile vs Desktop){N}')
    for mode in ('mobile','desktop'):
        p = perf.get(mode,{}).get('scores',{}).get('performance',0)
        lcp = perf.get(mode,{}).get('cwv',{}).get('lcp_ms',0)
        if p and p < 90: issue(f'{Y}⚠️{N}',f'{BO}{mode.title()}: Performance {p}%{N} (LCP {lcp/1000:.1f}s)')
    vc = r.get('visual_critique')
    if vc and vc.get('design_quality'):
        dq = vc['design_quality']
        if dq < 5: issue(f'{R}🎨{N}',f'{BO}Design visual: {dq}/10{N} — revisar layout/UI')
        log(f'\n  {BO}🎨 Design Visual{N}')
        log(f'    Qualidade: {dq}/10')
        if vc.get('key_issues'):
            for iss in vc['key_issues'][:3]: log(f'    • {iss}')
    log(f'\n  {BO}🔍 Recomendações:{N}')
    if not dns.get('dmarc'): log(f'    • {R}CRÍTICO{N}: Configure DMARC')
    lcp_m = perf.get('mobile',{}).get('cwv',{}).get('lcp_ms',0)
    if lcp_m > 2500: log(f'    • {Y}LENTO{N}: LCP mobile alto ({lcp_m:.0f}ms). Otimizar imagens, JS, caching')
    log(f'    • {BO}INFO{N}: {subs.get("count",0)} subdomínios — revisar shadow IT')
    log(f'    • {BO}INFO{N}: Criar relatório contínuo: python3 pentefino.py {r.get("domain","")}')
    log(f'\n{BO}{B}═══════════════════════════════════════════════════{N}')

def _build_json(r: dict, domain: str, out_json: Path, log):
    reg = r.get('registration',{}); dns = r.get('dns',{}); subs = r.get('subdomains',{})
    stk = r.get('stack',{}); ai = r.get('ai',{}); perf = r.get('performance',{})
    _n = lambda v: v if v else None
    def _s(s): return [_n(l) for l in (s if isinstance(s,list) else s.split('\n')) if l] if s else []
    data = dict(
        scan=dict(domain=domain, timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), tool='pentefino.py'),
        registration=dict(registrar=_n(reg.get('registrar')), registrant_name=_n(reg.get('registrant_name')),
                          registrant_org=_n(reg.get('registrant_org')), registrant_email=_n(reg.get('registrant_email')),
                          registrant_country=_n(reg.get('registrant_country')),
                          creation_date=_n(reg.get('creation')), expiration_date=_n(reg.get('expiration'))),
        dns=dict(a=_s(dns.get('a','')), aaaa=_s(dns.get('aaaa','')), cname=_n(dns.get('cname','')),
                 mx=_s(dns.get('mx_list',[])), ns=_s(dns.get('ns_list',[])), txt=_s(dns.get('txt_list',[])),
                 soa=_n(dns.get('soa','')), spf=_n(dns.get('spf')), dmarc=_n(dns.get('dmarc')), mx_provider=dns.get('mx_provider')),
        subdomains=dict(count=subs.get('count',0), file=subs.get('file')),
        stack=dict(raw_cpe=stk.get('cpe',[]), webserver=stk.get('webserver',''), title=stk.get('title',''),
                   nextjs_proven=any(stk.get('nextjs',{}).values())),
        performance=dict(
            mobile=dict(lh_scores=perf.get('mobile',{}).get('scores'), cwv=perf.get('mobile',{}).get('cwv')),
            desktop=dict(lh_scores=perf.get('desktop',{}).get('scores'), cwv=perf.get('desktop',{}).get('cwv'))))
    vc = r.get('visual_critique')
    if vc:
        data['visual_critique'] = vc
    imp = r.get('impeccable')
    if imp:
        data['impeccable'] = dict(findings=imp, count=len(imp))
    out_json.write_text(json.dumps(data, indent=2))
    log(f'  {G}JSON:{N} {out_json}')

# ── main orchestrator ─────────────────────────────────────────────

async def scan(domain_raw: str, batch: bool = False, visual: bool = False) -> dict | None:
    try:
        return await _scan(domain_raw, batch, visual)
    except Exception as e:
        if not batch:
            print(f'\033[0;31m❌ {domain_raw}: {e}\033[0m')
        return None

async def _scan(domain_raw: str, batch: bool = False, visual: bool = False) -> dict:
    domain = re.sub(r'^https?://', '', domain_raw).split('/')[0]
    report_dir = Path.cwd() / f'report_{domain}'
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_json = report_dir / f'pentefino_{ts}.json'
    out_txt  = report_dir / f'pentefino_{ts}.txt'
    tmpdir = Path(tempfile.mkdtemp(prefix='scan_'))

    out_lines = []
    def log(s='', end='\n'):
        if not batch:
            print(s, end=end)
        out_lines.append(re.sub(r'\033\[[0-9;]*m', '', s))

    log(f'{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║        PENTEFINO — OSINT + RECON + PERF         ║{N}')
    log(f'{BO}║        {domain}                                  ║{N}')
    log(f'{BO}║        {datetime.now().strftime("%a %b %d %H:%M:%S %Y")}             ║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')

    # ── launch all parallel tasks ──
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
    labels = dict(registration='Registro (RDAP + WHOIS)', dns='DNS', subdomains='Subdomínios',
                  stack='Stack', html='HTML', perf_mobile='⚡ Performance (Mobile)',
                  perf_desktop='⚡ Performance (Desktop)', impeccable='🔍 Design (impeccable)')
    if visual:
        labels['visual'] = '🎨 Crítica Visual'
    for lbl in labels.values(): log(f'  ⏳ {lbl}')

    # ── [1] Registration ──
    log(f'\n{BO}{B}═══ [1] REGISTRO DO DOMÍNIO ═══{N}')
    r = await tasks['registration']
    log(f'  {BO}Registrar:{N}         {r.get("registrar") or "N/A"}')
    log(f'  {BO}Titular:{N}          {r.get("registrant_name") or "N/A"}')
    log(f'  {BO}Organização:{N}       {r.get("registrant_org") or "N/A"}')
    log(f'  {BO}País:{N}              {r.get("registrant_country") or "N/A"}')
    log(f'  {BO}E-mail contato:{N}    {r.get("registrant_email") or "N/A"}')
    log(f'  {BO}Criação:{N}           {r.get("creation") or "N/A"}')
    log(f'  {BO}Expiração:{N}          {r.get("expiration") or "N/A"}')

    # ── [2] DNS ──
    log(f'\n{BO}{B}═══ [2] DNS ═══{N}')
    d = await tasks['dns']
    log(f'  {BO}A:{N}     {d.get("a") or "N/A"}')
    log(f'  {BO}AAAA:{N}  {d.get("aaaa") or "N/A"}')
    if d.get('cname'): log(f'  {BO}CNAME:{N}{d["cname"]}')
    if d.get('soa'): log(f'  {BO}SOA:{N}  {d["soa"]}')
    log(f'  {BO}MX:{N}')
    for mx in d.get('mx_list',[]): log(f'    {mx}')
    log(f'  {BO}NS:{N}')
    for ns in d.get('ns_list',[]): log(f'    {ns}')
    log(f'  {BO}TXT:{N}')
    for tx in d.get('txt_list',[])[:10]: log(f'    {tx}')
    spf_s = f'{G}Configurado{N}' if d.get('spf') else f'{R}Não configurado{N}'
    dmarc_s = f'{G}Configurado{N}' if d.get('dmarc') else f'{R}Não configurado{N}'
    log(f'  {BO}SPF:{N}   {spf_s}')
    log(f'  {BO}DMARC:{N} {dmarc_s}')
    log(f'  {BO}Provedor MX:{N} {d.get("mx_provider")}')

    # ── [3] Subdomains ──
    log(f'\n{BO}{B}═══ [3] SUBDOMÍNIOS ═══{N}')
    s = await tasks['subdomains']
    log(f'  {BO}Encontrados:{N} {s.get("count")}')
    if s.get('file'): log(f'  {BO}Arquivo:{N} {s["file"]}')

    # ── [4] Stack ──
    log(f'\n{BO}{B}═══ [4] STACK TECNOLÓGICA ═══{N}')
    st = await tasks['stack']
    log(f'  {BO}Status:{N}   {st.get("status_code") or "N/A"}')
    log(f'  {BO}Título:{N}   {st.get("title") or "N/A"}')
    log(f'  {BO}Servidor:{N} {st.get("webserver") or "N/A"}')
    if st.get('cpe'):
        log(f'  {BO}Framework:{N}')
        for fw in st['cpe']: log(f'    ✅ {fw}')
    log(f'  {BO}whatweb:{N}')
    for line in st.get('whatweb','').split('\n'):
        if line.strip(): log(f'    {line.strip()}')
    log(f'  {BO}Evidências Next.js:{N}')
    nj = st.get('nextjs',{})
    log(f'    {"✅" if nj.get("headers") else "❌"} Headers HTTP')
    log(f'    {"✅" if nj.get("next_data") else "❌"} __NEXT_DATA__')
    log(f'    {"✅" if nj.get("next_static") else "❌"} /_next/static/')

    # ── [5] AI Detection (aguarda HTML) ──
    log(f'\n{BO}{B}═══ [5] DETECÇÃO DE IA ═══{N}')
    html = await tasks['html']
    ai = await scan_ai(domain, html, tmpdir)
    log(f'  {BO}HTML:{N} {ai.get("html_size")} bytes')
    log(f'  {BO}JS baixados:{N} {ai.get("js_downloaded")} ({ai.get("js_count")} encontrados)')
    if ai.get('total_patterns'):
        log(f'    {Y}⚠️  {ai["total_patterns"]} padrões IA encontrados{N}')
    else:
        log(f'    - Nenhum padrão detectado')

    # ── [6] Performance ──
    log(f'\n{BO}{B}═══ [6] PERFORMANCE ═══{N}')
    perf_m = await tasks['perf_mobile']
    perf_d = await tasks['perf_desktop']
    _print_lh(log, 'MOBILE', perf_m)
    _print_lh(log, 'DESKTOP', perf_d)

    # ── [7] Impeccable Design Check ──
    log(f'\n{BO}{B}═══ [7] DESIGN CHECK (impeccable) ═══{N}')
    imp = await tasks['impeccable']
    if imp and len(imp):
        warn = sum(1 for f in imp if f.get('severity') == 'warning')
        adv = sum(1 for f in imp if f.get('severity') == 'advisory')
        log(f'  {BO}Total:{N} {len(imp)} problemas ({warn} warnings, {adv} advisories)')
        # group by antipattern
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

    # ── [8] Visual Critique (opcional) ──
    vis = tasks.get('visual')
    if vis:
        vis = await vis
        log(f'\n{BO}{B}═══ [7] CRÍTICA VISUAL ═══{N}')
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

    # ── [9] Executive Summary ──
    results = dict(domain=domain, registration=r, dns=d, subdomains=s, stack=st, ai=ai,
                   performance=dict(mobile=perf_m, desktop=perf_d),
                   impeccable=imp if imp else None,
                   visual_critique=vis if vis else None)
    _print_summary(results, log)

    # ── [10] Reports ──
    log(f'\n{BO}{B}═══ [10] REPORT ═══{N}')
    _build_json(results, domain, out_json, log)
    out_txt.write_text('\n'.join(out_lines))
    log(f'  {G}TXT:{N}  {out_txt}')

    shutil.rmtree(tmpdir, ignore_errors=True)

    log(f'\n{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║  ✅ {domain} CONCLUÍDO{" "*34}║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')
    return results

async def scan_all(domains: list[str], visual: bool = False):
    """Run parallel scans for multiple domains, show aggregate summary."""
    from time import time
    t0 = time()
    log = lambda s='': print(s)
    log(f'{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║  PENTEFINO — BATCH SCAN: {len(domains)} domínios{N}')
    log(f'{BO}╚{"═"*50}╝{N}')

    results = await asyncio.gather(*[scan(d, batch=True, visual=visual) for d in domains])

    ok = sum(1 for r in results if r)
    elapsed = time() - t0
    log(f'\n{BO}╔{"═"*50}╗{N}')
    log(f'{BO}║  ✅ BATCH CONCLUÍDO: {ok}/{len(domains)} domínios em {elapsed:.0f}s     ║{N}')
    log(f'{BO}╚{"═"*50}╝{N}')
    for d, r in zip(domains, results):
        if r:
            log(f'  📁 report_{r["domain"]}/')
        else:
            log(f'  {R}❌ {d}{N}')
    return results

def main():
    parser = argparse.ArgumentParser(prog='pentefino.py',
        description='pentefino — OSINT + recon + perf + visual critique scanner')
    parser.add_argument('domains', nargs='+', help='domain(s) to scan')
    parser.add_argument('--visual-critique', '-v', action='store_true',
        help='enable visual design critique via Gemini Vision (full-page screenshot)')
    args = parser.parse_args()
    if len(args.domains) == 1:
        asyncio.run(scan(args.domains[0], visual=args.visual_critique))
    else:
        asyncio.run(scan_all(args.domains, visual=args.visual_critique))

if __name__ == '__main__':
    main()
