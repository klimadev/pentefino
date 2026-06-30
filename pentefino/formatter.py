"""Terminal output + JSON dump formatters."""

import json
from pathlib import Path
from datetime import datetime

R, G, Y, B, N, BO = '\033[0;31m', '\033[0;32m', '\033[0;33m', '\033[0;34m', '\033[0m', '\033[1m'

def print_lighthouse(log, label: str, data: dict):
    """Print Lighthouse-style score block."""
    sc = data.get('scores', {})
    cw = data.get('cwv', {})
    if not sc:
        return log(f'  {BO}━━━ {label} (sem dados) ━━━{N}')
    p, a, bp, seo = sc.get('performance', 0), sc.get('accessibility', 0), sc.get('best_practices', 0), sc.get('seo', 0)
    lcp, cls, tbt, fcp, si = cw.get('lcp_ms', 0), cw.get('cls', 0), cw.get('tbt_ms', 0), cw.get('fcp_ms', 0), cw.get('si_ms', 0)

    def c(v): return G if v >= 90 else Y if v >= 50 else R
    def e(v): return '✅' if v >= 90 else '⚠️' if v >= 50 else '❌'
    def we(v, ok, warn): return '✅' if v < ok else '⚠️' if v < warn else '❌'

    log(f'\n  {BO}━━━ {label} ━━━{N}')
    log(f'  {BO}Scores:{N}')
    log(f'    {c(p)}{p}%{N} {e(p)} Performance')
    log(f'    {c(a)}{a}%{N} {e(a)} Acessibilidade')
    log(f'    {c(bp)}{bp}%{N} {e(bp)} Boas Práticas')
    log(f'    {c(seo)}{seo}%{N} {e(seo)} SEO')
    if any(cw.values()):
        log(f'  {BO}Core Web Vitals:{N}')
        log(f'    {we(lcp, 2500, 4000)} LCP {lcp:.0f}ms' if lcp else '')
        log(f'    {we(cls, 0.1, 0.25)} CLS {cls:.2f}' if cls else '')
        log(f'    {we(tbt, 200, 600)} TBT {tbt:.0f}ms' if tbt else '')
        log(f'    {we(fcp, 1800, 3000)} FCP {fcp:.0f}ms' if fcp else '')
        log(f'    {we(si, 3400, 5800)} SI  {si:.0f}ms' if si else '')

def print_summary(r: dict, log):
    """Print domain summary block."""
    log(f'\n{BO}{"─"*36}{N}')
    log(f'{BO}📋 {r.get("domain", "?")} — RESUMO{N}')
    log(f'{BO}{"─"*36}{N}')
    for k, v in r.items():
        if k == 'domain' or v is None or v == {} or v == []:
            continue
        if isinstance(v, dict):
            log(f'  {BO}{k}:{N}')
            for sk, sv in v.items():
                log(f'    {sk}: {sv}' if not isinstance(sv, (dict, list)) else f'    {sk}: {json.dumps(sv, ensure_ascii=False)[:200]}')
        elif isinstance(v, list):
            log(f'  {BO}{k}:{N} {len(v)} itens')
        else:
            log(f'  {BO}{k}:{N} {v}')

def build_json(r: dict, domain: str, out_json: Path, log):
    """Save results to JSON file."""
    out_json.write_text(json.dumps(r, ensure_ascii=False, indent=2, default=str))
    log(f'  📄 {out_json}')

def box_header(log, title: str, width: int = 50):
    log(f'{BO}╔{"═"*width}╗{N}')
    log(f'{BO}║  {title}{" "*(width - len(title) - 2)}║{N}')
    log(f'{BO}╚{"═"*width}╝{N}')
