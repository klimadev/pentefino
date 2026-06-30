#!/usr/bin/env python3
"""pentefino — async OSINT + recon + perf + visual / Instagram critique scanner.

Usage:
  pentefino.py [-v] <target> [target2 ...]
  pentefino.py --platform <name> [--prompt "text"] <target>
  pentefino.py --platform instagram [--prompt "foco em..."] @perfil
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pentefino.formatter import BO, G, N, R
from pentefino.platforms import list_platforms, resolve


async def scan(
    target: str, visual: bool = False, prompt: str | None = None, platform_hint: str | None = None, batch: bool = False
) -> dict | None:
    """Dispatch to the right platform and run scan."""
    try:
        plat, resolved_target = resolve(target, platform_hint)
        opts = dict(visual=visual, batch=batch)
        return await plat["scan"](resolved_target, prompt=prompt, opts=opts)
    except Exception as e:
        if not batch:
            print(f"{R}❌ {target}: {e}{N}")
        return None


async def scan_all(
    targets: list[str], visual: bool = False, prompt: str | None = None, platform_hint: str | None = None
):
    """Run parallel scans for multiple targets, show aggregate summary."""
    from time import time

    t0 = time()
    print(f"{BO}╔{'═' * 50}╗{N}")
    print(f"{BO}║  PENTEFINO — BATCH: {len(targets)} targets{N}")
    print(f"{BO}╚{'═' * 50}╝{N}")

    results = await asyncio.gather(
        *[scan(t, visual=visual, prompt=prompt, platform_hint=platform_hint, batch=True) for t in targets]
    )

    ok = sum(1 for r in results if r)
    elapsed = time() - t0
    print(f"\n{BO}╔{'═' * 50}╗{N}")
    print(f"{BO}║  ✅ BATCH CONCLUÍDO: {ok}/{len(targets)} targets em {elapsed:.0f}s{N}")
    print(f"{BO}╚{'═' * 50}╝{N}")
    for t, r in zip(targets, results):
        if r:
            domain = r.get("domain") or r.get("username", t)
            print(f"  📁 report_{domain}/")
        else:
            print(f"  {R}❌ {t}{N}")
    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="pentefino.py", description="pentefino — OSINT + recon + perf + visual / Instagram critique"
    )
    parser.add_argument("targets", nargs="*", help="target(s): domain, @username, or URL")
    parser.add_argument(
        "--platform",
        "-p",
        metavar="NAME",
        default=None,
        help=f"specific platform: {', '.join(p['name'] for p in list_platforms())} (default: auto-detect)",
    )
    parser.add_argument(
        "--prompt", "-P", metavar="TEXT", default=None, help="custom AI prompt for visual/instagram analysis"
    )
    parser.add_argument(
        "--visual-critique", "-v", action="store_true", help="enable visual design critique (site platform only)"
    )
    parser.add_argument("--list-platforms", action="store_true", help="list available platforms and exit")
    args = parser.parse_args()

    if args.list_platforms:
        print(f"{BO}Platforms disponíveis:{N}")
        for p in list_platforms():
            print(f"  {G}{p['name']}{N} — {p.get('label', '')}: {p.get('description', '')}")
        return

    if not args.targets:
        parser.print_help()
        return

    if len(args.targets) == 1:
        asyncio.run(
            scan(
                args.targets[0],
                visual=args.visual_critique,
                prompt=args.prompt,
                platform_hint=args.platform,
            )
        )
    else:
        asyncio.run(
            scan_all(
                args.targets,
                visual=args.visual_critique,
                prompt=args.prompt,
                platform_hint=args.platform,
            )
        )


if __name__ == "__main__":
    main()
