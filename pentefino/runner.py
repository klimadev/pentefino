"""Subprocess helpers — thin wrappers around asyncio subprocess."""

import asyncio
import subprocess


async def run(*args: str, timeout: int = 30) -> str:
    """Run executable, return stdout (empty on error)."""
    try:
        p = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        o, _ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return o.decode(errors="replace").strip()
    except Exception:
        return ""


async def sh(cmd: str, timeout: int = 30) -> str:
    """Run shell command, return stdout (empty on error)."""
    try:
        p = await asyncio.create_subprocess_shell(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        o, _ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return o.decode(errors="replace").strip()
    except Exception:
        return ""


async def curl(url: str, timeout: int = 15) -> str:
    """HTTP GET with curl, return body (empty on error)."""
    return await sh(f'curl -sL --max-time {timeout} "{url}"', timeout + 5)


async def curl_head(url: str) -> str:
    """HTTP HEAD with curl, return headers (empty on error)."""
    return await sh(f'curl -sI --max-time 10 "{url}"', 15)
