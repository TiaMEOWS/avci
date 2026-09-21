"""Async TCP port sweep — stdlib sockets, no nmap dependency.

Top-ports default set from ReconSettings; naabu bridge when installed.
Private ranges are scope-guarded separately (allow_private).
"""

from __future__ import annotations

import asyncio
import logging

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.recon.ports")

_OPEN_MSG_MAX = 30


async def _tcp_open(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


async def sweep_host(
    host: str, ports: tuple[int, ...], guard: ScopeGuard, concurrency: int = 64
) -> list[int]:
    # resolve-scope first: sweeping requires the host to be in scope
    if not guard.host_allowed(host):
        return []
    sem = asyncio.Semaphore(concurrency)

    async def one(p: int) -> int | None:
        async with sem:
            return p if await _tcp_open(host, p) else None

    results = await asyncio.gather(*(one(p) for p in ports))
    open_ports = sorted(p for p in results if p)
    if open_ports:
        log.info("ports %s: %s", host, open_ports[:_OPEN_MSG_MAX])
    return open_ports


async def sweep_hosts(
    hosts: list[str], ports: tuple[int, ...], guard: ScopeGuard
) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for host in hosts[:60]:  # keep sweeps bounded
        found = await sweep_host(host, ports, guard)
        if found:
            out[host] = found
    return out


def naabu_bridge(host: str, ports_csv: str = "80,443,8000,8080,8443,3000,5000") -> list[int]:
    import shutil
    import subprocess
    if not shutil.which("naabu"):
        return []
    try:
        out = subprocess.run(
            ["naabu", "-host", host, "-p", ports_csv, "-silent"],
            capture_output=True, text=True, timeout=180,
        )
        found = []
        for ln in out.stdout.splitlines():
            parts = ln.strip().rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                found.append(int(parts[1]))
        return sorted(set(found))
    except Exception as exc:  # noqa: BLE001
        log.debug("naabu bridge: %s", exc)
        return []
