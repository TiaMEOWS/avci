"""Subdomain enumeration — own sources + optional subfinder bridge.

Sources: crt.sh CT logs, Wayback CDX, small DNS wordlist bruteforce.
Each result is scope-checked before being returned (fail-closed doctrine).
"""

from __future__ import annotations

import asyncio
import logging
import socket
from urllib.parse import quote_plus

import httpx

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.recon.subdomains")

_DNS_WORDS = (
    "www", "api", "app", "dev", "staging", "stage", "test", "uat", "admin",
    "portal", "mail", "vpn", "cdn", "static", "assets", "img", "docs",
    "grafana", "jenkins", "git", "sso", "auth", "login", "id", "oauth",
    "internal", "intranet", "backup", "old", "new", "beta", "demo", "shop",
    "store", "pay", "payment", "checkout", "mobile", "m", "support", "help",
)


async def _crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=25,
        )
        if r.status_code != 200:
            return set()
        names = set()
        for row in r.json():
            for nm in str(row.get("name_value", "")).split("\n"):
                nm = nm.strip().lstrip("*.").lower()
                if nm.endswith(domain):
                    names.add(nm)
        return names
    except Exception as exc:  # noqa: BLE001
        log.debug("crt.sh failed: %s", exc)
        return set()


async def _wayback(domain: str, client: httpx.AsyncClient) -> set[str]:
    try:
        r = await client.get(
            f"http://web.archive.org/cdx/search/cdx?url={quote_plus('*.')}{domain}"
            f"&output=json&fl=original&collapse=urlkey&limit=20000",
            timeout=30,
        )
        if r.status_code != 200 or not r.text.strip().startswith("["):
            return set()
        names = set()
        for row in r.json()[1:]:
            url = row[0]
            host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0].lower()
            if host.endswith(domain):
                names.add(host)
        return names
    except Exception as exc:  # noqa: BLE001
        log.debug("wayback failed: %s", exc)
        return set()


def _dns_bruteforce(domain: str, words: tuple[str, ...]) -> set[str]:
    found: set[str] = set()

    def resolve(name: str) -> None:
        try:
            socket.getaddrinfo(name, None)
            found.add(name)
        except socket.gaierror:
            pass

    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(resolve, (f"{w}.{domain}" for w in words)))
    return found


async def enumerate_subdomains(
    domain: str, guard: ScopeGuard, client: httpx.AsyncClient, use_subfinder: bool = True
) -> list[str]:
    """Return in-scope, resolving subdomains for `domain`."""
    coros = [_crtsh(domain, client), _wayback(domain, client)]
    crt, way = await asyncio.gather(*coros)
    names = crt | way

    if use_subfinder:
        names |= _subfinder_bridge(domain)

    names |= await asyncio.to_thread(_dns_bruteforce, domain, _DNS_WORDS)

    resolving: set[str] = set()

    def _resolve(nm: str) -> None:
        try:
            socket.getaddrinfo(nm, None)
            resolving.add(nm)
        except socket.gaierror:
            pass

    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(_resolve, sorted(names)))

    scoped = sorted(n for n in resolving if guard.host_allowed(n))
    log.info("subdomains: %d raw → %d resolving → %d in-scope",
             len(names), len(resolving), len(scoped))
    return scoped


def _subfinder_bridge(domain: str) -> set[str]:
    """Use installed subfinder binary if present (passive, fast)."""
    import shutil
    import subprocess
    if not shutil.which("subfinder"):
        return set()
    try:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
            capture_output=True, text=True, timeout=60,
        )
        return {ln.strip().lower() for ln in out.stdout.splitlines() if ln.strip()}
    except Exception as exc:  # noqa: BLE001
        log.debug("subfinder bridge failed: %s", exc)
        return set()
