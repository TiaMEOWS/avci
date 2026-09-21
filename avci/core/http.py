"""Shared httpx client factory — one egress point for every module.

v0.6 egress doctrine: geo-blocked targets (Kruidvat www) and WAF burst-kills
(Akamai) need IP diversity. One env var reroutes EVERY outbound client —
probes, replay, identities, recon, mail — while ScopeGuard still decides
*where* we may go (proxy changes HOW, not WHAT).

    AVCI_PROXY=http://127.0.0.1:40000      # http(s) proxy
    AVCI_PROXY=socks5://127.0.0.1:1080     # socks5 (WARP local-share etc.)

WARP note: the desktop WARP client is system-level — when it is on, AVCI
egress follows it with no config. AVCI_PROXY covers explicit local proxies
(clash/v2ray/WARP-cli proxy mode/ssh -D). `avci egress` prints the live IP.
"""

from __future__ import annotations

import os

import httpx


def egress_proxy() -> str | None:
    """Configured proxy URL, or None for direct egress."""
    for var in ("AVCI_PROXY", "AVCI_HTTP_PROXY", "AVCI_ALL_PROXY",
                "AVCI_SOCKS5_PROXY"):
        val = os.environ.get(var, "").strip()
        if val:
            if var == "AVCI_SOCKS5_PROXY" and "://" not in val:
                val = "socks5://" + val
            return val
    return None


def make_client(**kw) -> httpx.AsyncClient:
    """httpx.AsyncClient with AVCI's egress defaults baked in.

    Callers keep their own timeout/verify/redirect knobs; the proxy is
    always injected so no module can silently bypass the egress policy.
    """
    proxy = egress_proxy()
    if proxy:
        kw.setdefault("proxy", proxy)  # httpx >= 0.26; `proxies=` before
    return httpx.AsyncClient(**kw)
