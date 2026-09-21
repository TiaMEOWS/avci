"""Subdomain takeover fingerprints — CNAME dangle detection.

~25 service fingerprints (the classic can-i-take-over-xyz set, pruned to
exploitable-in-practice). Pure stdlib DNS via socket + getaddrinfo fallback.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass

log = logging.getLogger("avci.recon.takeover")

# cname-suffix → (service, fingerprint-in-body/status, severity, sure?)
FINGERPRINTS: dict[str, tuple[str, str, str, bool]] = {
    "cloudfront.net": ("AWS CloudFront", "Bad request", "high", True),
    "azurewebsites.net": ("Azure App Service", "404 Web Site not found", "high", True),
    "azureedge.net": ("Azure CDN", "The requested content does not exist", "high", True),
    "cloudapp.net": ("Azure CloudApp", "", "medium", False),
    "blob.core.windows.net": ("Azure Blob", "The specified resource does not exist", "high", True),
    "herokuapp.com": ("Heroku", "No such app", "high", True),
    "herokudns.com": ("Heroku DNS", "", "medium", False),
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here", "high", True),
    "wordpress.com": ("WordPress.com", "Do you want to register", "high", True),
    "pantheon.io": ("Pantheon", "The gods are wise", "medium", True),
    "surge.sh": ("Surge.sh", "project not found", "high", True),
    "fastly.net": ("Fastly", "Fastly error: unknown domain", "high", True),
    "netlify.app": ("Netlify", "Not Found", "medium", True),
    "vercel.app": ("Vercel", "The deployment could not be found", "medium", True),
    "readme.io": ("ReadMe", "Project doesnt exist", "high", True),
    "shopify.com": ("Shopify", "Sorry, this shop is currently unavailable", "high", True),
    "myshopify.com": ("Shopify", "Only one step left", "high", True),
    "tumblr.com": ("Tumblr", "Whatever you were looking for doesn't exist", "high", True),
    "zendesk.com": ("Zendesk", "Help Center Closed", "high", True),
    "intercom.help": ("Intercom", "This page is reserved for artistic dogs", "high", True),
    "helpjuice.com": ("HelpJuice", "We could not find what you're looking for", "high", True),
    "cargo.site / cargocollective.com": ("Cargo", ("404 Not Found"), "medium", True),
    "ngrok.io": ("ngrok", "Tunnel not found", "medium", False),
    "awsstatic.com": ("AWS", "", "medium", False),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket", "high", True),
    "firebaseio.com": ("Firebase", "permission_denied", "medium", False),
}


@dataclass
class TakeoverHit:
    subdomain: str
    cname: str
    service: str
    severity: str
    fingerprinted: bool  # True = body fingerprint matched (sure)
    evidence: str


def _query_cname(host: str) -> str | None:
    """Cross-platform CNAME lookup: dnspython if present, else nslookup."""
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(host, "CNAME", lifetime=4)
        return str(answers[0].target).rstrip(".").lower()
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        return None
    import subprocess
    for cmd in (["nslookup", "-type=cname", host],
                ["nslookup", "-querytype=CNAME", host]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=6, creationflags=0x08000000)
            for line in (out.stdout or "").splitlines():
                if "canonical name" in line.lower() or "cname" in line.lower():
                    for tok in line.replace("=", " ").split():
                        if "." in tok and not tok.isdigit():
                            return tok.rstrip(".").lower()
        except Exception:  # noqa: BLE001
            continue
    return None


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


async def check_takeover(subdomains: list[str], fetch) -> list[TakeoverHit]:
    """`fetch(url) -> httpx.Response` async callable, scope-guarded upstream."""
    hits: list[TakeoverHit] = []
    for host in subdomains:
        if _resolves(host):
            continue  # resolving hosts are not dangling (unless CNAME→foreign)
        cname = _query_cname(host)
        if not cname:
            continue
        for suffix, (service, marker, severity, sure) in FINGERPRINTS.items():
            if not cname.endswith(suffix):
                continue
            ev = f"{host} CNAME→ {cname} (NXDOMAIN)"
            fingerprinted = False
            if marker:
                try:
                    r = await fetch(f"https://{host}")
                    if marker.lower() in (r.text or "")[:4000].lower():
                        ev += f"; body fingerprint: {marker!r}"
                        fingerprinted = True
                except Exception:  # noqa: BLE001
                    pass
            if fingerprinted or not sure:
                hits.append(TakeoverHit(host, cname, service,
                                        severity if fingerprinted else "medium",
                                        fingerprinted, ev))
            break
    for h in hits:
        log.info("takeover candidate: %s (%s) %s", h.subdomain, h.service,
                 "FINGERPRINTED" if h.fingerprinted else "unverified")
    return hits
