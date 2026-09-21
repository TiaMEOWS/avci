"""Live probing: HTTP fingerprints, tech detection, TLS basics.

Own implementation (httpx-based) so the agent never depends on an external
httpx-tool binary being installed. Every URL is scope-checked first.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.recon.probe")

_TECH_SIGNS: tuple[tuple[str, str], ...] = (
    ("X-Powered-By", ""),
    ("Server", ""),
)


@dataclass
class ProbeResult:
    url: str
    host: str
    scheme: str
    status: int
    title: str = ""
    server: str = ""
    powered_by: str = ""
    tech: list[str] = field(default_factory=list)
    redirect: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_sample: str = ""
    cdn: str = ""

    @property
    def alive(self) -> bool:
        return self.status > 0


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    tech: set[str] = set()
    h = {k.lower(): v for k, v in headers.items()}
    if "x-drupal-cache" in h or "drupal" in (h.get("x-generator", "") or "").lower():
        tech.add("Drupal")
    if "x-shopify" in h or "shopify" in body[:5000].lower():
        tech.add("Shopify")
    if "x-nextjs-cache" in h or "/_next/static" in body[:20000]:
        tech.add("Next.js")
    if "wp-content" in body[:20000] or "wp-json" in body[:20000]:
        tech.add("WordPress")
    if "__nuxt" in body[:20000] or "/_nuxt/" in body[:20000]:
        tech.add("Nuxt")
    if "sentry-id" in h or "sentry-trace" in h:
        tech.add("Sentry")
    for hdr in ("x-vercel-id", "x-amz-cf-id", "x-amz-request-id",
                "x-github-request-id", "cf-ray", "x-fastly-request-id"):
        if hdr in h:
            tech.add({
                "x-vercel-id": "Vercel", "x-amz-cf-id": "AWS CloudFront",
                "x-amz-request-id": "S3", "x-github-request-id": "GitHub Pages",
                "cf-ray": "Cloudflare", "x-fastly-request-id": "Fastly",
            }[hdr])
    if h.get("server", "").startswith("nginx"):
        tech.add("nginx")
    if "apache" in h.get("server", "").lower():
        tech.add("Apache")
    return sorted(tech)


def _title_of(body: str) -> str:
    try:
        start = body.lower().index("<title")
        gt = body.index(">", start)
        end = body.lower().index("</title>", gt)
        return " ".join(body[gt + 1:end].split())[:200]
    except ValueError:
        return ""


async def probe_url(
    url: str, guard: ScopeGuard, client: httpx.AsyncClient
) -> ProbeResult:
    guard.check_url(url)
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
    scheme = url.split(":", 1)[0]
    try:
        r = await client.get(url, follow_redirects=False)
    except Exception as exc:  # noqa: BLE001
        log.debug("probe %s failed: %s", url, exc)
        return ProbeResult(url=url, host=host, scheme=scheme, status=0)

    headers = {k: v for k, v in r.headers.items()}
    body = r.text if "text" in r.headers.get("content-type", "") else ""
    loc = r.headers.get("location", "")
    pr = ProbeResult(
        url=str(r.url), host=host, scheme=scheme, status=r.status_code,
        title=_title_of(body),
        server=r.headers.get("server", ""),
        powered_by=r.headers.get("x-powered-by", ""),
        tech=_detect_tech(headers, body),
        redirect=loc, headers=headers,
        body_sample=body[:4000],
        cdn=r.headers.get("cf-ray", "") and "Cloudflare" or "",
    )
    return pr


async def probe_hosts(
    hosts: list[str], guard: ScopeGuard, settings, client: httpx.AsyncClient
) -> list[ProbeResult]:
    sem = asyncio.Semaphore(settings.concurrency)

    async def one(host: str) -> ProbeResult | None:
        for scheme in ("https", "http"):
            async with sem:
                pr = await probe_url(f"{scheme}://{host}", guard, client)
            if pr.alive:
                return pr
        return None

    results = await asyncio.gather(*(one(h) for h in hosts))
    alive = [r for r in results if r]
    log.info("probe: %d hosts → %d alive", len(hosts), len(alive))
    return alive
