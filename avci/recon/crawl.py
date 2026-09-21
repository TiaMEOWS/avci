"""Own BFS crawler — AVCI's bespoke surface walker (criterion: 'every surface').

Fills the gap found in the strix audit: we do not *depend* on the agent
deciding to run katana/gospider. HTML parse + link extraction + form discovery,
same-host only (scope-enforced), depth- and page-capped, JS URLs handed to the
jsminer. Falls back to a katana bridge when the binary exists — extra coverage,
never a dependency.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, parse_qsl

import httpx

from ..scope.guard import ScopeGuard
from .jsminer import mine_js_text

log = logging.getLogger("avci.recon.crawl")

_HREF_RE = re.compile(
    r"""(?:href|src|action|data-url)=["']([^"']+)["']""",
    re.IGNORECASE,
)
_INNER_URL_RE = re.compile(
    r"""["'`](/(?:[A-Za-z0-9\-_.~%]{1,64}/){1,5}[A-Za-z0-9\-_.~%]{1,64}(?:\?[^"'`\s]{0,200})?)["'`]"""
)
_FORM_RE = re.compile(
    r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL
)
_FORM_FIELD_RE = re.compile(
    r"<(?:input|select|textarea)[^>]*?name=[\"']([^\"']+)[\"']", re.IGNORECASE
)
_JS_URL_RE = re.compile(r"\.js(?:\?|$)|\.mjs(?:\?|$)")

_SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".pdf", ".css",
)


@dataclass
class Page:
    url: str
    status: int
    title: str = ""
    forms: list[dict] = field(default_factory=list)     # {action, method, fields}
    params: set[str] = field(default_factory=set)       # query params seen
    js_urls: list[str] = field(default_factory=list)
    links: set[str] = field(default_factory=set)


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    js_urls: set[str] = field(default_factory=set)
    all_params: set[str] = field(default_factory=set)
    forms: list[dict] = field(default_factory=list)
    api_paths: set[str] = field(default_factory=set)


def _same_scope(url: str, guard: ScopeGuard) -> bool:
    try:
        guard.check_url(url)
        return True
    except Exception:  # noqa: BLE001
        return False


def _norm(base: str, href: str) -> str | None:
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absu = urljoin(base, href)
    parts = urlsplit(absu)
    if parts.scheme not in ("http", "https"):
        return None
    path = parts.path or "/"
    if path.lower().endswith(_SKIP_EXT):
        return None
    clean = f"{parts.scheme}://{parts.netloc}{path}"
    if parts.query:
        clean += f"?{parts.query}"
    return clean


def _parse_page(url: str, status: int, body: str) -> Page:
    page = Page(url=url, status=status)

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        page.title = " ".join(m.group(1).split())[:150]

    for fm in _FORM_RE.finditer(body):
        block = fm.group(0)
        act = re.search(r"action=[\"']([^\"']*)[\"']", block, re.I)
        meth = re.search(r"method=[\"']([^\"']*)[\"']", block, re.I)
        fields = _FORM_FIELD_RE.findall(block)
        if fields:
            page.forms.append({
                "action": act.group(1) if act else "",
                "method": (meth.group(1) if meth else "GET").upper(),
                "fields": fields[:30],
            })

    parts = urlsplit(url)
    for k, _ in parse_qsl(parts.query, keep_blank_values=True):
        page.params.add(k)

    for m in _HREF_RE.finditer(body):
        ref = _norm(url, m.group(1))
        if ref:
            page.links.add(ref)
            if _JS_URL_RE.search(ref):
                page.js_urls.append(ref)
    for m in _INNER_URL_RE.finditer(body):
        page.links.add(urljoin(url, m.group(1)))

    return page


async def crawl(
    start_urls: list[str],
    guard: ScopeGuard,
    settings,
    client: httpx.AsyncClient,
) -> CrawlResult:
    result = CrawlResult()
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque((u, 0) for u in start_urls)
    seen.update(start_urls)
    sem = asyncio.Semaphore(settings.concurrency)

    while queue and len(result.pages) < settings.crawl_max_pages:
        batch: list[tuple[str, int]] = []
        while queue and len(batch) < settings.concurrency * 2:
            batch.append(queue.popleft())

        async def fetch_one(u: str, depth: int) -> Page | None:
            try:
                guard.check_url(u)
            except Exception:  # noqa: BLE001
                return None
            async with sem:
                try:
                    r = await client.get(u, timeout=20)
                except Exception:  # noqa: BLE001
                    return None
            page = _parse_page(u, r.status_code, r.text)
            page.depth = depth  # type: ignore[attr-defined]
            return page

        pages = await asyncio.gather(*(fetch_one(u, d) for u, d in batch))
        for page in pages:
            if not page:
                continue
            result.pages.append(page)
            result.js_urls.update(page.js_urls)
            result.all_params.update(page.params)
            result.forms.extend(page.forms)
            depth = getattr(page, "depth", 0)
            if depth < settings.crawl_depth:
                for ln in sorted(page.links):
                    if ln not in seen and _same_scope(ln, guard):
                        seen.add(ln)
                        queue.append((ln, depth + 1))

    # JS quick-mine for API paths (agent gets these as leads)
    for js in list(result.js_urls)[:150]:
        try:
            guard.check_url(js)
            r = await client.get(js, timeout=20)
            if r.status_code == 200:
                mined = mine_js_text(js, r.text)
                result.api_paths.update(mined.endpoints)
                result.all_params.update(mined.params)
        except Exception:  # noqa: BLE001
            continue

    # katana bridge — bonus coverage, optional
    result.api_paths |= _katana_bridge(start_urls, guard)

    log.info("crawl: %d pages, %d js bundles, %d params, %d api paths, %d forms",
             len(result.pages), len(result.js_urls), len(result.all_params),
             len(result.api_paths), len(result.forms))
    return result


def _katana_bridge(start_urls: list[str], guard: ScopeGuard) -> set[str]:
    import shutil
    import subprocess
    if not shutil.which("katana"):
        return set()
    paths: set[str] = set()
    for u in start_urls[:3]:
        try:
            out = subprocess.run(
                ["katana", "-u", u, "-d", "3", "-silent", "-nc", "-kf", "all"],
                capture_output=True, text=True, timeout=180,
            )
            for line in out.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                p = urlsplit(line)
                if p.path and p.path != "/":
                    paths.add(p.path)
        except Exception as exc:  # noqa: BLE001
            log.debug("katana bridge: %s", exc)
    return {p for p in paths if len(p) < 300}
