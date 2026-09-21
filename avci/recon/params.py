"""Parameter discovery: reflection probing + arjun-style wordlist injection.

Finds hidden GET/POST/JSON params by injecting candidate names and diffing
response length/content against baseline. Wordlist is built-in (no files).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.recon.params")

# High-yield hidden-param names (distilled from burp-param-miner / arjun lists)
_PARAM_WORDS: tuple[str, ...] = (
    "id", "user", "user_id", "uid", "account", "account_id", "email", "mail",
    "debug", "test", "dev", "admin", "role", "roles", "is_admin", "isadmin",
    "internal", "callback", "redirect", "redirect_uri", "return", "returnUrl",
    "next", "url", "continue", "dest", "destination", "goto", "target",
    "file", "path", "doc", "document", "page", "folder", "root", "dir",
    "template", "render", "preview", "view", "include", "module", "load",
    "token", "access_token", "auth", "key", "apikey", "api_key", "secret",
    "password", "pass", "session", "csrf", "state", "nonce", "code",
    "format", "output", "type", "lang", "locale", "currency", "country",
    "query", "q", "search", "filter", "sort", "order", "limit", "offset",
    "page_size", "from", "to", "date", "start", "end", "count", "total",
    "action", "method", "cmd", "exec", "run", "command", "download",
    "export", "report", "invoice", "order_id", "ref", "reference", "uuid",
)


@dataclass
class ParamHit:
    url: str
    param: str
    method: str
    evidence: str  # why we think it exists


@dataclass
class ParamScanResult:
    url: str
    baseline_len: int = 0
    baseline_status: int = 0
    hits: list[ParamHit] = field(default_factory=list)


async def _baseline(url: str, client: httpx.AsyncClient) -> tuple[int, int, str]:
    r = await client.get(url, timeout=15)
    return r.status_code, len(r.content), r.text[:2000]


async def discover_params(
    url: str,
    guard: ScopeGuard,
    client: httpx.AsyncClient,
    words: tuple[str, ...] = _PARAM_WORDS,
    concurrency: int = 8,
) -> ParamScanResult:
    guard.check_url(url)
    res = ParamScanResult(url=url)
    try:
        res.baseline_status, res.baseline_len, _ = await _baseline(url, client)
    except Exception:  # noqa: BLE001
        return res

    parts = urlsplit(url)
    base_q = dict.fromkeys(
        k for k, _ in parse_qsl(parts.query, keep_blank_values=True)
    )
    sem = asyncio.Semaphore(concurrency)

    async def probe_word(word: str) -> ParamHit | None:
        q = dict(base_q)
        q[word] = "avciprobe1337"
        candidate = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                urlencode(q), parts.fragment))
        async with sem:
            try:
                r = await client.get(candidate, timeout=15)
            except Exception:  # noqa: BLE001
                return None
        delta = abs(len(r.content) - res.baseline_len)
        if r.status_code != res.baseline_status:
            return ParamHit(url, word, "GET", f"status {res.baseline_status}→{r.status_code}")
        if delta > max(64, res.baseline_len * 0.05) and "avciprobe1337" not in r.text:
            return ParamHit(url, word, "GET", f"length delta {delta}")
        if "avciprobe1337" in r.text and res.baseline_status == 200:
            # reflected — parameter consumed by the app, not echoed raw = interesting
            return ParamHit(url, word, "GET", "value consumed (non-echoed reflection)")
        return None

    tasks = [asyncio.create_task(probe_word(w)) for w in words]
    for t in asyncio.as_completed(tasks):
        hit = await t
        if hit:
            res.hits.append(hit)

    log.info("params %s: %d/%d candidates look live", url, len(res.hits), len(words))
    return res


async def arjun_bridge(url: str, guard: ScopeGuard) -> list[str]:
    """Optional arjun binary bridge for exhaustive discovery."""
    import shutil
    import subprocess
    if not shutil.which("arjun"):
        return []
    guard.check_url(url)
    try:
        out = subprocess.run(
            ["arjun", "-u", url, "-t", "10", "-quiet"],
            capture_output=True, text=True, timeout=300,
        )
        return [ln.strip() for ln in out.stdout.splitlines() if ":" in ln]
    except Exception as exc:  # noqa: BLE001
        log.debug("arjun bridge: %s", exc)
        return []
