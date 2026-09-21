"""JS miner: endpoints, secrets, sourcemaps from collected JS bundles.

Patterns distilled from LinkFinder/SecretFinder doctrine, reimplemented in
stdlib regex so AVCI carries zero binary dependencies.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.recon.jsminer")

# Endpoint-ish strings (LinkFinder-style, widened for modern SPAs)
_ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)(/{1,2}                      # leading slash(es)
        (?:[A-Za-z0-9\-_.~%]{1,64}/){0,6}      # path segments
        [A-Za-z0-9\-_.~%]{1,64}
        (?:\?(?:[A-Za-z0-9\-_.~%=&+,]*))?
    )(?:"|'|`)""",
    re.VERBOSE,
)

_API_CALL_RE = re.compile(
    r"""(?:"|'|`)((?:https?:)?//                  # absolute or protocol-relative
        [A-Za-z0-9.\-]+\.[a-z]{2,}
        (?:/[A-Za-z0-9\-_.~%/{1,2}]*)?
    )(?:"|'|`)""",
    re.VERBOSE,
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("firebase_project", re.compile(r"[a-z0-9-]+\.firebaseio\.com|XXXXXX\.firebaseapp\.com")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{16,}")),
    ("stripe_key", re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("jwt_literal", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("mailgun_key", re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9\-_]{20,}")),
    ("graphql_endpoint", re.compile(r"(?:graphql|gql)[\"'`]?[:\s]*[\"'`]((?:/|https?://)[^\"'`]+)", re.I)),
)

# Interesting parameter names to flag for the agent
_PARAM_HINT_RE = re.compile(
    r"[?&](debug|test|admin|internal|role|token|auth|key|secret|redirect|"
    r"url|return|next|callback|file|path|doc|page|render|template|preview)",
    re.I,
)


@dataclass
class JSFindings:
    source_url: str
    endpoints: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    secrets: list[dict] = field(default_factory=list)  # {kind, value, source}
    params: set[str] = field(default_factory=set)
    sourcemap: str = ""
    size: int = 0


def mine_js_text(source_url: str, text: str) -> JSFindings:
    f = JSFindings(source_url=source_url, size=len(text))

    for m in _ENDPOINT_RE.finditer(text):
        val = m.group(1)
        if 1 < len(val) <= 300 and not val.startswith("//") or "api" in val:
            f.endpoints.add(val)
    f.endpoints.discard("/")
    f.endpoints = {e for e in f.endpoints if len(e) > 2}

    for m in _API_CALL_RE.finditer(text):
        f.hosts.add(m.group(1))

    for kind, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            f.secrets.append({"kind": kind, "value": m.group(0)[:120], "source": source_url})

    for m in _PARAM_HINT_RE.finditer(text):
        f.params.add(m.group(1).lower())

    if "sourceMappingURL=" in text[-4000:] or "sourceMappingURL=" in text[:4000]:
        sm = re.search(r"sourceMappingURL=([^\s'\")}\]]+)", text)
        if sm:
            f.sourcemap = sm.group(1)
    if urlsplit(source_url).path.endswith(".js.map"):
        f.sourcemap = source_url
    return f


async def fetch_and_mine(
    js_urls: list[str], guard: ScopeGuard, client: httpx.AsyncClient
) -> list[JSFindings]:
    out: list[JSFindings] = []
    for url in js_urls[:400]:
        try:
            guard.check_url(url)
        except Exception:  # noqa: BLE001 — out of scope JS host
            continue
        try:
            r = await client.get(url, timeout=20)
            if r.status_code == 200 and len(r.text) > 100:
                out.append(mine_js_text(url, r.text))
        except Exception as exc:  # noqa: BLE001
            log.debug("js fetch %s: %s", url, exc)
    log.info("jsminer: %d/%d bundles mined", len(out), len(js_urls))
    return out


def decode_sourcemap_payload(payload: str) -> dict | None:
    """Extract sources + sourcesContent from a .map file (when open)."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return {
        "sources": data.get("sources", [])[:200],
        "has_content": bool(data.get("sourcesContent")),
    }


def base64_decode(value: str) -> str:
    try:
        return base64.b64decode(value + "===").decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def absolutize(js_url: str, ref: str) -> str:
    return urljoin(js_url, ref)
