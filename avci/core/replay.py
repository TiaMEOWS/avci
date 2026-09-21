"""http_replay — replay captured traffic with payloads as data.

CyberStrike doctrine (its most stealable mechanism): every request the
agent (or a proxy import) has ever seen is a replayable template. This
module loads captured requests from a run's `captured.jsonl` (full
headers+body, written by mitm import) or `requests.jsonl` (light log),
substitutes a payload into a chosen param (payload-as-data — never string
concatenation into templates), and replays it under the SAME guarantees
as every other AVCI request: scope guard on the captured host, rate
limiter, request log. Every variant exports as a copy-pasteable curl.

The captured-host guard matters: a poisoned capture file can't make AVCI
attack a host that isn't in authorized scope — the URL is re-checked at
replay time, not trusted from the log.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    status: int | None = None
    source: str = "log"  # log | mitm


def load_captured(run_dir: Path) -> list[CapturedRequest]:
    """captured.jsonl (full) first, requests.jsonl (light) as fallback."""
    out: list[CapturedRequest] = []
    full = run_dir / "captured.jsonl"
    if full.exists():
        for line in full.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                out.append(CapturedRequest(
                    method=row.get("method", "GET"),
                    url=row.get("url", ""),
                    headers=row.get("headers") or {},
                    body=row.get("body") or "",
                    status=row.get("status"),
                    source="mitm",
                ))
            except Exception:  # noqa: BLE001 — one corrupt row ≠ lost log
                continue
        if out:
            return out
    light = run_dir / "requests.jsonl"
    if light.exists():
        for line in light.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if row.get("url"):
                    out.append(CapturedRequest(
                        method=row.get("method", "GET"),
                        url=row["url"], status=row.get("status"),
                        source="log"))
            except Exception:  # noqa: BLE001
                continue
    return out


def find_matches(rows: list[CapturedRequest], needle: str) -> list[CapturedRequest]:
    n = needle.lower()
    return [r for r in rows if n in r.url.lower()]


def inject_payload(req: CapturedRequest, param: str, payload: str) -> CapturedRequest:
    """Payload-as-data: rewrite ONE param in query or body, keep the rest."""
    out = CapturedRequest(req.method, req.url, dict(req.headers),
                          req.body, req.status, req.source)
    parts = urlsplit(out.url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    if any(k == param for k, _ in q):
        q = [(k, payload if k == param else v) for k, v in q]
        out.url = urlunsplit(parts._replace(query=urlencode(q)))
        return out
    # JSON body
    stripped = (out.body or "").strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and param in obj:
                obj[param] = payload
                out.body = json.dumps(obj)
                return out
        except Exception:  # noqa: BLE001
            pass
    # form body
    fq = parse_qsl(out.body or "", keep_blank_values=True)
    if any(k == param for k, _ in fq):
        fq = [(k, payload if k == param else v) for k, v in fq]
        out.body = urlencode(fq)
        return out
    # not present anywhere: append as query param
    q.append((param, payload))
    out.url = urlunsplit(parts._replace(query=urlencode(q)))
    return out


def inject_headers(req: CapturedRequest, headers: dict[str, str]) -> CapturedRequest:
    """Merge session headers (Cookie/Authorization) into a copy — the
    dual-identity engine installs identities on captured templates this
    way; existing session headers of the same name are replaced."""
    out = CapturedRequest(req.method, req.url, dict(req.headers),
                          req.body, req.status, req.source)
    low = {k.lower() for k in out.headers}
    for k, v in (headers or {}).items():
        if k.lower() == "cookie" and "cookie" in low:
            # keep other cookies, replace would drop the jar — append instead
            base = next(x for x in out.headers if x.lower() == "cookie")
            out.headers[base] = out.headers[base] + "; " + v
        else:
            out.headers[k] = v
    return out


def to_curl(req: CapturedRequest) -> str:
    """Copy-pasteable curl — headers and body shell-quoted as data."""
    parts = [f"curl -i -X {req.method} {shlex.quote(req.url)}"]
    for k, v in req.headers.items():
        if k.lower() in ("host", "content-length", "accept-encoding"):
            continue
        parts.append(f"  -H {shlex.quote(f'{k}: {v}')}")
    if req.body:
        parts.append(f"  --data-raw {shlex.quote(req.body)}")
    return " \\\n".join(parts)


class Replayer:
    """Sends a variant through the same guard + limiter + log as probes."""

    def __init__(self, guard, limiter, logger) -> None:
        self.guard = guard
        self.rl = limiter
        self.log = logger  # RunState.log_request callable

    async def replay(self, client, req: CapturedRequest) -> dict:
        self.guard.check_url(req.url)          # captured-host guard
        await self.rl.acquire(req.url)
        r = await client.request(req.method, req.url,
                                 headers=req.headers or None,
                                 content=req.body or None)
        self.log("REPLAY", req.url, r.status_code, tool="http_replay")
        return {
            "status": r.status_code,
            "reason": r.reason_phrase,
            "headers": dict(list(r.headers.items())[:20]),
            "body": r.text[:4000],
            "curl": to_curl(req),
        }
