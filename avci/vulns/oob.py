"""OOB (out-of-band) callback channel — blind-bug oracle.

Blind SSRF/XXE/SQLi/RCE need an external listener. Zero-dependency design:
webhook.site as the default collector (free public API), any custom
collector implementing the same two calls can be dropped in.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import httpx

from avci.core.http import make_client

log = logging.getLogger("avci.vulns.oob")


@dataclass
class OOBChannel:
    poll_url: str          # GET → JSON list of callbacks
    plant_url: str         # put this into payloads
    service: str = "webhook.site"
    created: float = field(default_factory=time.time)

    def age_min(self) -> float:
        return (time.time() - self.created) / 60


class OOBManager:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or make_client(timeout=15)
        self._channels: list[OOBChannel] = []

    # ------------------------------------------------------------------
    async def create(self, content: str = "") -> OOBChannel:
        """webhook.site: POST /token → uuid; callbacks hit
        https://webhook.site/<uuid>; poll GET /token/<uuid>/requests.
        With `content` the channel serves YOUR exact bytes for any request
        whose path is the token root — the appended-? trick
        (https://webhook.site/<uuid>?anything) keeps sub-paths out, so this
        doubles as an RFI host for include/require bugs that concatenate a
        fixed suffix onto attacker input (PHP allow_url_include=On)."""
        r = await self._client.post("https://webhook.site/token", json={
            "default_status": 200,
            "default_content": content or "avci-oob",
            "timeout": 0,
        })
        r.raise_for_status()
        d = r.json()
        uuid = d["uuid"]
        ch = OOBChannel(
            poll_url=f"https://webhook.site/token/{uuid}/requests",
            plant_url=f"https://webhook.site/{uuid}",
        )
        self._channels.append(ch)
        log.info("OOB channel ready: %s", ch.plant_url)
        return ch

    # ------------------------------------------------------------------
    async def poll(self, ch: OOBChannel, since_min: float = 60.0) -> list[dict]:
        """Return callbacks as [{from_ip, method, url, headers, body, ts}]."""
        r = await self._client.get(ch.poll_url + "?page=1&per_page=50")
        r.raise_for_status()
        data = r.json() or {}
        out: list[dict] = []
        for row in data.get("data", []):
            ts = row.get("created_at") or 0
            try:
                ts_f = float(ts)
            except (TypeError, ValueError):
                ts_f = time.time()
            if ts_f < ch.created - 5:
                continue
            out.append({
                "from_ip": row.get("ip", ""),
                "method": row.get("method", ""),
                "url": row.get("query", ""),
                "user_agent": (row.get("headers") or {}).get("user-agent", ""),
                "body": (row.get("content") or "")[:400],
                "ts": ts_f,
            })
        return out

    # ------------------------------------------------------------------
    async def poll_all(self) -> dict[str, list[dict]]:
        results: dict[str, list[dict]] = {}
        for ch in self._channels:
            try:
                results[ch.plant_url] = await self.poll(ch)
            except Exception as exc:  # noqa: BLE001
                log.debug("oob poll %s: %s", ch.plant_url, exc)
                results[ch.plant_url] = []
        return results

    async def close(self) -> None:
        await self._client.aclose()
