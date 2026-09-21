"""Per-host politeness: token-bucket rate limiting + Retry-After respect.

Long-run endurance doctrine: a hunter that gets IP-banned in iteration 12
(Akamai path-family lesson) is worthless. Every outbound request passes
`await rl.acquire(host, method, url)`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

log = logging.getLogger("avci.core.ratelimit")


@dataclass
class HostBucket:
    rate: float            # requests/second sustained
    burst: int             # max instantaneous
    tokens: float = 0.0
    last: float = field(default_factory=time.monotonic)
    retry_after: float = 0.0  # monotonic deadline blocking this host

    def refill(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now


class RateLimiter:
    def __init__(self, default_rate: float = 4.0, default_burst: int = 8,
                 global_concurrency: int = 12) -> None:
        self.default_rate = default_rate
        self.default_burst = default_burst
        self.buckets: dict[str, HostBucket] = {}
        self.host_rates: dict[str, tuple[float, int]] = {}  # host overrides
        self._sem = asyncio.Semaphore(global_concurrency)
        self.stats: dict[str, int] = defaultdict(int)

    def tune(self, host: str, rate: float, burst: int) -> None:
        """Tighten a specific host (WAF lesson: per-host burst-kill)."""
        self.host_rates[host.lower()] = (rate, burst)

    def note_response(self, host: str, status: int,
                      retry_after: str | None = None) -> None:
        h = host.lower()
        b = self._bucket(h)
        if status == 429 or status >= 500:
            # back off hard: 30-60s depending on server word
            wait = 30.0
            if retry_after:
                try:
                    wait = max(5.0, min(120.0, float(retry_after)))
                except ValueError:
                    pass
            b.retry_after = max(b.retry_after, time.monotonic() + wait)
            # permanently tighten a host that 429s
            if status == 429:
                b.rate = max(0.5, b.rate / 2)
                b.burst = max(2, b.burst // 2)
            log.warning("rate-limit backoff %s: %.0fs (rate→%.1f/s)",
                        h, wait, b.rate)

    def _bucket(self, host: str) -> HostBucket:
        h = host.lower()
        if h not in self.buckets:
            rate, burst = self.host_rates.get(
                h, (self.default_rate, self.default_burst))
            self.buckets[h] = HostBucket(rate=rate, burst=burst,
                                         tokens=float(burst))
        return self.buckets[h]

    async def acquire(self, url: str) -> None:
        """Wait for a slot for this URL's host. Never holds the global
        semaphore while sleeping (a backing-off host must not starve others)."""
        host = (urlsplit(url).hostname or "").lower()
        b = self._bucket(host)
        while True:
            now = time.monotonic()
            if b.retry_after > now:
                await asyncio.sleep(min(b.retry_after - now, 60) + 0.1)
                b.refill()
                continue
            b.refill()
            if b.tokens >= 1:
                b.tokens -= 1
                self.stats[host] += 1
                return
            await asyncio.sleep(min((1 - b.tokens) / max(b.rate, 0.1), 2.0))
