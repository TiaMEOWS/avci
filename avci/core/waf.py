"""WAF layer — fingerprint what is blocking us, mutate payloads past it.

Akamai burst-kill lesson (Kruidvat hunt): a 403-family wall is not always a
dead end; it is usually signature matching. Detect the family, then mutate:
case randomisation, selective URL-encoding, comment-splitting of keywords.
Never hold state per-target beyond the fingerprint — the rate limiter owns
pacing, this owns shape.
"""

from __future__ import annotations

import random
import re

# (header/name, regex, family)
_FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    ("server", r"(?i)^cloudflare", "cloudflare"),
    ("cf-ray", r".", "cloudflare"),
    ("server", r"(?i)akamai", "akamai"),
    ("x-akamai-transformed", r".", "akamai"),
    ("server", r"(?i)^awselb", "aws-waf"),
    ("x-amzn-requestid", r".", "aws-waf"),
    ("server", r"(?i)^f5|bigip", "f5"),
    ("x-cnection", r".", "f5"),
    ("server", r"(?i)imperva|incapsula|distil", "imperva"),
    ("x-iinfo", r".", "imperva"),
    ("server", r"(?i)mod_security|modsecurity", "modsec"),
    ("server", r"(?i)^microsoft-iis", "iis-arr"),
)

_BLOCK_STATUS = {403, 406, 418, 429, 501}


class WAFDetector:
    def __init__(self) -> None:
        self.seen: dict[str, str] = {}   # host → family

    def fingerprint(self, host: str, status: int, headers: dict[str, str],
                    body: str = "") -> str | None:
        """Return the WAF family if the response smells like one; remember it."""
        fam = self.seen.get(host)
        if fam:
            return fam
        hl = {k.lower(): v for k, v in headers.items()}
        for name, rx, family in _FINGERPRINTS:
            v = hl.get(name, "")
            if v and re.search(rx, v):
                self.seen[host] = family
                return family
        if status in _BLOCK_STATUS and re.search(
                r"(?i)(access denied|blocked|firewall|request blocked"
                r"|reference #|captcha)", body):
            self.seen[host] = "generic-403-wall"
            return "generic-403-wall"
        return None


class PayloadMutator:
    """Deterministic-ish mutations for signature-based filters."""

    def __init__(self, seed: int = 1337) -> None:
        self._rng = random.Random(seed)

    def case_random(self, payload: str) -> str:
        return "".join(c.upper() if self._rng.random() < 0.5 else c.lower()
                       for c in payload)

    def urlencode_key_chars(self, payload: str) -> str:
        from urllib.parse import quote
        # encode only the chars signatures usually key on
        return quote(payload, safe="abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/")

    def comment_split(self, payload: str) -> str:
        """scr<script>ipt → breaks naive keyword blacklists (SQL/HTML)."""
        out = []
        for word in re.findall(r"[A-Za-z]+|[^A-Za-z]+", payload):
            if len(word) >= 6 and word.isalpha():
                mid = len(word) // 2
                out.append(f"{word[:mid]}<x>{word[mid:]}")
            else:
                out.append(word)
        return "".join(out)

    def mutate(self, payload: str, level: int = 1) -> list[str]:
        """Ordered variant list for retries; level bounds how exotic."""
        variants = [self.case_random(payload)]
        if level >= 2:
            variants.append(self.urlencode_key_chars(payload))
            variants.append(self.comment_split(
                self.case_random(payload)))
        return variants


def looks_blocked(status: int) -> bool:
    return status in _BLOCK_STATUS
