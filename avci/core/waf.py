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

# JS-challenge walls: the gate is a browser check, not a payload signature.
# Mutation CANNOT pass these — only a real JS engine can. Each entry is
# (kind, body-regex, strong) — `strong` markers fire even on a 200 status.
_JS_CHALLENGE_PATTERNS: tuple[tuple[str, str, bool], ...] = (
    ("cloudflare-iuam", r"(?i)just a moment|cf-chl|cf_chl_"
     r"|cdn-cgi/challenge-platform|cf-browser-verification"
     r"|checking your browser", True),
    ("incapsula-js", r"(?i)_incapsula_resource|incap_ses|visid_incap"
     r"|incapsula incident", True),
    ("akamai-sensor", r"(?i)bm_sz|_abck|ak_bmsc|sensor_data\.js"
     r"|akamai.*reference #", False),
    ("datadome", r"(?i)datadome|captcha-delivery\.com", True),
    ("perimeterx", r"(?i)px-captcha|_pxhd|perimeterx|human-challenge", True),
    ("generic-js-wall", r"(?i)enable javascript|javascript is required"
     r"|javascript must be enabled|ddos protection by", False),
)

# Cookies that prove a challenge was solved — watched by the browser solver.
CLEARANCE_COOKIE_NAMES = (
    "cf_clearance", "incap_ses_", "visid_incap", "ak_bmsc", "_abck",
    "bm_sz", "datadome", "_pxhd", "pxcts",
)


def challenge_markers(body: str) -> list[str]:
    """Challenge kinds whose markers are present in this body (any status)."""
    found = []
    for kind, rx, _strong in _JS_CHALLENGE_PATTERNS:
        if re.search(rx, body or ""):
            found.append(kind)
    return found


def detect_js_challenge(status: int, headers: dict[str, str],
                        body: str) -> str | None:
    """Return the JS-challenge kind if this response is a browser gate.

    Fires on block statuses (403/429/503) with any marker, or on a 200 with
    a STRONG marker (Cloudflare IUAM interstitials return 403/503, DataDome
    and some Incapsula configs answer 200 with the challenge page).
    """
    body = (body or "")[:20000]
    for kind, rx, strong in _JS_CHALLENGE_PATTERNS:
        if not re.search(rx, body):
            continue
        if status in _BLOCK_STATUS or status == 503 or (strong and status == 200):
            return kind
    # Cloudflare challenge pages often arrive as 503 + cf-mitigated header
    hl = {k.lower(): v for k, v in (headers or {}).items()}
    if status == 503 and ("cf-mitigated" in hl or "cf-ray" in hl):
        return "cloudflare-iuam"
    return None


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
