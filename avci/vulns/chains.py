"""Attack-chain discovery — finding combinations that outrank their parts.

pentest-ai chain doctrine, distilled to a rule table that runs over the
findings DB at report time: chain matches raise aggregate severity and give
the triage argument a human would make.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..store.state import Finding

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Chain:
    title: str
    pattern: list[str]              # regex over finding title+url+description
    requires: int                    # min matched findings
    severity: str                    # resulting severity
    impact: str


CHAINS: list[Chain] = [
    Chain(
        "XSS → session/account takeover",
        [r"xss", r"(cookie|session|token|jwt|localstorage|otp)"],
        2, "high",
        "Reflected/stored XSS combined with session or token handling allows "
        "full account takeover of a victim user.",
    ),
    Chain(
        "Open redirect → OAuth token theft",
        [r"redirect", r"(oauth|callback|state|authorize|token)"],
        2, "high",
        "Open redirect on the OAuth return path lets the attacker capture "
        "authorization codes/state and swap sessions.",
    ),
    Chain(
        "IDOR/BOLA → PII exfiltration",
        [r"(idor|bola)", r"(user|email|phone|address|order|invoice|pii)"],
        2, "high",
        "Object-level access control failure exposing other users' personal "
        "data at scale (regulatory impact: KVKK/GDPR).",
    ),
    Chain(
        "Secret leak → infrastructure access",
        [r"(api[_ ]?key|secret|credential|private key|token)"],
        1, "high",
        "Hardcoded/live credential in client-reachable code — direct path to "
        "upstream services (mail, payments, cloud).",
    ),
    Chain(
        "Sourcemap → hidden attack surface",
        [r"sourcemap", r"(secret|endpoint|internal|admin)"],
        2, "medium",
        "Exposed sourcemaps reveal internal endpoints and secrets, feeding "
        "further attacks on undocumented APIs.",
    ),
    Chain(
        "SSRF + metadata → cloud takeover",
        [r"ssrf", r"(metadata|169\.254|imds|cloud|aws|gcp)"],
        2, "critical",
        "Server-side request forgery reaching cloud metadata service yields "
        "instance credentials and full environment compromise.",
    ),
    Chain(
        "SQLi → authentication bypass / dump",
        [r"sql", r"(login|auth|password|dump|admin)"],
        2, "critical",
        "SQL injection on or near authentication allows bypass and/or bulk "
        "data extraction.",
    ),
    Chain(
        "CORS + credentials → authenticated data theft",
        [r"cors", r"(credential|cookie|origin)"],
        2, "high",
        "Arbitrary-origin CORS with credentials lets any site read "
        "authenticated responses of logged-in users.",
    ),
    Chain(
        "Upload + render → RCE",
        [r"upload", r"(xss|render|svg|exec|rce|content-type)"],
        2, "critical",
        "File upload whose content is rendered/executed server- or client-side "
        "converts to remote code execution.",
    ),
]


def discover_chains(findings: list[Finding]) -> list[dict]:
    found: list[dict] = []
    for chain in CHAINS:
        matched: list[Finding] = []
        for rx in chain.pattern:
            for f in findings:
                blob = f"{f.title} {f.url} {f.description}".lower()
                if re.search(rx, blob) and f not in matched:
                    matched.append(f)
                    break
        if len(matched) >= chain.requires and len(matched) >= len(chain.pattern):
            found.append({
                "title": chain.title,
                "severity": chain.severity,
                "impact": chain.impact,
                "findings": [f.title for f in matched],
            })
    found.sort(key=lambda c: _ORDER.get(c["severity"], 9))
    return found
