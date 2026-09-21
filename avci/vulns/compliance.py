"""Compliance mapping — CWE/bug-class → OWASP 2021 / PCI DSS 4.0 / SOC2."""

from __future__ import annotations

import re

# cwe number → control ids per framework
_MAP: dict[int, dict[str, list[str]]] = {
    79: {"owasp": ["A03:2021-Injection"], "pci": ["6.2.4"], "soc2": ["CC6.1", "CC7.1"]},
    89: {"owasp": ["A03:2021-Injection"], "pci": ["6.2.4", "6.3.3"], "soc2": ["CC6.1", "CC7.1"]},
    78: {"owasp": ["A03:2021-Injection"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    94: {"owasp": ["A03:2021-Injection"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    1336: {"owasp": ["A03:2021-Injection"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    22: {"owasp": ["A01:2021-Broken Access Control"], "pci": ["6.2.4", "7.2.2"], "soc2": ["CC6.1"]},
    35: {"owasp": ["A01:2021-Broken Access Control"], "pci": ["7.2.2"], "soc2": ["CC6.1"]},
    639: {"owasp": ["A01:2021-Broken Access Control"], "pci": ["7.2.2", "6.3.3"], "soc2": ["CC6.1"]},
    284: {"owasp": ["A01:2021-Broken Access Control"], "pci": ["7.2.2"], "soc2": ["CC6.1"]},
    287: {"owasp": ["A07:2021-Identification & Auth Failures"], "pci": ["8.3.1", "8.3.5"], "soc2": ["CC6.1"]},
    384: {"owasp": ["A07:2021-Identification & Auth Failures"], "pci": ["8.3.5"], "soc2": ["CC6.1"]},
    522: {"owasp": ["A07:2021-Identification & Auth Failures"], "pci": ["8.3.7"], "soc2": ["CC6.1"]},
    942: {"owasp": ["A05:2021-Security Misconfiguration"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    16: {"owasp": ["A05:2021-Security Misconfiguration"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    601: {"owasp": ["A01:2021-Broken Access Control"], "pci": ["6.4.1"], "soc2": ["CC6.1"]},
    611: {"owasp": ["A10:2021-SSRF"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    918: {"owasp": ["A10:2021-SSRF"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    502: {"owasp": ["A08:2021-Software & Data Integrity"], "pci": ["6.3.2"], "soc2": ["CC8.1"]},
    434: {"owasp": ["A03:2021-Injection"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    200: {"owasp": ["A01:2021-Broken Access Control (info)"], "pci": ["6.3.3"], "soc2": ["CC6.1"]},
    525: {"owasp": ["A09:2021-Logging & Monitoring"], "pci": ["10.2.1"], "soc2": ["CC7.2"]},
    538: {"owasp": ["A05:2021-Security Misconfiguration"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
    23: {"owasp": ["A02:2021-Cryptographic Failures"], "pci": ["3.5.1", "4.2.1"], "soc2": ["CC6.1", "CC6.7"]},
    327: {"owasp": ["A02:2021-Cryptographic Failures"], "pci": ["3.5.1"], "soc2": ["CC6.7"]},
    328: {"owasp": ["A02:2021-Cryptographic Failures"], "pci": ["3.5.1"], "soc2": ["CC6.7"]},
    798: {"owasp": ["A07:2021-Identification & Auth Failures"], "pci": ["8.6.1"], "soc2": ["CC6.1"]},
    403: {"owasp": ["A01:2021-Broken Access Control"], "pci": ["7.2.2"], "soc2": ["CC6.1"]},
    548: {"owasp": ["A08:2021-Software & Data Integrity"], "pci": ["6.2.4"], "soc2": ["CC6.1"]},
}

# keyword fallback when no CWE given
_KW: tuple[tuple[str, int], ...] = (
    ("xss", 79), ("sqli", 89), ("sql injection", 89), ("redirect", 601),
    ("cors", 942), ("traversal", 22), ("ssrf", 918), ("xxe", 611),
    ("rce", 78), ("command injection", 78), ("upload", 434), ("jwt", 347),
    ("sourcemap", 200), ("secret", 798), ("takeover", 403), ("idor", 639),
    ("bola", 639), ("header", 16), ("info", 200),
)


def cwe_of(title_or_cwe: str) -> int | None:
    m = re.search(r"cwe-(\d+)", title_or_cwe, re.I)
    if m:
        return int(m.group(1))
    low = title_or_cwe.lower()
    for kw, cwe in _KW:
        if kw in low:
            return cwe
    return None


def map_finding(title: str, cwe: str = "") -> dict[str, list[str]]:
    n = cwe_of(cwe or title)
    if n is None or n not in _MAP:
        return {}
    return _MAP[n]
