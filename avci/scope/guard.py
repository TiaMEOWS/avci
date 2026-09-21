"""Fail-closed scope guard — every outbound request passes through here.

Doctrine: H-mmer/pentest-agents' PreToolUse scope hook. If scope is empty,
everything is denied (fail-closed). Private/loopback IPs are denied unless
explicitly allowed (lab mode).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class ScopeViolation(PermissionError):
    """Raised when a request falls outside the authorized scope."""


@dataclass
class ScopeGuard:
    rules: list[str]
    allow_private: bool = False

    def __post_init__(self) -> None:
        # rules may be bare hosts ("example.com"), wildcard ("*.example.com"),
        # host:port ("127.0.0.1:8901"), or scheme://host:port
        self._exact: set[str] = set()
        self._suffixes: list[str] = []
        self._port_rules: dict[str, set[int]] = {}
        for raw in self.rules:
            wildcard = raw.strip().startswith("*.")
            rule = raw.strip().lower()
            if "://" in rule:
                rule = rule.split("://", 1)[1]
            rule = rule.split("/", 1)[0]
            port: int | None = None
            if ":" in rule:
                rule, maybe_port = rule.rsplit(":", 1)
                if maybe_port.isdigit():
                    port = int(maybe_port)
            rule = rule.lstrip("*.").rstrip(".")
            if not rule:
                continue
            if wildcard:
                self._suffixes.append(rule)
            else:
                self._exact.add(rule)
            if port is not None:
                # multiple pinned ports per host are legal (fleet over two
                # lab instances, multi-port services)
                self._port_rules.setdefault(rule, set()).add(port)

    # ------------------------------------------------------------------
    # loopback names all name the same machine — scoping one authorizes
    # the others (agents freely swap 127.0.0.1 ↔ localhost; blocking the
    # alias kills runs that are unambiguously in scope)
    _LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if host.startswith("[") and host.endswith("]"):  # IPv6 literal
            host = host[1:-1]
        if host in self._exact:
            return True
        if host in self._LOOPBACK and (self._exact & self._LOOPBACK):
            return True
        return any(host.endswith("." + suf) for suf in self._suffixes)

    def _private_ip(self, host: str) -> bool:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False  # unresolvable — the probe layer will handle it
        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return True
        return False

    def check_url(self, url: str) -> None:
        """Raise ScopeViolation unless `url` is authorized."""
        parts = urlsplit(url if "://" in url else "https://" + url)
        host = (parts.hostname or "").lower().rstrip(".")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if not host:
            raise ScopeViolation(f"no host in url: {url!r}")
        if not self.host_allowed(host):
            raise ScopeViolation(f"host out of scope: {host!r} (scope={self.rules})")
        # port-restricted scope rules (host:port) pin the request ports
        pinned: set[int] | None = None
        for rule_host, rule_ports in self._port_rules.items():
            if host == rule_host or host.endswith("." + rule_host):
                pinned = rule_ports
                break
        if pinned is not None and parts.port is not None and parts.port not in pinned:
            raise ScopeViolation(
                f"port {parts.port} out of scope: {host!r} is pinned to "
                f":{':'.join(str(p) for p in sorted(pinned))}"
            )
        if not self.allow_private and self._private_ip(host):
            raise ScopeViolation(
                f"host resolves to private/loopback IP: {host!r} "
                "(set AVCI_ALLOW_PRIVATE=1 for lab targets)"
            )

    def assert_scope_nonempty(self) -> None:
        if not self.rules:
            raise ScopeViolation(
                "scope is empty — AVCI is fail-closed; pass --scope <domain> "
                "for every engagement (written authorization assumed)."
            )
