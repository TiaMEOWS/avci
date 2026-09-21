"""mail.tm temp-inbox client — disposable email for offensive registration.

NeuroSploit/apex doctrine: create inbox → register on target → poll →
extract OTP/verification link → return the session. Fully own implementation
against the public mail.tm API (https://docs.mail.tm/).
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import string
from dataclasses import dataclass, field

import httpx

from avci.core.http import make_client

log = logging.getLogger("avci.email.mailtm")

_BASE = "https://api.mail.tm"

_OTP_RE = re.compile(
    r"\b(\d{4,8})\b"
)
_VERIFY_LINK_RE = re.compile(
    r"https?://[^\s\"'<>]+?(?:verify|confirm|activate|validate|token|magic)"
    r"[^\s\"'<>]*",
    re.IGNORECASE,
)

_NAME_PREFIX = ("huntsman", "grey", "silent", "raven", "iron", "north", "swift",
                "atlas", "kite", "ember", "onyx", "quill", "delta", "nomad")
_NAME_SUFFIX = ("fox", "wolf", "ray", "line", "crest", "forge", "shade", "bolt",
                "harbor", "ridge", "vale", "brook")


def random_localpart() -> str:
    first = random.choice(_NAME_PREFIX)
    second = random.choice(_NAME_SUFFIX)
    digits = "".join(random.choices(string.digits, k=random.randint(2, 5)))
    return f"{first}.{second}{digits}"


def random_password(length: int = 16) -> str:
    alpha = string.ascii_letters + string.digits + "!#$%&*?"
    return "".join(random.choices(alpha, k=length))


@dataclass
class Inbox:
    address: str
    password: str
    account_id: str
    token: str = ""
    domain: str = ""
    expires_hint: str = "mail.tm inboxes live ~7 days; treat as disposable"


@dataclass
class ParsedMail:
    from_addr: str
    subject: str
    intro: str
    text: str
    otp_codes: list[str] = field(default_factory=list)
    verify_links: list[str] = field(default_factory=list)


class MailTM:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or make_client(timeout=20)

    async def _aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    # ------------------------------------------------------------------
    async def domains(self) -> list[str]:
        r = await self._client.get(f"{_BASE}/domains?page=1")
        r.raise_for_status()
        return [
            d["domain"] for d in r.json().get("hydra:member", [])
            if d.get("isActive")
        ]

    async def create_inbox(self, address: str | None = None,
                           password: str | None = None) -> Inbox:
        domains = await self.domains()
        if not domains:
            raise RuntimeError("mail.tm returned no active domains")
        local = address or random_localpart()
        addr = address or f"{local}@{random.choice(domains)}"
        pwd = password or random_password()
        r = await self._client.post(
            f"{_BASE}/accounts",
            json={"address": addr, "password": pwd},
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"mail.tm account create failed: {r.status_code} {r.text[:200]}")
        acct = r.json()
        token = await self._token(addr, pwd)
        return Inbox(address=addr, password=pwd, account_id=acct["id"],
                     token=token, domain=addr.split("@")[1])

    async def _token(self, address: str, password: str) -> str:
        r = await self._client.post(
            f"{_BASE}/token", json={"address": address, "password": password}
        )
        r.raise_for_status()
        return r.json()["token"]

    # ------------------------------------------------------------------
    async def messages(self, inbox: Inbox) -> list[dict]:
        r = await self._client.get(
            f"{_BASE}/messages?page=1",
            headers={"Authorization": f"Bearer {inbox.token}"},
        )
        r.raise_for_status()
        return r.json().get("hydra:member", [])

    async def read(self, inbox: Inbox, message_id: str) -> ParsedMail:
        r = await self._client.get(
            f"{_BASE}/messages/{message_id}",
            headers={"Authorization": f"Bearer {inbox.token}"},
        )
        r.raise_for_status()
        d = r.json()
        text = d.get("text") or ""
        if not text:
            html = d.get("html") or []
            if isinstance(html, list):
                html = " ".join(html)
            text = re.sub(r"<[^>]+>", " ", html or "")
        return ParsedMail(
            from_addr=d.get("from", {}).get("address", ""),
            subject=d.get("subject", ""),
            intro=(d.get("intro") or "")[:300],
            text=text[:8000],
            otp_codes=_OTP_RE.findall(text)[:5],
            verify_links=_VERIFY_LINK_RE.findall(text)[:5],
        )

    # ------------------------------------------------------------------
    async def poll_for_message(
        self,
        inbox: Inbox,
        from_contains: str = "",
        subject_contains: str = "",
        timeout: float = 180.0,
        interval: float = 6.0,
    ) -> ParsedMail | None:
        """Wait until a matching message lands; return parsed mail."""
        elapsed = 0.0
        while elapsed < timeout:
            msgs = await self.messages(inbox)
            for m in msgs:
                if from_contains and from_contains.lower() not in m.get("from", {}).get("address", "").lower():
                    continue
                if subject_contains and subject_contains.lower() not in (m.get("subject") or "").lower():
                    continue
                return await self.read(inbox, m["id"])
            await asyncio.sleep(interval)
            elapsed += interval
        log.warning("mail poll timed out after %.0fs", timeout)
        return None

    async def extract_otp(self, inbox: Inbox, timeout: float = 180.0) -> tuple[str, ParsedMail] | None:
        parsed = await self.poll_for_message(inbox, timeout=timeout)
        if parsed and parsed.otp_codes:
            return parsed.otp_codes[0], parsed
        return None
