"""GuerrillaMail adapter — fallback inbox provider when mail.tm is down.

Same surface as MailTM: create_inbox / poll_for_message / OTP extraction.
API: https://www.guerrillamail.com/GuerrillaMailAPI.html (sid_token flow).
"""

from __future__ import annotations

import asyncio
import logging
import random
import string

import httpx

from avci.core.http import make_client

from .mailtm import ParsedMail, random_localpart, random_password, _OTP_RE, _VERIFY_LINK_RE

log = logging.getLogger("avci.email.guerrilla")

_BASE = "https://api.guerrillamail.com/ajax.php"


class GuerrillaMail:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or make_client(timeout=20)
        self.sid_token = ""
        self.addr = ""
        self.ts = 0

    async def _call(self, **params) -> dict:
        params.setdefault("sid_token", self.sid_token)
        r = await self._client.get(_BASE, params=params,
                                   headers={"User-Agent": "Mozilla/5.0 avci"})
        r.raise_for_status()
        d = r.json()
        if d.get("sid_token"):
            self.sid_token = d["sid_token"]
        return d

    # ------------------------------------------------------------------
    async def create_inbox(self, address: str | None = None,
                           password: str | None = None) -> object:
        from .mailtm import Inbox
        d = await self._call(f="get_email_address", lang="en")
        self.addr = d.get("email_addr", "")
        want = address or f"{random_localpart()}@sharklasers.com"
        if want != self.addr:
            local = want.split("@")[0]
            d2 = await self._call(f="set_email_user", email_user=local)
            self.addr = d2.get("email_addr", want)
        # Guerrilla inboxes have no password — return pseudo-vault creds
        return Inbox(address=self.addr,
                     password=password or random_password(),
                     account_id="guerrilla", token=self.sid_token,
                     domain=self.addr.split("@")[1] if "@" in self.addr else "")

    async def messages(self, inbox) -> list[dict]:
        d = await self._call(f="check_email", seq=0)
        return d.get("list", []) or []

    async def read(self, inbox, mail_id: str) -> ParsedMail:
        d = await self._call(f="fetch_email", email_id=mail_id)
        body = d.get("mail_body") or ""
        text = __import__("re").sub(r"<[^>]+>", " ", body)
        subject = d.get("mail_subject") or ""
        sender = d.get("mail_from") or ""
        return ParsedMail(from_addr=sender, subject=subject,
                          intro=(d.get("mail_excerpt") or "")[:300],
                          text=text[:8000],
                          otp_codes=_OTP_RE.findall(text)[:5],
                          verify_links=_VERIFY_LINK_RE.findall(text)[:5])

    async def poll_for_message(self, inbox, from_contains: str = "",
                               subject_contains: str = "",
                               timeout: float = 180.0,
                               interval: float = 7.0) -> ParsedMail | None:
        elapsed = 0.0
        while elapsed < timeout:
            try:
                msgs = await self.messages(inbox)
            except Exception as exc:  # noqa: BLE001
                log.debug("guerrilla poll: %s", exc)
                msgs = []
            for m in msgs:
                if from_contains and from_contains.lower() not in (m.get("mail_from") or "").lower():
                    continue
                if subject_contains and subject_contains.lower() not in (m.get("mail_subject") or "").lower():
                    continue
                return await self.read(inbox, m.get("mail_id", ""))
            await asyncio.sleep(interval)
            elapsed += interval
        return None

    async def aclose(self) -> None:
        await self._client.aclose()
