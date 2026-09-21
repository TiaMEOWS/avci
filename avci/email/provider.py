"""Provider-agnostic inbox factory: mail.tm primary, guerrilla fallback."""

from __future__ import annotations

import logging

import httpx

from avci.core.http import make_client

from .guerrilla import GuerrillaMail
from .mailtm import Inbox, MailTM, ParsedMail

log = logging.getLogger("avci.email.provider")


class InboxProvider:
    """Facade — create an inbox via the first provider that answers."""

    def __init__(self) -> None:
        self._client = make_client(timeout=20)
        self.backend: MailTM | GuerrillaMail | None = None
        self.backend_name = ""
        self.inbox: Inbox | None = None

    async def create_inbox(self) -> Inbox:
        for name in ("mail.tm", "guerrilla"):
            be = (MailTM(self._client) if name == "mail.tm"
                  else GuerrillaMail(self._client))
            try:
                inbox = await be.create_inbox()
                self.backend, self.backend_name, self.inbox = be, name, inbox
                log.info("inbox via %s: %s", name, inbox.address)
                return inbox
            except Exception as exc:  # noqa: BLE001
                log.warning("inbox provider %s failed: %s", name, exc)
        raise RuntimeError("no inbox provider reachable (mail.tm, guerrilla)")

    async def poll_for_message(self, **kw) -> ParsedMail | None:
        if self.backend is None or self.inbox is None:
            raise RuntimeError("create_inbox() first")
        return await self.backend.poll_for_message(self.inbox, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()
