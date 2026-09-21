"""Notifier — Discord / Telegram / generic webhook integration.

Enterprise requirement: a fleet run nobody watches still has to page its
operator when it finds something. Fire-and-forget by design — a dead
webhook must never kill a hunt. Config via env (cheapest to wire in CI):

    AVCI_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
    AVCI_TELEGRAM_TOKEN=...  + AVCI_TELEGRAM_CHAT_ID=...
    AVCI_WEBHOOK=https://any.endpoint/that/accepts {"title","message"}

or a configs/notify.json with the same keys (env wins).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("avci.notify")


def discord_payload(title: str, message: str, severity: str = "") -> dict:
    color = {"critical": 0xE8302A, "high": 0xE87A30,
             "medium": 0xE8C530, "low": 0x30A2E8}.get(severity, 0x888888)
    return {"embeds": [{
        "title": title[:250],
        "description": message[:3900],
        "color": color,
    }]}


def telegram_payload(title: str, message: str) -> dict:
    return {"text": f"*{title}*\n{message}"[:4000],
            "parse_mode": "Markdown"}


class Notifier:
    def __init__(self, discord: str = "", telegram_token: str = "",
                 telegram_chat: str = "", generic: str = "") -> None:
        self.discord = discord
        self.tg = (telegram_token, telegram_chat)
        self.generic = generic

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, cfg_path: Path | None = None) -> "Notifier":
        import os
        cfg: dict = {}
        if cfg_path is not None and cfg_path.exists():
            try:
                cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                cfg = {}
        return cls(
            discord=os.environ.get("AVCI_DISCORD_WEBHOOK",
                                   cfg.get("discord_webhook", "")),
            telegram_token=os.environ.get("AVCI_TELEGRAM_TOKEN",
                                          cfg.get("telegram_token", "")),
            telegram_chat=os.environ.get("AVCI_TELEGRAM_CHAT_ID",
                                         cfg.get("telegram_chat_id", "")),
            generic=os.environ.get("AVCI_WEBHOOK", cfg.get("webhook", "")),
        )

    @property
    def armed(self) -> bool:
        return bool(self.discord or self.generic
                    or (self.tg[0] and self.tg[1]))

    # ------------------------------------------------------------------
    def finding(self, f) -> None:
        """Page on critical/high findings only — noise kills alerting."""
        sev = getattr(f, "severity", "")
        if sev not in ("critical", "high"):
            return
        self.post(f"AVCI [{sev.upper()}] {f.title}",
                  f"{f.url}\n{getattr(f, 'description', '')[:500]}",
                  severity=sev)

    def run_end(self, summary: dict) -> None:
        self.post("AVCI run finished",
                  json.dumps(summary, default=str)[:3500])

    # ------------------------------------------------------------------
    def post(self, title: str, message: str, severity: str = "") -> None:
        if not self.armed:
            return
        import httpx
        jobs: list[tuple[str, dict]] = []
        if self.discord:
            jobs.append((self.discord,
                         discord_payload(title, message, severity)))
        if self.tg[0] and self.tg[1]:
            jobs.append((f"https://api.telegram.org/bot{self.tg[0]}/sendMessage",
                         telegram_payload(title, message)))
        if self.generic:
            jobs.append((self.generic, {"title": title, "message": message}))
        for url, payload in jobs:
            try:
                httpx.post(url, json=payload, timeout=6)
            except Exception as exc:  # noqa: BLE001 — never kill the hunt
                log.warning("notify %s failed: %s", url.split("?")[0], exc)
