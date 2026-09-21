"""Registration driver — the offensive account-creation chain.

Flow (apex doctrine, rebuilt):
  1. mail.tm inbox
  2. register on target (HTTP signup endpoint OR browser form via MCP)
  3. poll inbox → OTP / verify link
  4. activate, collect cookies/tokens
  5. persist into AuthVault for authenticated hunting

The agent drives this via the `register_account` tool; this module is the
machinery underneath.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx

from avci.core.http import make_client

from ..browser.driver import BrowserDriver
from ..scope.guard import ScopeGuard
from ..store.authvault import AuthVault, Session
from .mailtm import Inbox, MailTM, random_password

log = logging.getLogger("avci.email.registration")

_EMAIL_FIELD_HINTS = ("email", "mail", "e-mail", "username", "user", "identifier",
                      "login", "account")
_PASS_FIELD_HINTS = ("password", "pass", "passwd", "pwd")
_OTP_FIELD_HINTS = ("otp", "code", "verification", "verify", "pin", "token")


def _match_field(names: list[str], hints: tuple[str, ...]) -> str | None:
    for n in names:
        low = n.lower()
        for h in hints:
            if h in low:
                return n
    return None


@dataclass
class RegistrationResult:
    ok: bool
    target: str
    email: str = ""
    password: str = ""
    activated: bool = False
    otp: str = ""
    verify_url: str = ""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"ok={self.ok} email={self.email} activated={self.activated} "
            f"otp={self.otp or '-'} cookies={len(self.cookies)} "
            + (" ".join(self.notes))
        )


class RegistrationDriver:
    def __init__(self, guard: ScopeGuard, vault: AuthVault,
                 browser: BrowserDriver | None = None) -> None:
        self.guard = guard
        self.vault = vault
        self.browser = browser

    # ------------------------------------------------------------------
    async def http_signup(
        self,
        target_origin: str,
        signup_path: str,
        email: str,
        password: str,
        extra_fields: dict | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> RegistrationResult:
        """POST-style registration against a JSON or form endpoint."""
        url = target_origin.rstrip("/") + "/" + signup_path.lstrip("/")
        self.guard.check_url(url)
        own = client is None
        client = client or make_client(timeout=25, follow_redirects=True)
        res = RegistrationResult(ok=False, target=target_origin,
                                 email=email, password=password)
        try:
            payload = {"email": email, "password": password, "username": email.split("@")[0]}
            if extra_fields:
                payload.update(extra_fields)
            r = await client.post(url, json=payload)
            res.notes.append(f"signup POST {r.status_code}")
            if r.status_code >= 400:
                # some targets want form-encoded
                r2 = await client.post(url, data=payload)
                res.notes.append(f"form retry {r2.status_code}")
                if r2.status_code >= 400:
                    res.notes.append((r.text or r2.text)[:200])
                    return res
                r = r2
            if "set-cookie" in {k.lower() for k in r.headers}:
                res.cookies = [
                    {"name": c.name, "value": c.value, "domain": c.domain}
                    for c in client.cookies.jar
                ]
            tok = r.headers.get("authorization") or ""
            if tok:
                res.headers["Authorization"] = tok
            try:
                body = r.json()
                for key in ("token", "access_token", "accessToken", "jwt", "session"):
                    v = body.get(key) if isinstance(body, dict) else None
                    if v:
                        res.headers["Authorization"] = f"Bearer {v}"
                        break
            except Exception:  # noqa: BLE001
                pass
            res.ok = r.status_code < 400
            return res
        finally:
            if own:
                await client.aclose()

    # ------------------------------------------------------------------
    async def browser_signup(
        self,
        target_url: str,
        inbox: Inbox,
        mail: MailTM,
        form_hints: dict | None = None,
        submit_selector: str = "button[type=submit], input[type=submit], button",
    ) -> RegistrationResult:
        """Browser-driven registration (wondersuite MCP or local playwright)."""
        self.guard.check_url(target_url)
        res = RegistrationResult(ok=False, target=target_url,
                                 email=inbox.address, password=inbox.password)
        if self.browser is None:
            res.notes.append("no browser driver configured")
            return res

        mode = await self.browser.ensure()
        res.notes.append(f"browser={mode}")
        if mode == "none":
            return res

        status = await self.browser.goto(target_url)
        res.notes.append(f"goto: {status[:80]}")
        html = await self.browser.content()
        if not html.startswith("ERROR"):
            names = re.findall(
                r"<(?:input|select|textarea)[^>]*?name=[\"']([^\"']+)[\"']", html, re.I
            )
            email_f = (form_hints or {}).get("email") or _match_field(names, _EMAIL_FIELD_HINTS)
            pass_f = (form_hints or {}).get("password") or _match_field(names, _PASS_FIELD_HINTS)
            if email_f:
                await self.browser.fill(f'[name="{email_f}"]', inbox.address)
                res.notes.append(f"filled {email_f}")
            if pass_f:
                await self.browser.fill(f'[name="{pass_f}"]', inbox.password)
                res.notes.append(f"filled {pass_f}")
            await self.browser.click(submit_selector)
            res.notes.append("submitted")
            res.ok = True
        return res

    # ------------------------------------------------------------------
    async def full_chain(
        self,
        target_origin: str,
        signup_path: str = "",
        verify_base: str = "",
        use_browser: bool = False,
    ) -> RegistrationResult:
        """End-to-end: inbox (mail.tm→guerrilla fallback) → signup →
        OTP/verify → vault."""
        from .provider import InboxProvider
        provider = InboxProvider()
        inbox = await provider.create_inbox()
        log.info("inbox ready via %s: %s", provider.backend_name, inbox.address)

        if use_browser:
            res = await self.browser_signup(target_origin, inbox, None)
        else:
            res = await self.http_signup(target_origin, signup_path or "/api/register",
                                         inbox.address, inbox.password)
        if not res.ok:
            res.notes.append("signup failed — inspect notes")
            await provider.aclose()
            return res

        # wait for the email and try activation
        parsed = await provider.poll_for_message(timeout=240)
        if parsed:
            res.activated = True
            if parsed.otp_codes:
                res.otp = parsed.otp_codes[0]
            if parsed.verify_links:
                res.verify_url = parsed.verify_links[0]
                # follow the verification link if same-target
                try:
                    self.guard.check_url(res.verify_url)
                    async with make_client(timeout=20, follow_redirects=True) as c:
                        vr = await c.get(res.verify_url)
                        res.notes.append(f"verify GET {vr.status_code}")
                        if vr.status_code in (200, 302):
                            res.activated = True
                except Exception as exc:  # noqa: BLE001
                    res.notes.append(f"verify follow blocked: {exc}")
        else:
            res.notes.append("no email arrived in 240s")

        if self.browser is not None and self.browser.mode == "local":
            res.cookies = await self.browser.cookies()

        # vault it
        await provider.aclose()
        session = Session(
            label=f"auto-{inbox.address.split('@')[0]}", target=target_origin,
            email=inbox.address, password=inbox.password,
            cookies=res.cookies, headers=res.headers,
            notes=f"otp={res.otp} activated={res.activated}",
        )
        vault_note = self.vault.save(session)
        res.notes.append(vault_note)
        return res


def generate_identity() -> dict:
    """Human-plausible identity for signup forms that demand names."""
    from .mailtm import random_localpart
    local = random_localpart().replace(".", " ").title()
    first, *rest = local.split()
    return {
        "firstName": first,
        "lastName": (rest[0] if rest else "Smith"),
        "name": local,
        "username": local.lower().replace(" ", ""),
        "password": random_password(),
    }
