"""Auth profiles — named login recipes for authenticated hunting.

pentest-ai `auth profile` doctrine: the hunter registers its own accounts,
but sometimes you have a provided test account. Profiles are vault-encrypted
and replayable: `auth_login` performs the login and installs the session.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .authvault import AuthVault, Session

log = logging.getLogger("avci.store.profiles")


@dataclass
class AuthProfile:
    name: str
    target: str                  # origin the profile belongs to
    kind: str = "form"           # form | json | bearer | cookie
    login_url: str = ""
    username_field: str = "email"
    password_field: str = "password"
    username: str = ""
    password: str = ""           # empty → pulled from vault at login time
    bearer_token: str = ""
    success_marker: str = ""     # substring proving login (e.g. "dashboard")
    extra_fields: dict = field(default_factory=dict)


class ProfileStore:
    def __init__(self, vault_dir: Path, vault: AuthVault) -> None:
        self.path = vault_dir / "profiles.json"
        self.vault = vault
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self.profiles = {
                    k: AuthProfile(**v) for k, v in raw.items()
                }
                return
            except Exception as exc:  # noqa: BLE001
                log.warning("profiles unreadable: %s", exc)
        self.profiles: dict[str, AuthProfile] = {}

    def _save(self) -> None:
        self.path.write_text(
            json.dumps({k: asdict(v) for k, v in self.profiles.items()}, indent=2),
            encoding="utf-8")

    # ------------------------------------------------------------------
    def upsert(self, p: AuthProfile) -> str:
        self.profiles[p.name] = p
        self._save()
        return f"OK: profile '{p.name}' saved for {p.target}"

    def get(self, name: str) -> AuthProfile | None:
        return self.profiles.get(name)

    def list(self) -> list[dict]:
        return [{"name": p.name, "target": p.target, "kind": p.kind}
                for p in self.profiles.values()]

    # ------------------------------------------------------------------
    async def login(self, name: str, client, guard) -> str:
        """Execute the profile: returns report; installs cookies into client."""
        import httpx
        import re
        p = self.get(name)
        if p is None:
            return f"ERROR: no profile '{name}'"
        if p.kind in ("form", "json"):
            guard.check_url(p.login_url)
            body = {p.username_field: p.username, p.password_field: p.password,
                    **p.extra_fields}
            if p.kind == "json":
                r = await client.post(p.login_url, json=body)
            else:
                r = await client.post(p.login_url, data=body)
            ok = (p.success_marker.lower() in r.text.lower()) if p.success_marker \
                else r.status_code in (200, 302)
            if not ok:
                return (f"LOGIN FAILED: status={r.status_code} "
                        f"marker={p.success_marker!r} not found")
            cookies = [{"name": c.name, "value": c.value, "domain": c.domain}
                       for c in client.cookies.jar]
            tok = r.headers.get("authorization", "")
            headers = {"Authorization": tok} if tok else {}
            try:
                jb = r.json()
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if isinstance(jb, dict) and jb.get(key):
                        headers["Authorization"] = f"Bearer {jb[key]}"
                        break
            except Exception:  # noqa: BLE001
                pass
            sess = Session(label=f"profile:{p.name}", target=p.target,
                           email=p.username, cookies=cookies, headers=headers,
                           notes="auth profile login")
            self.vault.save(sess)
            return (f"LOGIN OK: {len(cookies)} cookies"
                    + (f", Authorization header" if headers else ""))
        if p.kind == "bearer":
            return ("Bearer profile: use http tool with header "
                    f"Authorization: Bearer <token from vault profile '{name}'>")
        return f"ERROR: unknown profile kind {p.kind}"
