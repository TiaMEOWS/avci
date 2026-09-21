"""Encrypted auth vault — cookies/tokens/accounts per target.

xalgorix go-rod vault doctrine: an agent that registers an account must be
able to hand the session back on the next run. At-rest encryption via
`cryptography` (optional extra); plaintext JSON only when lib missing AND
user explicitly allowed (AVCI_VAULT_PLAINTEXT=1).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

log = logging.getLogger("avci.store.authvault")

try:
    from cryptography.fernet import Fernet
    _CRYPTO = True
except Exception:  # noqa: BLE001
    _CRYPTO = False


@dataclass
class Session:
    label: str
    target: str
    email: str = ""
    password: str = ""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)  # Authorization etc.
    notes: str = ""


class AuthVault:
    def __init__(self, vault_dir: Path) -> None:
        self.dir = vault_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self._key = self._load_key()
        self._fernet = Fernet(self._key) if (_CRYPTO and self._key) else None

    # ------------------------------------------------------------------
    def _keyfile(self) -> Path:
        return self.dir / "vault.key"

    def _load_key(self) -> bytes | None:
        kf = self._keyfile()
        if _CRYPTO:
            if kf.exists():
                return kf.read_bytes()
            from cryptography.fernet import Fernet as _F
            key = _F.generate_key()
            kf.write_bytes(key)
            return key
        return None

    # ------------------------------------------------------------------
    def _enc_path(self, target: str) -> Path:
        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        return self.dir / f"{safe}.vault"

    def save(self, session: Session) -> str:
        blob = json.dumps(asdict(session)).encode()
        path = self._enc_path(session.target)
        if self._fernet:
            path.write_bytes(self._fernet.encrypt(blob))
        elif os.environ.get("AVCI_VAULT_PLAINTEXT") == "1":
            path.write_text(json.dumps(asdict(session), indent=2), encoding="utf-8")
            log.warning("vault saved PLAINTEXT for %s (cryptography missing)",
                        session.target)
        else:
            return "REJECTED: cryptography unavailable and plaintext not allowed"
        return f"OK: session '{session.label}' vaulted for {session.target}"

    def load(self, target: str) -> Session | None:
        path = self._enc_path(target)
        if not path.exists():
            return None
        raw = path.read_bytes()
        try:
            if self._fernet:
                raw = self._fernet.decrypt(raw)
            data = json.loads(raw)
            return Session(**data)
        except Exception as exc:  # noqa: BLE001
            log.error("vault load failed for %s: %s", target, exc)
            return None

    def delete(self, target: str) -> bool:
        path = self._enc_path(target)
        if path.exists():
            path.unlink()
            return True
        return False
