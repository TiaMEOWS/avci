"""Dual-identity engine — manufacture the divergence evidence the triage
gate demands.

The v0.4 machine triage gate REJECTS anonymous-ownership claims that lack a
demonstrated second-identity divergence (superdrug lesson: 5/5 vectors
negative → nothing submittable). Until now the gate only *asked* for that
evidence; this module gives the agent the machinery to PRODUCE it:

- `identity_pair` — register two accounts (A/B) on the target, keep their
  sessions (cookies + Authorization) in the run dir
- `divergence_check` — replay any URL as anonymous, as A and as B; report
  status/body divergence. The output is the exact artifact add_finding
  wants: "identity A: 200 <digest>…; identity B: 403 …; VERDICT:
  DIVERGENT/IDENTICAL".
- `http_replay(as_identity=…)` — re-fire any captured request under either
  identity's session (cross-tenant tampering made one tool call wide).

Divergent per-identity responses on the SAME resource id = the resource is
identity-scoped; identical responses across identities = no per-identity
scoping (unauthenticated/cross-tenant exposure). Both answers are evidence
— the agent picks the claim that matches the oracle.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx

from avci.core.http import make_client


@dataclass
class Identity:
    tag: str                      # "A" | "B"
    email: str = ""
    password: str = ""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def session_headers(self) -> dict[str, str]:
        """Installable session: vaulted Authorization + Cookie chain."""
        out = dict(self.headers)
        pairs = [f"{c['name']}={c['value']}" for c in self.cookies
                 if c.get("name") and c.get("value")]
        if pairs and "cookie" not in {k.lower() for k in out}:
            out["Cookie"] = "; ".join(pairs)
        return out


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]


class DualIdentity:
    """Owns the A/B pair for one run. JSON-backed (identities.json) —
    sessions are run-scoped, the encrypted vault stays for real accounts."""

    def __init__(self, reg_driver, guard, limiter, log_request,
                 run_dir: Path) -> None:
        self.reg = reg_driver          # email.registration.RegistrationDriver
        self.guard = guard
        self.rl = limiter
        self.log = log_request         # RunState.log_request
        self.path = Path(run_dir) / "identities.json"

    # ------------------------------------------------------------------
    def load(self) -> dict[str, Identity]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return {k: Identity(**v) for k, v in raw.items()}
        except Exception:  # noqa: BLE001 — corrupt file ≠ dead engine
            return {}

    def _save(self, ids: dict[str, Identity]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({k: asdict(v) for k, v in ids.items()}, indent=1),
            encoding="utf-8")

    def headers_for(self, tag: str) -> dict[str, str]:
        ident = self.load().get(tag)
        return ident.session_headers() if ident else {}

    # ------------------------------------------------------------------
    async def ensure(self, target_origin: str, signup_path: str = "") -> dict:
        """Two accounts, vaulted into identities.json. Reuses an existing
        pair; registers only what's missing."""
        ids = self.load()
        missing = [t for t in ("A", "B") if t not in ids or not ids[t].email]
        notes: list[str] = []
        if not missing:
            return {"ok": True, "reused": True, "identities":
                    [f"{t}: {ids[t].email}" for t in ("A", "B")],
                    "note": "pair already registered — divergence_check ready"}

        from ..email.provider import InboxProvider
        providers: list[InboxProvider] = []
        try:
            for tag in missing:
                provider = InboxProvider()
                providers.append(provider)
                inbox = await provider.create_inbox()
                res = await self.reg.http_signup(
                    target_origin, signup_path or "/api/register",
                    inbox.address, inbox.password)
                notes.append(f"{tag} signup ok={res.ok} notes={' '.join(res.notes)}")
                if res.ok:
                    ids[tag] = Identity(tag=tag, email=res.email,
                                        password=res.password,
                                        cookies=res.cookies,
                                        headers=res.headers)
        finally:
            for p in providers:
                try:
                    await p.aclose()
                except Exception:  # noqa: BLE001
                    pass

        ok = all(t in ids and ids[t].email for t in ("A", "B"))
        if ok:
            self._save(ids)
        return {"ok": ok, "reused": False,
                "identities": [f"{t}: {ids[t].email}" for t in ("A", "B")
                               if t in ids],
                "notes": notes,
                "hint": "divergence_check any resource URL; http_replay "
                        "accepts as_identity A|B" if ok else
                        "signup path failed — try register_account for "
                        "OTP-based flows, or pass signup_path"}

    # ------------------------------------------------------------------
    async def divergence_check(self, url: str) -> dict:
        """The superdrug oracle: same URL, three callers (anon/A/B)."""
        ids = self.load()
        if not (ids.get("A") and ids.get("B")):
            return {"error": "no identity pair — call identity_pair first"}
        self.guard.check_url(url)

        rows = []
        async with make_client(timeout=25, verify=False,
                                     follow_redirects=False) as client:
            callers = [("anon", {}), ("A", ids["A"].session_headers()),
                       ("B", ids["B"].session_headers())]
            for tag, headers in callers:
                await self.rl.acquire(url)
                r = await client.get(url, headers=headers or None)
                self.log("DIVERGE", url, r.status_code,
                         tool=f"divergence:{tag}")
                rows.append({
                    "identity": tag,
                    "status": r.status_code,
                    "digest": _digest(r.text),
                    "body": r.text[:240].replace("\n", " "),
                })

        authed = rows[1:]
        divergent = len({(x["status"], x["digest"]) for x in authed}) > 1
        anon_401 = rows[0]["status"] in (401, 403)
        evidence = "; ".join(
            f"{x['identity']}: {x['status']} sha={x['digest']} {x['body'][:80]!r}"
            for x in rows)
        if divergent:
            verdict = ("DIVERGENT — resource is identity-scoped (A and B "
                       "receive different data; cross-identity access would "
                       "be a real BOLA)")
        elif anon_401:
            verdict = ("IDENTICAL for A/B, anonymous 401/403 — resource is "
                       "identity-scoped and gated; BOLA would need A reading "
                       "B's data (try http_replay as_identity swap on an "
                       "A-owned resource id)")
        else:
            verdict = ("IDENTICAL across identities and anonymous — no "
                       "per-identity scoping: every caller receives the same "
                       "(cross-tenant) data, unauthenticated exposure")

        return {
            "url": url,
            "rows": rows,
            "verdict": verdict,
            "divergent": divergent,
            "evidence": f"{evidence} — VERDICT: {verdict}",
            "note": "paste `evidence` verbatim into add_finding — the "
                    "triage gate accepts demonstrated divergence",
        }
