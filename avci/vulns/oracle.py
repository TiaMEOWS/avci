"""Evidence oracle — no finding ships without proof.

Doctrine merged from PriestsBasilisk (exploit-oracle verdicts) and
pentest-ai (machine oracle receipts): every candidate passes through
`judge()` with raw HTTP request/response pairs; verdicts are
CONFIRMED / FAILED / PENDING — never 'the LLM thinks so'.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger("avci.vulns.oracle")

VERDICTS = ("CONFIRMED", "FAILED", "PENDING")


@dataclass
class Evidence:
    """One request/response pair proving (or disproving) a claim."""
    request: str = ""          # full HTTP request, curl or raw
    response_status: int = 0
    response_excerpt: str = "" # the exact bytes that show the issue
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def receipt(self) -> dict:
        return {
            "request": self.request[:4000],
            "status": self.response_status,
            "evidence_excerpt": self.response_excerpt[:2000],
            "observed_at": self.observed_at,
        }


@dataclass
class OracleVerdict:
    claim: str
    verdict: str            # CONFIRMED | FAILED | PENDING
    checks: list[dict] = field(default_factory=list)   # named boolean checks
    evidence: list[Evidence] = field(default_factory=list)
    reason: str = ""

    def __post_init__(self) -> None:
        # Several probes pass the reason string as the 4th positional arg
        # (it lands in `evidence`); route it where it belongs so receipt()
        # never explodes on a str. A lone Evidence object is normalized too.
        if isinstance(self.evidence, str):
            if not self.reason:
                self.reason = self.evidence
            self.evidence = []
        elif isinstance(self.evidence, Evidence):
            self.evidence = [self.evidence]

    @property
    def ok(self) -> bool:
        return self.verdict == "CONFIRMED"

    def receipt(self) -> dict:
        return {
            "claim": self.claim,
            "verdict": self.verdict,
            "reason": self.reason,
            "checks": self.checks,
            "evidence": [e.receipt() if hasattr(e, "receipt") else str(e)
                         for e in self.evidence],
        }


class Oracle:
    """Deterministic judges for common bug classes.

    Each judge takes concrete artifacts (strings/statuses), not model beliefs.
    The agent registers evidence; the oracle stamps the verdict.
    """

    # ------------------------------------------------------------------
    def judge_reflection(self, payload_sent: str, body_received: str,
                         context_breakers: bool = False) -> OracleVerdict:
        checks = []
        raw = payload_sent in body_received
        checks.append({"check": "payload_present_verbatim", "pass": raw})
        if not raw:
            # HTML-entity encoded reflection still matters for some sinks
            ent = payload_sent.replace("<", "&lt;").replace(">", "&gt;")
            ent_hit = ent in body_received
            checks.append({"check": "entity_encoded_reflection", "pass": ent_hit})
            if not ent_hit:
                return self._v("XSS reflection", "FAILED", checks,
                               "payload not present in response body")
            raw = True
        if context_breakers:
            broke = bool(re.search(re.escape(payload_sent[:6]) + r"[^>]{0,80}>",
                                   body_received))
            checks.append({"check": "html_context_breakout", "pass": broke})
            if not broke:
                return self._v("XSS reflection", "PENDING", checks,
                               "reflected but breakout not demonstrated")
        return self._v("XSS reflection", "CONFIRMED" if raw else "FAILED",
                       checks, "payload reflected in response")

    # ------------------------------------------------------------------
    def judge_sqli(self, baseline_status: int, baseline_len: int,
                   payload_status: int, payload_len: int,
                   error_signatures: list[str] | None = None,
                   body: str = "") -> OracleVerdict:
        sigs = error_signatures or [
            "you have an error in your sql syntax", "warning: mysql",
            "unclosed quotation mark", "quoted string not properly terminated",
            "pg_query(", "psql", "sqlite3.OperationalError",
            "ORA-01756", "Microsoft SQL Server", "syntax error",
            "unterminated string", "SQLSTATE",
        ]
        checks = [
            {"check": "error_signature", "pass": any(s.lower() in body.lower() for s in sigs)},
            {"check": "status_delta", "pass": abs(baseline_status - payload_status) >= 400 or
             payload_status >= 500},
            {"check": "length_delta_gt_15pct", "pass":
             abs(payload_len - baseline_len) > max(200, baseline_len * 0.15)},
        ]
        if checks[0]["pass"]:
            return self._v("SQLi", "CONFIRMED", checks, "DB error signature in response")
        if checks[1]["pass"] or checks[2]["pass"]:
            return self._v("SQLi", "PENDING", checks,
                           "response perturbation without signature — needs boolean/time oracle")
        return self._v("SQLi", "FAILED", checks, "no error, no perturbation")

    # ------------------------------------------------------------------
    def judge_redirect(self, request_url: str, response_location: str,
                       allow_external: bool = True) -> OracleVerdict:
        checks = [{"check": "location_header_present", "pass": bool(response_location)}]
        same_host = request_url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
        loc_host = (response_location or "").split("//", 1)[-1].split("/", 1)[0].split(":")[0]
        checks.append({"check": "external_host", "pass": bool(loc_host) and loc_host not in same_host})
        if not response_location:
            return self._v("Open redirect", "FAILED", checks, "no Location header")
        if not allow_external and loc_host not in same_host:
            return self._v("Open redirect", "FAILED", checks,
                           "external redirect not permitted by policy")
        return self._v("Open redirect", "CONFIRMED", checks,
                       f"redirects to {response_location[:100]}")

    # ------------------------------------------------------------------
    def judge_cors(self, origin_sent: str, acao_header: str) -> OracleVerdict:
        checks = [
            {"check": "acao_reflects_arbitrary_origin", "pass":
             acao_header.strip() == origin_sent and origin_sent.endswith(".evil.com")},
        ]
        reflect = checks[0]["pass"]
        return self._v("CORS misconfig", "CONFIRMED" if reflect else "FAILED",
                       checks,
                       f"ACAO={acao_header!r}" if reflect else
                       "ACAO does not reflect attacker origin")

    # ------------------------------------------------------------------
    def judge_generic(self, claim: str, must_contain: list[str],
                      body: str, status: int = 200,
                      expect_status: int | None = None) -> OracleVerdict:
        checks = []
        for needle in must_contain:
            checks.append({"check": f"contains:{needle[:40]}",
                           "pass": needle.lower() in body.lower()})
        if expect_status is not None:
            checks.append({"check": f"status=={expect_status}",
                           "pass": status == expect_status})
        all_pass = all(c["pass"] for c in checks)
        any_pass = any(c["pass"] for c in checks)
        if all_pass and checks:
            return self._v(claim, "CONFIRMED", checks, "all checks passed")
        if any_pass:
            return self._v(claim, "PENDING", checks, "partial checks")
        return self._v(claim, "FAILED", checks, "no checks passed")

    # ------------------------------------------------------------------
    def judge_any(self, claim: str, signatures: list[str],
                  body: str) -> OracleVerdict:
        """OR-semantics signature judge: ANY one signature present confirms.
        For batteries where the signatures are alternatives (file-read
        markers from different OSes, error strings from different stacks) —
        judge_generic ANDs them, which can never confirm a single-response
        read."""
        checks = []
        hit = ""
        for sig in signatures:
            present = sig.lower() in (body or "").lower()
            checks.append({"check": f"contains:{sig[:40]}", "pass": present})
            if present and not hit:
                hit = sig
        if hit:
            return self._v(claim, "CONFIRMED", checks,
                           f"signature {hit!r} present in response")
        return self._v(claim, "FAILED", checks,
                       "none of the signatures present")

    # ------------------------------------------------------------------
    def judge_timing(self, claim: str, elapsed_s: float, threshold_s: float,
                     payload_note: str = "") -> OracleVerdict:
        """Time-oracle: a sleep-style payload that measurably stalls the
        response is machine-checkable proof (blind cmd-inj / blind SQLi)."""
        checks = [{"check": f"elapsed>{threshold_s}s", "pass": elapsed_s > threshold_s},
                  {"check": "payload_reached_backend", "pass": bool(payload_note)}]
        if checks[0]["pass"]:
            return self._v(claim, "CONFIRMED", checks,
                           f"response took {elapsed_s:.1f}s after {payload_note}")
        return self._v(claim, "FAILED", checks,
                       f"response took {elapsed_s:.1f}s (no measurable delay)")

    # ------------------------------------------------------------------
    def judge_differential(self, claim: str, status_a: int, len_a: int,
                           status_b: int, len_b: int,
                           sigs: list[str] | None = None,
                           body_b: str = "") -> OracleVerdict:
        """Boolean differential between a true-ish and false-ish payload (or
        valid vs invalid username). Divergence without signature = PENDING."""
        sigs = sigs or []
        checks = [
            {"check": "status_divergence", "pass": status_a != status_b},
            {"check": "length_divergence",
             "pass": abs(len_a - len_b) > max(120, len_a * 0.10)},
            {"check": "signature", "pass": any(s.lower() in body_b.lower() for s in sigs)},
        ]
        if checks[2]["pass"]:
            return self._v(claim, "CONFIRMED", checks,
                           "error/technology signature present")
        if checks[0]["pass"] or checks[1]["pass"]:
            return self._v(claim, "PENDING", checks,
                           f"divergent responses ({status_a}/{len_a} vs "
                           f"{status_b}/{len_b}) — boolean-style oracle suspected")
        return self._v(claim, "FAILED", checks, "responses identical")

    # ------------------------------------------------------------------
    def judge_race(self, statuses: list[int], bodies: list[str]) -> OracleVerdict:
        """TOCTOU/race: N identical concurrent requests yielding divergent
        outcomes is a machine-checkable race indicator."""
        distinct = sorted(set(statuses))
        checks = [
            {"check": "distinct_statuses", "pass": len(distinct) > 1},
            {"check": "conflict_markers",
             "pass": any(w in b.lower() for b in bodies
                         for w in ("conflict", "already", "claimed", "once"))},
        ]
        if checks[0]["pass"]:
            return self._v("Race condition/TOCTOU", "CONFIRMED", checks,
                           f"identical concurrent requests → statuses {distinct}")
        return self._v("Race condition/TOCTOU", "FAILED", checks,
                       "all concurrent responses identical")

    # ------------------------------------------------------------------
    def judge_cache_deception(self, body_suffix: str, body_base: str,
                              cache_control: str) -> OracleVerdict:
        """Web cache deception: private body served on a cacheable-looking
        suffix (path.css) without no-store protection."""
        private_markers = ('"email"', '"password"', '"token"', '"balance"',
                           '"ssn"', '"address"', '"iban"')
        checks = [
            {"check": "private_markers_on_suffix", "pass":
             any(m in body_suffix for m in private_markers)},
            {"check": "not_marked_no_store",
             "pass": "no-store" not in cache_control.lower()},
            {"check": "suffix_serves_same_payload", "pass":
             body_suffix[:80] == body_base[:80]},
        ]
        if checks[0]["pass"] and checks[1]["pass"]:
            return self._v("Web cache deception", "CONFIRMED", checks,
                           f"suffix served private data with Cache-Control="
                           f"{cache_control!r}")
        return self._v("Web cache deception", "FAILED", checks,
                       "suffix path not serving private cacheable data")

    # ------------------------------------------------------------------
    def _v(self, claim: str, verdict: str, checks: list[dict], reason: str) -> OracleVerdict:
        log.info("oracle[%s] %s: %s", verdict, claim, reason)
        return OracleVerdict(claim=claim, verdict=verdict, checks=checks, reason=reason)
