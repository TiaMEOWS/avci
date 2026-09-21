"""Deterministic finding triage — the machine version of the 7-Question Gate.

CyberStrike doctrine (vuln-scope.ts): a finding is a *candidate* until a
machine gate proves it carries a submittable vector and a defensible
severity. This module productises the triage lessons this operator has
paid for in real programs:

- farfetch: vectorless redirects are not submittable (cancelUrl KILL)
- superdrug: anonymous-resource ownership needs a demonstrated
  second-identity divergence (5/5 vectors negative → no submission)
- watsons: CORS decision tree — reflection alone is Low; arbitrary-origin
  reflection + credentials + private data is High
- digi: upload without render/serve path is a service bug, not XSS (M→L)
- PII redaction discipline: evidence carrying third-party PII is flagged

add_finding() runs this before recording; REJECT kills the finding,
DOWNGRADE adjusts severity and appends the reason to the description.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

ACCEPT, DOWNGRADE, REJECT = "accept", "downgrade", "reject"

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_SECRET_MARKERS = (
    "password", "passwd", "pwd", "api_key", "apikey", "api-key",
    "secret", "token", "dsn", "connection string", "private key",
    "striipe", "stripe", "aws_", "begin rsa",
)
_CRITICAL_MARKERS = (
    "rce", "remote code", "command exec", "shell", "7*7", "49",
    "sql dump", "union select", "dumped", "admin token", "auth bypass",
    "authentication bypass", "account takeover", "ato", "metadata",
    "169.254.169.254", "win.ini", "/etc/passwd", "root:", "flag{",
    "uid=", "unserializ", "deserializ", "file_get_contents(", "popen(",
    "os.system", "whoami", "cmd.exe",
)
_RCE_MARKERS = (
    "rce", "remote code", "command exec", "shell", "uid=", "flag{",
    "unserializ", "deserializ", "file_get_contents(", "popen(",
    "os.system", "whoami", "cmd.exe", "eval(",
)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[A-Za-z]{2,}\b")


@dataclass
class TriageVerdict:
    action: str = ACCEPT
    severity: str = ""
    reasons: list[str] = field(default_factory=list)

    def cap(self, sev: str, reason: str) -> None:
        """Lower the severity if currently above `sev` (never raise)."""
        if _SEV_RANK.get(self.severity, 2) > _SEV_RANK.get(sev, 2):
            self.severity = sev
            self.reasons.append(reason)
            if self.action == ACCEPT:
                self.action = DOWNGRADE

    def reject(self, reason: str) -> None:
        self.action = REJECT
        self.reasons.append(reason)


def redact_pii(text: str, keep_hosts: list[str] | None = None) -> str:
    """Mask e-mail addresses that don't belong to the target's own hosts.

    PII redaction discipline: reports must not carry third-party personal
    data. Target-domain addresses (the operator's own registered accounts)
    survive.
    """
    keep = [h.lower().lstrip("*.") for h in (keep_hosts or [])]

    def _sub(m: re.Match) -> str:
        addr = m.group(0)
        dom = addr.split("@", 1)[1].lower()
        if any(dom == k or dom.endswith("." + k) for k in keep):
            return addr
        local, _, tld = addr.partition("@")
        return f"{local[:2]}***@{dom}" if len(local) > 2 else f"***@{dom}"

    return _EMAIL_RE.sub(_sub, text)


def triage(finding) -> TriageVerdict:
    """Run the gate. `finding` is a store.state.Finding (duck-typed)."""
    blob = " ".join([
        finding.title or "", finding.description or "",
        (finding.cwe or "").lower(), finding.evidence or "",
    ]).lower()
    ev = (finding.evidence or "").lower()
    v = TriageVerdict(severity=finding.severity)

    if finding.verdict == "refuted":
        v.reject("verdict is refuted — oracle already falsified this claim")
        return v

    if not finding.evidence or len(finding.evidence.strip()) < 15:
        v.reject("evidence too thin — verbatim request/response proof required")
        return v

    # -- 1. redirects / SSO flows need a demonstrated hop -----------------
    if re.search(r"redirect|oauth|sso|callback|logout|returnurl|next=", blob):
        hop = re.search(
            r"location:\s*https?://([^\s/\"]+)", finding.evidence or "", re.I)
        off_scope = bool(hop)
        if off_scope:
            # a Location header exists — prove it leaves the target host
            target_host = _host_of(finding.url or "")
            loc_host = hop.group(1).lower()
            off_scope = target_host == "" or (
                loc_host != target_host
                and not loc_host.endswith("." + target_host)
            )
        if not (off_scope or "confirmed" in ev or "oob" in ev):
            v.reject("vectorless redirect — no demonstrated off-target hop "
                     "(farfetch cancelUrl lesson: not submittable)")
            return v

    # -- 2. anonymous resource ownership needs divergence -------------------
    if re.search(r"anonym|guest|unauth", blob) and re.search(
            r"cart|basket|order|profile|account|address", blob):
        divergence = bool(re.search(
            r"40[13].*(200|diverg|mismatch|different)|"
            r"(diverg|mismatch|different).*40[13]|session", blob))
        if not divergence:
            v.reject("anonymous-resource ownership without a demonstrated "
                     "second-identity divergence (superdrug lesson: "
                     "vectorless BOLA is not submittable)")
            return v

    # -- 3. CORS decision tree ----------------------------------------------
    if "cors" in blob or finding.cwe.lower().endswith("942"):
        flat = blob.replace(" ", "")
        creds = "access-control-allow-credentials:true" in flat \
            or "allow-credentials" in flat
        wildcard = "access-control-allow-origin:*" in flat
        private = any(m in ev for m in ("token", "email", "api_key", "apikey",
                                        '"id"', "session"))
        if wildcard or not creds:
            v.cap("low", "CORS reflection without credentials — Low "
                         "(watsons decision tree)")
        elif not private:
            v.cap("medium", "CORS with credentials but no private data in "
                            "the reflected response — Medium")

    # -- 4. upload without render/serve -------------------------------------
    if "upload" in blob:
        served = any(m in blob for m in (
            "render", "served", "xss", "<script", "svg", "text/html",
            "content-type: image", "location:", "execute"))
        # digi lesson targets upload-as-XSS hopes; an upload that delivers
        # code execution (phar/pickle deserialization, webshell) is the
        # opposite of "service bug" — never cap those.
        rce = any(m in blob for m in _RCE_MARKERS)
        if not served and not rce:
            v.cap("low", "upload stored but never rendered/served — service "
                         "bug, not XSS (digi chat-mdt lesson)")

    # -- 5. disclosure caps ----------------------------------------------------
    if re.search(r"stack ?trace|traceback|debug mode|debug = true", blob):
        if not any(m in ev for m in _SECRET_MARKERS):
            v.cap("low", "stack trace without secrets — Low")
    if "sourcemap" in blob or ".map" in blob:
        if not any(m in ev for m in _SECRET_MARKERS):
            v.cap("low", "sourcemap without embedded secrets — Low")
    if re.search(r"version|banner|server header", blob) and \
            not any(m in blob for m in ("sourcemap", ".git", ".env",
                                        "credential", "secret", "backup")):
        if not any(m in ev for m in _SECRET_MARKERS):
            v.cap("info", "pure version/banner disclosure — Info")

    # -- 6. critical sanity -----------------------------------------------------
    if _SEV_RANK.get(v.severity, 2) >= _SEV_RANK["critical"] and \
            not any(m in ev for m in _CRITICAL_MARKERS):
        v.cap("high", "critical requires RCE/auth-bypass/data-dump markers "
                      "in evidence — capped at High")

    # -- 7. PII flag (advisory, never blocks) ------------------------------------
    emails = _EMAIL_RE.findall(finding.evidence or "")
    host = _host_of(finding.url or "")
    third_party = [e for e in emails
                   if not host or not e.split("@")[1].lower().endswith(host)]
    if third_party:
        v.reasons.append(f"PII in evidence ({len(third_party)} third-party "
                         "addresses) — redact before submission")

    return v


def _host_of(url: str) -> str:
    return url.split("//", 1)[-1].split("/", 1)[0].split(":")[0].lower().lstrip("*.")
