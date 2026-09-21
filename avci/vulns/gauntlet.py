"""AI Gauntlet — adversarial second pass over every recorded finding.

RedAmon doctrine: the hunting model wrote the claim; a separate adversarial
review pass tries to kill it before it reaches the report. For each finding
one cheap LLM call receives the claim + verbatim evidence and must answer
KEEP / DOWNGRADE / KILL with a rationale. Deterministic rules in
`vulns/triage.py` run first (at add_finding); the Gauntlet runs last (at
run end) and catches what regexes cannot: WAF pages read as reflections,
default bodies read as data, 404s read as disclosures.

Kill does not delete history: the finding is marked verdict="refuted" with
the rationale appended, and the report moves it to a refuted section.
Disable with AVCI_GAUNTLET=0.
"""

from __future__ import annotations

import json
import logging
import os

log = logging.getLogger("avci.gauntlet")

_SEV = ("critical", "high", "medium", "low", "info")

_GAUNTLET_PROMPT = """You are the GAUNTLET — an adversarial reviewer on an \
offensive-security hunting team. Your job is to KILL weak findings before \
they reach a client report. You are skeptical, technical, and you hate \
false positives.

A hunter submits this finding:

TITLE: {title}
SEVERITY: {severity}
URL: {url}
CWE: {cwe}
DESCRIPTION: {description}
VERBATIM EVIDENCE:
---
{evidence}
---
POC: {poc}

Attack it:
1. Does the evidence literally prove the claim (status codes, reflected
   bytes, timing, callback)? Or could the "proof" be a WAF page, a default
   body, a 404, an error page unrelated to the payload?
2. Is the impact real for THIS target (authentication state, data
   sensitivity, exploitability), or theoretical ("could potentially")?
3. Is the severity defensible to a triage team?

Answer STRICT JSON only:
{{"verdict": "keep" | "downgrade" | "kill",
  "severity": "critical"|"high"|"medium"|"low"|"info",
  "rationale": "one or two sentences, concrete"}}
"""


async def run_gauntlet(agent) -> dict:
    """Adversarially review every non-refuted finding. Mutates state.

    `agent` is a HunterAgent (uses its LLM client + cost tracker + state).
    Fail-closed on LLM errors: findings keep their pre-gauntlet standing
    and the failure is reported in the summary.
    """
    if os.environ.get("AVCI_GAUNTLET", "1") != "1":
        return {"skipped": "disabled via AVCI_GAUNTLET=0"}

    import asyncio

    findings = [f for f in agent.state.findings if f.verdict != "refuted"]
    if not findings:
        return {"reviewed": 0}

    kept = downgraded = killed = 0
    for f in findings:
        prompt = _GAUNTLET_PROMPT.format(
            title=f.title, severity=f.severity, url=f.url, cwe=f.cwe or "-",
            description=(f.description or "")[:1200],
            evidence=(f.evidence or "")[:2500],
            poc=(f.poc or "")[:800],
        )
        try:
            resp = await asyncio.to_thread(
                agent.llm.chat,
                [{"role": "user", "content": prompt}], None)
        except Exception as exc:  # noqa: BLE001 — brain hiccup ≠ finding death
            log.warning("gauntlet LLM call failed for %r: %s", f.title, exc)
            continue
        agent.cost.record(resp.usage.get("prompt_tokens", 0),
                          resp.usage.get("completion_tokens", 0))
        verdict = _parse(resp.text)
        if verdict is None:
            continue
        action = verdict.get("verdict", "keep")
        rationale = (verdict.get("rationale") or "").strip()[:500]
        new_sev = verdict.get("severity", f.severity)
        if new_sev not in _SEV:
            new_sev = f.severity
        if action == "kill":
            f.verdict = "refuted"
            f.description = (f.description + f"\n\n[gauntlet: KILLED — {rationale}]").strip()
            killed += 1
        elif action == "downgrade" and _rank(new_sev) < _rank(f.severity):
            f.severity = new_sev
            f.description = (f.description +
                             f"\n\n[gauntlet: {f.severity}→{new_sev} — {rationale}]").strip()
            downgraded += 1
        else:
            kept += 1
        agent.state.log_event("gauntlet", title=f.title, action=action,
                              severity=f.severity, rationale=rationale)

    return {"reviewed": len(findings), "kept": kept,
            "downgraded": downgraded, "killed": killed}


def _parse(text: str) -> dict | None:
    """Extract the first JSON object from a possibly chatty answer."""
    t = text.strip()
    a, b = t.find("{"), t.rfind("}")
    if a == -1 or b <= a:
        return None
    try:
        obj = json.loads(t[a:b + 1])
    except Exception:  # noqa: BLE001
        return None
    return obj if isinstance(obj, dict) else None


def _rank(sev: str) -> int:
    return _SEV.index(sev) if sev in _SEV else 2
