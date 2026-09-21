"""Markdown report writer — findings + coverage ledger + receipts."""

from __future__ import annotations

import json
from pathlib import Path

from ..store.state import RunState

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_report(state: RunState, meta: dict | None = None) -> str:
    meta = meta or {}
    lines: list[str] = []
    lines.append(f"# AVCI Hunt Report")
    lines.append("")
    lines.append(f"*Target:* `{meta.get('target', state.run_id)}`  ")
    lines.append(f"*Run:* `{state.run_id}`  ")
    if meta.get("model"):
        lines.append(f"*Model:* `{meta['model']}`  ")
    lines.append(f"*Scope:* `{'; '.join(meta.get('scope', []))}`  ")
    lines.append(f"*Requests logged:* {len(state.request_log)}  ")
    if meta.get("tokens"):
        t = meta["tokens"]
        lines.append(f"*Tokens:* prompt {t.get('prompt', 0):,} / "
                     f"completion {t.get('completion', 0):,}")
    lines.append("")

    # ---- findings -----------------------------------------------------
    from ..vulns.triage import redact_pii
    keep_hosts = [str(u) for u in (meta.get("scope") or [])]

    live = [f for f in state.findings if f.verdict != "refuted"]
    refuted = [f for f in state.findings if f.verdict == "refuted"]
    lines.append("## Findings")
    lines.append("")
    if not live:
        lines.append("_No findings recorded._")
    else:
        for i, f in enumerate(
            sorted(live, key=lambda f: _SEV_ORDER.get(f.severity, 9)), 1
        ):
            lines.append(f"### {i}. [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"* URL: `{f.url}`")
            if f.cwe:
                lines.append(f"* CWE: {f.cwe}")
            try:
                from ..vulns.compliance import map_finding
                cmap = map_finding(f.title, f.cwe or "")
                chips = cmap.get("owasp", []) + cmap.get("pci", []) + cmap.get("soc2", [])
                if chips:
                    lines.append(f"* Compliance: {', '.join(f'`{c}`' for c in chips)}")
            except Exception:  # noqa: BLE001
                pass
            lines.append(f"* Verdict: **{f.verdict}** (confidence: {f.confidence})")
            lines.append("")
            if f.description:
                lines.append(f.description)
                lines.append("")
            if f.evidence:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(redact_pii(f.evidence[:3000], keep_hosts))
                lines.append("```")
                lines.append("")
            if f.poc:
                lines.append("**PoC:**")
                lines.append("```")
                lines.append(redact_pii(f.poc[:2000], keep_hosts))
                lines.append("```")
                lines.append("")
    lines.append("")

    if refuted:
        lines.append("## Refuted by Gauntlet (kept for audit)")
        lines.append("")
        for f in refuted:
            lines.append(f"- ~~[{f.severity.upper()}] {f.title}~~ — "
                         f"`{f.url}` — "
                         f"{(f.description or '').split('[gauntlet:')[-1].strip(' ]')[:300]}")
        lines.append("")

    # ---- attack chains ---------------------------------------------------
    if state.findings:
        try:
            from ..vulns.chains import discover_chains
            chains = discover_chains(state.findings)
        except Exception:  # noqa: BLE001
            chains = []
        if chains:
            lines.append("## Attack Chains")
            lines.append("")
            for c in chains:
                steps = " → ".join(c.get("findings", []))
                lines.append(f"* **[{c.get('severity', '?').upper()}]** "
                             f"{c.get('title', 'chain')}: {steps}  ")
                if c.get("impact"):
                    lines.append(f"  *{c['impact']}*")
            lines.append("")

    # ---- threat model ---------------------------------------------------
    if state.threat_model:
        lines.append("## Threat Model")
        lines.append("")
        lines.append(state.threat_model)
        lines.append("")

    # ---- coverage ledger --------------------------------------------------
    lines.append("## Coverage Ledger")
    lines.append("")
    cs = state.coverage_summary()
    lines.append("| Outcome | Count |")
    lines.append("|---|---|")
    for k, v in cs.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")
    for c in state.coverage:
        lines.append(f"- `{c.target}` — **{c.check}** → *{c.outcome}* — {c.evidence[:300]}")
    lines.append("")

    # ---- notes -------------------------------------------------------------
    if state.notes:
        lines.append("## Notes")
        lines.append("")
        for n in state.notes:
            lines.append(f"- {n.get('content', '')[:400]}")
        lines.append("")

    # ---- footer --------------------------------------------------------------
    lines.append("---")
    lines.append("*Generated by AVCI (Autonomous Offensive Blackbox Hunter).*")
    lines.append("*Authorized testing only. Every request passed the fail-closed scope guard.*")
    return "\n".join(lines)


def write_report(state: RunState, out_dir: Path, meta: dict | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    path.write_text(render_report(state, meta), encoding="utf-8")
    # machine-readable twin
    (out_dir / "report.json").write_text(json.dumps({
        "run_id": state.run_id,
        "findings": [f.__dict__ for f in state.findings],
        "coverage": [c.__dict__ for c in state.coverage],
        "meta": meta or {},
    }, indent=2, default=str), encoding="utf-8")
    return path
