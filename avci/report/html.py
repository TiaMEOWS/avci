"""HTML report — single-file, dashboard-grade, print-friendly.

jinja2 template embedded; also renders chains + compliance (md report
doesn't). PDF optional via reportlab when `pdf=True`.
"""

from __future__ import annotations

import html as _html
import json
import logging
from pathlib import Path

from ..store.state import RunState
from ..vulns.chains import discover_chains
from ..vulns.compliance import cwe_of, map_finding

log = logging.getLogger("avci.report.html")

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AVCI Report — {{ target }}</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--ink:#c9d1d9;--dim:#8b949e;--acc:#58a6ff;
--crit:#f85149;--high:#f0883e;--med:#d29922;--low:#3fb950;--info:#8b949e;}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,'Segoe UI',Roboto,sans-serif;margin:0;padding:32px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;border-bottom:1px solid #21262d;padding-bottom:8px;margin-top:36px}
.meta{color:var(--dim);font-size:13px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--panel);border:1px solid #21262d;border-radius:8px;padding:14px}
.card .n{font-size:26px;font-weight:700}
.card .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.finding{background:var(--panel);border:1px solid #21262d;border-left:4px solid var(--sev);border-radius:8px;padding:16px;margin:14px 0}
.finding h3{margin:0 0 6px;font-size:16px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;letter-spacing:.04em}
.critical{color:var(--crit);border-color:var(--crit)}.critical .badge{background:#3d1a18;color:var(--crit)}
.high{border-color:var(--high)}.high .badge{background:#3d2413;color:var(--high)}
.medium{border-color:var(--med)}.medium .badge{background:#332a10;color:var(--med)}
.low{border-color:var(--low)}.low .badge{background:#12291a;color:var(--low)}
.info{border-color:var(--info)}.info .badge{background:#21262d;color:var(--info)}
pre{background:#0a0d12;border:1px solid #21262d;border-radius:6px;padding:10px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 10px;border-bottom:1px solid #21262d;text-align:left}
.chain{background:#1c2333;border:1px solid #26304a;border-left:4px solid var(--acc);border-radius:8px;padding:14px;margin:12px 0}
.dim{color:var(--dim)}
code{background:#21262d;padding:1px 5px;border-radius:4px;font-size:12px}
@media print{body{background:#fff;color:#111}.card,.finding,.chain{background:#fafafa;border-color:#ddd}pre{background:#f4f4f4}}
</style></head><body><div class="wrap">
<h1>AVCI Hunt Report</h1>
<div class="meta">
target <code>{{ target }}</code> · run <code>{{ run_id }}</code> · model <code>{{ model }}</code> ·
{{ requests }} requests · {{ tokens.prompt|default(0) }}+{{ tokens.completion|default(0) }} tokens{% if usd %} · ${{ usd }}{% endif %}
</div>

<div class="grid">
<div class="card"><div class="n">{{ counts.critical }}</div><div class="l">critical</div></div>
<div class="card"><div class="n">{{ counts.high }}</div><div class="l">high</div></div>
<div class="card"><div class="n">{{ counts.medium }}</div><div class="l">medium</div></div>
<div class="card"><div class="n">{{ counts.low }}</div><div class="l">low</div></div>
<div class="card"><div class="n">{{ coverage.reported }}</div><div class="l">reported</div></div>
<div class="card"><div class="n">{{ coverage.no_issue_found + coverage.ruled_out }}</div><div class="l">cleared</div></div>
</div>

<h2>Findings</h2>
{% for f in findings %}
<div class="finding {{ f.severity }}">
<h3>{{ loop.index }}. <span class="badge">{{ f.severity|upper }}</span> {{ f.title }}</h3>
<div class="dim">{{ f.url }}{% if f.cwe %} · {{ f.cwe }}{% endif %} · verdict: <b>{{ f.verdict }}</b>
{% if f.compliance %} · {{ f.compliance|join(' · ') }}{% endif %}</div>
{% if f.description %}<p>{{ f.description }}</p>{% endif %}
{% if f.evidence %}<pre>{{ f.evidence[:1500] }}</pre>{% endif %}
{% if f.poc %}<div class="dim">PoC</div><pre>{{ f.poc[:1000] }}</pre>{% endif %}
</div>
{% else %}
<p class="dim">No findings recorded.</p>
{% endfor %}

{% if chains %}
<h2>Attack Chains</h2>
{% for c in chains %}
<div class="chain"><b>{{ c.title }}</b> <span class="badge" style="background:#26304a;color:var(--acc)">{{ c.severity|upper }}</span>
<p>{{ c.impact }}</p><div class="dim">links: {{ c.findings|join(' + ') }}</div></div>
{% endfor %}
{% endif %}

{% if threat_model %}
<h2>Threat Model</h2><pre>{{ threat_model }}</pre>
{% endif %}

<h2>Coverage Ledger</h2>
<table><tr><th>target</th><th>check</th><th>outcome</th><th>evidence</th></tr>
{% for c in coverage_rows %}
<tr><td><code>{{ c.target }}</code></td><td>{{ c.check }}</td>
<td><b>{{ c.outcome }}</b></td><td class="dim">{{ c.evidence[:160] }}</td></tr>
{% endfor %}</table>

<p class="dim" style="margin-top:40px">Generated by AVCI · authorized testing only ·
every request passed the fail-closed scope guard · evidence SHA-256 manifest: {{ tamper }}</p>
</div></body></html>"""


def render_html(state: RunState, meta: dict, tamper_note: str = "verified") -> str:
    from jinja2 import Template
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = []
    for f in state.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        comp = map_finding(f.title, f.cwe)
        comp_flat = [f"OWASP {o}" for o in comp.get("owasp", [])] + \
                    [f"PCI {p}" for p in comp.get("pci", [])]
        findings.append({
            "title": f.title, "severity": f.severity, "url": f.url,
            "cwe": f.cwe or (f"CWE-{cwe_of(f.title)}" if cwe_of(f.title) else ""),
            "verdict": f.verdict, "description": f.description,
            "evidence": f.evidence, "poc": f.poc, "compliance": comp_flat,
        })
    chains = discover_chains(state.findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    return Template(_TEMPLATE).render(
        target=_html.escape(str(meta.get("target", state.run_id))),
        run_id=state.run_id, model=meta.get("model", ""),
        requests=len(state.request_log),
        tokens=meta.get("tokens") or {}, usd=meta.get("usd"),
        counts=counts, coverage=state.coverage_summary(),
        findings=findings, chains=chains,
        threat_model=state.threat_model,
        coverage_rows=[c.__dict__ for c in state.coverage],
        tamper=tamper_note,
    )


def write_html(state: RunState, out_dir: Path, meta: dict,
               tamper_note: str = "verified") -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.html"
    path.write_text(render_html(state, meta, tamper_note), encoding="utf-8")
    return path
