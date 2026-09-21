"""SARIF 2.1.0 export — findings into CI/GitHub code-scanning format.

Enterprise requirement: the same run feeds the security team's SARIF
consumers (GitHub code scanning, Azure DevOps, DefectDojo imports) without
a human translating markdown.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

_LEVEL = {"critical": "error", "high": "error",
          "medium": "warning", "low": "note", "info": "note"}


def build_sarif(findings: list, run_id: str = "") -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        if getattr(f, "verdict", "") == "refuted":
            continue
        rule_id = f.cwe or "AVCI-GENERIC"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": rule_id},
            "properties": {"tags": ["security", "avci"]},
        })
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {(f.description or '')[:800]}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(f.url or "", safe=":/?&=%"),
                        "uriBaseId": "target",
                    },
                },
            }],
            "partialFingerprints": {"avciTitle/hash": _h(f.title + f.url)},
            "properties": {"severity": f.severity, "verdict": f.verdict,
                           "run": run_id},
        })
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AVCI",
                "informationUri": "https://example.invalid/avci",
                "rules": list(rules.values()),
            }},
            "originalUriBaseIds": {"target": {"uri": "https://target.invalid/"}},
            "results": results,
        }],
    }


def write_sarif(findings: list, out_dir: Path, run_id: str = "") -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.sarif"
    path.write_text(json.dumps(build_sarif(findings, run_id), indent=1),
                    encoding="utf-8")
    return path


def _h(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
