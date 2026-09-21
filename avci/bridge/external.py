"""External tool bridges — nuclei / sqlmap / httpx as optional force
multipliers, scope-guarded and RoE-gated.

Design (audit lesson): bridges never widen scope. We pass exactly one URL,
disable crawling, and parse machine output only. sqlmap additionally
requires AVCI_ENABLE_SQLMAP=1 because active SQL exploitation is invasive.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field

from ..scope.guard import ScopeGuard

log = logging.getLogger("avci.bridge")


@dataclass
class BridgeResult:
    tool: str
    ok: bool
    findings: list[dict] = field(default_factory=list)
    raw_summary: str = ""
    error: str = ""


async def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "timeout"
    return proc.returncode or 0, out.decode("utf-8", errors="replace")


async def run_nuclei(target: str, guard: ScopeGuard, tags: str = "",
                      timeout: int = 420) -> BridgeResult:
    """nuclei -u <one url> -jsonl — no crawling, single host, JSONL parse."""
    guard.check_url(target)
    if not shutil.which("nuclei"):
        return BridgeResult("nuclei", False, error="nuclei binary not found")
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent",
           "-duc", "-timeout", "8", "-retries", "1"]
    if tags:
        cmd += ["-tags", tags]
    rc, out = await _run(cmd, timeout)
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        findings.append({
            "template": j.get("template-id") or j.get("info", {}).get("name"),
            "severity": (j.get("info", {}).get("severity") or "unknown"),
            "matched_at": j.get("matched-at") or j.get("host"),
            "curl": j.get("curl-command"),
            "reference": (j.get("references") or [None])[0],
        })
    return BridgeResult("nuclei", rc == 0 or bool(findings), findings=findings,
                        raw_summary=f"{len(findings)} template matches (rc={rc})")


async def run_sqlmap(url: str, guard: ScopeGuard, timeout: int = 480,
                     level: int = 2) -> BridgeResult:
    """sqlmap --batch on ONE url. Gated behind AVCI_ENABLE_SQLMAP=1."""
    guard.check_url(url)
    if os.environ.get("AVCI_ENABLE_SQLMAP") != "1":
        return BridgeResult("sqlmap", False,
                            error="sqlmap disabled (set AVCI_ENABLE_SQLMAP=1 "
                                  "— active SQL exploitation is RoE-sensitive)")
    if not shutil.which("sqlmap"):
        return BridgeResult("sqlmap", False, error="sqlmap binary not found")
    cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level),
           "--risk", "1", "--threads", "3", "--timeout", "10",
           "--retries", "2", "--output-dir", "runs/sqlmap",
           "--flush-session"]
    rc, out = await _run(cmd, timeout)
    findings = []
    for m in ("is vulnerable", "back-end DBMS", "sqlmap identified the "
              "following injection point"):
        if m.lower() in out.lower():
            findings.append({"marker": m})
            break
    for param_m in ("Parameter: ",):
        for line in out.splitlines():
            if line.startswith(param_m):
                findings.append({"parameter": line.strip()[:120]})
    return BridgeResult("sqlmap", bool(findings), findings=findings,
                        raw_summary=out[-3000:] if findings else
                        "no injection points reported")


async def run_httpx_tech(host: str, guard: ScopeGuard,
                         timeout: int = 120) -> BridgeResult:
    """projectdiscovery httpx tech-detect on a single host (safe, passive)."""
    if not guard.host_allowed(host):
        return BridgeResult("httpx", False, error="host out of scope")
    if not shutil.which("httpx"):
        return BridgeResult("httpx", False, error="httpx binary not found")
    cmd = ["httpx", "-u", host, "-tech-detect", "-status-code",
           "-title", "-silent", "-json"]
    rc, out = await _run(cmd, timeout)
    findings = []
    for line in out.splitlines():
        try:
            j = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        findings.append({"url": j.get("url"), "status": j.get("status_code"),
                         "title": j.get("title"),
                         "tech": j.get("tech")})
    return BridgeResult("httpx", bool(findings), findings=findings,
                        raw_summary=f"{len(findings)} hosts fingerprinted")


BRIDGES = {"nuclei": run_nuclei, "sqlmap": run_sqlmap, "httpx": run_httpx_tech}
