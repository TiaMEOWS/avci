"""Run state + findings persistence. JSONL event log + findings DB + todos.

Doctrine: strix's coverage ledger — every outcome lands in one of
{reported, no_issue_found, ruled_out, needs_follow_up, not_applicable}
with evidence, and the agent is not allowed to 'finish' with open items.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

OUTCOMES = ("reported", "no_issue_found", "ruled_out", "needs_follow_up", "not_applicable")

_SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    title: str
    severity: str  # critical|high|medium|low|info
    url: str
    cwe: str = ""
    description: str = ""
    evidence: str = ""
    poc: str = ""
    verdict: str = "candidate"  # candidate|confirmed|refuted
    confidence: str = "medium"

    def validate(self) -> list[str]:
        errs = []
        if self.severity not in _SEVERITIES:
            errs.append(f"bad severity {self.severity}")
        if not self.evidence:
            errs.append("no evidence — oracle requires proof")
        if not self.url:
            errs.append("no url")
        return errs


@dataclass
class TodoItem:
    id: int
    content: str
    status: str = "pending"  # pending|in_progress|completed


@dataclass
class CoverageEntry:
    target: str        # host/path/param surface id
    check: str         # what was checked
    outcome: str       # OUTCOMES
    evidence: str      # one-line proof / reason
    ts: float = 0.0


class RunState:
    """Thread-safe run store; writes JSON files under runs/<run_id>/."""

    def __init__(self, run_dir: Path, run_id: str) -> None:
        self.dir = run_dir
        self.run_id = run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.findings: list[Finding] = []
        self.todos: dict[int, TodoItem] = {}
        self.coverage: list[CoverageEntry] = []
        self.notes: list[dict] = []
        self.threat_model: str = ""
        self.events: list[dict] = []
        self.request_log: list[dict] = []
        # rolling corpus of tool-result text (responses, probe outputs) —
        # the fabrication guard checks FLAG_FOUND claims against it
        self.observed: deque[str] = deque(maxlen=800)
        self.started = time.time()

    # ------------------------------------------------------------------
    def log_event(self, kind: str, **data) -> None:
        evt = {"ts": time.time(), "kind": kind, **data}
        with self._lock:
            self.events.append(evt)
        with (self.dir / "events.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(evt, default=str) + "\n")

    def observe(self, text: str) -> None:
        """Record tool-result text (capped) for the fabrication guard."""
        if not text:
            return
        with self._lock:
            self.observed.append(text[:2000])

    def observed_corpus(self) -> str:
        with self._lock:
            return "".join(self.observed)

    def log_request(self, method: str, url: str, status: int | None = None,
                    tool: str = "") -> None:
        row = {"ts": time.time(), "method": method, "url": url,
               "status": status, "tool": tool}
        with self._lock:
            self.request_log.append(row)
        with (self.dir / "requests.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

    def log_captured(self, row: dict) -> None:
        """Full-fidelity captured request (headers+body) — http_replay feed."""
        with self._lock:
            self.request_log.append({
                "ts": row.get("ts", time.time()), "method": row.get("method", ""),
                "url": row.get("url", ""), "status": row.get("status"),
                "tool": row.get("tool", "mitm"),
            })
        with (self.dir / "captured.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

    # ------------------------------------------------------------------
    def add_finding(self, f: Finding) -> str:
        errs = f.validate()
        if errs:
            return "REJECTED: " + "; ".join(errs)
        # machine 7-Question Gate — deterministic triage before recording
        from ..vulns.triage import triage, DOWNGRADE, REJECT
        v = triage(f)
        if v.action == REJECT:
            self.log_event("finding_rejected", title=f.title,
                           severity=f.severity, url=f.url, reasons=v.reasons)
            return ("REJECTED (triage gate): " + "; ".join(v.reasons) +
                    " — fix the claim or provide vector evidence")
        if v.action == DOWNGRADE and v.severity and v.severity != f.severity:
            note = (f"[triage: {f.severity}→{v.severity} — "
                    f"{v.reasons[0]}]")
            f.description = (f.description + "\n" + note).strip()
            f.severity = v.severity
        if v.reasons and v.action != REJECT:
            f.confidence = "triaged"
        with self._lock:
            self.findings.append(f)
        self.log_event("finding", title=f.title, severity=f.severity, url=f.url,
                       triage=v.action, reasons=v.reasons)
        extra = ("" if not v.reasons else
                 f" (triage notes: {'; '.join(v.reasons)})")
        return f"OK: finding #{len(self.findings)} recorded" + extra

    def add_coverage(self, target: str, check: str, outcome: str,
                     evidence: str) -> str:
        if outcome not in OUTCOMES:
            return f"REJECTED: outcome must be one of {OUTCOMES}"
        if outcome in ("no_issue_found", "ruled_out") and not evidence.strip():
            return "REJECTED: no_issue_found/ruled_out require evidence"
        with self._lock:
            self.coverage.append(CoverageEntry(
                target, check, outcome, evidence.strip(), time.time()
            ))
        return f"OK: coverage #{len(self.coverage)} ({outcome})"

    # -- todos -----------------------------------------------------------
    def todo_write(self, items: list[str]) -> str:
        with self._lock:
            self.todos = {i: TodoItem(i, c) for i, c in enumerate(items)}
        return f"OK: {len(items)} todos"

    def todo_update(self, idx: int, status: str) -> str:
        if status not in ("pending", "in_progress", "completed"):
            return "REJECTED: bad status"
        with self._lock:
            t = self.todos.get(idx)
            if not t:
                return "REJECTED: no such todo id"
            t.status = status
        return f"OK: todo {idx} → {status}"

    # ------------------------------------------------------------------
    def coverage_summary(self) -> dict:
        with self._lock:
            out: dict[str, int] = {k: 0 for k in OUTCOMES}
            for c in self.coverage:
                out[c.outcome] += 1
        return out

    def open_items(self) -> list[str]:
        with self._lock:
            return [
                f"#{i} {t.content}" for i, t in self.todos.items()
                if t.status != "completed"
            ]

    # ------------------------------------------------------------------
    def snapshot(self) -> Path:
        data = {
            "run_id": self.run_id,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_s": round(time.time() - self.started, 1),
            "findings": [asdict(f) for f in self.findings],
            "coverage": [asdict(c) for c in self.coverage],
            "coverage_summary": self.coverage_summary(),
            "open_items": self.open_items(),
            "todos": [asdict(t) for t in self.todos.values()],
            "notes": self.notes,
            "threat_model": self.threat_model,
            "requests": len(self.request_log),
        }
        path = self.dir / "state.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path
