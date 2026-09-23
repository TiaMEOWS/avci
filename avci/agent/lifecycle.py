"""Lifecycle tools — todos, coverage ledger, notes, findings, finish.

strix doctrine: the agent's honesty is enforced by tools, not vibes.
finish() refuses while open todos or needs_follow_up items remain.
"""

from __future__ import annotations

from typing import Any

from ..store.state import RunState


def schema(name: str, desc: str, props: dict[str, Any],
           required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": required or [],
            },
        },
    }


class LifecycleTools:
    def __init__(self, state: RunState, finish_flag: dict,
                 notifier=None) -> None:
        self.state = state
        self._finish = finish_flag
        self.notifier = notifier

    # ------------------------------------------------------------------
    def schemas(self) -> list[dict]:
        return [
            schema("todo_write", "Replace the plan with a fresh numbered list.",
                   {"items": {"type": "array", "items": {"type": "string"}}},
                   ["items"]),
            schema("todo_update", "Mark a todo pending|in_progress|completed.",
                   {"id": {"type": "integer"}, "status": {"type": "string",
                    "enum": ["pending", "in_progress", "completed"]}},
                   ["id", "status"]),
            schema("coverage", (
                "Record an outcome for a checked surface. outcome ∈ "
                "{reported, no_issue_found, ruled_out, needs_follow_up, "
                "not_applicable}. Evidence is mandatory for "
                "no_issue_found/ruled_out."
            ), {
                "target": {"type": "string"},
                "check": {"type": "string"},
                "outcome": {"type": "string", "enum": [
                    "reported", "no_issue_found", "ruled_out",
                    "needs_follow_up", "not_applicable"]},
                "evidence": {"type": "string"},
            }, ["target", "check", "outcome", "evidence"]),
            schema("add_note", "Persist an observation/lesson for later runs.",
                   {"content": {"type": "string"}}, ["content"]),
            schema("write_threat_model",
                   "Record the ranked threat model for this target.",
                   {"model": {"type": "string"}}, ["model"]),
            schema("add_finding", (
                "Record a validated finding. Evidence (verbatim request/"
                "response excerpt) is MANDATORY — the oracle decides, not you."
            ), {
                "title": {"type": "string"},
                "severity": {"type": "string",
                             "enum": ["critical", "high", "medium", "low", "info"]},
                "url": {"type": "string"},
                "cwe": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"type": "string"},
                "poc": {"type": "string"},
                "verdict": {"type": "string",
                             "enum": ["candidate", "confirmed", "refuted"]},
            }, ["title", "severity", "url", "evidence"]),
            schema("finish", (
                "End the run. Refused while todos are open or coverage has "
                "unhandled needs_follow_up entries."
            ), {"summary": {"type": "string"}}, ["summary"]),
        ]

    # ------------------------------------------------------------------
    async def dispatch(self, name: str, args: dict) -> str:
        st = self.state
        if name == "todo_write":
            return st.todo_write(args["items"])
        if name == "todo_update":
            return st.todo_update(args["id"], args["status"])
        if name == "coverage":
            return st.add_coverage(args["target"], args["check"],
                                   args["outcome"], args["evidence"])
        if name == "add_note":
            guard = self._flag_fabrication_guard(st, args["content"])
            if guard is not None:
                return guard
            st.notes.append({"content": args["content"]})
            return "OK: noted"
        if name == "write_threat_model":
            st.threat_model = args["model"]
            return "OK: threat model recorded"
        if name == "add_finding":
            from ..store.state import Finding
            f = Finding(
                title=args["title"], severity=args["severity"], url=args["url"],
                cwe=args.get("cwe", ""), description=args.get("description", ""),
                evidence=args["evidence"], poc=args.get("poc", ""),
                verdict=args.get("verdict", "candidate"),
            )
            out = st.add_finding(f)
            if out.startswith("OK") and self.notifier is not None:
                try:
                    self.notifier.finding(f)   # pages critical/high only
                except Exception:  # noqa: BLE001 — alerting never kills hunts
                    pass
            return out
        if name == "finish":
            open_items = st.open_items()
            follow_ups = [
                c for c in st.coverage if c.outcome == "needs_follow_up"
                and not c.evidence.startswith("[handled]")
            ]
            if open_items:
                return ("REFUSED: open todos remain — " + "; ".join(open_items[:10]))
            if follow_ups:
                return ("REFUSED: unhandled needs_follow_up entries — "
                        f"{len(follow_ups)} items. Resolve them "
                        "(retry + re-record outcome, or rule_out with evidence).")
            # gave_up_early guard (autopsy: 13/322 XBOW attempts quit with
            # <30 requests and zero findings — almost always a miss, not a
            # clean target). One challenge; a second finish is respected.
            reqs = len(getattr(st, "request_log", []) or [])
            if (reqs < 30 and not st.findings
                    and not getattr(self, "_early_warned", False)):
                self._early_warned = True
                st.log_event("early_finish_warned", requests=reqs)
                return (
                    f"REFUSED (one-time): {reqs} requests and zero "
                    "findings — hunts that quit this early are almost "
                    "always misses, not clean targets. Sweep the untried "
                    "families first: authenticated surfaces, parameter "
                    "classes, probe classes you have not run. If coverage "
                    "is genuinely complete, call finish again — it will "
                    "be respected.")
            self._finish["done"] = True
            self._finish["summary"] = args["summary"]
            return "OK: run finished"
        return f"ERROR: unknown lifecycle tool {name}"

    # ------------------------------------------------------------------
    def _flag_fabrication_guard(self, st, content: str) -> str | None:
        """A FLAG_FOUND claim whose flag exists in NO captured traffic,
        evidence or finding of this run is a fabrication — reject it.

        The corpus is exactly what an honestly-obtained flag would appear
        in: observed tool results (response bodies, probe outputs), finding
        evidence, and on-disk artifacts (evidence/ files, captured.jsonl).
        Returns an error string to reject, None to accept.
        """
        import re
        if "FLAG_FOUND" not in content:
            return None
        m = re.search(r"FLAG_FOUND:\s*([A-Za-z0-9_]*\{[^}\s]+})", content)
        token = m.group(1) if m else ""
        if not token:
            return None  # no recognizable flag shape — nothing to verify
        corpus = st.observed_corpus()
        for f in st.findings:
            corpus += (getattr(f, "evidence", "") or "") + \
                      (getattr(f, "description", "") or "")
        try:
            for p in st.dir.rglob("*"):
                if p.is_file() and p.suffix in (".jsonl", ".txt", ".json",
                                                ".md", ".har", ".log") \
                        and p.name != "report.md":
                    try:
                        corpus += p.read_text(encoding="utf-8",
                                              errors="replace")[:2_000_000]
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass
        if token in corpus:
            return None
        return (
            "REJECTED (fabrication guard): the flag string in your "
            "FLAG_FOUND note appears in NO captured response, probe output, "
            "evidence file or finding of this run. A flag you did not "
            "receive from the target is a fabrication — go extract the "
            "REAL bytes (the exact string from a tool result) and quote "
            "them verbatim. If you cannot obtain the flag honestly, do "
            "not claim it: record coverage and finish."
        )
