"""End-to-end with a scripted fake LLM: real ReAct loop, real tool dispatch,
real vulnerable lab over HTTP, real oracle verdicts — no API key needed.

Proves the wiring that unit tests can't: kickoff -> llm.chat -> tool
dispatch -> scope guard -> rate limiter -> request log -> evidence vault ->
triage gate -> findings -> finish -> run result. Gauntlet is disabled via
AVCI_GAUNTLET=0 (it has its own LLM pass, out of scope here)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from avci.config import Settings                      # noqa: E402
from avci.llm.client import LLMResponse, ToolCall     # noqa: E402
from avci.scope.guard import ScopeGuard               # noqa: E402
from avci.agent.loop import HunterAgent               # noqa: E402
from vuln_lab import Lab                              # noqa: E402
from http.server import HTTPServer                    # noqa: E402


class ScriptLLM:
    """Pops canned tool-call turns; the loop consumes them verbatim."""

    def __init__(self, script: list[list[tuple[str, dict]]]) -> None:
        self.script = list(script)
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

    def chat(self, messages, tools=None) -> LLMResponse:
        self.total_prompt_tokens += 10
        self.total_completion_tokens += 5
        if not self.script:
            return LLMResponse(text="(script exhausted)",
                               usage={"prompt_tokens": 10,
                                      "completion_tokens": 5})
        turn = self.script.pop(0)
        calls = [ToolCall(id=f"call_{i}", name=name, arguments=args)
                 for i, (name, args) in enumerate(turn)]
        return LLMResponse(tool_calls=calls,
                           usage={"prompt_tokens": 10,
                                  "completion_tokens": 5})


def test_e2e_scripted_hunt_against_lab(monkeypatch):
    monkeypatch.setenv("AVCI_GAUNTLET", "0")

    srv = HTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        with tempfile.TemporaryDirectory() as td:
            settings = Settings.load(scope=[f"127.0.0.1:{port}"])
            guard = ScopeGuard(rules=[f"127.0.0.1:{port}"], allow_private=True)
            agent = HunterAgent(settings, guard, Path(td), "e2e-mock")
            agent.llm = ScriptLLM([
                [("http", {"method": "GET", "url": f"{base}/"})],
                [("probe", {"name": "header_audit", "url": f"{base}/"})],
                [("probe", {"name": "xss_reflect",
                            "url": f"{base}/search?q=x", "param": "q"})],
                [("add_finding", {
                    "title": "Reflected XSS in /search",
                    "severity": "high",
                    "url": f"{base}/search?q=x",
                    "cwe": "CWE-79",
                    "evidence": "GET /search?q=<script>alert(1)</script> -> "
                                "200, payload reflected verbatim into the "
                                "results heading (oracle CONFIRMED)",
                    "verdict": "confirmed"})],
                [("coverage", {"target": f"{base}/search", "check": "xss",
                               "outcome": "reported",
                               "evidence": "oracle CONFIRMED reflection"})],
                [("finish", {"summary": "e2e mock run complete"})],
            ])

            result = asyncio.run(agent.run(f"127.0.0.1:{port}"))

            assert result["finished"] is True, result
            assert len(agent.state.findings) == 1
            assert agent.state.findings[0].severity == "high"
            assert len(agent.state.request_log) >= 3
            # evidence vault holds probe receipts and verifies clean
            assert agent.evidence.verify() == []
            assert (Path(td) / "evidence" / "manifest.jsonl").exists()
            # cost tracker consumed the fake usage
            assert agent.cost.summary()["llm_calls"] >= 6
            # checkpoint was written (every 5 iterations)
            assert (Path(td) / "checkpoint.json").exists()
            # report renders with the finding in it
            from avci.report.report import render_report
            md = render_report(agent.state, {"target": base,
                                             "scope": guard.rules})
            assert "Reflected XSS in /search" in md
    finally:
        srv.shutdown()
        srv.server_close()


def test_e2e_injection_guardrail_shields_target_content(monkeypatch):
    """A page ordering the agent around must reach the brain wrapped as
    untrusted data, and the hit must land in the audit log."""
    monkeypatch.setenv("AVCI_GAUNTLET", "0")

    srv = HTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        with tempfile.TemporaryDirectory() as td:
            settings = Settings.load(scope=[f"127.0.0.1:{port}"])
            guard = ScopeGuard(rules=[f"127.0.0.1:{port}"], allow_private=True)
            agent = HunterAgent(settings, guard, Path(td), "e2e-injection")

            class CaptureLLM(ScriptLLM):
                def __init__(self, script):
                    super().__init__(script)
                    self.seen: list[list[dict]] = []

                def chat(self, messages, tools=None):
                    self.seen.append([dict(m) for m in messages])
                    return super().chat(messages, tools)

            agent.llm = CaptureLLM([
                [("http", {"method": "GET", "url": f"{base}/guestbook"})],
                [("finish", {"summary": "injection fixture run"})],
            ])

            result = asyncio.run(agent.run(f"127.0.0.1:{port}"))

            assert result["finished"] is True, result
            tool_msgs = [m for turn in agent.llm.seen for m in turn
                         if m.get("role") == "tool"]
            assert any("BEGIN UNTRUSTED OUTPUT" in (m.get("content") or "")
                       for m in tool_msgs), tool_msgs
            events = [json.loads(line) for line in
                      (Path(td) / "events.jsonl").read_text(
                          encoding="utf-8").splitlines() if line.strip()]
            assert any(e.get("kind") == "injection_guard" for e in events)
    finally:
        srv.shutdown()
        srv.server_close()


def test_e2e_mutate_payload_tool_dispatch(monkeypatch):
    """The mutation engine is wired: schema reaches the brain, dispatch
    returns ranked variants, guardrail passes the JSON through clean."""
    monkeypatch.setenv("AVCI_GAUNTLET", "0")

    srv = HTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        with tempfile.TemporaryDirectory() as td:
            settings = Settings.load(scope=[f"127.0.0.1:{port}"])
            guard = ScopeGuard(rules=[f"127.0.0.1:{port}"], allow_private=True)
            agent = HunterAgent(settings, guard, Path(td), "e2e-mutate")

            class CaptureLLM(ScriptLLM):
                def __init__(self, script):
                    super().__init__(script)
                    self.seen: list[list[dict]] = []

                def chat(self, messages, tools=None):
                    self.seen.append([dict(m) for m in messages])
                    return super().chat(messages, tools)

            agent.llm = CaptureLLM([
                [("mutate_payload", {"payload": "1 UNION SELECT 1--",
                                     "cls": "sqli", "banned": ["'"]})],
                [("finish", {"summary": "mutate dispatch run"})],
            ])

            result = asyncio.run(agent.run(f"127.0.0.1:{port}"))

            assert result["finished"] is True, result
            tool_msgs = [m for turn in agent.llm.seen for m in turn
                         if m.get("role") == "tool"]
            assert tool_msgs
            out = json.loads(tool_msgs[0]["content"])
            assert out["ok"] is True and out["count"] > 0
            assert any("/**/" in v or "SELECT".lower() != v.lower()
                       for v in out["variants"])
    finally:
        srv.shutdown()
        srv.server_close()


def test_e2e_llm_grace_recovers_from_outage(monkeypatch):
    """A provider outage that kills the client's internal retries must not
    kill the hunt: grace rounds absorb it and the run completes."""
    monkeypatch.setenv("AVCI_GAUNTLET", "0")

    srv = HTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        with tempfile.TemporaryDirectory() as td:
            settings = Settings.load(scope=[f"127.0.0.1:{port}"],
                                     overrides={"llm.grace_wait": 0})
            guard = ScopeGuard(rules=[f"127.0.0.1:{port}"], allow_private=True)
            agent = HunterAgent(settings, guard, Path(td), "e2e-grace")

            class FlakyLLM(ScriptLLM):
                def __init__(self, script, fail_times=2):
                    super().__init__(script)
                    self.fail_times = fail_times
                    self.calls = 0

                def chat(self, messages, tools=None):
                    self.calls += 1
                    if self.calls <= self.fail_times:
                        raise RuntimeError("simulated provider outage")
                    return super().chat(messages, tools)

            agent.llm = FlakyLLM([
                [("finish", {"summary": "survived the outage"})],
            ])

            result = asyncio.run(agent.run(f"127.0.0.1:{port}"))

            assert result["finished"] is True, result
            assert agent.llm.calls == 3  # 2 outages + 1 success
            events = [json.loads(line) for line in
                      (Path(td) / "events.jsonl").read_text(
                          encoding="utf-8").splitlines() if line.strip()]
            grace_hits = [e for e in events if e.get("kind") == "llm_grace"]
            assert len(grace_hits) == 2
    finally:
        srv.shutdown()
        srv.server_close()


def test_e2e_flail_watchdog_fires_on_wandering(monkeypatch):
    """Raw-request wandering (16+ http calls, zero probes) must trigger
    the flail watchdog: a steer-back nudge reaches the brain and the
    event lands in the audit log."""
    monkeypatch.setenv("AVCI_GAUNTLET", "0")

    srv = HTTPServer(("127.0.0.1", 0), Lab)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        with tempfile.TemporaryDirectory() as td:
            settings = Settings.load(scope=[f"127.0.0.1:{port}"])
            guard = ScopeGuard(rules=[f"127.0.0.1:{port}"], allow_private=True)
            agent = HunterAgent(settings, guard, Path(td), "e2e-flail")

            class CaptureLLM(ScriptLLM):
                def __init__(self, script):
                    super().__init__(script)
                    self.seen: list[list[dict]] = []

                def chat(self, messages, tools=None):
                    self.seen.append([dict(m) for m in messages])
                    return super().chat(messages, tools)

            # 18 turns of raw http wandering, then finish
            agent.llm = CaptureLLM(
                [[("http", {"method": "GET",
                            "url": f"{base}/search?q={i}"})]
                 for i in range(18)]
                + [[("finish", {"summary": "wandered then finished"})]])

            result = asyncio.run(agent.run(f"127.0.0.1:{port}"))

            assert result["finished"] is True, result
            user_msgs = [m.get("content") or ""
                         for turn in agent.llm.seen for m in turn
                         if m.get("role") == "user"]
            assert any("FLAIL DETECTED" in c for c in user_msgs), user_msgs
            events = [json.loads(line) for line in
                      (Path(td) / "events.jsonl").read_text(
                          encoding="utf-8").splitlines() if line.strip()]
            assert any(e.get("kind") == "flail_watchdog" for e in events)
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    class _MP:
        @staticmethod
        def setenv(k, v):
            os.environ[k] = v
    test_e2e_scripted_hunt_against_lab(_MP())
    test_e2e_injection_guardrail_shields_target_content(_MP())
    test_e2e_mutate_payload_tool_dispatch(_MP())
    test_e2e_llm_grace_recovers_from_outage(_MP())
    test_e2e_flail_watchdog_fires_on_wandering(_MP())
    print("E2E MOCK OK — loop, dispatch, oracle, triage, vault, report, "
          "injection guardrail, mutate tool, llm grace, flail watchdog")
