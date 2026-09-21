"""End-to-end with a scripted fake LLM: real ReAct loop, real tool dispatch,
real vulnerable lab over HTTP, real oracle verdicts — no API key needed.

Proves the wiring that unit tests can't: kickoff -> llm.chat -> tool
dispatch -> scope guard -> rate limiter -> request log -> evidence vault ->
triage gate -> findings -> finish -> run result. Gauntlet is disabled via
AVCI_GAUNTLET=0 (it has its own LLM pass, out of scope here)."""

from __future__ import annotations

import asyncio
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


if __name__ == "__main__":
    class _MP:
        @staticmethod
        def setenv(k, v):
            os.environ[k] = v
    test_e2e_scripted_hunt_against_lab(_MP())
    print("E2E MOCK OK — loop, dispatch, oracle, triage, vault, report")
