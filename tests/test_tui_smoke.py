"""Headless TUI smoke — composes the dashboard, polls state, no network.

Run: python tests/test_tui_smoke.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from avci.config import Settings  # noqa: E402
from avci.scope.guard import ScopeGuard  # noqa: E402
from avci.store.state import Finding, RunState  # noqa: E402
from avci.tui.app import AvciTui  # noqa: E402


class StubAgent:
    """Duck-typed HunterAgent — what the TUI polls."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.iterations = 3
        self.phase_label = "hunt"

    def cost_summary(self) -> dict:
        return {"model": "claude-sonnet-4-5", "llm_calls": 3, "prompt_tokens": 1234,
                "completion_tokens": 567, "total_tokens": 1801, "usd": 0.0}


async def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        st = RunState(Path(td), "smoke")
        st.findings.append(Finding("Reflected XSS", "high",
                                   "https://t.io/s?q=1", evidence="x"))
        st.add_coverage("t.io/s", "xss", "reported", "oracle CONFIRMED")
        settings = Settings.load(scope=["t.io"])
        guard = ScopeGuard(rules=["t.io"])
        app = AvciTui(settings, guard, Path(td), "smoke", "t.io")

        started = {"n": 0}

        def fake_hunt() -> None:
            started["n"] += 1
            app.bind_agent(StubAgent(st))
            app._push_feed("stub hunt wired")

        app._run_hunt = fake_hunt  # no real hunt in smoke mode

        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            assert started["n"] == 1, "worker should have run"
            await pilot.pause(1.5)   # let poll_state tick
            meter = app.query_one("#meter")
            assert meter.is_mounted and app.snapshot.get("iterations") == 3
            ftab = app.query_one("#findings")
            assert ftab.row_count == 1, f"findings row {ftab.row_count}"
            ltab = app.query_one("#ledger")
            assert ltab.row_count == 1, f"ledger row {ltab.row_count}"
            await pilot.press("f")
            await pilot.press("c")
        print("TUI SMOKE OK — dashboard composed, state polled, "
              "findings/ledger rendered, bindings fire")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
