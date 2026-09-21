"""AVCI TUI — live hunt dashboard (Textual).

Runs the HunterAgent loop in a worker thread; the UI polls shared RunState
and renders: iteration feed, findings, coverage ledger, token/cost meter,
todo list. Keys: q=quit(snapshot)  p=pause-feed  c=coverage  f=findings.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (DataTable, Footer, Header, RichLog, Static)

from ..config import Settings
from ..scope.guard import ScopeGuard
from ..store.state import RunState

SEV_STYLE = {
    "critical": "bold red", "high": "bold orange1", "medium": "yellow",
    "low": "green", "info": "dim",
}


class Meter(Static):
    def on_mount(self) -> None:
        self.set_interval(1.0, self.refresh_values)

    def refresh_values(self) -> None:
        app = self.app
        if not isinstance(app, AvciTui):
            return
        s = app.snapshot
        cost = s.get("cost", {})
        feed = s.get("feed", [])
        last = feed[-1] if feed else ""
        self.update(
            f"[b]{s.get('phase', 'boot')}[/b] · iter [b]{s.get('iterations', 0)}[/b] · "
            f"req [b]{s.get('requests', 0)}[/b] · "
            f"tok {cost.get('prompt_tokens', 0):,}↑ {cost.get('completion_tokens', 0):,}↓"
            + (f" · ${cost.get('usd', 0)}" if cost.get("usd") else "")
            + f"\n[dim]{last[:110]}[/dim]"
        )


class AvciTui(App):
    TITLE = "AVCI — Autonomous Offensive Blackbox Hunter"
    CSS = """
    Screen { layout: vertical; }
    #top { height: 4; }
    #cols { height: 1fr; }
    #left { width: 40%; }
    #right { width: 60%; }
    #feed { height: 1fr; border: round $accent; }
    #findings { height: 12; border: round $success; }
    #ledger { height: 10; border: round $primary; }
    #todos { height: 1fr; border: round $secondary; }
    Meter { border: round $accent; height: 4; padding: 0 1; }
    """
    BINDINGS = [
        ("q", "quit", "quit (snapshots run)"),
        ("f", "focus_findings", "findings"),
        ("c", "focus_ledger", "coverage"),
    ]

    def __init__(self, settings: Settings, guard: ScopeGuard,
                 run_dir: Path, run_id: str, target: str,
                 mcp_manager=None, resume_state: dict | None = None) -> None:
        super().__init__()
        self.avci_settings = settings
        self.avci_guard = guard
        self.run_dir = run_dir
        self.run_id = run_id
        self.target = target
        self.mcp = mcp_manager
        self.resume_state = resume_state
        self.snapshot: dict = {"phase": "boot", "iterations": 0,
                               "requests": 0, "cost": {}, "feed": []}
        self._feed_lines: list[str] = []
        self._worker: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.result: dict = {}
        self._quit_requested = False

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical():
            yield Meter(id="meter")
            with Horizontal(id="cols"):
                with Vertical(id="left"):
                    yield DataTable(id="findings")
                    yield DataTable(id="ledger")
                with Vertical(id="right"):
                    yield RichLog(id="feed", markup=True, highlight=False, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        for table_id, title in (("findings", "FINDINGS"),
                                ("ledger", "COVERAGE LEDGER")):
            t = self.query_one(f"#{table_id}", DataTable)
            t.add_columns(*([title, "sev/outcome", "detail"][:3]))
        self.query_one("#feed", RichLog).write(
            f"[b]target[/b] {self.target} · [b]model[/b] "
            f"{self.avci_settings.llm.model} · [b]scope[/b] "
            f"{self.avci_guard.rules}")
        self.set_interval(0.6, self.poll_state)
        self._worker = threading.Thread(target=self._run_hunt, daemon=True)
        self._worker.start()

    # ------------------------------------------------------------------
    def _run_hunt(self) -> None:
        from ..agent.loop import HunterAgent
        from ..mcp.client import MCPManager
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            # MCP sessions are event-loop-bound: load them HERE, in the
            # worker loop, never on the UI thread's loop.
            mcp = self.mcp if self.mcp is not None else MCPManager()
            if not mcp.tool_names():
                self._loop.run_until_complete(
                    mcp.load(self.avci_settings.mcp_config_path))
            agent = HunterAgent(self.avci_settings, self.avci_guard,
                                self.run_dir, self.run_id,
                                mcp_manager=mcp, tui=self,
                                resume_state=self.resume_state)
            self.result = self._loop.run_until_complete(agent.run(self.target))
            self.snapshot["phase"] = "done"
            line = (f"RUN COMPLETE · findings={self.result.get('findings')} · "
                    f"finished={self.result.get('finished')}")
            self._push_feed(line)
        except Exception as exc:  # noqa: BLE001
            self.snapshot["phase"] = f"error: {exc}"
            self._push_feed(f"RUN ERROR: {exc}")
        finally:
            self._loop.close()

    def _push_feed(self, line: str) -> None:
        self._feed_lines.append(f"[dim]{time.strftime('%H:%M:%S')}[/dim] {line}")
        if len(self._feed_lines) > 400:
            self._feed_lines = self._feed_lines[-300:]

    def agent_hook(self, kind: str, detail: str = "") -> None:
        """Called by the loop thread (not UI thread) — just appends."""
        icon = {"iter": "→", "tool": "⚙", "finding": "★", "coverage": "✓",
                "recon": "◈", "register": "✉", "error": "✗"}.get(kind, "·")
        self._push_feed(f"{icon} {detail}")

    # ------------------------------------------------------------------
    def poll_state(self) -> None:
        state: RunState | None = None
        agent = getattr(self, "_agent_ref", None)
        snap = self.snapshot
        if agent is not None:
            state = agent.state
            snap["iterations"] = agent.iterations
            snap["phase"] = agent.phase_label
            cost = agent.cost_summary()
            snap["cost"] = cost
            snap["requests"] = len(agent.state.request_log)
        snap["feed"] = self._feed_lines[-1:]

        log_w = self.query_one("#feed", RichLog)
        shown = getattr(self, "_shown", 0)
        if len(self._feed_lines) > shown:
            for line in self._feed_lines[shown:]:
                log_w.write(line)
            self._shown = len(self._feed_lines)

        if state is not None:
            ftab = self.query_one("#findings", DataTable)
            if len(state.findings) != ftab.row_count:
                ftab.clear()
                for f in state.findings:
                    ftab.add_row(f.title[:52], f.severity, f.url[:44])
            ltab = self.query_one("#ledger", DataTable)
            if len(state.coverage) != ltab.row_count:
                ltab.clear()
                for c in state.coverage[-40:]:
                    ltab.add_row(c.target[:30], c.outcome, c.evidence[:60])

    # ------------------------------------------------------------------
    def bind_agent(self, agent) -> None:
        self._agent_ref = agent

    def action_focus_findings(self) -> None:
        self.query_one("#findings", DataTable).focus()

    def action_focus_ledger(self) -> None:
        self.query_one("#ledger", DataTable).focus()

    async def action_quit(self) -> None:
        self._quit_requested = True
        # ask the loop to stop after current tool call
        agent = getattr(self, "_agent_ref", None)
        if agent is not None:
            agent.stop_requested = True
        for _ in range(80):  # wait up to ~8s for graceful snapshot
            if self.snapshot.get("phase", "").startswith(("done", "stopped", "error")):
                break
            await asyncio.sleep(0.1)
        self.exit()


def launch_tui(settings: Settings, guard: ScopeGuard, run_dir: Path,
               run_id: str, target: str, mcp_manager=None,
               resume_state: dict | None = None) -> dict:
    app = AvciTui(settings, guard, run_dir, run_id, target,
                  mcp_manager, resume_state)
    app.run()
    return app.result or {"note": "no result (quit early)"}
