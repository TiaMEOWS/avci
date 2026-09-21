"""Fireteam — parallel hunts, one agent per target.

RedAmon doctrine: a fleet of cooperating hunters beats one exhausted
hunter on wide scope. AVCI's version is deliberately boring: N fully
equipped HunterAgents, each with its own run dir, state, probes, OOB
channels and rate budget, sharing one MCP manager (sessions serialize
per server anyway) and one scope guard. A semaphore caps concurrency so
a 50-asset program doesn't melt the LLM proxy.

Cross-agent coordination in v0.4 is the shared SQLite DB: every agent
records its findings at run end, and the fleet summary dedupes against
it — the fireteam's shared blackboard is the database, not chat.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("avci.fleet")


async def run_fleet(settings, targets: list[str], concurrency: int = 3,
                    mcp_manager=None, max_iterations: int | None = None) -> dict:
    from .agent.loop import HunterAgent
    from .core.notify import Notifier
    from .mcp.client import MCPManager
    from .scope.guard import ScopeGuard
    from .store.db import AvciDB

    guard = ScopeGuard(rules=list(settings.scope_rules),
                       allow_private=settings.agent.allow_private_targets)
    guard.assert_scope_nonempty()

    mcp = mcp_manager
    own_mcp = mcp is None
    if own_mcp and settings.mcp_config_path.exists():
        mcp = MCPManager()
        await mcp.load(settings.mcp_config_path)

    sem = asyncio.Semaphore(max(1, concurrency))
    results: dict[str, dict] = {}
    states: dict[str, object] = {}

    async def _hunt(target: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_dir = settings.state_dir / f"fleet-{stamp}-{_slug(target)}"
        agent = HunterAgent(settings, guard, run_dir, run_dir.name,
                            mcp_manager=mcp)
        async with sem:
            log.info("fleet hunter → %s (%s)", target, run_dir.name)
            try:
                results[target] = await agent.run(target)
                states[target] = agent.state
            except Exception as exc:  # noqa: BLE001 — one dead hunter ≠ fleet
                log.exception("fleet hunter %s crashed", target)
                results[target] = {"error": f"{type(exc).__name__}: {exc}",
                                   "findings": 0}

    try:
        await asyncio.gather(*(_hunt(t) for t in targets))
    finally:
        if own_mcp and mcp is not None:
            await mcp.close()

    total_findings = sum(r.get("findings", 0) for r in results.values())
    summary = {
        "targets": len(targets),
        "concurrency": concurrency,
        "total_findings": total_findings,
        "per_target": {t: {k: r.get(k) for k in
                           ("findings", "iterations", "finished",
                            "llm_lost", "requests")}
                       for t, r in results.items()},
    }

    # shared blackboard: every hunter's findings land in one DB
    try:
        db = AvciDB(settings.state_dir / "avci.db")
        try:
            for t, st in states.items():
                db.record_run(st, target=t, model=settings.llm.model)
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001
        log.warning("fleet db record failed: %s", exc)

    try:
        Notifier.from_env(Path("configs/notify.json")).post(
            "AVCI fleet finished",
            json.dumps(summary, default=str)[:3000])
    except Exception:  # noqa: BLE001
        pass
    return summary


def _slug(target: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in target)[:40].strip("-")
