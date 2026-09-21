"""Surface watchtower — continuous monitoring (v0.5).

Enterprise programs don't run one hunt; they run a standing watch. This
module cycles recon over a scope, diffs every cycle against the previous
one and the cross-run DB, and pages the webhook when NEW surface appears
(a fresh subdomain is a fresh attack surface — and often a fresh bug).
`--hunt-new` escalates: brand-new subdomains get a bounded fleet hunt
automatically.

State: runs/watch-<domain>.json (last cycle's surface), AvciDB.hosts
(first_seen / last_seen across every watch ever run).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SurfaceDiff:
    new_subdomains: list[str] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    gone_hosts: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.new_subdomains or self.new_hosts or self.new_endpoints)

    def summary(self) -> str:
        parts = []
        if self.new_subdomains:
            parts.append(f"+{len(self.new_subdomains)} subdomains "
                         f"({', '.join(self.new_subdomains[:5])})")
        if self.new_hosts:
            parts.append(f"+{len(self.new_hosts)} live hosts")
        if self.new_endpoints:
            parts.append(f"+{len(self.new_endpoints)} endpoints")
        if self.gone_hosts:
            parts.append(f"-{len(self.gone_hosts)} hosts gone "
                         "(takeover candidates?)")
        return "; ".join(parts) or "no surface change"


def diff_surfaces(prev: dict, new: dict) -> SurfaceDiff:
    """Set-diff two surface snapshots ({subdomains,hosts,api_paths})."""
    def s(v: list | None) -> set[str]:
        return set(v or [])
    return SurfaceDiff(
        new_subdomains=sorted(s(new.get("subdomains")) - s(prev.get("subdomains"))),
        new_hosts=sorted(s(new.get("hosts")) - s(prev.get("hosts"))),
        new_endpoints=sorted(s(new.get("api_paths")) - s(prev.get("api_paths"))),
        gone_hosts=sorted(s(prev.get("hosts")) - s(new.get("hosts"))),
    )


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]+", "-", domain.lower()).strip("-") or "target"


def snapshot_of(surface_json: dict) -> dict:
    """Flatten a saved SurfaceModel into comparable sets."""
    hosts = {h.get("url", "") for h in surface_json.get("live_hosts", [])
             if isinstance(h, dict)}
    return {
        "subdomains": sorted(surface_json.get("subdomains", [])),
        "hosts": sorted(hosts),
        "api_paths": sorted(set(surface_json.get("api_paths", []))),
    }


async def watch_cycle(domain: str, settings, guard, db, notifier=None,
                      state_root: Path | None = None,
                      hunt_new: bool = False,
                      hunt_iterations: int = 20) -> dict:
    """One recon → diff → record → notify cycle. Returns the diff."""
    from .engine import run_recon, save_surface

    root = state_root or Path("runs")
    root.mkdir(parents=True, exist_ok=True)
    model = await run_recon(domain, settings, guard)
    surface_path = save_surface(model, root / f"watch-{_slug(domain)}")
    snap = snapshot_of(json.loads(surface_path.read_text(encoding="utf-8")))

    state_file = root / f"watch-{_slug(domain)}.state.json"
    prev: dict = {}
    if state_file.exists():
        try:
            prev = json.loads(state_file.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            prev = {}
    diff = diff_surfaces(prev, snap)
    state_file.write_text(json.dumps(snap, indent=1), encoding="utf-8")

    if db is not None:
        try:
            db.record_hosts([u.split("//", 1)[-1].split("/")[0]
                             for u in snap["hosts"]])
        except Exception:  # noqa: BLE001 — DB is an optimization, not a gate
            pass

    escalated: list[str] = []
    if hunt_new and diff.new_subdomains:
        try:
            from ..fleet import run_fleet
            res = await run_fleet(settings, list(diff.new_subdomains),
                                  concurrency=2, max_iterations=hunt_iterations)
            escalated = [t for t, r in (res.get("targets") or {}).items()
                         if (r or {}).get("findings")]
        except Exception:  # noqa: BLE001 — escalation is best-effort
            pass

    if notifier is not None and notifier.armed and not diff.empty:
        try:
            notifier.post(
                "AVCI watchtower",
                f"NEW SURFACE on {domain}: {diff.summary()}"
                + (f" — auto-hunted: {', '.join(escalated)}" if escalated else ""))
        except Exception:  # noqa: BLE001
            pass

    return {
        "domain": domain,
        "change": diff.summary(),
        "diff": {
            "new_subdomains": diff.new_subdomains,
            "new_hosts": diff.new_hosts,
            "new_endpoints": diff.new_endpoints[:80],
            "gone_hosts": diff.gone_hosts,
        },
        "snapshot": surface_path.name,
        "auto_hunted": escalated,
    }
