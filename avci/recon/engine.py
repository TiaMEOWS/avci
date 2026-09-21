"""Recon orchestrator — phased fan-out, produces the SurfaceModel JSON.

Phases (RedAmon doctrine, adapted):
  1. subdomains   — CT logs / wayback / dns bf / subfinder bridge
  2. probe        — liveness, tech, titles, TLS-scheme
  3. crawl        — own BFS + katana bridge
  4. js           — endpoint / secret / sourcemap mining
  5. params       — reflection discovery on interesting URLs
  6. ports        — top-port sweep on live hosts
  7. paths        — sensitive-path discovery, signature-verified
  8. takeover     — dangling-CNAME takeover fingerprints
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

from avci.core.http import make_client

from ..config import Settings
from ..scope.guard import ScopeGuard
from .crawl import crawl as crawl_surfaces
from .jsminer import fetch_and_mine
from .params import discover_params
from .ports import sweep_hosts
from .probe import probe_hosts
from .subdomains import enumerate_subdomains

log = logging.getLogger("avci.recon.engine")


@dataclass
class SurfaceModel:
    target: str
    started_at: str = ""
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)   # ProbeResult dicts
    pages: list[dict] = field(default_factory=list)        # Page dicts (capped)
    js_findings: list[dict] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    params: list[dict] = field(default_factory=list)       # ParamScan results
    forms: list[dict] = field(default_factory=list)
    ports: dict[str, list[int]] = field(default_factory=dict)
    secrets: list[dict] = field(default_factory=list)
    sourcemaps_open: list[str] = field(default_factory=list)
    path_hits: list[dict] = field(default_factory=list)    # PathHit dicts
    takeover: list[dict] = field(default_factory=list)     # TakeoverHit dicts

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)

    def summary(self) -> str:
        return (
            f"subdomains={len(self.subdomains)} live={len(self.live_hosts)} "
            f"pages={len(self.pages)} js={len(self.js_findings)} "
            f"api_paths={len(self.api_paths)} param_hits={len(self.params)} "
            f"forms={len(self.forms)} secrets={len(self.secrets)} "
            f"ports_hosts={len(self.ports)} sourcemaps={len(self.sourcemaps_open)} "
            f"path_hits={len(self.path_hits)} takeover={len(self.takeover)}"
        )


async def run_recon(
    domain: str, settings: Settings, guard: ScopeGuard
) -> SurfaceModel:
    guard.assert_scope_nonempty()
    # accept origin/URL-ish input: https://host:port/path → host (+port kept
    # for probing — a lab on :8901 must be probed ON :8901, not on 443/80)
    raw = domain.strip().lower()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    host = raw
    hostport = raw
    if ":" in raw and not raw.startswith("["):
        maybe_host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            host, hostport = maybe_host, f"{maybe_host}:{maybe_port}"
    if not guard.host_allowed(host):
        raise ValueError(f"{host} (from {domain!r}) not in scope {guard.rules}")

    model = SurfaceModel(target=host,
                         started_at=datetime.now(timezone.utc).isoformat())
    headers = {"User-Agent": settings.recon.user_agent}

    async with make_client(
        headers=headers, follow_redirects=True, verify=False, timeout=20
    ) as client:
        # ---- phase 1: subdomains
        log.info("[recon:1/8] subdomains for %s", host)
        model.subdomains = await enumerate_subdomains(host, guard, client)

        # ---- phase 2: probe (port-pinned origins probed on their port)
        log.info("[recon:2/8] probing %d hosts", len(model.subdomains) + 1)
        probe_targets = list({hostport, *model.subdomains})
        probed = await probe_hosts(probe_targets, guard, settings.recon, client)
        model.live_hosts = [
            {k: v for k, v in asdict(p).items() if k != "body_sample"}
            for p in probed
        ]

        # ---- phase 3: crawl live hosts (cap start URLs)
        log.info("[recon:3/8] crawling %d live roots", len(probed))
        roots = [p.url for p in probed][:20]
        crawled = await crawl_surfaces(roots, guard, settings.recon, client)
        model.pages = [
            {"url": pg.url, "status": pg.status, "title": pg.title,
             "params": sorted(pg.params)[:20]}
            for pg in crawled.pages[:400]
        ]
        model.forms = crawled.forms[:150]
        model.api_paths = sorted(crawled.api_paths)[:600]

        # ---- phase 4: JS mining
        log.info("[recon:4/8] mining %d JS bundles", len(crawled.js_urls))
        js = await fetch_and_mine(sorted(crawled.js_urls)[:400], guard, client)
        model.js_findings = []
        secrets: list[dict] = []
        for f in js:
            model.api_paths = sorted(set(model.api_paths) | {
                a for a in f.endpoints if len(a) < 300
            })[:600]
            secrets.extend(f.secrets)
            if f.sourcemap:
                model.sourcemaps_open.append(f.sourcemap)
            model.js_findings.append({
                "source": f.source_url, "size": f.size,
                "endpoints": sorted(f.endpoints)[:80],
                "hosts": sorted(f.hosts)[:30],
                "params": sorted(f.params)[:30],
            })
        model.secrets = secrets[:200]
        model.api_paths = sorted(set(model.api_paths))[:800]

        # ---- phase 5: params on juicy URLs
        juicy = [
            p["url"] for p in model.pages
            if p["status"] == 200 and ("?" in p["url"] or p.get("params"))
        ][:12]
        log.info("[recon:5/8] param discovery on %d urls", len(juicy))
        for u in juicy:
            scan = await discover_params(u, guard, client)
            if scan.hits:
                model.params.append({
                    "url": scan.url,
                    "hits": [{"param": h.param, "evidence": h.evidence}
                             for h in scan.hits[:25]],
                })

        # ---- phase 6: ports on live hosts
        log.info("[recon:6/8] port sweep on %d hosts", len(probed))
        model.ports = await sweep_hosts(
            [p.host for p in probed][:40], settings.recon.top_ports, guard
        )

        # ---- phase 7: sensitive-path sweep on primary live hosts
        log.info("[recon:7/8] sensitive paths on %d roots", len(roots))
        from .paths import discover_paths
        for root in roots[:3]:
            try:
                hits = await discover_paths(root, guard, client)
                model.path_hits.extend(asdict(h) for h in hits)
            except Exception as exc:  # noqa: BLE001
                log.debug("paths %s: %s", root, exc)
        model.path_hits = model.path_hits[:80]

        # ---- phase 8: dangling-CNAME takeover on subdomains
        log.info("[recon:8/8] takeover check on %d subdomains",
                 len(model.subdomains))
        from .takeover import check_takeover
        try:
            async def _fetch(u: str):
                return await client.get(u, timeout=12, follow_redirects=True)
            tk = await check_takeover(model.subdomains[:60], _fetch)
            model.takeover = [asdict(t) for t in tk]
        except Exception as exc:  # noqa: BLE001
            log.debug("takeover phase: %s", exc)

    log.info("recon done: %s", model.summary())
    return model


def save_surface(model: SurfaceModel, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"surface_{model.target.replace('*', '_')}.json"
    path.write_text(model.to_json(), encoding="utf-8")
    return path
