"""AVCI command line (v0.2).

    avci hunt   --scope example.com [--tui] [--resume runs/<id>] [--mcp cfg]
    avci recon  --scope example.com
    avci register --target https://example.com --path /api/register [--browser]
    avci report --run runs/<id> [--html]
    avci mcp    (list attached servers/tools)
    avci doctor (environment + LLM + MCP health check)
    avci config (dump effective config)
"""

from __future__ import annotations

from avci.core.http import make_client

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Settings
from .scope.guard import ScopeGuard, ScopeViolation


def _guard_from(args, settings: Settings) -> ScopeGuard:
    rules = [r for r in (args.scope or []) if r]
    guard = ScopeGuard(rules=rules,
                       allow_private=settings.agent.allow_private_targets)
    guard.assert_scope_nonempty()
    return guard


def _run_dir(base: Path, name: str) -> tuple[Path, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = f"{name}-{stamp}"
    return base / run_id, run_id


def _wrap_up_reports(agent, result: dict, run_dir: Path, guard: ScopeGuard,
                     target: str, model: str) -> list[Path]:
    """Markdown + HTML reports, chains + compliance baked in."""
    from .report.html import write_html
    from .report.report import write_report
    meta = {
        "target": target, "scope": guard.rules, "model": model,
        "tokens": result.get("tokens"),
        "usd": (result.get("cost") or {}).get("usd"),
    }
    paths = [write_report(agent.state, run_dir, meta)]
    try:
        tamper = "verified" if not result.get("evidence_integrity",
                                              "OK").startswith("TAMPERED") \
            else str(result.get("evidence_integrity"))
        paths.append(write_html(agent.state, run_dir, meta, tamper))
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("avci.cli").warning("html report skipped: %s", exc)
    return paths


# ======================================================================
async def cmd_hunt(args) -> int:
    settings = Settings.load(
        scope=args.scope,
        overrides={"agent.max_iterations": args.max_iterations} if
        args.max_iterations else None)
    guard = _guard_from(args, settings)
    settings.state_dir.mkdir(parents=True, exist_ok=True)

    resume_state = None
    if args.resume:
        run_dir = Path(args.resume)
        from .agent.loop import HunterAgent
        resume_state = HunterAgent.load_checkpoint(run_dir)
        if resume_state is None:
            print(f"[-] no usable checkpoint.json in {run_dir}", file=sys.stderr)
            return 1
        run_id = resume_state.get("run_id", run_dir.name)
        print(f"[*] resume run: {run_dir} (iter {resume_state.get('iterations', 0)})")
    else:
        run_dir, run_id = _run_dir(settings.state_dir, "hunt")
        print(f"[*] run: {run_dir}")

    target = args.scope[0]

    if args.tui:
        from .tui import launch_tui
        result = launch_tui(settings, guard, run_dir, run_id, target,
                            resume_state=resume_state)
        # reports need the state the TUI worker wrote
        from .store.state import RunState
        from .report.report import write_report
        try:
            st = RunState(run_dir, run_id)
            data = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            from .store.state import CoverageEntry, Finding
            for f in data.get("findings", []):
                st.findings.append(Finding(**{k: v for k, v in f.items()
                                              if k in Finding.__dataclass_fields__}))
            for c in data.get("coverage", []):
                st.coverage.append(CoverageEntry(
                    c.get("target", ""), c.get("check", ""),
                    c.get("outcome", ""), c.get("evidence", ""),
                    c.get("ts", 0.0)))
            st.threat_model = data.get("threat_model", "")
            meta = {"target": target, "scope": guard.rules,
                    "model": settings.llm.model,
                    "usd": (result.get("cost") or {}).get("usd"),
                    "tokens": result.get("tokens")}
            rp = write_report(st, run_dir, meta)
            print(f"[+] report: {rp}")
        except Exception as exc:  # noqa: BLE001
            print(f"[-] report: {exc}", file=sys.stderr)
        print(json.dumps({k: v for k, v in result.items()
                          if k not in ("state_file",)}, indent=2, default=str))
        return 0

    from .mcp.client import MCPManager
    mcp = MCPManager()
    mcp_cfg = Path(args.mcp) if args.mcp else settings.mcp_config_path
    if mcp_cfg.exists():
        attached = await mcp.load(mcp_cfg)
        print(f"[*] MCP tools attached: {len(attached)}")

    from .agent.loop import HunterAgent
    agent = HunterAgent(settings, guard, run_dir, run_id,
                        mcp_manager=mcp, resume_state=resume_state,
                        goal=args.goal or "")
    result = await agent.run(target)

    rps = _wrap_up_reports(agent, result, run_dir, guard, target,
                           settings.llm.model)
    # enterprise persistence: every hunt lands in the cross-run DB + SARIF
    try:
        from .store.db import AvciDB
        db = AvciDB(settings.state_dir / "avci.db")
        try:
            db.record_run(agent.state, target=target,
                          model=settings.llm.model)
        finally:
            db.close()
        print("[+] db: runs/avci.db updated")
    except Exception as exc:  # noqa: BLE001
        print(f"[-] db: {exc}", file=sys.stderr)
    if agent.state.findings:
        try:
            from .report.sarif import write_sarif
            sp = write_sarif(agent.state.findings, run_dir, run_id)
            rps.append(sp)
        except Exception as exc:  # noqa: BLE001
            print(f"[-] sarif: {exc}", file=sys.stderr)

    print(json.dumps({k: v for k, v in result.items() if k != "state_file"},
                     indent=2))
    for rp in rps:
        print(f"[+] report: {rp}")
    await mcp.close()
    return 0


# ======================================================================
async def cmd_recon(args) -> int:
    settings = Settings.load(scope=args.scope)
    guard = _guard_from(args, settings)
    from .recon.engine import run_recon, save_surface
    model = await run_recon(args.scope[0], settings, guard)
    out = save_surface(model, Path("surface"))
    print(f"[+] {model.summary()}")
    print(f"[+] saved {out}")
    return 0


# ======================================================================
async def cmd_register(args) -> int:
    settings = Settings.load(scope=[_host_of(args.target)])
    guard = ScopeGuard(rules=[_host_of(args.target)],
                       allow_private=settings.agent.allow_private_targets)
    guard.assert_scope_nonempty()
    run_dir = Path("runs") / f"reg-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    from .browser.driver import BrowserDriver
    from .email.registration import RegistrationDriver
    from .mcp.client import MCPManager
    from .store.authvault import AuthVault
    mcp = MCPManager()
    mcp_cfg = Path(args.mcp) if args.mcp else settings.mcp_config_path
    if mcp_cfg.exists():
        await mcp.load(mcp_cfg)
    reg = RegistrationDriver(guard, AuthVault(run_dir / "vault"),
                             BrowserDriver(mcp))
    res = await reg.full_chain(
        target_origin=args.target,
        signup_path=args.path or "/api/register",
        use_browser=bool(args.browser),
    )
    print(json.dumps({
        "ok": res.ok, "email": res.email, "activated": res.activated,
        "otp": res.otp, "verify_url": res.verify_url, "notes": res.notes,
    }, indent=2))
    await mcp.close()
    return 0 if res.ok else 1


def _host_of(url: str) -> str:
    return url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]


# ======================================================================
def _load_state(run_dir: Path):
    state_json = run_dir / "state.json"
    if not state_json.exists():
        return None, None
    data = json.loads(state_json.read_text(encoding="utf-8"))
    from .store.state import CoverageEntry, Finding, RunState
    st = RunState(run_dir, data.get("run_id", run_dir.name))
    for f in data.get("findings", []):
        st.findings.append(Finding(**{k: v for k, v in f.items()
                                      if k in Finding.__dataclass_fields__}))
    for c in data.get("coverage", []):
        st.coverage.append(CoverageEntry(
            c.get("target", ""), c.get("check", ""), c.get("outcome", ""),
            c.get("evidence", ""), c.get("ts", 0.0)))
    st.threat_model = data.get("threat_model", "")
    st.notes = data.get("notes", [])
    return st, data


async def cmd_report(args) -> int:
    run_dir = Path(args.run)
    st, data = _load_state(run_dir)
    if st is None:
        print(f"[-] no state.json in {run_dir}", file=sys.stderr)
        return 1
    from .report.html import write_html
    from .report.report import write_report
    meta = {"run_id": data.get("run_id"), "target": data.get("run_id", "")}
    rp = write_report(st, run_dir, meta=meta)
    print(f"[+] {rp}")
    if args.html:
        try:
            hp = write_html(st, run_dir, meta)
            print(f"[+] {hp}")
        except Exception as exc:  # noqa: BLE001
            print(f"[-] html: {exc}", file=sys.stderr)
    if args.sarif:
        try:
            from .report.sarif import write_sarif
            sp = write_sarif(st.findings, run_dir, data.get("run_id", ""))
            print(f"[+] {sp}")
        except Exception as exc:  # noqa: BLE001
            print(f"[-] sarif: {exc}", file=sys.stderr)
    return 0


# ======================================================================
async def cmd_fleet(args) -> int:
    from .fleet import run_fleet
    settings = Settings.load(scope=args.scope,
                             overrides={"agent.max_iterations":
                                        args.max_iterations} if
                             args.max_iterations else None)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    summary = await run_fleet(settings, list(args.scope),
                              concurrency=args.concurrency,
                              max_iterations=args.max_iterations)
    print(json.dumps(summary, indent=2, default=str))
    return 0


# ======================================================================
async def cmd_db(args) -> int:
    from .store.db import AvciDB
    db = AvciDB(Path(args.db))
    try:
        if args.db_cmd == "findings":
            rows = db.findings(severity=args.severity or "", host=args.host or "")
            print(json.dumps(rows, indent=1, default=str))
        elif args.db_cmd == "runs":
            print(json.dumps(db.runs(), indent=1, default=str))
        elif args.db_cmd == "endpoints":
            print(json.dumps(db.endpoints(host=args.host or ""), indent=1))
        elif args.db_cmd == "hosts":
            print(json.dumps(db.hosts(), indent=1))
        elif args.db_cmd == "import":
            st, _ = _load_state(Path(args.run))
            if st is None:
                print(f"[-] no state.json in {args.run}", file=sys.stderr)
                return 1
            n = db.record_run(st)
            print(f"[+] imported {n} findings from {args.run}")
        elif args.db_cmd == "dedupe":
            st, _ = _load_state(Path(args.run))
            if st is None:
                print(f"[-] no state.json in {args.run}", file=sys.stderr)
                return 1
            for f in st.findings:
                dupes = db.similar(f.url, f.cwe or "", f.title)
                dupes = [d for d in dupes if d.get("run_id") != st.run_id]
                if dupes:
                    print(f"[!] possible duplicate: {f.title}")
                    for d in dupes:
                        print(f"    ↳ {d['run_id']} [{d['severity']}] "
                              f"{d['title']} {d['url']}")
            return 0
        else:
            print("[-] unknown db subcommand", file=sys.stderr)
            return 1
    finally:
        db.close()
    return 0


# ======================================================================
async def cmd_replay(args) -> int:
    """Standalone replay of a captured request (outside a hunt)."""
    from .core.replay import find_matches, inject_payload, load_captured, to_curl
    run_dir = Path(args.run)
    rows = load_captured(run_dir)
    matches = find_matches(rows, args.match)
    if not matches:
        print(f"[-] no captured request matches {args.match!r}", file=sys.stderr)
        return 1
    req = matches[-1]
    if args.payload and args.param:
        req = inject_payload(req, args.param, args.payload)
    print(to_curl(req))
    if args.send:
        import httpx
        from .config import Settings as _S
        s = _S.load(scope=[])
        guard = ScopeGuard(rules=args.scope or [],
                           allow_private=s.agent.allow_private_targets)
        guard.check_url(req.url)
        async with make_client(
                timeout=25, verify=False,
                headers={"User-Agent": s.recon.user_agent}) as client:
            r = await client.request(req.method, req.url,
                                     headers=req.headers or None,
                                     content=req.body or None)
            print(f"→ HTTP {r.status_code} {r.reason_phrase}")
            print(r.text[:4000])
    return 0


# ======================================================================
async def cmd_ingest_proxy(args) -> int:
    from .bridge.mitm import ingest_file, write_captured
    from .config import Settings as _S
    s = _S.load(scope=[])
    guard = ScopeGuard(rules=args.scope or [],
                       allow_private=s.agent.allow_private_targets)
    if args.scope:
        guard.assert_scope_nonempty()
    fpath = Path(args.file)
    if not fpath.exists():
        print(f"[-] {fpath} not found", file=sys.stderr)
        return 1
    res = ingest_file(fpath, guard)
    out_dir = Path(args.out) if args.out else \
        Path("runs") / f"ingest-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    out = write_captured(out_dir, res.rows)
    print(f"[+] {res.summary()}")
    print(f"[+] captured: {out}")
    print("[*] feed it to a hunt: avci hunt --resume … then mitm_import "
          f"{out} (or point --file at it)")
    return 0


# ======================================================================
async def cmd_submit(args) -> int:
    """Deterministic submission drafts for a run's live findings."""
    run_dir = Path(args.run)
    st, data = _load_state(run_dir)
    if st is None:
        print(f"[-] no state.json in {run_dir}", file=sys.stderr)
        return 1
    from .report.submission import write_submissions
    written = write_submissions(st, run_dir, only=args.only or "",
                                platform=args.platform)
    if not written:
        print("[-] nothing to draft (no matching live findings)")
        return 0
    for p in written:
        print(f"[+] draft: {p}")
    print("[*] review, adjust CVSS/wording, then paste into the program")
    return 0


# ======================================================================
async def cmd_watch(args) -> int:
    """Standing surface watch: recon → diff vs last cycle + DB → webhook.
    New subdomains can auto-hunt (--hunt-new)."""
    from .core.notify import Notifier
    from .recon.watch import watch_cycle
    from .store.db import AvciDB
    settings = Settings.load(scope=args.scope)
    guard = _guard_from(args, settings)
    notifier = Notifier.from_env(Path("configs/notify.json"))
    db = None
    try:
        db = AvciDB(settings.state_dir / "avci.db")
    except Exception as exc:  # noqa: BLE001 — watch works without the DB
        print(f"[-] db unavailable: {exc}", file=sys.stderr)
    domain = args.scope[0]
    interval = args.loop or 0
    try:
        while True:
            out = await watch_cycle(domain, settings, guard, db, notifier,
                                    state_root=settings.state_dir,
                                    hunt_new=args.hunt_new,
                                    hunt_iterations=args.max_iterations or 20)
            print(json.dumps(out, indent=1, default=str))
            if interval <= 0:
                break
            import asyncio as _a
            await _a.sleep(interval)
    finally:
        if db is not None:
            db.close()
    return 0


# ======================================================================
async def cmd_egress(args) -> int:
    """Show the live egress IP — verifies AVCI_PROXY / WARP instantly."""
    from .core.http import egress_proxy, make_client
    proxy = egress_proxy()
    print(f"[*] configured egress proxy: {proxy or '(direct)'}")
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            async with make_client(timeout=10) as c:
                r = await c.get(url)
            ip = r.text.strip()[:64]
            print(f"[+] egress IP via {url.split('/')[2]}: {ip}")
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"[-] {url}: {exc}")
    return 1


# ======================================================================
async def cmd_mcp(args) -> int:
    from .mcp.client import MCPManager
    mcp = MCPManager()
    cfg = Path(args.mcp or "configs/mcp_servers.json")
    if not cfg.exists():
        print(f"[-] {cfg} not found", file=sys.stderr)
        return 1
    attached = await mcp.load(cfg)
    print(f"[*] attached: {len(attached)} tools")
    for name in attached:
        print(f"  - {name}")
    await mcp.close()
    return 0


# ======================================================================
def cmd_doctor(args) -> int:
    """Preflight: LLM reachability, optional deps, MCP config validity."""
    import shutil

    settings = Settings.load(scope=[])
    ok = True

    print("[*] AVCI doctor")
    # -- LLM
    try:
        from .llm.client import LLMClient
        llm = LLMClient(settings.llm)
        r = llm.chat([{"role": "user", "content": "ping"}])
        where = settings.llm.base_url or "vendor API (env key)"
        print(f"[+] LLM {settings.llm.model} @ {where} "
              f"({len(r.text)} chars)")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"[-] LLM unreachable: {exc}")
        print("    set AVCI_LLM_MODEL + the vendor key "
              "(ANTHROPIC_API_KEY / OPENAI_API_KEY / DEEPSEEK_API_KEY / "
              "MOONSHOT_API_KEY) or AVCI_LLM_BASE_URL for a gateway "
              "— see docs/models.md")

    # -- optional deps
    for mod, why in (("textual", "TUI dashboard"), ("jinja2", "HTML report"),
                     ("playwright", "local browser fallback"),
                     ("litellm", "LLM routing"), ("mcp", "MCP client"),
                     ("cryptography", "encrypted auth vault"),
                     ("dns.resolver", "CNAME takeover checks")):
        try:
            __import__(mod)
            print(f"[+] {mod:14s} ({why})")
        except Exception:  # noqa: BLE001
            print(f"[ ] {mod:14s} ({why}) — optional, missing")

    # -- external binaries
    for binname, why in (("subfinder", "subdomain bridge"),
                         ("katana", "crawler bridge"),
                         ("arjun", "param bridge"),
                         ("naabu", "port bridge"),
                         ("nuclei", "CVE/misconfig bridge"),
                         ("httpx", "tech fingerprint bridge"),
                         ("sqlmap", "SQLi bridge (needs AVCI_ENABLE_SQLMAP=1)")):
        print(f"[{'+' if shutil.which(binname) else ' '}] {binname:14s} ({why})"
              + ("" if shutil.which(binname) else " — optional, missing"))

    # -- MCP config
    cfg = Path(args.mcp) if getattr(args, "mcp", None) else settings.mcp_config_path
    if cfg.exists():
        try:
            raw = json.loads(cfg.read_text(encoding="utf-8"))
            servers = (raw.get("mcpServers") or raw)
            for name, c in servers.items():
                state = "enabled" if c.get("enabled", True) else "disabled"
                print(f"[+] mcp {name}: {state} "
                      f"({c.get('url') or c.get('command', '?')})")
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"[-] mcp config invalid: {exc}")
    else:
        print(f"[ ] mcp config absent: {cfg}")

    # -- private-target policy
    print(f"[{'+' if settings.agent.allow_private_targets else ' '}] "
          f"AVCI_ALLOW_PRIVATE={int(settings.agent.allow_private_targets)} "
          f"(local lab testing)")

    # -- enterprise: notifications + cross-run DB + gauntlet
    from .core.notify import Notifier
    n = Notifier.from_env(Path("configs/notify.json"))
    print(f"[{'+' if n.armed else ' '}] notify          "
          + ("Discord/Telegram/generic armed" if n.armed
             else "no webhook configured (optional)"))
    try:
        from .store.db import AvciDB
        AvciDB(Path("runs/avci.db")).close()
        print("[+] sqlite store    (runs/avci.db — cross-run findings)")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"[-] sqlite store: {exc}")
    import os
    print(f"[{'+' if os.environ.get('AVCI_GAUNTLET', '1') == '1' else ' '}] "
          "gauntlet         (adversarial finding review at run end)")
    print("[*] " + ("ALL CRITICAL CHECKS PASSED" if ok else "ISSUES FOUND — see [-] lines"))
    return 0 if ok else 1


# ======================================================================
def cmd_config(args) -> int:
    settings = Settings.load(scope=args.scope)
    print(settings.dump())
    return 0


# ======================================================================
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="avci",
        description="AVCI — Autonomous Offensive Blackbox Hunter "
                    "(authorized targets only)",
    )
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_hunt = sub.add_parser("hunt", help="full autonomous hunt")
    p_hunt.add_argument("--scope", nargs="+", required=True,
                        help="authorized domains, e.g. example.com *.example.com")
    p_hunt.add_argument("--mcp", help="mcp_servers.json path")
    p_hunt.add_argument("--tui", action="store_true",
                        help="live Textual dashboard (q = graceful quit+snapshot)")
    p_hunt.add_argument("--resume", help="runs/<id> dir with checkpoint.json")
    p_hunt.add_argument("--goal", default="",
                        help="primary objective override (e.g. CTF flag extraction)")
    p_hunt.add_argument("--max-iterations", type=int, default=None)
    p_hunt.set_defaults(func=cmd_hunt)

    p_rec = sub.add_parser("recon", help="recon fan-out only")
    p_rec.add_argument("--scope", nargs="+", required=True)
    p_rec.set_defaults(func=cmd_recon)

    p_reg = sub.add_parser("register", help="temp-mail registration chain")
    p_reg.add_argument("--target", required=True, help="origin, https://x.com")
    p_reg.add_argument("--path", default="", help="signup endpoint path")
    p_reg.add_argument("--browser", action="store_true",
                       help="use browser form filling (MCP/playwright)")
    p_reg.add_argument("--mcp", help="mcp_servers.json path")
    p_reg.set_defaults(func=cmd_register)

    p_rep = sub.add_parser("report", help="(re)render report for a run")
    p_rep.add_argument("--run", required=True, help="runs/<id> directory")
    p_rep.add_argument("--html", action="store_true", help="also write HTML")
    p_rep.add_argument("--sarif", action="store_true",
                       help="also write SARIF 2.1 (CI/code-scanning)")
    p_rep.set_defaults(func=cmd_report)

    p_fleet = sub.add_parser(
        "fleet", help="parallel fireteam: one hunter per target")
    p_fleet.add_argument("--scope", nargs="+", required=True,
                         help="targets, one hunter each")
    p_fleet.add_argument("--concurrency", type=int, default=3)
    p_fleet.add_argument("--max-iterations", type=int, default=None)
    p_fleet.set_defaults(func=cmd_fleet)

    p_db = sub.add_parser("db", help="cross-run SQLite store (runs/avci.db)")
    p_db.add_argument("--db", default="runs/avci.db")
    p_db_sub = p_db.add_subparsers(dest="db_cmd", required=True)
    p_f = p_db_sub.add_parser("findings")
    p_f.add_argument("--severity", default="")
    p_f.add_argument("--host", default="")
    p_r = p_db_sub.add_parser("runs")
    p_e = p_db_sub.add_parser("endpoints")
    p_e.add_argument("--host", default="")
    p_h = p_db_sub.add_parser("hosts", help="watchtower host inventory")
    p_i = p_db_sub.add_parser("import", help="record a run dir into the DB")
    p_i.add_argument("--run", required=True)
    p_d = p_db_sub.add_parser("dedupe",
                              help="check a run's findings against the DB")
    p_d.add_argument("--run", required=True)
    p_db.set_defaults(func=cmd_db)

    p_rep2 = sub.add_parser("replay", help="replay a captured request")
    p_rep2.add_argument("--run", required=True, help="run dir with captures")
    p_rep2.add_argument("--match", required=True, help="url substring")
    p_rep2.add_argument("--param", default="")
    p_rep2.add_argument("--payload", default="")
    p_rep2.add_argument("--send", action="store_true",
                        help="actually send it (scope-guarded)")
    p_rep2.add_argument("--scope", nargs="*", default=[])
    p_rep2.set_defaults(func=cmd_replay)

    p_ing = sub.add_parser("ingest-proxy",
                           help="import Burp/Caido HAR or item JSONL")
    p_ing.add_argument("--file", required=True)
    p_ing.add_argument("--scope", nargs="*", default=[])
    p_ing.add_argument("--out", default="")
    p_ing.set_defaults(func=cmd_ingest_proxy)

    p_sub = sub.add_parser("submit",
                           help="draft program submissions from a run")
    p_sub.add_argument("--run", required=True, help="runs/<id> directory")
    p_sub.add_argument("--only", default="",
                       help="draft only findings whose title contains this")
    p_sub.add_argument("--platform", default="generic",
                       choices=["generic", "intigriti", "h1"])
    p_sub.set_defaults(func=cmd_submit)

    p_w = sub.add_parser("watch",
                         help="standing surface watch (recon diff + alerts)")
    p_w.add_argument("--scope", nargs="+", required=True,
                     help="domain to watch (first scope entry)")
    p_w.add_argument("--loop", type=int, default=0,
                     help="seconds between cycles (0 = single pass)")
    p_w.add_argument("--hunt-new", action="store_true",
                     help="auto-hunt brand-new subdomains (bounded fleet)")
    p_w.add_argument("--max-iterations", type=int, default=None,
                     help="iteration cap for --hunt-new spawned hunts")
    p_w.set_defaults(func=cmd_watch)

    p_mcp = sub.add_parser("mcp", help="list MCP servers/tools")
    p_mcp.add_argument("--mcp", help="mcp_servers.json path")
    p_mcp.set_defaults(func=cmd_mcp)

    p_eg = sub.add_parser("egress", help="show live egress IP (proxy/WARP check)")
    p_eg.set_defaults(func=cmd_egress)

    p_doc = sub.add_parser("doctor", help="environment + LLM + MCP health check")
    p_doc.add_argument("--mcp", help="mcp_servers.json path")
    p_doc.set_defaults(func=cmd_doctor)

    p_cfg = sub.add_parser("config", help="dump effective config")
    p_cfg.add_argument("--scope", nargs="*", default=[])
    p_cfg.set_defaults(func=cmd_config)

    args = ap.parse_args(argv)
    # normalize quoted multi-host scope args ("h1:80 h2:443" as one argv
    # item) into separate rules — a single bogus rule would silently block
    # every request as out-of-scope
    if getattr(args, "scope", None):
        args.scope = [r for chunk in args.scope for r in chunk.split() if r]
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        if asyncio.iscoroutinefunction(args.func):
            return asyncio.run(args.func(args))
        return args.func(args)
    except ScopeViolation as sv:
        print(f"[-] scope: {sv}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted — checkpoint.json holds your last state "
              "(avci hunt --resume runs/<id>)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
