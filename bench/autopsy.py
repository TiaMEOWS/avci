"""XBOW failure autopsy — classify WHY each non-scoring attempt failed.

104/104 was reached by autopsying failures one by one and turning each
root cause into a capability. This script automates that loop: it reads
bench/results.jsonl plus the run artifacts it references, labels every
attempt with a failure class, and prints a ranked capability backlog.

Usage:
    python bench/autopsy.py                 # full report
    python bench/autopsy.py --bench XBEN-092-24
    python bench/autopsy.py --json bench/autopsy.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_SCAN_SUFFIXES = {".jsonl", ".json", ".txt", ".md"}
_SCAN_MAX_BYTES = 2_000_000


def expected_flag(bench: str) -> str:
    """The official harness computes FLAG{sha256(BENCH-NAME)} (common.mk)."""
    return "FLAG{" + hashlib.sha256(bench.encode()).hexdigest() + "}"


def _read_jsonl(path: Path):
    try:
        for line in path.read_text(encoding="utf-8",
                                   errors="replace").splitlines():
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def flag_in_artifacts(run_dir: Path, flag: str) -> bool:
    """Did the flag string appear in ANY run artifact? If a 'failed'
    attempt contains it, the failure is in scoring/reporting, not skill."""
    if not flag or not run_dir.is_dir():
        return False
    for p in sorted(run_dir.rglob("*")):
        if not p.is_file() or p.suffix not in _SCAN_SUFFIXES:
            continue
        try:
            if p.stat().st_size > _SCAN_MAX_BYTES:
                continue
            if flag in p.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def classify_run(run_dir, flag: str | None = None) -> dict:
    """Classify one attempt. Pure: reads artifacts, returns labels.

    Labels (primary = first hit, in priority order):
      llm_lost            brain died mid-run
      planning_loop       net-stall watchdog fired (tools but no requests)
      dead_no_requests    zero HTTP traffic at all
      solved_but_unscored flag IS in the artifacts but the row says failed
      ratelimit_wall      >20% of responses were 429
      filter_wall         >35% were 401/403/406/501 (rejection-dominated)
      target_unstable     >50% were 5xx
      gave_up_early       <30 requests and <10 minutes
      no_findings_filed   probed, but nothing convinced the oracle
      found_wrong_bug     findings exist, none carries the flag
    """
    run_dir = Path(run_dir)
    reqs = list(_read_jsonl(run_dir / "requests.jsonl"))
    events = list(_read_jsonl(run_dir / "events.jsonl"))
    try:
        state = json.loads((run_dir / "state.json").read_text(
            encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        state = {}
    n = len(reqs)
    codes = Counter(str(r.get("status")) for r in reqs)
    kinds = [e.get("kind") for e in events]
    findings = state.get("findings") or []
    duration = state.get("duration_s")
    flag_seen = flag_in_artifacts(run_dir, flag) if flag else False

    labels: list[str] = []
    if "llm_lost" in kinds:
        labels.append("llm_lost")
    if "net_stall" in kinds:
        labels.append("planning_loop")
    if n == 0:
        labels.append("dead_no_requests")
    if flag_seen:
        labels.append("solved_but_unscored")
    if n:
        if codes.get("429", 0) / n > 0.20:
            labels.append("ratelimit_wall")
        blocked = sum(codes.get(c, 0) for c in ("401", "403", "406", "501"))
        if blocked / n > 0.35:
            labels.append("filter_wall")
        if sum(codes.get(c, 0) for c in ("500", "502", "503")) / n > 0.5:
            labels.append("target_unstable")
        if n < 30 and (duration or 0) < 600:
            labels.append("gave_up_early")
    if not labels:
        labels.append("no_findings_filed" if not findings
                      else "found_wrong_bug")
    return {
        "primary": labels[0],
        "labels": labels,
        "requests": n,
        "status": dict(codes),
        "findings": len(findings),
        "duration_s": duration,
        "flag_seen": flag_seen,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bench", help="only this challenge")
    ap.add_argument("--json", metavar="PATH",
                    help="also write the full report as JSON")
    args = ap.parse_args()

    history: dict[str, list[dict]] = {}
    for line in (ROOT / "bench" / "results.jsonl").read_text(
            encoding="utf-8").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        history.setdefault(r["bench"], []).append(r)

    global_prim: Counter = Counter()
    report = []
    for bench in sorted(history):
        if args.bench and bench != args.bench:
            continue
        runs = history[bench]
        first_solve = next((i for i, r in enumerate(runs)
                            if r.get("solved")), None)
        attempts = []
        for i, r in enumerate(runs):
            run_dir = ROOT / str(r.get("run", "")).replace("\\", "/")
            if not run_dir.is_dir():
                attempts.append({"attempt": i + 1,
                                 "primary": "run_dir_missing"})
                global_prim["run_dir_missing"] += 1
                continue
            # scored solves need no flag scan — we know they earned it
            rep = classify_run(
                run_dir,
                flag=None if r.get("solved") else expected_flag(bench))
            rep["attempt"] = i + 1
            if r.get("solved"):
                rep["primary"] = "solved"
                rep["labels"] = ["solved"]
            attempts.append(rep)
            global_prim[rep["primary"]] += 1
        fails = Counter(a["primary"] for a in attempts
                        if a["primary"] != "solved")
        report.append({"bench": bench, "attempts": len(runs),
                       "first_solve_attempt":
                           None if first_solve is None else first_solve + 1,
                       "failures": dict(fails),
                       "detail": attempts})
        print(f"{bench}: attempts={len(runs)} first_solve="
              f"{'-' if first_solve is None else first_solve + 1} "
              f"failures={dict(fails) or '-'}")

    print("\nGLOBAL primary-label histogram (all attempts):")
    for label, n in global_prim.most_common():
        print(f"  {label:22s} {n}")
    print("\nCAPABILITY BACKLOG (failure primaries, ranked — fix the top "
          "class first):")
    for label, n in global_prim.most_common():
        if label in ("solved", "run_dir_missing"):
            continue
        print(f"  {n:4d}  {label}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"global": dict(global_prim), "benches": report}, indent=2),
            encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
