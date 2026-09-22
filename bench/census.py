"""XBOW scoreboard + attempt metrics from bench/results.jsonl.

104/104 is a pass@N figure (a challenge counts as solved if ANY attempt
solved it). For honest comparison with agents that report single-pass or
median scores, this script also prints pass@1 (first-attempt solves) and
the attempts-to-solve distribution."""
from __future__ import annotations

import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

history: dict[str, list[dict]] = {}
for line in (ROOT / "bench" / "results.jsonl").read_text(encoding="utf-8").splitlines():
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    history.setdefault(r["bench"], []).append(r)

rows = {b: runs[-1] for b, runs in history.items()}  # last row per bench wins

bench_root = ROOT / "xbow-bench" / "benchmarks"
levels: dict[str, list[str]] = {}
if bench_root.exists():
    for p in sorted(bench_root.iterdir()):
        if p.name.startswith("XBEN-"):
            try:
                d = json.loads((p / "benchmark.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            levels.setdefault(str(d.get("level")), []).append(p.name)
else:
    # benchmarks not cloned — tally what results know about
    for b, r in rows.items():
        levels.setdefault(str(r.get("level") or "?"), []).append(b)

total = solved_total = first_total = 0
for lv in sorted(levels):
    benches = sorted(levels[lv])
    solved = [b for b in benches if rows.get(b, {}).get("solved")]
    first = [b for b in benches
             if history.get(b) and history[b][0].get("solved")]
    total += len(benches)
    solved_total += len(solved)
    first_total += len(first)
    print(f"LEVEL{lv}: {len(solved)}/{len(benches)} solved "
          f"(pass@1 {len(first)}/{len(benches)})")
    for b in benches:
        r = rows.get(b)
        if not r or not r.get("solved"):
            print(f"   open {b}: " + ("never attempted" if not r else
                  f"iters={r.get('iterations')}"))
print(f"TOTAL: {solved_total}/{total} solved "
      f"(pass@1 {first_total}/{total}, {first_total / max(total, 1):.0%})")

solved_runs = {b: runs for b, runs in history.items()
               if rows.get(b, {}).get("solved")}
if solved_runs:
    def _first_solve(runs: list[dict]) -> int:
        # attempts until the FIRST solve — re-verification runs of an
        # already-solved challenge must not inflate the distribution
        for i, r in enumerate(runs, 1):
            if r.get("solved"):
                return i
        return len(runs)

    counts = sorted(_first_solve(runs) for runs in solved_runs.values())
    buckets = {"1": 0, "2-3": 0, "4-10": 0, "11+": 0}
    for n in counts:
        buckets["1" if n == 1 else "2-3" if n <= 3
                else "4-10" if n <= 10 else "11+"] += 1
    n_runs = sum(len(runs) for runs in history.values())
    stamps = sorted(r["ts"] for runs in history.values() for r in runs
                    if r.get("ts"))
    span = f"{stamps[0][:10]} -> {stamps[-1][:10]}" if stamps else "?"
    print(f"RUNS: {n_runs} attempts, {span}")
    print(f"ATTEMPTS-TO-SOLVE: median {statistics.median(counts)}, "
          f"mean {statistics.mean(counts):.1f}, max {max(counts)}")
    print("DISTRIBUTION: " + "  ".join(f"{k}:{v}"
                                       for k, v in buckets.items()))
