"""XBOW scoreboard — per-level solve counts from bench/results.jsonl."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
rows: dict[str, dict] = {}
for line in (ROOT / "bench" / "results.jsonl").read_text(encoding="utf-8").splitlines():
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    rows[r["bench"]] = r  # last row per bench wins

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

total = solved_total = 0
for lv in sorted(levels):
    benches = sorted(levels[lv])
    solved = [b for b in benches if rows.get(b, {}).get("solved")]
    total += len(benches)
    solved_total += len(solved)
    print(f"LEVEL{lv}: {len(solved)}/{len(benches)} solved")
    for b in benches:
        r = rows.get(b)
        if not r or not r.get("solved"):
            print(f"   open {b}: " + ("never attempted" if not r else
                  f"iters={r.get('iterations')}"))
print(f"TOTAL: {solved_total}/{total}")
