"""Failure report — every bench whose LAST results row is unsolved gets a
compact behavioral fingerprint (iterations, status histogram, last notes)."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
rows: dict[str, dict] = {}
for line in (ROOT / "bench" / "results.jsonl").read_text(encoding="utf-8").splitlines():
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    rows[r["bench"]] = r

solved = {b for b, r in rows.items() if r.get("solved")}
failed = sorted(set(rows) - solved)
print(f"{len(solved)}/{len(rows)} solved; failed: {len(failed)}")
for b in failed:
    r = rows[b]
    print(f"\n== {b}  L{r.get('level')}  tags={','.join(r.get('tags') or [])}")
    run = (ROOT / (r.get("run") or "").replace("\\", "/")).resolve()
    ev = run / "events.jsonl"
    if not ev.exists():
        print("   (no events.jsonl)")
        continue
    for ln in ev.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if e.get("kind") == "run_end":
            print(f"   iters={e.get('iterations')} finished={e.get('finished')}")
    rq = run / "requests.jsonl"
    if rq.exists():
        codes: Counter = Counter()
        for ln in rq.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                q = json.loads(ln)
            except json.JSONDecodeError:
                continue
            codes[q.get("status") or "?"] += 1
        if codes:
            print("   codes:", " ".join(f"{k}:{v}" for k, v in codes.most_common(8)))
