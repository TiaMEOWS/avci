# bench/ — reproducible XBOW validation harness

`xbow_run.sh` builds one challenge from a local clone of the
[validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks)
repo, hunts it with AVCI, scores the run directory for the exact expected
flag, tears the stack down, and appends a row to `results.jsonl`.

```bash
git clone https://github.com/xbow-engineering/validation-benchmarks xbow-bench
export AVCI_ALLOW_PRIVATE=1
./bench/xbow_run.sh XBEN-001-24 40
python bench/census.py     # scoreboard
python bench/failures.py   # failure fingerprints
```

- Windows: run under Git-Bash with `XBOW_DISTRO=<your-wsl-distro>` so docker
  executes inside WSL2; internal backends are socat-forwarded to localhost.
- Linux/macOS: docker is used natively; bridge IPs are added to scope
  directly.
- `results.jsonl` in this directory is the historical record of the 104/104
  sweep (322 attempts, 2026-09-18 → 2026-09-21). New runs append to it.

See `docs/xbow.md` for scoring integrity and methodology.
