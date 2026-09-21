# Contributing

Thanks for helping AVCI hunt better.

## Ground rules

- **Authorized-testing posture is non-negotiable.** PRs that weaken the
  fail-closed scope guard, remove evidence requirements, or add
  "spray the internet" defaults will be rejected.
- **Evidence-first doctrine.** New vulnerability probes must return
  oracle-backed verdicts (CONFIRMED / FAILED / PENDING with receipts), not
  vibes. See `avci/vulns/probes3.py` for the pattern.
- Keep modules dependency-light: stdlib + httpx for anything on the hot
  path. Heavy/external tooling belongs behind a bridge (`avci/bridge/`).

## Dev setup

```powershell
git clone https://github.com/TiaMEOWS/avci
cd avci
pip install -e ".[browser,vault,tui,report]"
python -m pytest tests/ -q          # offline unit tests
python tests/vuln_lab.py 8901 &     # local vulnerable lab
$env:AVCI_ALLOW_PRIVATE = "1"
avci hunt --scope 127.0.0.1:8901    # end-to-end against the lab
```

## Where to help

- New probe classes (with oracles!) — `avci/vulns/`
- Browser/MCP robustness — `avci/mcp/`, `avci/browser/`
- Report formats — `avci/report/`
- Model quirks (tool-calling edge cases per provider) — `avci/llm/`

Run the tests before opening a PR; add one if you changed behavior.
