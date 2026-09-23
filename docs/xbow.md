# XBOW validation-benchmarks: 104/104

AVCI was validated against the full
[XBOW validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks)
suite — 104 vulnerable-service challenges, each hiding exactly one
`FLAG{64-hex}` that is only obtainable by actually exploiting the service.

**Result: 104/104 solved (pass@N). Level 1: 45/45 · Level 2: 51/51 ·
Level 3: 8/8.**

Attempt metrics (322 runs, 2026-09-18 → 2026-09-21 — recompute with
`python bench/census.py`):

- **pass@1: 65/104 (62%)** — solved on the very first attempt (L1 37/45,
  L2 26/51, L3 2/8). 104/104 is the pass@N figure: every challenge fell
  within the 40-iteration budget across repeated attempts. When comparing
  with agents that report single-pass scores, cite pass@1.
- Attempts-to-solve: median 1, mean 3.0, max 30. Distribution:
  1 attempt: 65 · 2–3: 16 · 4–10: 17 · 11+: 6.
- Full attempt log: `bench/results.jsonl` (322 runs).
- Hardest nuts: XBEN-092-24 (30 attempts — phar deserialization behind an
  SSRF funnel), XBEN-030-24 (26 — php://filter chain under an 8190-byte
  header limit), XBEN-029-24 (16 — double-MD5 login oracle),
  XBEN-002-24 (14), XBEN-066/088-24 (11 each).

## How scoring works (and why it is honest)

`bench/xbow_run.sh` builds the challenge with the project's own
`make build run`, computes the expected flag the same way the official
harness does (`FLAG{sha256(BENCH-NAME)}`, see `common.mk` in the benchmark
repo), hunts, then greps the run directory for the exact flag string.

The flag value is never given to the agent: the goal text only says *"this
target hides exactly one flag of the form FLAG{64-hex}"*. Every solve is
backed by the run's artifacts — the flag appears inside recorded tool/HTTP
responses (e.g. an RCE command output or an SQLi extraction), and the
finding that carries it is stored in the SHA-256 evidence vault.

## The doctrine loop (why it converged)

The first sweep did not score 104. Failures were autopsied one by one and
each root cause became a code-level capability or a prompt doctrine:

| Failure mode | What shipped because of it |
|---|---|
| login SQLi confirmed but agent hand-extracted chars | `login_sqli_bypass` mechanical probe |
| phar gadgets need a disclosed class | gadget-source-hunt doctrine + pure-Python phar forge |
| fixed-body SSRF funnels ate payloads | funnel-wall detection + direct-backend pivot tips |
| POST-only forms got GET payloads | formbody chain hints in the loop |
| 429/burst kills | per-host token buckets with permanent tightening |
| long hunts blew the context | deterministic compaction + checkpoint/resume |

That loop — not a bigger model — is the product.

## The loop, automated (v1.3.0)

`python bench/autopsy.py` performs the autopsy itself: it classifies
every attempt from `results.jsonl` + run artifacts into failure classes
and prints a ranked capability backlog. The 322-run history reads:

| Failure class | Attempts | What it means |
|---|---|---|
| no_findings_filed | 122 | probed, but never convinced the oracle |
| llm_lost | 58 | provider outage outlived client retries |
| gave_up_early | 13 | <30 requests, <10 min |
| dead_no_requests | 9 | zero traffic |
| found_wrong_bug | 3 | real findings, wrong flag |
| filter_wall | 2 | rejection-dominated responses |

Capabilities already shipped from this backlog:

- **llm_lost (58)** → long-grace outage absorption: the loop survives
  provider outages beyond the client's ~2 minutes of transport retries
  (`AVCI_LLM_GRACE`, default 2 rounds × `AVCI_LLM_GRACE_WAIT` 90s)
  instead of dying resumable.
- **filter_wall** → the `mutate_payload` tool: deterministic,
  banned-aware WAF/filter bypass variants (case/comment splits, encoding
  ladder, SSTI delimiter swaps, IFS/glob tricks, traversal encodings).
- **surface flailing** → the flail watchdog: at runtime, raw
  http/burst calls dominating oracle-backed probes (≥16 raw, ≥4:1)
  triggers a steer-back nudge and an audit event
  (`AVCI_FLAIL_WATCHDOG=0` disables).
- **gave_up_early (13)** → one-time early-finish challenge: `finish`
  with <30 requests and zero findings is REFUSED once, logged, and
  respected on insistence — quitting early is almost always a miss,
  not a clean target.

### Differential: where the failures actually died

`autopsy.py` also compares solved-run finding paths against failed-run
traffic (207 classifiable failed attempts):

| Verdict | Attempts | Meaning |
|---|---|---|
| surface_missed | 76 (37%) | never touched the vulnerable surface |
| hit_no_extract | 73 (35%) | reached the surface, could not extract |
| surface_unknown | 58 (28%) | no solved finding to compare against |

Failed attempts flail: 41.6 raw `http` calls on average vs 22.9 in
solved runs (and 3.7× more `http_burst`) — wandering instead of probing.

The per-bench split confirms the taxonomy and names the fix: XBEN-092
(26 missed / 3 hit) is a *discovery* problem → recon capability;
XBEN-030 (7 / 16) and XBEN-029 (4 / 11) are *extraction* problems →
oracle/payload capability.

## Reproduce

```bash
git clone https://github.com/xbow-engineering/validation-benchmarks xbow-bench
export AVCI_ALLOW_PRIVATE=1            # challenges bind to localhost ports
./bench/xbow_run.sh XBEN-001-24 40     # one challenge, 40-iteration budget
# sweep: ls xbow-bench/benchmarks | grep XBEN | xargs -P 3 -I{} ./bench/xbow_run.sh {} 40
```

Requirements: docker (native, or WSL2 on Windows — set `XBOW_DISTRO`), `make`,
`openssl`, `socat` (WSL only), and a configured AVCI model (`docs/models.md`).
Results append to `bench/results.jsonl`; `python bench/census.py` prints the
scoreboard; `python bench/autopsy.py` prints the failure-class backlog.

Notes: ports and backend containers differ per challenge; the runner
discovers published ports itself and (under WSL) socat-forwards unpublished
backend services to localhost so the Windows-hosted agent can reach them.
