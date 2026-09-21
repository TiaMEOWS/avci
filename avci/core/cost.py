"""Cost tracking: per-call token accounting + USD estimates + JSONL audit."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("avci.core.cost")

# USD per 1M tokens (prompt, completion) — public list prices, approximate;
# unknown models and self-hosted/proxied gateways count as 0 (flat).
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4-1": (15.00, 75.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "gpt-5": (1.25, 10.00),
    "gpt-5-mini": (0.25, 2.00),
    "deepseek-chat": (0.27, 1.10),
    "kimi-k2": (0.60, 2.50),
}


@dataclass
class CostEntry:
    ts: float
    model: str
    prompt_tokens: int
    completion_tokens: int
    usd: float


class CostTracker:
    def __init__(self, model: str, out_dir: Path | None = None) -> None:
        self.model = model
        self.out_dir = out_dir
        self.entries: list[CostEntry] = []
        self._lock = threading.Lock()
        self.total_prompt = 0
        self.total_completion = 0
        self.total_usd = 0.0

    def record(self, prompt_tokens: int, completion_tokens: int) -> CostEntry:
        p_in, p_out = PRICES.get(self.model, (0.0, 0.0))
        usd = (prompt_tokens * p_in + completion_tokens * p_out) / 1_000_000
        e = CostEntry(time.time(), self.model, prompt_tokens,
                      completion_tokens, round(usd, 6))
        with self._lock:
            self.entries.append(e)
            self.total_prompt += prompt_tokens
            self.total_completion += completion_tokens
            self.total_usd += usd
        if self.out_dir is not None:
            try:
                self.out_dir.mkdir(parents=True, exist_ok=True)
                with (self.out_dir / "cost.jsonl").open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(e.__dict__) + "\n")
            except Exception as exc:  # noqa: BLE001
                log.debug("cost log write failed: %s", exc)
        return e

    def summary(self) -> dict:
        with self._lock:
            calls = len(self.entries)
        return {
            "model": self.model,
            "llm_calls": calls,
            "prompt_tokens": self.total_prompt,
            "completion_tokens": self.total_completion,
            "total_tokens": self.total_prompt + self.total_completion,
            "usd": round(self.total_usd, 4),
        }
