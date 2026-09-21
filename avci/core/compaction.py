"""Deterministic context compaction for long hunts.

A 120-iteration hunt produces megabytes of tool output; no context window
survives that. strix-style pruning, rebuilt deterministically (no LLM call):
old tool messages are folded to head+tail excerpts, ancient assistant prose
is dropped, and a compaction marker is injected so the model knows.
"""

from __future__ import annotations

import json
import logging

log = logging.getLogger("avci.core.compaction")

TOOL_KEEP_CHARS = 1200     # per old tool message after compaction
RECENT_WINDOW = 14         # messages kept fully verbatim


def _compact_tool_content(content: str) -> str:
    if len(content) <= TOOL_KEEP_CHARS:
        return content
    head = content[:TOOL_KEEP_CHARS // 2]
    tail = content[-TOOL_KEEP_CHARS // 4:]
    return (f"{head}\n…[compacted from {len(content)} chars]…\n{tail}")


def estimate_chars(messages: list[dict]) -> int:
    total = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, str):
            total += len(c)
        elif c is None:
            total += len(json.dumps(m.get("tool_calls", [])))
        else:
            total += len(str(c))
    return total


def compact(messages: list[dict], threshold_chars: int = 120_000,
            recent_window: int = RECENT_WINDOW) -> tuple[list[dict], bool]:
    """Fold old tool outputs once the transcript exceeds `threshold_chars`.

    Returns (new_messages, did_compact). System prompt and the last
    `recent_window` messages are never touched.
    """
    size = estimate_chars(messages)
    if size <= threshold_chars:
        return messages, False

    cutoff = len(messages) - recent_window
    out: list[dict] = []
    for i, m in enumerate(messages):
        if i == 0 or i >= cutoff:
            out.append(m)
            continue
        role = m.get("role")
        if role == "tool":
            m = dict(m)
            m["content"] = _compact_tool_content(str(m.get("content") or ""))
            out.append(m)
        elif role == "assistant" and not m.get("tool_calls"):
            # drop ancient pure-prose turns; keep tool-call turns (history)
            continue
        else:
            out.append(m)

    marker = {
        "role": "user",
        "content": (
            f"[context compacted: transcript was {size:,} chars; older tool "
            f"outputs were folded to excerpts. Re-read surfaces with "
            f"read_surface / http if you need the full bytes.]"
        ),
    }
    out.insert(1, marker)
    log.info("compaction: %d → %d messages (%s → %s chars)",
             len(messages), len(out), f"{size:,}",
             f"{estimate_chars(out):,}")
    return out, True
