"""Evidence vault — every receipt is an on-disk artifact with SHA-256.

pentest-ai doctrine: tamper-evident proof. Findings reference artifact
files; the manifest pins their hashes; `verify()` catches any later
modification of evidence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path

log = logging.getLogger("avci.store.evidence")


def _slug(text: str, maxlen: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:maxlen]
    return s or "evidence"


class EvidenceVault:
    def __init__(self, out_dir: Path) -> None:
        self.dir = out_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = self.dir / "manifest.jsonl"
        self._n = 0

    # ------------------------------------------------------------------
    def store(self, title: str, payload: dict) -> dict:
        """Write artifact + manifest row; return the receipt reference."""
        self._n += 1
        name = f"{self._n:03d}-{_slug(title)}.json"
        blob = json.dumps(payload, indent=2, default=str).encode("utf-8")
        digest = hashlib.sha256(blob).hexdigest()
        (self.dir / name).write_bytes(blob)
        row = {
            "n": self._n, "file": name, "sha256": digest,
            "title": title, "ts": time.time(), "bytes": len(blob),
        }
        with self.manifest.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        return {"artifact": name, "sha256": digest}

    # ------------------------------------------------------------------
    def verify(self) -> list[dict]:
        """Re-hash every artifact; return mismatch rows (empty = intact)."""
        problems: list[dict] = []
        if not self.manifest.exists():
            return problems
        for line in self.manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            path = self.dir / row["file"]
            if not path.exists():
                problems.append({"file": row["file"], "problem": "missing"})
                continue
            got = hashlib.sha256(path.read_bytes()).hexdigest()
            if got != row["sha256"]:
                problems.append({"file": row["file"], "problem": "hash-mismatch",
                                 "expected": row["sha256"], "actual": got})
        if problems:
            log.error("EVIDENCE TAMPERING DETECTED: %d artifacts", len(problems))
        return problems
