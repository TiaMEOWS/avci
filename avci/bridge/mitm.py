"""Proxy capture ingest — Burp Suite / Caido / mitmproxy traffic in, hunt
surface out.

strix ships Caido MITM inside its container and RedAmon has TrafficMind;
the enterprise reality is the operator ALREADY has a proxy full of
authenticated traffic. This bridge ingests it:

- HAR (JSON, `entries[].request`) — Burp "Save items" / browser exports
- Caido/Burp item JSONL — one JSON object per line with a nested request
- mitmproxy flow dump (readable form) is handled via HAR conversion

Rows are scope-filtered (a capture file must never widen scope), then
written to the run's `captured.jsonl` where http_replay picks them up as
full-fidelity replay templates (headers + body included).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IngestResult:
    rows: list[dict]
    skipped_out_of_scope: int
    parser: str

    def summary(self) -> str:
        hosts: dict[str, int] = {}
        for r in self.rows:
            h = r["url"].split("//", 1)[-1].split("/", 1)[0]
            hosts[h] = hosts.get(h, 0) + 1
        top = ", ".join(f"{h}×{n}" for h, n in
                        sorted(hosts.items(), key=lambda kv: -kv[1])[:10])
        return (f"{len(self.rows)} captured requests ({self.parser}); "
                f"{self.skipped_out_of_scope} out-of-scope skipped; hosts: {top}")


def _norm(method: str, url: str, headers: list | dict, body: str,
          status) -> dict | None:
    if not url:
        return None
    if isinstance(headers, list):  # HAR style [{name, value}]
        hdrs = {h.get("name", ""): h.get("value", "")
                for h in headers if isinstance(h, dict)}
    else:
        hdrs = dict(headers or {})
    return {"method": (method or "GET").upper(), "url": url,
            "headers": hdrs, "body": body or "",
            "status": status if isinstance(status, int) else None,
            "tool": "mitm"}


def parse_har(data: dict) -> list[dict]:
    out: list[dict] = []
    for entry in data.get("log", {}).get("entries", []):
        req = entry.get("request", {}) or {}
        post = req.get("postData") or {}
        if not isinstance(post, dict):
            post = {"text": str(post)}
        row = _norm(req.get("method"), req.get("url"),
                    req.get("headers", []),
                    post.get("text", ""),
                    (entry.get("response", {}) or {}).get("status"))
        if row:
            out.append(row)
    return out


def parse_items_jsonl(text: str) -> list[dict]:
    """Caido/Burp item-per-line exports with nested request objects."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        req = obj.get("request", obj)
        if not isinstance(req, dict):
            continue
        post = req.get("postData", req.get("body", ""))
        if isinstance(post, dict):
            post = post.get("text", "")
        row = _norm(req.get("method"), req.get("url"),
                    req.get("headers", []),
                    post or "",
                    (obj.get("response", {}) or {}).get("status"))
        if row:
            out.append(row)
    return out


def ingest_file(path: Path, guard) -> IngestResult:
    """Parse + scope-filter a capture file → normalized rows."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".har" or '"log"' in raw[:500]:
        rows, parser = parse_har(json.loads(raw)), "har"
    else:
        rows, parser = parse_items_jsonl(raw), "items-jsonl"

    kept: list[dict] = []
    skipped = 0
    for r in rows:
        try:
            guard.check_url(r["url"])
            kept.append(r)
        except Exception:  # noqa: BLE001 — scope filter, not an error path
            skipped += 1
    return IngestResult(rows=kept, skipped_out_of_scope=skipped, parser=parser)


def write_captured(run_dir: Path, rows: list[dict]) -> Path:
    """Append full-fidelity rows to the run's captured.jsonl."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "captured.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path
