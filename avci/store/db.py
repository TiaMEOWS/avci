"""Enterprise persistence — one SQLite DB across every run.

RedAmon keeps a Neo4j knowledge graph; the enterprise version of that for
AVCI is a dependency-free sqlite3 database holding every run, finding and
discovered endpoint, with cross-run dedupe (the operator's duplicate-
report scar tissue: 8 dups in 19 reports). `avci db findings|runs|export`
queries it; `hunt` records into it automatically at run end.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT, model TEXT, started TEXT, finished TEXT,
    findings INTEGER, requests INTEGER, finished_clean INTEGER,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT REFERENCES runs(run_id),
    title TEXT, severity TEXT, url TEXT, cwe TEXT,
    verdict TEXT, description TEXT, created TEXT,
    UNIQUE(run_id, title, url)
);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, method TEXT, url TEXT, status INTEGER, tool TEXT,
    UNIQUE(run_id, method, url)
);
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_hosts_seen ON hosts(last_seen);
"""

_TOKEN_STOP = re.compile(r"[^a-z0-9]+")


class AvciDB:
    def __init__(self, path: Path | str = Path("runs/avci.db")) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------
    def record_run(self, state, target: str = "", model: str = "") -> int:
        """Persist a finished RunState (findings + logged requests)."""
        c = self.conn
        c.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?)",
            (state.run_id, target, model, "", _now(),
             len(state.findings), len(state.request_log), 0, ""))
        for f in state.findings:
            c.execute(
                "INSERT OR IGNORE INTO findings "
                "(run_id,title,severity,url,cwe,verdict,description,created) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (state.run_id, f.title, f.severity, f.url, f.cwe or "",
                 f.verdict, (f.description or "")[:2000], _now()))
        for r in state.request_log[-2000:]:
            c.execute(
                "INSERT OR IGNORE INTO endpoints (run_id,method,url,status,tool) "
                "VALUES (?,?,?,?,?)",
                (state.run_id, r.get("method", ""), r.get("url", ""),
                 r.get("status"), r.get("tool", "")))
        self.conn.commit()
        return len(state.findings)

    # ------------------------------------------------------------------
    def similar(self, url: str, cwe: str, title: str) -> list[dict]:
        """Cross-run duplicate radar: same path + (same CWE or title≥0.5
        token overlap). Checked before a report goes out the door."""
        try:
            parts = urlsplit(url)
            base = f"{parts.netloc}{parts.path}"
        except Exception:  # noqa: BLE001
            return []
        rows = self.conn.execute(
            "SELECT run_id, title, severity, url, cwe, created FROM findings "
            "WHERE url LIKE ? AND run_id != ''", (f"%{base}%",)
        ).fetchall()
        out = []
        t_tokens = _tokens(title)
        for r in rows:
            if cwe and r["cwe"] and cwe == r["cwe"]:
                out.append(dict(r))
                continue
            other = _tokens(r["title"])
            overlap = len(t_tokens & other)
            if t_tokens and overlap / max(len(t_tokens | other), 1) >= 0.5:
                out.append(dict(r))
        return out

    # ------------------------------------------------------------------
    def findings(self, severity: str = "", host: str = "") -> list[dict]:
        q = "SELECT * FROM findings"
        conds, args = [], []
        if severity:
            conds.append("severity = ?")
            args.append(severity)
        if host:
            conds.append("url LIKE ?")
            args.append(f"%{host}%")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY rowid DESC LIMIT 500"
        return [dict(r) for r in self.conn.execute(q, args)]

    def runs(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM runs ORDER BY rowid DESC LIMIT 200")]

    def endpoints(self, host: str = "") -> list[dict]:
        q = "SELECT DISTINCT method, url, status FROM endpoints"
        args: list = []
        if host:
            q += " WHERE url LIKE ?"
            args.append(f"%{host}%")
        q += " LIMIT 1000"
        return [dict(r) for r in self.conn.execute(q, args)]

    # ------------------------------------------------------------------
    def record_hosts(self, hosts: list[str]) -> int:
        """Watchtower bookkeeping: first_seen sticks, last_seen refreshes."""
        n = 0
        for h in hosts:
            h = (h or "").strip()
            if not h:
                continue
            self.conn.execute(
                "INSERT INTO hosts (host, first_seen, last_seen) "
                "VALUES (?,?,?) ON CONFLICT(host) DO UPDATE SET last_seen=?",
                (h, _now(), _now(), _now()))
            n += 1
        self.conn.commit()
        return n

    def hosts(self, since: str = "") -> list[dict]:
        q = "SELECT * FROM hosts"
        args: list = []
        if since:
            q += " WHERE last_seen >= ?"
            args.append(since)
        q += " ORDER BY last_seen DESC LIMIT 1000"
        return [dict(r) for r in self.conn.execute(q, args)]


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _tokens(title: str) -> set[str]:
    return {t for t in _TOKEN_STOP.split((title or "").lower())
            if len(t) > 2}
