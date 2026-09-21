"""file_ops — download artifacts and inspect them offline.

Generic bug-bounty capability: exposed S3 buckets, backup endpoints and
db dumps hand you BINARY artifacts (SQLite databases, ZIP/TAR archives,
APKs). An 8 KB tool-result excerpt of a binary is unreadable — the agent
needs to save the bytes to disk and analyze them: strings, SQLite table
dumps, archive listings, base64-column decoding. All pure stdlib.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import sqlite3
import zipfile
from pathlib import Path

import httpx

from ..scope.guard import ScopeGuard

_MAX_BYTES = 8 * 1024 * 1024   # hard cap on a saved artifact
_STRINGS_MIN = 5               # printable-run threshold for `strings`


def http_save(guard: ScopeGuard, url: str, name: str,
              artifacts_dir: str = ".") -> dict:
    """Download `url` into the run's artifacts dir; return path+sha+size."""
    guard.check_url(url)
    adir = Path(artifacts_dir)
    adir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "artifact")[:120]
    dest = adir / safe
    h = hashlib.sha256()
    n = 0
    try:
        with httpx.Client(verify=False, follow_redirects=True,
                          timeout=30) as client:
            with client.stream("GET", url) as r:
                if r.status_code >= 400:
                    return {"ok": False,
                            "error": f"HTTP {r.status_code} for {url}",
                            "status": r.status_code}
                with open(dest, "wb") as fh:
                    for chunk in r.iter_bytes(65536):
                        n += len(chunk)
                        if n > _MAX_BYTES:
                            return {"ok": False, "path": str(dest),
                                    "error": f"exceeds {_MAX_BYTES} byte cap"}
                        fh.write(chunk)
                        h.update(chunk)
    except Exception as exc:  # noqa: BLE001 - network failures are data
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
    return {"ok": True, "path": str(dest), "bytes": n,
            "sha256": h.hexdigest(),
            "hint": "inspect it now: file_inspect(path=...)"}


def _strings(data: bytes, limit: int = 4000) -> list[str]:
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= _STRINGS_MIN:
                out.append(cur.decode("ascii", "replace"))
                if sum(len(s) for s in out) > limit:
                    break
            cur.clear()
    if len(cur) >= _STRINGS_MIN:
        out.append(cur.decode("ascii", "replace"))
    return out


def _b64_candidates(strs: list[str]) -> list[str]:
    """Printable tokens that look like base64 — try decoding, keep hits."""
    hits = []
    for s in strs:
        for tok in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", s):
            try:
                dec = base64.b64decode(tok, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                continue
            if dec and sum(c.isalnum() or c in "_@.-" for c in dec) / len(dec) > 0.8:
                hits.append(f"{tok} -> {dec}")
            if len(hits) > 60:
                return hits
    return hits


def file_inspect(path: str) -> dict:
    """Offline analysis of a saved artifact: kind, SQLite dump, archive
    listing, strings excerpt, base64-token decode table."""
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": f"no such file: {path}"}
    data = p.read_bytes()[:_MAX_BYTES]
    out: dict = {"ok": True, "path": str(p), "bytes": len(data)}

    # SQLite database → dump schema + rows (the money shot for leaked dumps)
    if data.startswith(b"SQLite format 3"):
        out["kind"] = "sqlite"
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            tables = [r[0] for r in con.execute(
                "select name from sqlite_master where type='table'")]
            out["tables"] = tables
            dump: dict = {}
            for t in tables[:12]:
                cols = [d[1] for d in con.execute(f'pragma table_info("{t}")')]
                rows = con.execute(
                    f'select * from "{t}" limit 25').fetchall()
                dump[t] = {"columns": cols,
                           "rows": [[str(c)[:80] for c in r] for r in rows]}
            con.close()
            out["dump"] = dump
        except Exception as exc:  # noqa: BLE001
            out["sqlite_error"] = f"{type(exc).__name__}: {exc}"[:200]

    elif data.startswith(b"PK\x03\x04"):
        out["kind"] = "zip"
        try:
            zf = zipfile.ZipFile(p)
            out["entries"] = [(i.filename, i.file_size) for i in zf.infolist()
                              if not i.is_dir()][:200]
        except Exception as exc:  # noqa: BLE001
            out["zip_error"] = str(exc)[:200]

    else:
        out["kind"] = "binary" if b"\x00" in data[:512] else "text"
        out["head_hex"] = data[:96].hex()

    strs = _strings(data)
    out["strings_count"] = len(strs)
    out["strings"] = strs[:120]
    b64 = _b64_candidates(strs)
    if b64:
        out["base64_decoded"] = b64[:40]
    return out


def read_file(path: str, max_bytes: int = 6000) -> dict:
    """Read a saved artifact (or any local file) as text/hex excerpt."""
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": f"no such file: {path}"}
    data = p.read_bytes()[:max_bytes]
    try:
        return {"ok": True, "path": str(p), "text": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"ok": True, "path": str(p), "bytes": len(data),
                "head_hex": data[:512].hex()}
