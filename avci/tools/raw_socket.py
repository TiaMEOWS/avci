"""raw_socket — send arbitrary bytes to a TCP port and read what comes back.

Generic bug-bounty capability, not a CTF gadget: request-smuggling suites
(CL.TE / TE.CL / TE.TE desync, header-name splitting, H2.CL) need BYTES the
httpx-backed `http` tool cannot express — a conflicting Content-Length plus
Transfer-Encoding, or a half-finished smuggled header waiting for the next
request on the same connection. This tool owns one TCP connection for the
whole call: every entry in `sends` goes out on the SAME socket in order
(that is the smuggling primitive — the follow-up request completes the
poisoned prefix), and the full transcript comes back. Scope-enforced like
every other egress.
"""

from __future__ import annotations

import asyncio

from ..scope.guard import ScopeGuard

_ESCAPES = {
    "\\r": "\r", "\\n": "\n", "\\t": "\t", "\\0": "\0",
    "\\\\": "\\",
}


def _decode(data: str) -> bytes:
    """Accept real newlines AND literal '\\r\\n' sequences, plus \\xHH."""
    out: list[str] = []
    i = 0
    while i < len(data):
        two = data[i:i + 2]
        if two in _ESCAPES:
            out.append(_ESCAPES[two])
            i += 2
            continue
        if two == "\\x" and i + 4 <= len(data):
            try:
                out.append(chr(int(data[i + 2:i + 4], 16)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(data[i])
        i += 1
    return "".join(out).encode("latin-1", "replace")


async def raw_socket(guard: ScopeGuard, host: str, port: int,
                     sends: list[str], gap_seconds: float = 1.0,
                     read_seconds: float = 4.0,
                     max_bytes: int = 262144) -> dict:
    """Open one TCP connection, send each payload in order, return the
    full raw transcript (server bytes are latin-1-decoded for display)."""
    port = int(port)
    guard.check_url(f"tcp://{host}:{port}")
    if not sends:
        return {"ok": False, "error": "sends must be a non-empty list"}
    payloads = [_decode(s) for s in sends]

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=8)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"connect failed: {exc}"}

    transcript: list[str] = []
    total = 0

    def _snapshot() -> str:
        buf = b""
        while True:
            chunk = reader._buffer[:max_bytes - len(buf)]  # noqa: SLF001
            if not chunk:
                break
            buf += chunk
            del reader._buffer[:len(chunk)]  # noqa: SLF001
        return buf.decode("latin-1", "replace")

    try:
        for idx, payload in enumerate(payloads):
            writer.write(payload)
            try:
                await asyncio.wait_for(writer.drain(), timeout=8)
            except Exception as exc:  # noqa: BLE001
                transcript.append(f"[send {idx + 1} failed: {exc!r}]")
                break
            # read whatever arrives while waiting for the next send
            await asyncio.sleep(gap_seconds)
            got = _snapshot()
            total += len(got)
            transcript.append(
                f"── after send {idx + 1} ({len(payload)} bytes) "
                f"received {len(got)} bytes ──\n{got}")
        # final quiet read: hold the socket open for leftover responses
        deadline = asyncio.get_event_loop().time() + read_seconds
        while asyncio.get_event_loop().time() < deadline and total < max_bytes:
            await asyncio.sleep(0.4)
            got = _snapshot()
            if got:
                total += len(got)
                transcript.append(f"── late read {len(got)} bytes ──\n{got}")
                deadline = asyncio.get_event_loop().time() + read_seconds
    except Exception as exc:  # noqa: BLE001
        transcript.append(f"[error: {exc!r}]")
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "host": host, "port": port,
            "sent": len(payloads), "received": total,
            "transcript": "\n".join(transcript)}
