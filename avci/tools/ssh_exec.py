"""ssh_exec — use DISCLOSED credentials against in-scope SSH ports.

Generic bug-bounty capability, not a CTF gadget: credential-disclosure
findings (source leaks, config dumps, base64/obfuscated passwords) only
become impact when they can be replayed against the service they belong
to. Scope-enforced like every other egress: ssh://host:port goes through
the same ScopeGuard as http.
"""

from __future__ import annotations

import asyncio

from ..scope.guard import ScopeGuard, ScopeViolation


def ssh_exec(guard: ScopeGuard, host: str, port: int, username: str,
             password: str = "", key_path: str = "",
             command: str = "id; hostname") -> dict:
    """Connect, run one bounded command, return {ok, stdout, stderr}."""
    guard.check_url(f"ssh://{host}:{port}")
    try:
        import paramiko
    except ImportError as exc:   # pragma: no cover - env-dependent
        return {"ok": False, "error": f"paramiko unavailable: {exc}"}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs: dict = {"hostname": host, "port": int(port),
                        "username": username, "timeout": 15,
                        "allow_agent": False, "look_for_keys": False}
        if key_path:
            kwargs["key_filename"] = key_path
        elif password:
            kwargs["password"] = password
        client.connect(**kwargs)
        _stdin, stdout, stderr = client.exec_command(command, timeout=25)
        out = stdout.read().decode("utf-8", "replace")[:8000]
        err = stderr.read().decode("utf-8", "replace")[:2000]
        return {"ok": True, "stdout": out, "stderr": err}
    except ScopeViolation:
        raise
    except Exception as exc:  # noqa: BLE001 - auth failures etc are data
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:400]}
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


async def ssh_exec_async(guard: ScopeGuard, **kw) -> dict:
    return await asyncio.to_thread(ssh_exec, guard, **kw)
