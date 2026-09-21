"""Generic MCP client — attach ANY Model Context Protocol server.

This is AVCI's wondersuite door (criterion 4): drop a server entry into
configs/mcp_servers.json and its tools appear to the agent as first-class
hunting tools (`mcp_<server>__<tool>`), scope-guarded at call time.

Pattern borrowed from strix / GH05TCREW `mcpServers.json` loading, hardened
with prompt-injection stripping (lesson from the MCP-Kali-Server audit).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import httpx

log = logging.getLogger("avci.mcp")

try:  # official SDK is the supported path
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamablehttp_client
    _MCP_OK = True
except Exception:  # noqa: BLE001 — degrade to config-only mode
    _MCP_OK = False


# Zero-width / bidi control chars — stripped from every tool result
_INVISIBLE = {
    "​", "‌", "‍", "‎", "‏",
    "‪", "‫", "‬", "‭", "‮",
    "⁠", "⁡", "⁢", "⁣", "⁤",
    "﻿", "­",
}


def strip_invisibles(text: str) -> str:
    return "".join(ch for ch in text if ch not in _INVISIBLE)


@dataclass
class MCPServerDef:
    name: str
    transport: str  # "stdio" | "http"
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    allow_tools: list[str] = field(default_factory=list)  # empty = all (strix)


def filter_tools(tool_names: list[str], allow: list[str]) -> list[str]:
    """strix doctrine: a per-server allowlist beats a 90-tool prompt dump."""
    if not allow:
        return list(tool_names)
    exact = set(allow)
    pats = [a for a in allow if a.endswith("*")]
    return [t for t in tool_names
            if t in exact or any(t.startswith(p[:-1]) for p in pats)]


def load_server_defs(path: Path) -> dict[str, MCPServerDef]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    defs: dict[str, MCPServerDef] = {}
    for name, cfg in (raw.get("mcpServers") or raw).items():
        if not cfg.get("enabled", True):
            continue
        if "url" in cfg:
            defs[name] = MCPServerDef(
                name=name, transport="http", url=cfg["url"],
                headers=cfg.get("headers", {}),
                allow_tools=cfg.get("allow_tools", []),
            )
        else:
            defs[name] = MCPServerDef(
                name=name, transport="stdio", command=cfg.get("command", ""),
                args=cfg.get("args", []), env=cfg.get("env", {}),
                allow_tools=cfg.get("allow_tools", []),
            )
    return defs


class MCPManager:
    """Owns live MCP sessions; exposes tools to the agent loop.

    Sessions are long-lived tasks; calls are serialized per server via a lock
    (the stdio transport is a single pipe).
    """

    def __init__(self) -> None:
        self.defs: dict[str, MCPServerDef] = {}
        self._sessions: dict[str, ClientSession] = {}
        self._ctxs: dict[str, object] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._tool_index: dict[str, tuple[str, str]] = {}  # full_name → (server, tool)

    # ------------------------------------------------------------------
    async def load(self, config_path: Path) -> list[str]:
        self.defs = load_server_defs(config_path)
        if not _MCP_OK:
            log.warning("mcp SDK unavailable — %d servers defined but dormant",
                        len(self.defs))
            return []
        for name, d in self.defs.items():
            if not self._preflight(d):
                continue
            try:
                if d.transport == "stdio":
                    params = StdioServerParameters(
                        command=d.command, args=d.args, env=d.env or None
                    )
                    ctx = stdio_client(params)
                else:
                    ctx = streamablehttp_client(d.url, headers=d.headers or None)
                read, write, *rest = await ctx.__aenter__()
                session = ClientSession(read, write)
                await session.__aenter__()
                await session.initialize()
                self._sessions[name] = session
                self._ctxs[name] = ctx
                self._locks[name] = asyncio.Lock()
                tools = await session.list_tools()
                names = [t.name for t in tools.tools or []]
                kept = filter_tools(names, d.allow_tools)
                for t in tools.tools or []:
                    if t.name in kept:
                        full = f"mcp_{name}__{t.name}"
                        self._tool_index[full] = (name, t.name)
                log.info("MCP '%s' attached (%d tools%s)", name, len(kept),
                         f", {len(names) - len(kept)} filtered by allowlist"
                         if len(kept) != len(names) else "")
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:  # noqa: BLE001 — stdio attach can raise CancelledError
                log.warning("MCP '%s' attach failed: %s (%s)", name, exc,
                            type(exc).__name__)
        return sorted(self._tool_index)

    # ------------------------------------------------------------------
    @staticmethod
    def _preflight(d: MCPServerDef) -> bool:
        """Cheap liveness check so dead entries never poison the event loop
        with half-entered anyio cancel scopes."""
        import shutil
        if d.transport == "stdio":
            if not d.command:
                log.warning("MCP '%s': no command — skipped", d.name)
                return False
            if not shutil.which(d.command):
                log.warning("MCP '%s': command %r not on PATH — skipped",
                            d.name, d.command)
                return False
            return True
        # http: probe reachability
        try:
            r = httpx.request("HEAD", d.url, timeout=4,
                              headers=d.headers or None, follow_redirects=True)
            if r.status_code >= 500:
                log.warning("MCP '%s': HTTP %d — skipped", d.name, r.status_code)
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("MCP '%s': unreachable (%s) — skipped", d.name, exc)
            return False

    # ------------------------------------------------------------------
    def tool_names(self) -> list[str]:
        return sorted(self._tool_index)

    def has(self, server: str) -> bool:
        return server in self._sessions

    async def tool_schemas(self) -> list[dict]:
        """OpenAI-style tool schemas for every attached MCP tool."""
        schemas: list[dict] = []
        for full, (server, tool) in self._tool_index.items():
            try:
                async with self._locks[server]:
                    info = await self._sessions[server].list_tools()
                for t in info.tools or []:
                    if t.name != tool:
                        continue
                    schema = dict(t.inputSchema or {"type": "object", "properties": {}})
                    schemas.append({
                        "type": "function",
                        "function": {
                            "name": full,
                            "description": (
                                f"[MCP:{server}] " + (t.description or tool)
                            )[:800],
                            "parameters": schema,
                        },
                    })
                    break
            except Exception as exc:  # noqa: BLE001
                log.debug("schema for %s: %s", full, exc)
        return schemas

    # ------------------------------------------------------------------
    async def call(self, full_name: str, arguments: dict,
                   max_chars: int = 20000) -> str:
        if full_name not in self._tool_index:
            return f"ERROR: unknown MCP tool {full_name}"
        server, tool = self._tool_index[full_name]
        async with self._locks[server]:
            try:
                result = await self._sessions[server].call_tool(tool, arguments or {})
            except Exception as exc:  # noqa: BLE001
                return f"ERROR: MCP call failed: {exc}"
        parts: list[str] = []
        for c in getattr(result, "content", None) or []:
            txt = getattr(c, "text", None)
            if txt:
                parts.append(strip_invisibles(str(txt)))
        out = "\n".join(parts)[:max_chars]
        return out or "(empty MCP result)"

    # ------------------------------------------------------------------
    async def close(self) -> None:
        for name, session in self._sessions.items():
            try:
                await session.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
        for name, ctx in self._ctxs.items():
            try:
                await ctx.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
