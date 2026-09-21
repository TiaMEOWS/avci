"""Browser driver: MCP passthrough first, Playwright fallback second.

If a browser MCP server (wondersuite) is attached, we drive it via MCPManager.
Otherwise, and only when playwright is installed, we spin a local Chromium —
useful for headless registration flows and JS-heavy targets.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin

log = logging.getLogger("avci.browser")

_ACTIONS = ("goto", "click", "fill", "eval", "screenshot", "content", "wait",
            "links", "forms")

# MCP tool-name keywords per action — generic enough for wondersuite,
# playwright-mcp, puppeteer-mcp and friends.
_MCP_KEYWORDS = {
    "goto": ("navigate", "goto", "open"),
    "click": ("click",),
    "fill": ("fill", "type", "set_input", "setvalue"),
    "eval": ("eval", "execute", "run_js", "script"),
    "content": ("content", "html", "snapshot", "text"),
    "screenshot": ("screenshot", "capture"),
}


def extract_links(html: str, base: str = "") -> list[str]:
    """Absolute hrefs + JS-dispatched paths — works on any mode's content."""
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html or "", re.I)
    found: list[str] = []
    for h in hrefs:
        if h.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        found.append(urljoin(base, h) if base else h)
    return sorted(dict.fromkeys(found))


def extract_forms(html: str) -> list[dict]:
    """Forms with their fields — the SPA-era signup/login surface map."""
    forms: list[dict] = []
    for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", html or "",
                         re.I | re.S):
        block = m.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', block, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', block, re.I)
        fields = re.findall(
            r"<(?:input|select|textarea)\b[^>]*?name=[\"']([^\"']+)[\"']",
            block, re.I)
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "fields": fields,
        })
    return forms



class BrowserDriver:
    """Unified face over [MCP browser | local playwright]."""

    def __init__(self, mcp_manager: Any = None) -> None:
        self.mcp = mcp_manager
        self._pw = None
        self._page = None
        self._mode = "none"
        self._mcp_open: bool | None = None   # wondersuite session state
        self._pending_url: str = ""          # URL for lazy browser_open

    # ------------------------------------------------------------------
    def _pick_mode(self) -> str:
        if self.mcp is not None and getattr(self.mcp, "has", None):
            for server in ("wondersuite", "browser", "playwright", "puppeteer"):
                if self.mcp.has(server):
                    self._mode = f"mcp:{server}"
                    return self._mode
        try:
            from playwright.async_api import async_playwright  # noqa: F401
            self._mode = "local"
        except Exception:  # noqa: BLE001
            self._mode = "none"
        return self._mode

    @property
    def mode(self) -> str:
        return self._mode

    async def ensure(self) -> str:
        mode = self._pick_mode()
        if mode == "local" and self._page is None:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            browser = await self._pw.chromium.launch(headless=True)
            ctx = await browser.new_context()
            self._page = await ctx.new_page()
        if mode.startswith("mcp:") and self._mcp_open is not True:
            # wondersuite flow: proxy up + browser session open, once
            await self._mcp_bootstrap()
        return mode

    async def _mcp_bootstrap(self) -> None:
        """Idempotent bring-up of a wondersuite-style browser MCP session."""
        if not self.mcp:
            return
        server = self._mode.split(":", 1)[1]
        prefix = f"mcp_{server}__"
        names = {t.split("__", 1)[1] for t in self.mcp.tool_names()
                 if t.startswith(prefix)}

        def has(tool: str) -> bool:
            return tool in names

        if has("proxy_status") and has("proxy_start"):
            status = str(await self.mcp.call(prefix + "proxy_status", {}))
            if '"running"' not in status and "running" not in status.lower():
                await self.mcp.call(prefix + "proxy_start", {})
        if has("browser_snapshot"):
            probe = str(await self.mcp.call(prefix + "browser_snapshot", {}))
            if "NOT_OPEN" in probe:
                url = self._pending_url or "about:blank"
                if has("browser_open"):
                    await self.mcp.call(prefix + "browser_open", {"url": url})
                self._mcp_open = True
                return
        self._mcp_open = True

    # ------------------------------------------------------------------
    def _mcp_tool_for(self, action: str) -> str | None:
        """Find the MCP tool that implements `action` by name keyword."""
        if not self._mode.startswith("mcp:") or not self.mcp:
            return None
        prefix = f"mcp_{self._mode.split(':', 1)[1]}__"
        names = [t for t in self.mcp.tool_names() if t.startswith(prefix)]
        for kw in _MCP_KEYWORDS.get(action, (action,)):
            for full in names:
                if kw in full.lower():
                    return full
        return None

    def _mcp_tool(self) -> tuple[str, str] | None:
        if not self._mode.startswith("mcp:"):
            return None
        server = self._mode.split(":", 1)[1]
        tool = self._mcp_tool_for("goto")
        if tool:
            return server, tool
        for full in (self.mcp.tool_names() if self.mcp else []):
            if full.startswith(f"mcp_{server}__"):
                return server, full
        return None

    async def _mcp_call(self, tool: str, args: dict) -> str:
        return await self.mcp.call(tool, args) if self.mcp else "ERROR: no MCP"

    @staticmethod
    def _unwrap_value(raw: str) -> str:
        """wondersuite evaluate wraps results as {"success", "value"} — unwrap."""
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and "value" in obj:
                return str(obj["value"])
        except Exception:  # noqa: BLE001 — raw isn't JSON, return as-is
            pass
        return raw

    # ------------------------------------------------------------------
    async def goto(self, url: str) -> str:
        self._pending_url = url
        await self.ensure()
        if self._mode.startswith("mcp:"):
            tool = self._mcp_tool_for("goto")
            if not tool:
                return "ERROR: browser MCP server exposes no navigation tool"
            out = await self._mcp_call(tool, {"url": url})
            # a cold session may have opened straight to the URL already
            if "NOT_OPEN" in out:
                self._mcp_open = None
                await self.ensure()
                out = await self._mcp_call(tool, {"url": url})
            return out
        if self._mode == "local":
            resp = await self._page.goto(url, wait_until="domcontentloaded",
                                         timeout=45000)
            return f"status={resp.status if resp else '?'} url={self._page.url}"
        return "ERROR: no browser available (attach browser MCP or pip install avci[browser])"

    async def click(self, selector: str) -> str:
        if self._mode.startswith("mcp:"):
            tool = self._mcp_tool_for("click")
            return (await self._mcp_call(tool, {"selector": selector,
                                                "element": selector})
                    if tool else "ERROR: no click tool on browser MCP")
        if self._mode == "local" and self._page:
            await self._page.click(selector, timeout=10000)
            return "clicked"
        return "ERROR: click only supported in local playwright mode"

    async def fill(self, selector: str, value: str) -> str:
        if self._mode.startswith("mcp:"):
            tool = self._mcp_tool_for("fill")
            return (await self._mcp_call(tool, {"selector": selector,
                                                "value": value, "text": value})
                    if tool else "ERROR: no fill tool on browser MCP")
        if self._mode == "local" and self._page:
            await self._page.fill(selector, value, timeout=10000)
            return "filled"
        return "ERROR: fill only supported in local playwright mode"

    async def eval_js(self, expr: str) -> str:
        if self._mode.startswith("mcp:"):
            tool = self._mcp_tool_for("eval")
            return (await self._mcp_call(tool, {"expression": expr,
                                                "code": expr})
                    if tool else "ERROR: no eval tool on browser MCP")
        if self._mode == "local" and self._page:
            val = await self._page.evaluate(expr)
            return str(val)[:8000]
        return "ERROR: eval only supported in local playwright mode"

    async def content(self) -> str:
        if self._mode.startswith("mcp:"):
            # whole-page HTML via evaluate beats ref-based outer_html tools
            # (wondersuite get_outer_html needs a snapshot ref)
            eval_tool = self._mcp_tool_for("eval")
            if eval_tool:
                raw = await self._mcp_call(
                    eval_tool, {"code": "document.documentElement.outerHTML",
                                "expression": "document.documentElement.outerHTML"})
                html = self._unwrap_value(raw)
                if html and "Missing code" not in html and "ERROR" not in html[:40]:
                    return html[:60000]
            tool = self._mcp_tool_for("content")
            return (await self._mcp_call(tool, {})
                    if tool else "ERROR: no content tool on browser MCP")
        if self._mode == "local" and self._page:
            return (await self._page.content())[:60000]
        return "ERROR: content only supported in local playwright mode"

    async def screenshot(self, path: str) -> str:
        if self._mode.startswith("mcp:"):
            tool = self._mcp_tool_for("screenshot")
            return (await self._mcp_call(tool, {"path": path, "fullPage": True})
                    if tool else "ERROR: no screenshot tool on browser MCP")
        if self._mode == "local" and self._page:
            await self._page.screenshot(path=path, full_page=True)
            return path
        return "ERROR: screenshot only supported in local playwright mode"

    async def cookies(self) -> list[dict]:
        if self._mode == "local" and self._page:
            ctx = self._page.context
            return [dict(c) for c in await ctx.cookies()]
        return []

    # ------------------------------------------------------------------
    async def links(self, base: str = "") -> str:
        """All links on the current page — SPA depth reconnaissance."""
        html = await self.content()
        if html.startswith("ERROR"):
            return html
        return json.dumps(extract_links(html, base or self._page_url()),
                          indent=1)[:12000]

    async def forms(self) -> str:
        """Every form + its fields — the auth-surface map for a target."""
        html = await self.content()
        if html.startswith("ERROR"):
            return html
        return json.dumps(extract_forms(html), indent=1)[:12000]

    def _page_url(self) -> str:
        if self._mode == "local" and self._page:
            return self._page.url
        return self._pending_url


    # ------------------------------------------------------------------
    async def close(self) -> None:
        if self._pw is not None:
            try:
                await self._pw.stop()
            except Exception:  # noqa: BLE001
                pass
            self._pw = None
            self._page = None
