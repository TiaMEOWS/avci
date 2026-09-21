"""Generate docs/media/tui.svg — headless screenshot of the AVCI dashboard
with representative (synthetic) hunt data. Pure Textual pilot, no network."""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from avci.config import Settings
from avci.scope.guard import ScopeGuard
from avci.store.state import CoverageEntry, Finding, RunState
from avci.tui.app import AvciTui

FINDINGS = [
    ("phar deserialization RCE via upload", "critical",
     "http://shop.local:24555/read_sku.php"),
    ("Blind SQLi (time oracle) on login", "high",
     "http://shop.local:8081/login.php"),
    ("IDOR on /api/orders/{id} (A/B divergent)", "high",
     "http://shop.local:8081/api/orders/1332"),
    ("Reflected XSS in /search?q=", "medium",
     "http://shop.local:8081/search?q=x"),
    (".git exposure: config readable", "medium",
     "http://shop.local:8081/.git/config"),
]
COVERAGE = [
    ("shop.local:8081/search", "xss", "reported", "oracle CONFIRMED: unencoded reflection"),
    ("shop.local:8081/login", "sqli", "reported", "time oracle +5.2s on SLEEP payload"),
    ("shop.local:24555/read_sku", "deser", "reported", "phar unserialize -> eval, flag read"),
    ("shop.local:8081/orders", "idor", "reported", "A/B divergence sha mismatch"),
    ("shop.local:8081/.env", "exposure", "ruled_out", "404 + no signature"),
    ("shop.local:8081/graphql", "introspection", "no_issue_found", "introspection disabled"),
    ("shop.local:8081/cart", "race", "needs_follow_up", "divergent 200/409 on burst"),
]
FEED = [
    "◈ recon complete: live=2 pages=14 forms=5 api_paths=9",
    "⚙ probe ssrf_param http://shop.local:8081/sku_url.php → FAILED",
    "⚙ http GET /backup/backup.zip → 200 (1.2 MB)",
    "⚙ file_inspect backup.zip → ReadClass.php disclosed",
    "⚙ phar_rce channel=return → phar forged (CustomTemplate)",
    "★ FINDING phar:// deserialization RCE [critical]",
    "⚙ divergence_check /api/orders/1332 → DIVERGENT (A≠B)",
    "★ FINDING IDOR on /api/orders/{id} [high]",
    "✓ coverage: /graphql introspection → no_issue_found",
    "⚙ http_burst 6x /api/cart/coupon → 200/409 divergent",
]


class StubAgent:
    def __init__(self, state: RunState) -> None:
        self.state = state
        self.iterations = 34
        self.phase_label = "hunt"

    def cost_summary(self) -> dict:
        return {"model": "claude-sonnet-4-5", "llm_calls": 34,
                "prompt_tokens": 1_204_311, "completion_tokens": 18_204,
                "total_tokens": 1_222_515, "usd": 3.88}


async def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        st = RunState(Path(td), "shot")
        for t, sev, url in FINDINGS:
            st.findings.append(Finding(t, sev, url, evidence="x"))
        for target, check, outcome, ev in COVERAGE:
            st.coverage.append(CoverageEntry(target, check, outcome, ev, 0.0))
        for i in range(312):
            st.request_log.append({"method": "GET", "url": f"http://shop.local/{i}",
                                   "status": 200})
        settings = Settings.load(scope=["shop.local"])
        guard = ScopeGuard(rules=["shop.local"])
        app = AvciTui(settings, guard, Path(td), "shot", "shop.local")

        def fake_hunt() -> None:
            app.bind_agent(StubAgent(st))
            for line in FEED:
                app._push_feed(line)

        app._run_hunt = fake_hunt
        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause(2.0)
            svg = app.export_screenshot()
            Path("docs/media/tui.svg").write_text(svg, encoding="utf-8")
            print("wrote docs/media/tui.svg")


if __name__ == "__main__":
    asyncio.run(main())
