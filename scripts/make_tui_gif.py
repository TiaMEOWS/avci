"""Generate docs/media/tui.gif — animated replay of the live AVCI TUI
dashboard (same synthetic hunt data as scripts/make_tui_svg.py, so the
static and animated assets tell one story).

Faithful to avci/tui/app.py layout: header + clock, Meter strip
(phase · iter · req · tokens · $ + last feed line), FINDINGS table,
COVERAGE LEDGER table, scrolling feed with kind icons, footer bindings.
Pure Pillow, uniform ~90ms frames. Run: python scripts/make_tui_gif.py"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1000, 600
BG = "#0d1117"
PANEL = "#10151c"
CHROME = "#161b22"
BORDER = "#30363d"
FG = "#c9d1d9"
DIM = "#8b949e"
GREEN = "#3fb950"
ORANGE = "#d29922"
RED = "#f85149"
BLUE = "#58a6ff"
PURPLE = "#bc8cff"
ACCENT = "#ff7b3d"
FLASH = "#2b1c10"

SEV = {"critical": RED, "high": ACCENT, "medium": ORANGE, "low": GREEN,
       "info": DIM}
OUTCOME = {"reported": GREEN, "ruled_out": DIM, "no_issue_found": BLUE,
           "needs_follow_up": ORANGE}


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for path in (
        "C:/Windows/Fonts/CascadiaCode.ttf" if bold
        else "C:/Windows/Fonts/CascadiaMono.ttf",
        "C:/Windows/Fonts/consolab.ttf" if bold
        else "C:/Windows/Fonts/consola.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


F13 = _font(13)
F13B = _font(13, bold=True)
F15 = _font(15)
F15B = _font(15, bold=True)
CHAR = 8  # approx char width at 13px mono

FEED_W = (W - 424) // CHAR          # right panel text width in chars
FEED_ROWS = 26
SPIN = "|/-\\"

SCRIPT = [
    ("phase", "boot"),
    ("feed", "→", DIM, "target shop.local:8081 · model claude-sonnet-4-5 "
                        "· scope ['shop.local:8081', 'shop.local:24555']"),
    ("phase", "recon"),
    ("ramp", 700, {"iters": 3, "reqs": 26}),
    ("feed", "◈", BLUE, "recon complete: live=2 pages=14 forms=5 "
                        "api_paths=9"),
    ("phase", "hunt"),
    ("ramp", 900, {"iters": 9, "reqs": 58, "usd": 0.41}),
    ("feed", "»", FG, "probe ssrf_param /sku_url.php -> FAILED"),
    ("feed", "»", FG, "http GET /backup/backup.zip -> 200 (1.2 MB)"),
    ("flash_feed", "!", ACCENT, "GUARDRAIL page body tried to instruct "
                                "the agent — shielded (override)"),
    ("ramp", 700, {"iters": 14, "reqs": 77, "usd": 0.96}),
    ("feed", "»", FG, "file_inspect backup.zip -> ReadClass.php disclosed"),
    ("feed", "»", FG, "phar_rce channel=return -> phar forged "
                      "(CustomTemplate)"),
    ("ramp", 800, {"iters": 21, "reqs": 102, "usd": 1.83}),
    ("feed", "◆", RED, "FINDING phar:// deserialization RCE [critical]"),
    ("finding", ("phar deserialization RCE via upload", "critical",
                 "shop.local:24555/read_sku.php")),
    ("ledger", ("/read_sku", "reported", "phar unserialize -> eval")),
    ("feed", "»", FG, "divergence_check /api/orders/1332 -> DIVERGENT"),
    ("feed", "◆", ACCENT, "FINDING IDOR on /api/orders/{id} [high]"),
    ("finding", ("IDOR on /api/orders/{id} (A/B divergent)", "high",
                 "shop.local:8081/api/orders/1332")),
    ("ledger", ("/orders", "reported", "A/B divergence sha mismatch")),
    ("ramp", 800, {"iters": 27, "reqs": 118, "usd": 2.64}),
    ("feed", "◆", ACCENT, "FINDING blind SQLi (time oracle) [high]"),
    ("finding", ("Blind SQLi (time oracle) on login", "high",
                 "shop.local:8081/login.php")),
    ("ledger", ("/login", "reported", "time oracle +5.2s on SLEEP")),
    ("feed", "◆", ORANGE, "FINDING reflected XSS in /search?q= [medium]"),
    ("finding", ("Reflected XSS in /search?q=", "medium",
                 "shop.local:8081/search?q=x")),
    ("ledger", ("/search", "reported", "oracle CONFIRMED reflection")),
    ("feed", "✓", GREEN, "coverage: /.env -> ruled_out (404 + no sig)"),
    ("ledger", ("/.env", "ruled_out", "404 + no signature")),
    ("feed", "✓", GREEN, "coverage: /graphql introspection -> "
                         "no_issue_found"),
    ("ledger", ("/graphql", "no_issue_found", "introspection disabled")),
    ("feed", "»", FG, "http_burst 6x /api/cart/coupon -> 200/409 "
                      "divergent"),
    ("ledger", ("/cart", "needs_follow_up", "divergent 200/409 on burst")),
    ("feed", "◆", ORANGE, "FINDING .git exposure: config readable "
                          "[medium]"),
    ("finding", (".git exposure: config readable", "medium",
                 "shop.local:8081/.git/config")),
    ("ramp", 900, {"iters": 34, "reqs": 131, "usd": 3.88}),
    ("phase", "done"),
    ("feed", "◆", GREEN, "RUN COMPLETE · findings=5 · finished=True"),
    ("pause", 2600),
]


def clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[:width - 1] + "…"


def panel(d: ImageDraw.ImageDraw, box, title: str, color: str) -> None:
    d.rounded_rectangle(box, radius=6, outline=color, width=1)
    tw = d.textlength(f" {title} ", font=F13B)
    d.rectangle([box[0] + 10, box[1] - 7, box[0] + 10 + tw, box[1] + 7],
                fill=BG)
    d.text((box[0] + 10, box[1] - 8), f" {title} ", font=F13B, fill=color)


def draw(st: dict, tick: int) -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    # header
    d.rectangle([0, 0, W, 28], fill=CHROME)
    d.text((12, 6), "AVCI — Autonomous Offensive Blackbox Hunter",
           font=F13B, fill=FG)
    clock = f"14:03:{7 + tick // 11:02d}"
    d.text((W - 12 - d.textlength(clock, font=F13), 6), clock, font=F13,
           fill=DIM)
    # meter strip
    panel(d, [12, 36, W - 12, 90], "METER", ACCENT)
    phase = st["phase"]
    spin = SPIN[(tick // 2) % 4] if phase not in ("done",) else "■"
    line1 = (f"{spin} {phase}  ·  iter {st['iters']:>3}  ·  "
             f"req {st['reqs']:>3}  ·  tok {st['tok']:,}  ·  "
             f"${st['usd']:.2f}")
    d.text((24, 48), line1, font=F15B,
           fill=GREEN if phase == "done" else ACCENT)
    last = st["feed"][-1][2] if st["feed"] else ""
    d.text((24, 68), clip(last, 120), font=F13, fill=DIM)
    # findings table
    panel(d, [12, 100, 400, 262], "FINDINGS", GREEN)
    for i, row in enumerate(st["findings"][-7:]):
        title, sev, url = row
        y = 112 + i * 20
        if st["flash_row"] == ("finding", i):
            d.rectangle([16, y - 2, 396, y + 16], fill=FLASH)
        d.text((20, y), clip(title, 30), font=F13, fill=FG)
        d.text((272, y), sev, font=F13B, fill=SEV.get(sev, DIM))
    # coverage ledger
    panel(d, [12, 272, 400, H - 34], "COVERAGE LEDGER", BLUE)
    for i, row in enumerate(st["ledger"][-12:]):
        target, outcome, ev = row
        y = 284 + i * 20
        d.text((20, y), clip(target, 16), font=F13, fill=FG)
        d.text((140, y), clip(outcome, 15), font=F13,
               fill=OUTCOME.get(outcome, DIM))
        d.text((262, y), clip(ev, 17), font=F13, fill=DIM)
    # feed
    panel(d, [412, 100, W - 12, H - 34], "FEED", ACCENT)
    rows = st["feed"][-FEED_ROWS:]
    base = len(st["feed"]) - len(rows)
    for i, (icon, color, text) in enumerate(rows):
        y = 112 + i * 18
        if st["flash_row"] == ("feed", base + i):
            d.rectangle([416, y - 2, W - 16, y + 16], fill=FLASH)
        d.text((420, y), f"14:03:{7 + (base + i) // 3:02d}", font=F13,
               fill=DIM)
        d.text((500, y), icon, font=F13B, fill=color)
        d.text((518, y), clip(text, FEED_W - 15), font=F13,
               fill=color if icon in ("◆", "!") else FG)
    # footer
    d.rectangle([0, H - 26, W, H], fill=CHROME)
    d.text((12, H - 20), "q quit (snapshot)   f findings   c coverage",
           font=F13, fill=DIM)
    return im


def main() -> None:
    frames: list[Image.Image] = []
    durations: list[int] = []
    st: dict = {"phase": "boot", "iters": 0, "reqs": 0, "tok": 0,
                "usd": 0.0, "feed": [], "findings": [], "ledger": [],
                "flash_row": None}
    tick = 0

    def emit(ms: int) -> None:
        nonlocal tick
        for _ in range(max(1, round(ms / 90))):
            frames.append(draw(st, tick))
            durations.append(90)
            tick += 1
            if tick % 3 == 0:
                st["flash_row"] = None

    for kind, *payload in SCRIPT:
        if kind == "phase":
            st["phase"] = payload[0]
            emit(160)
        elif kind in ("feed", "flash_feed"):
            icon, color, text = payload
            st["feed"].append((icon, color, text))
            if kind == "flash_feed":
                st["flash_row"] = ("feed", len(st["feed"]) - 1)
            emit(320 if kind == "feed" else 700)
        elif kind == "finding":
            st["findings"].append(payload[0])
            st["flash_row"] = ("finding", len(st["findings"]) - 1)
            emit(420)
        elif kind == "ledger":
            st["ledger"].append(payload[0])
            emit(240)
        elif kind == "ramp":
            ms, targets = payload
            start = {k: st[k] for k in targets}
            steps = max(1, round(ms / 90))
            for s in range(steps):
                for k, end in targets.items():
                    a = start[k]
                    st[k] = a + (end - a) * (s + 1) / steps
                st["tok"] = int(st["iters"] * 36011)
                frames.append(draw(st, tick))
                durations.append(90)
                tick += 1
            for k, end in targets.items():
                st[k] = end
            st["tok"] = int(st["iters"] * 36011)
        elif kind == "pause":
            emit(payload[0])

    st["iters"] = int(st["iters"])
    st["reqs"] = int(st["reqs"])
    out = Path(__file__).resolve().parents[1] / "docs" / "media" / "tui.gif"
    frames[0].save(out, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"wrote {out} ({len(frames)} frames, "
          f"{sum(durations) / 1000:.1f}s, {out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
