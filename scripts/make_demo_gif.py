"""Generate docs/media/demo.gif — a terminal replay of a REAL AVCI run
(XBEN-092-24 solve, runs/hunt-20260921-191750): recon -> source disclosure
-> phar forge -> upload -> unserialize -> flag, with the v1.2+ guardrail
beat shown when the target's page tries to instruct the agent.

Pure Pillow, no network. Effects: typewriter command, live status bar
(iters/requests/findings), blinking cursor, highlight flash on the
guardrail + FLAG lines. Uniform ~90ms frame granularity so every GIF
viewer paces it correctly. Run: python scripts/make_demo_gif.py"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 900, 560
BG = "#0d1117"
CHROME = "#161b22"
FG = "#c9d1d9"
DIM = "#8b949e"
GREEN = "#3fb950"
ORANGE = "#d29922"
RED = "#f85149"
BLUE = "#58a6ff"
PURPLE = "#bc8cff"
ACCENT = "#ff7b3d"
FLASH = "#2b1c10"


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


FONT = _font(15)
FONT_B = _font(15, bold=True)
FONT_S = _font(13)
LINE_H = 20
TOP = 66          # below chrome (30px) + status bar (26px) + padding
MAX_LINES = (H - TOP - 16) // LINE_H
WRAP = 96

# -----------------------------------------------------------------------
# narrative: (kind, payload)
#   type <text>            typewriter, then commit as a green line
#   line <text,color>      append instantly
#   flash <text,color>     append with a fading highlight behind it
#   status <dict>          update the status bar counters
#   pause <ms>             idle frames (cursor keeps blinking)
SCRIPT = [
    ("type", "$ avci hunt --scope 127.0.0.1:8081 127.0.0.1:24555"),
    ("status", {"phase": "recon"}),
    ("line", "[*] run: runs/hunt-20260921-191750", DIM),
    ("pause", 350),
    ("line", "[recon] subdomains > probe > crawl > js > params > ports "
             "> paths > takeover", BLUE),
    ("status", {"iters": 6, "reqs": 41}),
    ("line", "[ok] recon complete: live=1 pages=6 forms=3 api_paths=5", DIM),
    ("pause", 300),
    ("status", {"phase": "hunt"}),
    ("line", "> GET /index.php 200 · /sku_system.php 200 · "
             "/sku_url.php 200", FG),
    ("status", {"iters": 9, "reqs": 58}),
    ("line", "> GET /backup/backup.zip 404 — pivot internal :24555", FG),
    ("pause", 250),
    ("line", "[tool] http http://127.0.0.1:24555/backup/backup.zip "
             "-> 200", ORANGE),
    ("flash", "[guardrail] page body tried to instruct the agent — "
              "shielded (override, tool-coercion)", ACCENT),
    ("status", {"iters": 14, "reqs": 71}),
    ("line", "[tool] file_inspect backup.zip -> ReadClass.php + "
             "read_sku.php (source disclosed)", ORANGE),
    ("pause", 300),
    ("line", "-- chain tip -- unserialize gadget: CustomTemplate -> "
             "eval($data)", PURPLE),
    ("line", "[tool] phar_rce code=\"echo file_get_contents('/flag.txt');"
             "\" -> phar forged", ORANGE),
    ("status", {"iters": 27, "reqs": 96}),
    ("pause", 350),
    ("line", "> POST /sku_process data=<phar> -> "
             "{\"file_path\":\"/tmp/56e8f1c6...d8.jpg\"}", FG),
    ("line", "> POST /read_sku.php file_path=/tmp/56e8f1c6...d8.jpg "
             "-> 200", FG),
    ("status", {"iters": 41, "reqs": 128}),
    ("flash", "*** FLAG{31e0f4208f7e281e085f10d078a03222b25914cedb8ce61"
              "d46520002b74086a0}", GREEN),
    ("status", {"findings": 1}),
    ("line", "* finding [CONFIRMED] unrestricted upload + phar:// "
             "deserialization RCE", RED),
    ("pause", 400),
    ("line", "[ok] gauntlet: KEEP · evidence vault sha256 verified", BLUE),
    ("line", "[+] report: report.md · report.html · report.sarif", DIM),
    ("status", {"phase": "done", "iters": 46, "reqs": 131}),
    ("flash", "[+] done — 46 iters · 131 requests · 1 finding · "
              "guardrail armed", GREEN),
    ("pause", 2600),
]


def wrap(text: str, width: int = WRAP) -> list[str]:
    out = []
    while len(text) > width:
        out.append(text[:width])
        text = text[width:]
    out.append(text)
    return out


def draw(lines, status, typed="", flash_idx=-1, flash_ttl=0,
         cursor_on=True) -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    # window chrome
    d.rectangle([0, 0, W, 30], fill=CHROME)
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse([14 + i * 20, 11, 26 + i * 20, 23], fill=c)
    d.text((84, 7), "avci — autonomous hunt", font=FONT_S, fill=DIM)
    # status bar
    d.rectangle([0, 30, W, 56], fill="#10151c")
    d.text((16, 35), f"phase: {status.get('phase', 'boot')}", font=FONT_S,
           fill=ACCENT)
    counters = (f"iters {status.get('iters', 0):>3} · "
                    f"reqs {status.get('reqs', 0):>3} · "
                    f"findings {status.get('findings', 0)}")
    d.text((W - 16 - d.textlength(counters, font=FONT_S), 35), counters,
           font=FONT_S, fill=GREEN if status.get("findings") else DIM)
    vis = lines[-MAX_LINES:]
    y = TOP
    base = len(lines) - len(vis)
    for i, (text, color) in enumerate(vis):
        segs = wrap(text)
        if base + i == flash_idx and flash_ttl > 0:
            fade = 1.0 - (4 - flash_ttl) * 0.22
            d.rectangle([8, y - 2, W - 8, y + LINE_H * len(segs) - 4],
                        fill=_blend(FLASH, BG, 1 - fade))
        for seg in segs:
            d.text((16, y), seg, font=FONT, fill=color)
            y += LINE_H
    if typed or cursor_on:
        d.text((16, y), typed + ("_" if cursor_on else " "),
               font=FONT_B, fill=GREEN)
    return im


def _blend(a: str, b: str, t: float) -> str:
    ca, cb = (int(a[i:i + 2], 16) for i in (1, 3, 5)), \
             (int(b[i:i + 2], 16) for i in (1, 3, 5))
    return "#" + "".join(f"{round(x + (y - x) * t):02x}"
                         for x, y in zip(ca, cb))


def main() -> None:
    frames: list[Image.Image] = []
    durations: list[int] = []
    lines: list[tuple[str, str]] = []
    status: dict = {"phase": "boot", "iters": 0, "reqs": 0, "findings": 0}
    tick = 0
    flash_idx, flash_ttl = -1, 0

    def emit(ms: int, typed: str = "", show_cursor: bool = True) -> None:
        nonlocal tick, flash_ttl
        steps = max(1, round(ms / 90))
        for _ in range(steps):
            frames.append(draw(lines, status, typed,
                               flash_idx, flash_ttl,
                               cursor_on=(tick // 5) % 2 == 0))
            durations.append(90)
            tick += 1
            if flash_ttl:
                flash_ttl -= 1

    for kind, *payload in SCRIPT:
        if kind == "type":
            text = payload[0]
            cur = ""
            for ch in text:
                cur += ch
                emit(28, typed=cur)
            lines.append((text, GREEN))
            emit(420)
        elif kind == "line":
            lines.append((payload[0], payload[1]))
            emit(210)
        elif kind == "flash":
            lines.append((payload[0], payload[1]))
            flash_idx, flash_ttl = len(lines) - 1, 4
            emit(650)
        elif kind == "status":
            status.update(payload[0])
            emit(120)
        elif kind == "pause":
            emit(payload[0])

    out = Path(__file__).resolve().parents[1] / "docs" / "media" / "demo.gif"
    frames[0].save(out, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    total = sum(durations) / 1000
    print(f"wrote {out} ({len(frames)} frames, {total:.1f}s, "
          f"{out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
