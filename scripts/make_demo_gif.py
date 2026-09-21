"""Generate docs/media/demo.gif — a terminal replay of a REAL AVCI run
(XBEN-092-24 solve, runs/hunt-20260921-191750): recon -> source disclosure
-> phar forge -> upload -> unserialize -> flag. Pure Pillow, no network."""
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

W, H = 900, 560
FONT = "C:/Windows/Fonts/CascadiaMono.ttf"
FONT_B = "C:/Windows/Fonts/CascadiaCode.ttf"
BG = "#0d1117"
FG = "#c9d1d9"
DIM = "#8b949e"
GREEN = "#3fb950"
ORANGE = "#d29922"
RED = "#f85149"
BLUE = "#58a6ff"
PURPLE = "#bc8cff"
ACCENT = "#ff7b3d"

font = ImageFont.truetype(FONT, 15)
font_b = ImageFont.truetype(FONT_B, 15)
CHAR_W = 9
LINE_H = 20
TOP = 44          # below the window chrome
MAX_LINES = (H - TOP - 16) // LINE_H

# (text, color, pause_ms_after)
SCRIPT = [
    ("$ avci hunt --scope 127.0.0.1:8081 127.0.0.1:24555", GREEN, 500, "type"),
    ("[*] run: runs/hunt-20260921-191750", DIM, 260, None),
    ("[recon] subdomains -> probe -> crawl -> js -> params -> ports -> paths -> takeover", BLUE, 320, None),
    ("[ok] recon complete: live=1 pages=6 forms=3 api_paths=5", DIM, 300, None),
    ("-> GET /index.php 200 · /sku_system.php 200 · /sku_url.php 200", FG, 240, None),
    ("-> GET /backup/backup.zip -> 404 — trying internal service :24555", FG, 300, None),
    ("[tool] http http://127.0.0.1:24555/backup/backup.zip -> 200", ORANGE, 340, None),
    ("[tool] file_inspect backup.zip -> ReadClass.php + read_sku.php (source disclosed)", ORANGE, 420, None),
    ("-- chain tip -- unserialize gadget: CustomTemplate -> eval($data)", PURPLE, 420, None),
    ("[tool] phar_rce code=\"echo file_get_contents('/flag.txt');\" -> phar forged", ORANGE, 420, None),
    ("-> POST /sku_process data=<phar> -> {\"file_path\":\"/tmp/56e8f1c6...d8.jpg\"}", FG, 340, None),
    ("-> POST /read_sku.php file_path=/tmp/56e8f1c6...d8.jpg -> 200", FG, 420, None),
    ("*** FLAG{31e0f4208f7e281e085f10d078a03222b25914cedb8ce61d46520002b74086a0}", GREEN, 700, None),
    ("* finding [CONFIRMED] Unrestricted upload + phar:// deserialization RCE", RED, 500, None),
    ("[ok] gauntlet: KEEP · evidence vault sha256 verified", BLUE, 400, None),
    ("[+] report: report.md · report.html · report.sarif", DIM, 300, None),
    ("[+] done — 46 iterations · 47 requests · 1 finding", GREEN, 3400, None),
]


def wrap(text: str, width: int = 96) -> list[str]:
    out = []
    while len(text) > width:
        out.append(text[:width])
        text = text[width:]
    out.append(text)
    return out


def draw_frame(lines: list[tuple[str, str]], typed: str = "") -> Image.Image:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    # window chrome
    d.rectangle([0, 0, W, 30], fill="#161b22")
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        d.ellipse([14 + i * 20, 11, 26 + i * 20, 23], fill=c)
    d.text((84, 7), "avci — autonomous hunt", font=font, fill=DIM)
    vis = lines[-MAX_LINES:]
    y = TOP
    for text, color in vis:
        for seg in wrap(text):
            d.text((16, y), seg, font=font, fill=color)
            y += LINE_H
    if typed:
        d.text((16, y), typed + "_", font=font_b, fill=GREEN)
    return im


def main() -> None:
    frames: list[Image.Image] = []
    durations: list[int] = []
    lines: list[tuple[str, str]] = []
    for text, color, pause, mode in SCRIPT:
        if mode == "type":
            cur = ""
            for ch in text:
                cur += ch
                frames.append(draw_frame(lines, cur))
                durations.append(26)
            lines.append((text, color))
            frames.append(draw_frame(lines))
            durations.append(pause)
        else:
            lines.append((text, color))
            frames.append(draw_frame(lines))
            durations.append(pause)
    out = Path("docs/media/demo.gif")
    frames[0].save(out, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"wrote {out} ({out.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
