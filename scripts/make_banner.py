"""Generate docs/media/banner.png — 1280x640 GitHub social preview."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = "#0d1117"
FG = "#f0f6fc"
DIM = "#8b949e"
ACCENT = "#ff7b3d"
GREEN = "#3fb950"
BORDER = "#30363d"

mono = "C:/Windows/Fonts/CascadiaMono.ttf"
mono_b = "C:/Windows/Fonts/CascadiaCode.ttf"
ui_b = "C:/Windows/Fonts/segoeuib.ttf"

im = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(im)

# subtle dot grid
for x in range(24, W, 40):
    for y in range(24, H, 40):
        d.ellipse([x, y, x + 2, y + 2], fill="#1c2128")

# reticle mark (matches logo.svg)
cx, cy, r = 200, 320, 130
d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=ACCENT, width=14)
for x1, y1, x2, y2 in ((cx, 92, cx, 148), (cx, 492, cx, 548),
                       (12, cy, 68, cy), (332, cy, 388, cy)):
    d.line([x1, y1, x2, y2], fill=ACCENT, width=14)
d.polygon([(112, 268), (200, 404), (288, 268), (244, 268), (200, 330), (156, 268)],
          fill=FG)

# wordmark + taglines
d.text((400, 140), "AVCI", font=ImageFont.truetype(ui_b, 128), fill=FG)
d.text((404, 292), "Autonomous Offensive Blackbox Hunter",
       font=ImageFont.truetype(mono, 36), fill=DIM)
d.text((404, 350), "point at an authorized target. it hunts, proves, reports.",
       font=ImageFont.truetype(mono, 25), fill=DIM)

# chips
f_chip = ImageFont.truetype(mono_b, 22)
chips = [("XBOW 104/104", GREEN), ("45 probe classes", ACCENT),
         ("any LLM", "#58a6ff"), ("evidence oracle", "#bc8cff")]
x = 404
for label, color in chips:
    tw = d.textlength(label, font=f_chip)
    d.rounded_rectangle([x, 448, x + tw + 28, 494], radius=10,
                        outline=color, width=2)
    d.text((x + 14, 458), label, font=f_chip, fill=color)
    x += tw + 28 + 14

d.rectangle([0, 0, W - 1, H - 1], outline=BORDER, width=2)
out = Path("docs/media/banner.png")
im.save(out, optimize=True)
print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
