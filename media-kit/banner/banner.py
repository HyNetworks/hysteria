#!/usr/bin/env python3
"""Generate a Hysteria release banner for the Telegram channel.

Usage:
    python3 banner.py config.json [-o banner.png] [--hd]

Config (JSON):
    {
      "version": "2.13.0",                        required; a leading "v" is fine
      "date": "2026-11-08",                       optional; defaults to today
      "highlights": [                             required; 1 to 4 items
        {"title": "QUIC sniffing, fixed",
         "desc": "Domain ACL rules now apply to browser QUIC"}
      ],
      "footer": {"left": "...", "right": "..."}   optional; defaults below
    }

The banner is 1280x960, the size Telegram stores channel photos at, so it is
shown without being scaled down. --hd renders 2560x1920 for photos sent in HD.

Text never shrinks to fit, since small text is unreadable in the channel feed.
Anything too long is rejected with an error saying how much to cut, except the
version number, which shrinks if needed. Requires Pillow.
"""

import argparse
import datetime
import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
FONTS = HERE / "fonts"
PNG = HERE.parent / "png"

# Every coordinate and size below is in the 1280x960 layout space.
W, H = 1280, 960
LEFT, RIGHT = 72, 1208
SUPERSAMPLE = 2  # Pillow does not antialias polygons, so render large and downscale

BG = (11, 11, 13)
ACCENT = (255, 188, 0)
WHITE = (255, 255, 255)
DESC = (184, 184, 191)
MUTED = (154, 154, 161)  # date
FOOTER = (142, 142, 149)
RULE_TOP = (42, 42, 48)
RULE_BOTTOM = (31, 31, 36)

# Top row: "v" + version on the left, wordmark and date on the right.
VERSION_X, VERSION_BASELINE = 64, 250
VERSION_V_SIZE, VERSION_SIZE, VERSION_GAP = 140, 205, 4
WORDMARK_W, WORDMARK_TOP = 422, 116
WORDMARK_GAP = 40  # minimum space between version and wordmark
DATE_BASELINE, DATE_SIZE = 246, 32

# Body: highlights centred vertically between the two rules.
RULE_Y_TOP, RULE_Y_BOTTOM, RULE_WIDTH = 304, 862, 3
MAX_HIGHLIGHTS = 4
ITEM_PITCH, ITEM_HEIGHT = 124, 96
TEXT_X = 116
TITLE_SIZE, TITLE_OFFSET = 50, 46  # baseline offset from the item top
DESC_SIZE, DESC_OFFSET = 36, 94
MARKER = [(80, 0), (94, 0), (86, ITEM_HEIGHT), (72, ITEM_HEIGHT)]  # ~5 deg, like the logo

FOOTER_BASELINE, FOOTER_SIZE, FOOTER_GAP = 914, 30, 40
DEFAULT_FOOTER = {"left": "github.com/HyNetworks/hysteria", "right": "hysteria.network"}

# Faint logo symbol bleeding off the right edge behind the list.
WATERMARK_X, WATERMARK_Y, WATERMARK_W, WATERMARK_OPACITY = 640, 300, 711, 0.045

FONT_FILES = {
    "version": "ChakraPetch-BoldItalic.ttf",
    "bold": "Poppins-SemiBold.ttf",
    "regular": "Poppins-Regular.ttf",
}


class ConfigError(Exception):
    pass


_font_cache = {}


def font(kind, size):
    key = (kind, size)
    if key not in _font_cache:
        _font_cache[key] = ImageFont.truetype(str(FONTS / FONT_FILES[kind]), size)
    return _font_cache[key]


def text_width(kind, size, text):
    return font(kind, size).getlength(text)


def missing_glyphs(kind, text):
    """Characters the font has no glyph for, which would render as boxes.

    A missing glyph renders as the font's .notdef box, so compare each
    character's box and advance against those of an unassigned code point.
    """
    f = font(kind, 100)
    notdef = (f.getbbox("\U0010fffd"), f.getlength("\U0010fffd"))
    return sorted(
        {ch for ch in text if not ch.isspace() and (f.getbbox(ch), f.getlength(ch)) == notdef}
    )


def check_text(label, kind, size, text, max_width):
    missing = missing_glyphs(kind, text)
    if missing:
        chars = " ".join(missing)
        raise ConfigError(f"{label}: the banner fonts have no glyphs for {chars}")
    width = text_width(kind, size, text)
    if width > max_width:
        over = width - max_width
        raise ConfigError(
            f"{label} is too long by about {over:.0f}px "
            f"(~{over / width * len(text):.0f} characters): {text!r}"
        )


def require_string(obj, key, label, optional=False):
    value = obj.get(key)
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a non-empty string")
    return value.strip()


def load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"can't read {path}: {e}")
    if not isinstance(cfg, dict):
        raise ConfigError("the config must be a JSON object")

    unknown = set(cfg) - {"version", "date", "highlights", "footer"}
    if unknown:
        raise ConfigError(f"unknown config keys: {', '.join(sorted(unknown))}")

    version = require_string(cfg, "version", "version")
    if version[0] in "vV":
        version = version[1:]
    date = require_string(cfg, "date", "date", optional=True)
    if date is None:
        date = datetime.date.today().isoformat()

    items = cfg.get("highlights")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_HIGHLIGHTS:
        got = f"got {len(items)}" if isinstance(items, list) else "missing or not a list"
        raise ConfigError(f"highlights must be a list of 1 to {MAX_HIGHLIGHTS} items ({got})")
    highlights = []
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise ConfigError(f"highlight {i} must be an object with title and desc")
        title = require_string(item, "title", f"highlight {i} title")
        desc = require_string(item, "desc", f"highlight {i} desc")
        highlights.append((title, desc))

    footer = dict(DEFAULT_FOOTER)
    if "footer" in cfg:
        if not isinstance(cfg["footer"], dict):
            raise ConfigError("footer must be an object with left and right")
        for side in ("left", "right"):
            if side in cfg["footer"]:
                footer[side] = require_string(cfg["footer"], side, f"footer {side}")

    # Check that everything fits before drawing anything.
    check_text("version", "version", VERSION_SIZE, version, float("inf"))
    check_text("date", "regular", DATE_SIZE, date, WORDMARK_W)
    text_max = RIGHT - TEXT_X
    for i, (title, desc) in enumerate(highlights, 1):
        check_text(f"highlight {i} title", "bold", TITLE_SIZE, title, text_max)
        check_text(f"highlight {i} desc", "regular", DESC_SIZE, desc, text_max)
    right_w = text_width("regular", FOOTER_SIZE, footer["right"])
    check_text("footer right", "regular", FOOTER_SIZE, footer["right"], RIGHT - LEFT)
    check_text("footer left", "regular", FOOTER_SIZE, footer["left"],
               RIGHT - LEFT - right_w - FOOTER_GAP)

    return version, date, highlights, footer


def version_scale(version):
    """Shrink factor so "v" + version stays clear of the wordmark (1.0 = no shrink)."""
    width = (text_width("version", VERSION_V_SIZE, "v") + VERSION_GAP
             + text_width("version", VERSION_SIZE, version))
    available = RIGHT - WORDMARK_W - WORDMARK_GAP - VERSION_X
    return min(1.0, available / width)


def load_logo(name, width, k, opacity=1.0):
    img = Image.open(PNG / name).convert("RGBA")
    size = (round(width * k), round(width * k * img.height / img.width))
    img = img.resize(size, Image.LANCZOS)
    if opacity < 1.0:
        alpha = img.getchannel("A").point(lambda a: round(a * opacity))
        img.putalpha(alpha)
    return img


def paste_clipped(canvas, img, x, y):
    """alpha_composite() wants the overlay inside the canvas, so crop it to fit."""
    img = img.crop((0, 0, min(img.width, canvas.width - x), min(img.height, canvas.height - y)))
    canvas.alpha_composite(img, (x, y))


def render(version, date, highlights, footer, scale=1):
    k = scale * SUPERSAMPLE

    def px(v):
        return round(v * k)

    canvas = Image.new("RGBA", (px(W), px(H)), BG + (255,))
    paste_clipped(canvas, load_logo("symbol 2@2x.png", WATERMARK_W, k, WATERMARK_OPACITY),
                  px(WATERMARK_X), px(WATERMARK_Y))
    canvas.alpha_composite(load_logo("dark bg 1@2x.png", WORDMARK_W, k),
                           (px(RIGHT - WORDMARK_W), px(WORDMARK_TOP)))

    draw = ImageDraw.Draw(canvas)

    def text(xy, s, kind, size, fill, anchor="ls"):
        draw.text((px(xy[0]), px(xy[1])), s, font=font(kind, px(size)), fill=fill, anchor=anchor)

    def hline(y, color):
        draw.rectangle([px(LEFT), px(y - RULE_WIDTH / 2), px(RIGHT), px(y + RULE_WIDTH / 2) - 1],
                       fill=color)

    # Version, with the "v" in amber and smaller.
    s = version_scale(version)
    v_size, ver_size = VERSION_V_SIZE * s, VERSION_SIZE * s
    text((VERSION_X, VERSION_BASELINE), "v", "version", v_size, ACCENT)
    x = VERSION_X + text_width("version", VERSION_V_SIZE, "v") * s + VERSION_GAP * s
    text((x, VERSION_BASELINE), version, "version", ver_size, WHITE)

    text((RIGHT, DATE_BASELINE), date, "regular", DATE_SIZE, MUTED, anchor="rs")
    hline(RULE_Y_TOP, RULE_TOP)

    block = (len(highlights) - 1) * ITEM_PITCH + ITEM_HEIGHT
    top = (RULE_Y_TOP + RULE_Y_BOTTOM) / 2 - block / 2
    for i, (title, desc) in enumerate(highlights):
        y = top + i * ITEM_PITCH
        draw.polygon([(px(mx), px(y + my)) for mx, my in MARKER], fill=ACCENT)
        text((TEXT_X, y + TITLE_OFFSET), title, "bold", TITLE_SIZE, WHITE)
        text((TEXT_X, y + DESC_OFFSET), desc, "regular", DESC_SIZE, DESC)

    hline(RULE_Y_BOTTOM, RULE_BOTTOM)
    text((LEFT, FOOTER_BASELINE), footer["left"], "regular", FOOTER_SIZE, FOOTER)
    text((RIGHT, FOOTER_BASELINE), footer["right"], "regular", FOOTER_SIZE, FOOTER, anchor="rs")

    return canvas.convert("RGB").resize((W * scale, H * scale), Image.LANCZOS)


def main():
    ap = argparse.ArgumentParser(description="Generate a Hysteria release banner.")
    ap.add_argument("config", help="JSON config file (see the docstring at the top of this script)")
    ap.add_argument("-o", "--output", help="output PNG (default: hysteria-v<version>.png)")
    ap.add_argument("--hd", action="store_true", help="render at 2560x1920 instead of 1280x960")
    args = ap.parse_args()

    try:
        version, date, highlights, footer = load_config(args.config)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    out = args.output or f"hysteria-v{version}.png"
    render(version, date, highlights, footer, scale=2 if args.hd else 1).save(out, optimize=True)
    print(out)


if __name__ == "__main__":
    main()
