#!/usr/bin/env python3
"""Render JSON frames exported by the ignored TUI walkthrough test (requires Pillow)."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from PIL import Image, ImageDraw, ImageFont

COLORS = {
    "Reset": "#111821", "Black": "#111821", "Red": "#f07178",
    "Green": "#b8d77d", "Yellow": "#ffcb6b", "Blue": "#82aaff",
    "Magenta": "#c792ea", "Cyan": "#89ddff", "Gray": "#b0bec5",
    "DarkGray": "#8796a5", "LightRed": "#ff8f95", "LightGreen": "#c9e69a",
    "LightYellow": "#ffdc9c", "LightBlue": "#a3bfff", "LightMagenta": "#dab4ff",
    "LightCyan": "#b2ebff", "White": "#e6edf3",
}


def color(value, foreground=False):
    if value == "Reset" and foreground:
        return COLORS["White"]
    rgb = re.fullmatch(r"Rgb\((\d+), (\d+), (\d+)\)", value)
    return tuple(map(int, rgb.groups())) if rgb else COLORS.get(value, COLORS["White"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("frames", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--font", type=Path)
    parser.add_argument("--preview-dir", type=Path)
    args = parser.parse_args()
    font_path = args.font or Path(subprocess.check_output(
        ["fc-match", "-f", "%{file}", "monospace"], text=True).strip())
    font = ImageFont.truetype(str(font_path), 16)
    frames = []
    chapters = []
    for index, path in enumerate(sorted(args.frames.glob("*.json"))):
        data = json.loads(path.read_text())
        canvas = Image.new("RGB", (data["width"] * 10 + 32, data["height"] * 22 + 72), COLORS["Reset"])
        draw = ImageDraw.Draw(canvas)
        draw.text((16, 10), data["title"], font=font, fill=COLORS["Cyan"])
        for position, (symbol, fg, bg) in enumerate(data["cells"]):
            x, y = 16 + position % data["width"] * 10, 46 + position // data["width"] * 22
            draw.rectangle((x, y, x + 9, y + 21), fill=color(bg))
            if symbol != " ":
                draw.text((x, y), symbol, font=font, fill=color(fg, True))
        if args.preview_dir:
            args.preview_dir.mkdir(parents=True, exist_ok=True)
            canvas.save(args.preview_dir / f"{index:02}.png")
        frames.append(canvas.quantize(colors=64))
        chapters.append(f"{index * 4:6.1f}s  {data['title']}")
    if not frames:
        parser.error("no JSON frames found")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(args.output, save_all=True, append_images=frames[1:], duration=4000, loop=0, optimize=True)
    args.output.with_suffix(".chapters.txt").write_text("\n".join(chapters) + "\n")
    print(f"Wrote {len(frames)} frames to {args.output}")


if __name__ == "__main__":
    main()
