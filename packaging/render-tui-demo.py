#!/usr/bin/env python3
"""Render a recorded TUI input timeline as a GIF (requires Pillow; optional MP4 requires ffmpeg)."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

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


def render(data, font):
    canvas = Image.new("RGB", (data["width"] * 10 + 32, data["height"] * 22 + 92), COLORS["Reset"])
    draw = ImageDraw.Draw(canvas)
    draw.text((16, 8), data["title"], font=font, fill=COLORS["Cyan"])
    draw.text((16, 30), data["input"], font=font, fill=COLORS["Yellow"])
    for position, (symbol, fg, bg) in enumerate(data["cells"]):
        x, y = 16 + position % data["width"] * 10, 66 + position // data["width"] * 22
        draw.rectangle((x, y, x + 9, y + 21), fill=color(bg))
        if symbol != " ":
            draw.text((x, y), symbol, font=font, fill=color(fg, True))
    return canvas


def concat_path(path):
    return "'" + str(path.resolve()).replace("'", "'\\''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recording", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--font", type=Path)
    parser.add_argument("--preview-dir", type=Path)
    parser.add_argument("--video", type=Path, help="also encode the continuous recording as MP4")
    args = parser.parse_args()
    timeline_path = args.recording / "timeline.json"
    if not timeline_path.is_file():
        parser.error("timeline.json missing: record the TUI input session first")
    timeline = json.loads(timeline_path.read_text())
    if timeline.get("real_time") is not True:
        parser.error("a real-time recording is required; validation-only captures are not videos")
    if not timeline["frames"]:
        parser.error("recording contains no frames")
    font_path = args.font or Path(subprocess.check_output(
        ["fc-match", "-f", "%{file}", "monospace"], text=True).strip())
    font = ImageFont.truetype(str(font_path), 16)
    frames, durations = [], []
    with tempfile.TemporaryDirectory(prefix="traffic-masq-record-") as temporary:
        png_dir = args.preview_dir or Path(temporary)
        if args.preview_dir or args.video:
            png_dir.mkdir(parents=True, exist_ok=True)
        concat = ["ffconcat version 1.0"]
        for index, entry in enumerate(timeline["frames"]):
            data = json.loads((args.recording / entry["file"]).read_text())
            canvas = render(data, font)
            if args.preview_dir or args.video:
                png = png_dir / f"{index:05}.png"
                canvas.save(png)
                concat += [f"file {concat_path(png)}", f"duration {entry['duration_ms'] / 1000:.3f}"]
            frames.append(canvas.quantize(colors=256))
            durations.append(entry["duration_ms"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        frames[0].save(args.output, save_all=True, append_images=frames[1:], duration=durations,
                       loop=0, optimize=True, disposal=1)
        if args.video:
            concat.append(f"file {concat_path(png)}")
            manifest = Path(temporary) / "recording.ffconcat"
            manifest.write_text("\n".join(concat) + "\n")
            args.video.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0",
                            "-i", str(manifest), "-t", f"{sum(durations) / 1000:.3f}", "-vf", "fps=20",
                            "-c:v", "libx264", "-crf", "18", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                            str(args.video)], check=True)
    chapters = [f"{entry['at_ms'] / 1000:6.1f}s  {entry['title']}" for entry in timeline["chapters"]]
    args.output.with_suffix(".chapters.txt").write_text("\n".join(chapters) + "\n")
    print(f"Wrote {len(frames)} recorded frames, {sum(durations) / 1000:g}s, to {args.output}")


if __name__ == "__main__":
    main()
