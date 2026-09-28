#!/usr/bin/env python3
"""Generate a separate, valid and playable MP4 fixture near 1 MiB.

Unlike generate_mp4_duplicate_boxes.py, this script creates a normal MP4:
there is exactly one mdia and one minf per track, and mdat contains real H.264
encoded samples. It requires ffmpeg and ffprobe on PATH.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_TARGET = 1_048_576  # 1 MiB
DEFAULT_DURATION = 10.0


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(
            f"{name} was not found on PATH. Install FFmpeg, then retry."
        )
    return path


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    subprocess.run(command, check=True)


def generate_valid_mp4(output: Path, target_bytes: int, duration: float) -> None:
    ffmpeg = require_tool("ffmpeg")
    ffprobe = require_tool("ffprobe")
    if target_bytes < 64 * 1024:
        raise ValueError("target size must be at least 65536 bytes")
    if duration <= 0:
        raise ValueError("duration must be greater than zero")

    output.parent.mkdir(parents=True, exist_ok=True)
    output = output.resolve()

    # Reserve some space for MP4 metadata and encoder overhead. The output is
    # intentionally near the target, not padded with fake mdat bytes.
    total_bitrate = int((target_bytes * 8 / duration) * 0.90)
    audio_bitrate = 96_000
    video_bitrate = max(100_000, total_bitrate - audio_bitrate)

    command = [
        ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30",
        "-f", "lavfi", "-i", "sine=frequency=1000:sample_rate=48000",
        "-t", str(duration),
        "-map", "0:v:0", "-map", "1:a:0",
        "-c:v", "libx264", "-preset", "veryfast", "-b:v", str(video_bitrate),
        "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", str(audio_bitrate),
        "-movflags", "+faststart",
        str(output),
    ]
    run(command)

    # A successful ffprobe parse verifies that this is a real MP4, rather than
    # merely a file containing plausible box headers.
    run([
        ffprobe, "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=codec_name,width,height,duration",
        "-of", "default=noprint_wrappers=1", str(output),
    ])

    actual = output.stat().st_size
    print(f"Created: {output}")
    print(f"Size: {actual:,} bytes ({actual / (1024 * 1024):.3f} MiB)")
    print("Structure: one valid moov/trak/mdia/minf hierarchy with real H.264/AAC samples")
    print("This file should be playable in QuickTime and other standard players.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).resolve().parent / "output" / "valid_mp4_1mb.mp4",
        help="output MP4 path",
    )
    parser.add_argument(
        "--size", type=int, default=DEFAULT_TARGET,
        help="approximate target size in bytes (default: 1048576)",
    )
    parser.add_argument(
        "--duration", type=float, default=DEFAULT_DURATION,
        help="duration in seconds (default: 10)",
    )
    args = parser.parse_args()
    try:
        generate_valid_mp4(args.output, args.size, args.duration)
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
