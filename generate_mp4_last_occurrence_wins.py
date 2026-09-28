#!/usr/bin/env python3
"""Generate a real H.264 MP4 with an empty duplicate minf after stbl.

The generated video track has:

    mdia
      mdhd
      hdlr (vide)
      minf                 # original, complete
        ... stbl ...
      minf                 # duplicate, exactly size=8, no children

That is the minimal layout needed to exercise parsers that store
m_non_leaves["minf"] with last-occurrence-wins semantics. The duplicate is
intentionally malformed as a media container; use the output only in an
isolated parser regression test.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_TARGET = 1_048_576
DEFAULT_DURATION = 10.0
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta"}


def tool(name: str) -> str:
    result = shutil.which(name)
    if not result:
        raise RuntimeError(f"{name} is required and was not found on PATH")
    return result


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    subprocess.run(command, check=True)


class Box:
    __slots__ = ("type", "payload", "children")

    def __init__(self, box_type: bytes, payload: bytes = b"", children: list["Box"] | None = None):
        self.type = box_type
        self.payload = payload
        self.children = children

    @property
    def size(self) -> int:
        return 8 + (len(self.payload) if self.children is None else sum(c.size for c in self.children))

    def to_bytes(self) -> bytes:
        body = self.payload if self.children is None else b"".join(c.to_bytes() for c in self.children)
        if len(body) + 8 >= 2**32:
            raise ValueError("box is too large")
        return struct.pack(">I4s", len(body) + 8, self.type) + body

    def find_all(self, box_type: bytes) -> list["Box"]:
        result = [self] if self.type == box_type else []
        for child in self.children or ():
            result.extend(child.find_all(box_type))
        return result


def parse_boxes(data: bytes) -> list[Box]:
    result: list[Box] = []
    pos = 0
    while pos + 8 <= len(data):
        size, box_type = struct.unpack_from(">I4s", data, pos)
        if size == 0:
            size = len(data) - pos
        elif size == 1:
            raise ValueError("extended-size child boxes are not supported")
        if size < 8 or pos + size > len(data):
            raise ValueError(f"invalid {box_type!r} box at offset {pos}")
        body = data[pos + 8:pos + size]
        if box_type in CONTAINERS:
            result.append(Box(box_type, children=parse_boxes(body)))
        else:
            result.append(Box(box_type, body))
        pos += size
    if pos != len(data):
        raise ValueError("trailing bytes in container")
    return result


def top_level(path: Path) -> list[tuple[bytes, int, int]]:
    result: list[tuple[bytes, int, int]] = []
    total = path.stat().st_size
    with path.open("rb") as handle:
        pos = 0
        while pos < total:
            handle.seek(pos)
            header = handle.read(8)
            if len(header) != 8:
                raise ValueError("truncated top-level box header")
            size, box_type = struct.unpack(">I4s", header)
            if size == 0:
                size = total - pos
            elif size == 1:
                size = 16 + struct.unpack(">Q", handle.read(8))[0]
            if size < 8 or pos + size > total:
                raise ValueError(f"invalid top-level {box_type!r}")
            result.append((box_type, pos, size))
            pos += size
    return result


def shift_offsets(moov: Box, delta: int) -> int:
    """Keep the original valid stco/co64 entries pointing into mdat."""
    if delta == 0:
        return 0
    changed = 0
    for box in moov.find_all(b"stco"):
        if len(box.payload) < 8:
            continue
        count = struct.unpack_from(">I", box.payload, 4)[0]
        values = struct.unpack_from(f">{count}I", box.payload, 8)
        if any(value + delta >= 2**32 for value in values):
            raise ValueError("stco offset overflow")
        box.payload = box.payload[:8] + struct.pack(f">{count}I", *(v + delta for v in values))
        changed += count
    for box in moov.find_all(b"co64"):
        if len(box.payload) < 8:
            continue
        count = struct.unpack_from(">I", box.payload, 4)[0]
        values = struct.unpack_from(f">{count}Q", box.payload, 8)
        box.payload = box.payload[:8] + struct.pack(f">{count}Q", *(v + delta for v in values))
        changed += count
    return changed


def append_empty_minf(moov: Box, include_audio: bool) -> int:
    """Append exactly 00 00 00 08 'minf' after the original minf.

    By default only the video mdia is modified, matching the supplied
    first/only-mdia vide reproducer. --all-tracks can add the same trigger to
    the audio mdia as well.
    """
    added = 0
    for trak in moov.find_all(b"trak"):
        mdia = next((c for c in trak.children or () if c.type == b"mdia"), None)
        if mdia is None:
            continue
        handler = next((c for c in mdia.children or () if c.type == b"hdlr"), None)
        handler_name = handler.payload[8:12] if handler and len(handler.payload) >= 12 else b""
        if handler_name == b"soun" and not include_audio:
            continue
        original = next((c for c in mdia.children or () if c.type == b"minf"), None)
        if original is None:
            continue
        # children=[] is important: it serializes to an 8-byte minf header.
        mdia.children.append(Box(b"minf", children=[]))
        added += 1
        print(f"Added empty duplicate minf after original {handler_name.decode(errors='replace')} minf")
    if not added:
        raise ValueError("no eligible mdia/minf found")
    return added


def encode_source(path: Path, target_bytes: int, duration: float) -> None:
    ffmpeg = tool("ffmpeg")
    if target_bytes < 64 * 1024 or duration <= 0:
        raise ValueError("use --size >= 65536 and --duration > 0")
    video_bitrate = max(100_000, int(target_bytes * 8 / duration * 0.90))
    run([
        ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30",
        "-t", str(duration), "-an",
        "-c:v", "libx264", "-preset", "veryfast", "-b:v", str(video_bitrate),
        "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(path),
    ])


def build(source: Path, output: Path, all_tracks: bool) -> None:
    entries = top_level(source)
    moov_info = next((entry for entry in entries if entry[0] == b"moov"), None)
    if moov_info is None:
        raise ValueError("source has no moov")
    _, moov_offset, moov_size = moov_info
    with source.open("rb") as handle:
        handle.seek(moov_offset)
        moov = parse_boxes(handle.read(moov_size))[0]
    old_size = moov.size
    added = append_empty_minf(moov, all_tracks)
    delta = moov.size - old_size
    shifted = shift_offsets(moov, delta)
    print(f"Added {added} empty duplicate minf box(es), each exactly 8 bytes")
    print(f"moov grew by {delta} bytes; shifted {shifted} valid chunk offset entries")
    output.parent.mkdir(parents=True, exist_ok=True)
    replacement = moov.to_bytes()
    with source.open("rb") as src, output.open("wb") as dst:
        for box_type, offset, size in entries:
            if box_type == b"moov":
                dst.write(replacement)
            else:
                src.seek(offset)
                dst.write(src.read(size))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parent / "output" / "mp4_empty_duplicate_minf.mp4"
    parser.add_argument("--output", type=Path, default=default)
    parser.add_argument("--size", type=int, default=DEFAULT_TARGET)
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    parser.add_argument("--all-tracks", action="store_true",
                        help="also append empty minf under audio mdia; default is video only")
    args = parser.parse_args()
    try:
        ffprobe = tool("ffprobe")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.mp4"
            encode_source(source, args.size, args.duration)
            run([ffprobe, "-v", "error", "-select_streams", "v:0",
                 "-show_entries", "stream=codec_name,width,height",
                 "-of", "default=noprint_wrappers=1", str(source)])
            build(source, args.output, args.all_tracks)
        print(f"Created {args.output} ({args.output.stat().st_size:,} bytes)")
        print("Expected video layout: complete minf/stbl followed immediately by minf size=8")
        return 0
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
