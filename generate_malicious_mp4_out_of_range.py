#!/usr/bin/env python3
"""Generate an MP4 that replicates the out-of-range offset issue.

The vulnerability occurs when:
  1. A parser uses last-occurrence-wins semantics for minf/mdia boxes
  2. The duplicate minf has a malformed stco/co64 with an out-of-range offset
  3. prepare_trak_slice() computes offset from the wrong (duplicate) stco
  4. The computed range exceeds the file size or mdat bounds

This generator creates:
  - A valid first minf/stbl with correct sample offsets
  - A duplicate minf after stbl whose stco/co64 points beyond the file
  - Real H.264/AAC samples in mdat
  - Sufficient file size so the first track would be valid, but the duplicate
    offsets overflow
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


# --------------------------------------------------------------------------- #
# Minimal box tree
# --------------------------------------------------------------------------- #
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
    """Rewrite stco/co64 tables so chunk offsets stay correct after moov grows."""
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


def corrupt_duplicate_stco(duplicate_minf: Box, file_size: int) -> None:
    """Make the duplicate minf's stco point beyond the file.
    
    This simulates the last-occurrence-wins parser bug:
    when the parser encounters the duplicate stco, it overwrites the valid one.
    """
    stbl = next((c for c in (duplicate_minf.children or []) if c.type == b"stbl"), None)
    if stbl is None:
        raise ValueError("duplicate minf has no stbl")
    
    stco_box = next((c for c in (stbl.children or []) if c.type == b"stco"), None)
    if stco_box is None:
        raise ValueError("stbl has no stco")
    
    # Parse the stco box: [version/flags: 4 bytes][entry_count: 4 bytes][offsets...]
    version_flags = stco_box.payload[:4]
    entry_count_bytes = stco_box.payload[4:8]
    entry_count = struct.unpack(">I", entry_count_bytes)[0]
    
    if entry_count == 0:
        # No samples to corrupt, but that's fine; a parser still tries to parse it
        print("Warning: stco has no entries to corrupt")
        return
    
    # Create out-of-range offsets: set each offset to beyond the file size
    # This ensures prepare_trak_slice() will compute an overflow
    out_of_range_offset = file_size + 1_000_000  # Well beyond the file
    new_offsets = struct.pack(f">{entry_count}I", *([out_of_range_offset] * entry_count))
    
    # Reconstruct stco with corrupted offsets
    stco_box.payload = version_flags + entry_count_bytes + new_offsets
    print(f"Corrupted duplicate stco: set {entry_count} chunk offset(s) to {out_of_range_offset:,}")


def inject_out_of_range_duplicate(moov: Box, file_size: int) -> None:
    """Inject a duplicate minf with out-of-range stco offsets.
    
    The first minf is valid; the duplicate will be used by last-occurrence-wins
    parsers and cause out-of-range issues.
    """
    targets = moov.find_all(b"mdia")
    injected = 0
    
    for parent in targets:
        if not parent.children:
            continue
        original = next((c for c in parent.children if c.type == b"minf"), None)
        if original is None:
            continue
        
        # Create a copy and corrupt it
        duplicate = original.copy()
        corrupt_duplicate_stco(duplicate, file_size)
        
        # Append the malicious duplicate after the original
        parent.children.append(duplicate)
        injected += 1
    
    if not injected:
        raise ValueError("no minf box found to duplicate")
    print(f"Injected {injected} out-of-range duplicate minf box(es)")


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
    
    # Get the final file size before modification
    final_file_size = source.stat().st_size
    
    # Inject out-of-range duplicates
    inject_out_of_range_duplicate(moov, final_file_size)
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
        
        # Verify the encoder produced a valid file
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
    print("⚠️  MALICIOUS FIXTURE ⚠️")
    print("This file has:")
    print("  • Real H.264/AAC samples in the first minf/stbl (valid)")
    print("  • A duplicate minf after stbl with out-of-range chunk offsets")
    print("  • Parser bug: last-occurrence-wins will use the duplicate stco")
    print("  • Result: prepare_trak_slice() computes offset beyond file size")
    print()
    print("Expected behavior (fixed parser):")
    print("  • Reject the file due to duplicate minf, OR")
    print("  • Use first-occurrence-wins and bounds-check the slice, OR")
    print("  • Reject with 'out of range offset'")
    print()
    print("To inspect the structure:")
    print(f"  mp4dump {output}")
    print(f"  ffprobe -v trace {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_dir = Path(__file__).resolve().parent / "output"
    parser.add_argument("--output", type=Path,
                        default=default_dir / "malicious_mp4_out_of_range.mp4",
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
