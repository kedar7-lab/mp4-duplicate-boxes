#!/usr/bin/env python3
"""Create a roughly 1 MiB MP4 with real H.264/AAC and corrupted nested duplicate minf."""
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
        return 8 + (len(self.payload) if self.children is None else sum(c.size for c in self.children))

    def to_bytes(self) -> bytes:
        body = self.payload if self.children is None else b"".join(c.to_bytes() for c in self.children)
        return struct.pack(">I4s", 8 + len(body), self.type) + body

    def find_all(self, box_type: bytes) -> list["Box"]:
        found = [self] if self.type == box_type else []
        for child in self.children or ():
            found.extend(child.find_all(box_type))
        return found


def parse_boxes(data: bytes) -> list[Box]:
    boxes: list[Box] = []
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
            boxes.append(Box(box_type, children=parse_boxes(body)))
        else:
            boxes.append(Box(box_type, body))
        offset += size
    return boxes


def top_level(path: Path) -> list[tuple[bytes, int, int]]:
    result = []
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
            if size == 1:
                raise ValueError("extended-size top-level boxes are unsupported")
            if size < 8 or offset + size > total:
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


def make_corrupted_stco(out_of_range_offset: int) -> Box:
    """Create a malicious stco box pointing way out of range."""
    version_flags = struct.pack(">I", 0)
    # One entry pointing to an invalid offset
    entry_count = 1
    payload = version_flags + struct.pack(">I", entry_count) + struct.pack(">I", out_of_range_offset)
    return Box(b"stco", payload)


def make_corrupted_stsz(inflated_size: int) -> Box:
    """Create a malicious stsz box with inflated sample sizes."""
    version_flags = struct.pack(">I", 0)
    # 4 samples with enormous size each
    sample_count = 4
    payload = version_flags + struct.pack(">II", inflated_size, sample_count)
    return Box(b"stsz", payload)


def inject_corrupted_nested_duplicate_minf(moov: Box, file_size: int) -> int:
    """Inject a corrupted duplicate minf immediately after stbl inside the first minf.
    
    The corrupted minf contains:
    - stco pointing way out of range (file_size + 100MB)
    - stsz claiming 100MB per sample
    
    This ensures a crash when the parser tries to use this duplicate.
    """
    injected = 0
    out_of_range = file_size + 100_000_000
    
    for trak in moov.find_all(b"trak"):
        mdia = next((c for c in trak.children or () if c.type == b"mdia"), None)
        if mdia is None:
            continue
        hdlr = next((c for c in mdia.children or () if c.type == b"hdlr"), None)
        if hdlr is None or len(hdlr.payload) < 12 or hdlr.payload[8:12] != b"vide":
            continue
        minf = next((c for c in mdia.children or () if c.type == b"minf"), None)
        if minf is None or not minf.children:
            continue
        stbl_index = next((i for i, c in enumerate(minf.children) if c.type == b"stbl"), None)
        if stbl_index is None:
            continue
        
        # Create a corrupted stbl inside the duplicate minf
        corrupted_stbl = Box(
            b"stbl",
            b"".join([
                make_corrupted_stco(out_of_range).to_bytes(),
                make_corrupted_stsz(100_000_000).to_bytes(),
            ])
        )
        
        # Create the corrupted minf with the malicious stbl
        corrupted_minf = Box(b"minf", children=[corrupted_stbl])
        
        # Insert it immediately after the original stbl
        minf.children.insert(stbl_index + 1, corrupted_minf)
        injected += 1
        print(f"Injected corrupted nested minf (stco={out_of_range}, stsz=100MB)")
    
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
    moov_type, moov_offset, moov_size = next(e for e in entries if e[0] == b"moov")
    file_size = source.stat().st_size
    
    with source.open("rb") as handle:
        handle.seek(moov_offset)
        moov = parse_boxes(handle.read(moov_size))[0]
    
    old_size = moov.size
    injected = inject_corrupted_nested_duplicate_minf(moov, file_size)
    if not injected:
        raise ValueError("no video minf/stbl found")
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
    print(f"Injected {injected} corrupted nested minf; moov grew {delta} bytes; shifted {shifted} offsets")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "output" / "1mb_nested_duplicate_minf.mp4")
    parser.add_argument("--size", type=int, default=DEFAULT_TARGET)
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    args = parser.parse_args()
    try:
        ffprobe = tool("ffprobe")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.mp4"
            encode_source(source, args.size, args.duration)
            run([ffprobe, "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,width,height", "-of", "default=noprint_wrappers=1", str(source)])
            build(source, args.output)
        size = args.output.stat().st_size
        print(f"Created {args.output} ({size:,} bytes, {size / (1024 * 1024):.2f} MiB)")
        print("Contains real H.264 video, AAC audio, and a corrupted nested minf with:")
        print("  - stco pointing 100MB+ out of range")
        print("  - stsz claiming 100MB per sample")
        return 0
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
