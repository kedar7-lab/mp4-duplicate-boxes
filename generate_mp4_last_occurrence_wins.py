#!/usr/bin/env python3
"""Create the minimal duplicate-minf MP4 reproducer.

This intentionally hand-builds the box layout from the regression description;
it does not use FFmpeg. The resulting track is:

  trak
    tkhd (92)
    mdia
      mdhd (32)
      hdlr (33)
      minf                  # original, valid
        stbl
          stsd (16, entry_count=0)
          stts (24)
          stsc (28)
          stsz (36)
          stco (20, chunk offset=0x200)
      minf (8, no children) # empty duplicate

The bug depends on these relative values:

  stbl_start = 181
  prependsz  = 189
  minf_offset = 305

This is the exact condition used by the vulnerable assert:

  assert(minf_offset < prependsz)

because 305 < 189 is false, the parser aborts.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def box(kind: bytes, payload: bytes = b"") -> bytes:
    if len(kind) != 4:
        raise ValueError("box type must be four bytes")
    size = 8 + len(payload)
    if size >= 2**32:
        raise ValueError("box is too large")
    return struct.pack(">I4s", size, kind) + payload


def fullbox(version: int = 0, flags: int = 0) -> bytes:
    return struct.pack(">I", (version << 24) | flags)


def make_ftyp() -> bytes:
    # 8-byte header + 16-byte payload = 24 bytes
    return box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isommp42")


def make_mvhd() -> bytes:
    payload = bytearray(100)
    payload[0:4] = fullbox()
    struct.pack_into(">I", payload, 12, 1)
    struct.pack_into(">I", payload, 16, 10)
    return box(b"mvhd", bytes(payload))


def make_tkhd() -> bytes:
    payload = bytearray(84)
    payload[0:4] = fullbox(flags=0x000007)
    struct.pack_into(">I", payload, 12, 1)
    return box(b"tkhd", bytes(payload))


def make_mdhd() -> bytes:
    payload = bytearray(24)
    payload[0:4] = fullbox()
    struct.pack_into(">I", payload, 12, 1)
    struct.pack_into(">I", payload, 16, 10)
    return box(b"mdhd", bytes(payload))


def make_hdlr() -> bytes:
    # 25-byte payload (4 fullbox + 4 handler_type + 12 reserved + 1 name)
    payload = fullbox() + struct.pack(">I4s12sB", 0, b"vide", b"" * 12, 0)
    assert len(payload) == 25
    return box(b"hdlr", payload)


def make_stsd() -> bytes:
    # version/flags + entry_count = 8 bytes payload; 16 total box size
    return box(b"stsd", fullbox() + struct.pack(">I", 0))


def make_stts() -> bytes:
    # 4-byte version/flags + 4-byte entry_count + 4-byte sample_count + 4-byte delta
    payload = fullbox() + struct.pack(">III", 1, 4, 1)
    assert len(payload) == 16
    return box(b"stts", payload)


def make_stsc() -> bytes:
    # 4 bytes version/flags + 4 bytes entry_count + 4 bytes first_chunk + 4 bytes samples + 4 bytes desc_index
    payload = fullbox() + struct.pack(">IIII", 1, 1, 4, 1)
    assert len(payload) == 20
    return box(b"stsc", payload)


def make_stsz() -> bytes:
    payload = fullbox() + struct.pack(">II", 0, 4) + struct.pack(">IIII", 16, 16, 16, 16)
    assert len(payload) == 28
    return box(b"stsz", payload)


def make_stco() -> bytes:
    payload = fullbox() + struct.pack(">II", 1, 0x200)
    assert len(payload) == 12
    return box(b"stco", payload)


def make_fixture() -> bytes:
    stsd = make_stsd()  # 16 bytes
    stts = make_stts()  # 24 bytes
    stsc = make_stsc()  # 28 bytes
    stsz = make_stsz()  # 36 bytes
    stco = make_stco()  # 20 bytes

    stbl = box(b"stbl", stsd + stts + stsc + stsz + stco)
    first_minf = box(b"minf", stbl)
    second_minf = box(b"minf")  # exactly 8 bytes

    mdia = box(b"mdia", make_mdhd() + make_hdlr() + first_minf + second_minf)
    trak = box(b"trak", make_tkhd() + mdia)
    moov = box(b"moov", make_mvhd() + trak)

    output = make_ftyp() + moov + box(b"mdat")

    # Exact offsets required by the reproducer.
    stbl_start = 8 + 92 + 8 + 32 + 33 + 8
    assert stbl_start == 181, f"stbl_start mismatch: got {stbl_start}"
    prependsz = stbl_start + 8
    stbl_end = stbl_start + len(stbl)
    minf_offset = stbl_end - 8
    assert prependsz == 189, f"prependsz mismatch: got {prependsz}"
    assert minf_offset == 305, f"minf_offset mismatch: got {minf_offset}"
    assert minf_offset >= prependsz, "this reproducer expects the parser to see the duplicate minf before prependsz"

    print(f"stbl_start={stbl_start}, prependsz={prependsz}, stbl_end={stbl_end}, minf_offset={minf_offset}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "output" / "minimal_duplicate_minf.mp4",
    )
    args = parser.parse_args()

    data = make_fixture()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"Created {args.output} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
