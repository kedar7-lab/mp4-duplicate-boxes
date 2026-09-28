#!/usr/bin/env python3
"""Create the minimal duplicate-minf MP4 reproducer.

This intentionally hand-builds the box layout from the regression description;
it does not use FFmpeg.  The resulting track is:

  trak
    tkhd (92)
    mdia (32 + 33 + first minf + empty duplicate minf)
      minf
        stbl
          stsd (16, entry_count=0)
          stts (24, 4 samples, delta 1)
          stsc (28, 4 samples/chunk)
          stsz (36, four 16-byte samples)
          stco (20, one chunk at 0x200)
      minf (8, no children)

The important relative offsets are:

  stbl start relative to trak: 181
  prependsz = stbl start + stbl header: 189
  stbl end relative to trak: 313
  minf_offset = stbl end - (trak start + 8): 305

Thus the vulnerable assertion sees assert(305 < 189).

The file is deliberately malformed and is intended only for an isolated parser
regression test.  It contains an 8-byte mdat with no media payload because the
crash occurs while processing the duplicate minf layout.
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


def fullbox_payload(version: int = 0, flags: int = 0) -> bytes:
    return struct.pack(">I", (version << 24) | flags)


def make_ftyp() -> bytes:
    # 8-byte header + 16-byte payload = 24 bytes.
    return box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isommp42")


def make_mvhd() -> bytes:
    # Version 0 mvhd payload is 100 bytes, hence a 108-byte box.
    payload = bytearray(100)
    payload[0:4] = fullbox_payload()
    struct.pack_into(">I", payload, 12, 1)   # timescale
    struct.pack_into(">I", payload, 16, 10)  # duration
    return box(b"mvhd", bytes(payload))


def make_tkhd() -> bytes:
    # Version 0 tkhd payload is 84 bytes, hence a 92-byte box.
    payload = bytearray(84)
    payload[0:4] = fullbox_payload(flags=0x000007)
    struct.pack_into(">I", payload, 12, 1)  # track_ID
    return box(b"tkhd", bytes(payload))


def make_mdhd() -> bytes:
    # 8-byte header + 24-byte payload = 32 bytes.
    payload = bytearray(24)
    payload[0:4] = fullbox_payload()
    struct.pack_into(">I", payload, 12, 1)  # timescale
    struct.pack_into(">I", payload, 16, 10) # duration
    return box(b"mdhd", bytes(payload))


def make_hdlr() -> bytes:
    # 4 vf + 4 pre_defined + 4 handler_type + 12 reserved + 1 name = 25.
    payload = fullbox_payload() + struct.pack(">I4s12sB", 0, b"vide", b"" * 12, 0)
    assert len(payload) == 25
    return box(b"hdlr", payload)


def make_stsd() -> bytes:
    # version/flags + entry_count; deliberately zero sample entries.
    return box(b"stsd", fullbox_payload() + struct.pack(">I", 0))


def make_stts() -> bytes:
    # One time-to-sample entry: four samples, delta one.
    payload = fullbox_payload() + struct.pack(">III", 1, 4, 1)
    assert len(payload) == 16
    return box(b"stts", payload)


def make_stsc() -> bytes:
    # One chunk-map entry: chunk 1, four samples/chunk, description 1.
    payload = fullbox_payload() + struct.pack(">IIII", 1, 1, 4, 1)
    assert len(payload) == 20
    return box(b"stsc", payload)


def make_stsz() -> bytes:
    # Variable sample sizes: four samples, each 16 bytes.
    payload = fullbox_payload() + struct.pack(">II", 0, 4) + struct.pack(">IIII", 16, 16, 16, 16)
    assert len(payload) == 28
    return box(b"stsz", payload)


def make_stco() -> bytes:
    # One chunk at absolute file offset 0x200, as in the reproducer.
    payload = fullbox_payload() + struct.pack(">II", 1, 0x200)
    assert len(payload) == 12
    return box(b"stco", payload)


def make_fixture() -> bytes:
    stbl = box(b"stbl", b"".join((
        make_stsd(),    # 16
        make_stts(),    # 24
        make_stsc(),    # 28
        make_stsz(),    # 36
        make_stco(),    # 20
    )))                 # 132
    first_minf = box(b"minf", stbl)       # 140
    second_minf = box(b"minf")             # exactly 8, no children

    mdia = box(b"mdia", b"".join((
        make_mdhd(),    # 32
        make_hdlr(),    # 33
        first_minf,     # 140
        second_minf,    # 8
    )))                 # 221
    trak = box(b"trak", make_tkhd() + mdia)  # 321
    moov = box(b"moov", make_mvhd() + trak)  # 437
    output = make_ftyp() + moov + box(b"mdat")

    # Verify the exact sizes and relative positions described by the bug.
    assert len(make_ftyp()) == 24
    assert len(make_mvhd()) == 108
    assert len(make_tkhd()) == 92
    assert len(make_mdhd()) == 32
    assert len(make_hdlr()) == 33
    assert len(first_minf) == 140
    assert len(stbl) == 132
    assert len(second_minf) == 8
    assert len(mdia) == 221
    assert len(trak) == 321
    assert len(moov) == 437
    assert len(output) == 469

    # trak-relative positions: trak header at 0, tkhd starts at 8.
    # mdia starts at 100; mdia children: mdhd 8..40, hdlr 40..73,
    # minf header 73..81, stbl header 81..89.
    stbl_start = 8 + 92 + 8 + 32 + 33 + 8 + 8
    assert stbl_start == 181
    prependsz = stbl_start + 8
    stbl_end = stbl_start + len(stbl)
    minf_offset = stbl_end - 8
    assert prependsz == 189
    assert minf_offset == 305
    assert minf_offset >= prependsz  # the vulnerable assertion is expected to fail

    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).resolve().parent / "output" / "minimal_duplicate_minf.mp4",
    )
    args = parser.parse_args()
    data = make_fixture()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"Created {args.output} ({len(data)} bytes)")
    print("Expected boxes: ftyp=24, mvhd=108, tkhd=92, mdhd=32, hdlr=33")
    print("Expected boxes: stsd=16, stts=24, stsc=28, stsz=36, stco=20")
    print("Expected layout: complete minf/stbl followed by empty minf size=8")
    print("Expected assertion values: prependsz=189, minf_offset=305")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
