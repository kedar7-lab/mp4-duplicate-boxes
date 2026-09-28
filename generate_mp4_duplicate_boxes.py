#!/usr/bin/env python3
"""Generate two intentionally malformed, ~100 MiB MP4 box-tree test fixtures.

The second minf follows the first minf's stbl as a sibling in mdia; the
second mdia follows the first mdia (whose minf ends in stbl) in trak.
These are structural parser fixtures, NOT playable video: sample tables are
empty and mdat is unreferenced zero padding, not encoded media.
"""

import argparse
from pathlib import Path
import struct

DEFAULT_SIZE = 100 * 1024 * 1024  # 100 MiB, exactly 104,857,600 bytes


def box(kind, payload=b''):
    """ISO BMFF box: 4-byte big-endian total size, 4-byte type, payload."""
    size = 8 + len(payload)
    if size >= 2**32:
        raise ValueError('Box too large for a 32-bit size')
    return struct.pack('>I4s', size, kind) + payload


def u32(value):
    return struct.pack('>I', value)


def full_box(kind, payload=b'', flags=0):
    return box(kind, u32(flags) + payload)  # version 0, 24-bit flags


def ftyp():
    return box(b'ftyp', b'isom' + u32(512) + b'isomiso2mp41')


def matrix():
    return struct.pack('>9i', 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)


def mvhd():
    return full_box(b'mvhd',
                    u32(3600) + u32(3600) + u32(1000) + u32(0) +
                    u32(0x10000) + struct.pack('>H', 0x100) + b'\0' * 10 +
                    matrix() + b'\0' * 24 + u32(2))


def tkhd():
    return full_box(b'tkhd',
                    u32(3600) + u32(3600) + u32(1) + u32(0) + u32(0) +
                    b'\0' * 8 + struct.pack('>HHHH', 0, 0, 0, 0) +
                    matrix() + u32(320 << 16) + u32(240 << 16), flags=0x0f)


def mdhd():
    return full_box(b'mdhd', u32(3600) + u32(3600) + u32(1000) +
                    u32(0) + struct.pack('>HH', 0x55c4, 0))


def hdlr():
    return full_box(b'hdlr', u32(0) + b'vide' + b'\0' * 12 + b'VideoHandler\0')


def stbl():
    # No samples: neither sample offsets nor an H.264 codec are claimed.
    return box(b'stbl',
               full_box(b'stsd', u32(0)) +
               full_box(b'stts', u32(0)) +
               full_box(b'stsc', u32(0)) +
               full_box(b'stsz', u32(0) + u32(0)) +
               full_box(b'stco', u32(0)))


def minf():
    vmhd = full_box(b'vmhd', b'\0' * 8, flags=1)
    dref = full_box(b'dref', u32(1) + full_box(b'url ', flags=1))
    return box(b'minf', vmhd + box(b'dinf', dref) + stbl())


def mdia():
    return box(b'mdia', mdhd() + hdlr() + minf())


def movie(duplicate):
    if duplicate == 'minf':
        # Both minf boxes have identical bytes and sizes; both are children
        # of the same mdia. The first one's last child is stbl.
        media = box(b'mdia', mdhd() + hdlr() + minf() + minf())
        track = box(b'trak', tkhd() + media)
    elif duplicate == 'mdia':
        # Both mdia boxes have identical bytes and sizes; both are children
        # of the same trak. Each ends with minf/stbl.
        track = box(b'trak', tkhd() + mdia() + mdia())
    else:
        raise ValueError('duplicate must be minf or mdia')
    return box(b'moov', mvhd() + track)


def generate(output_file, duplicate, target_size=DEFAULT_SIZE):
    """Write exactly target_size bytes, using an unreferenced mdat for padding."""
    prefix = ftyp() + movie(duplicate)
    padding = target_size - len(prefix) - 8  # 8 bytes for mdat header
    if padding < 0 or target_size >= 2**32:
        raise ValueError(f'target_size must be between {len(prefix) + 8} and {2**32 - 1} bytes')
    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb') as output:
        output.write(prefix)
        output.write(struct.pack('>I4s', padding + 8, b'mdat'))
        # Write bounded chunks rather than allocating a large zero buffer.
        while padding:
            length = min(padding, 1024 * 1024)
            output.write(b'\0' * length)
            padding -= length
    return path


def generate_mp4_with_duplicate_minf(output_file, target_size=DEFAULT_SIZE):
    return generate(output_file, 'minf', target_size)


def generate_mp4_with_duplicate_mdia(output_file, target_size=DEFAULT_SIZE):
    return generate(output_file, 'mdia', target_size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--size', type=int, default=DEFAULT_SIZE,
                        help='output size in bytes for EACH file (default: 104857600 = 100 MiB)')
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent / 'output')
    args = parser.parse_args()
    for kind, name in (('minf', 'mp4_with_duplicate_minf_100mb.mp4'),
                       ('mdia', 'mp4_with_duplicate_mdia_100mb.mp4')):
        try:
            path = generate(args.output_dir / name, kind, args.size)
        except ValueError as exc:
            parser.error(str(exc))
        print(f'{path}: {path.stat().st_size} bytes (duplicate {kind})')
    print('Structural fixtures only: no playable video samples.')


if __name__ == '__main__':
    main()
