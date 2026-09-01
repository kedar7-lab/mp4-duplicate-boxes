#!/usr/bin/env python3
"""
Generate MP4 files with duplicate minf/mdia boxes for testing purposes.

This script creates intentionally malformed MP4 files to test parser robustness
and understand ISOBMFF (ISO Base Media File Format) structure.

Box Hierarchy Reference:
- ftyp: File Type Box
- moov: Movie Box
  - mvhd: Movie Header
  - trak: Track Box
    - tkhd: Track Header
    - mdia: Media Box
      - mdhd: Media Header
      - hdlr: Handler Reference
      - minf: Media Information Box
        - vmhd/smhd: Video/Audio Media Header
        - dinf: Data Information Box
        - stbl: Sample Table Box
"""

import struct
import os
from datetime import datetime


class MP4BoxWriter:
    """Utility class to write MP4 boxes in ISOBMFF format."""
    
    @staticmethod
    def write_box_header(box_type, box_size):
        """Write a box header (size + type)."""
        return struct.pack('>I4s', box_size, box_type.encode('ascii'))
    
    @staticmethod
    def write_full_box_header(box_type, box_size, version=0, flags=0):
        """Write a full box header (size + type + version + flags)."""
        header = MP4BoxWriter.write_box_header(box_type, box_size)
        version_flags = struct.pack('>I', (version << 24) | flags)
        return header + version_flags
    
    @staticmethod
    def create_ftyp_box():
        """Create File Type Box."""
        brand = b'isom'
        minor_version = struct.pack('>I', 512)
        compatible_brands = b'isom' + b'iso2' + b'mp41'
        
        box_size = 8 + 4 + 4 + len(compatible_brands)
        box = MP4BoxWriter.write_box_header('ftyp', box_size)
        box += brand + minor_version + compatible_brands
        return box
    
    @staticmethod
    def create_mvhd_box():
        """Create Movie Header Box (version 1)."""
        version_flags = struct.pack('>I', 0)  # version=0, flags=0
        creation_time = struct.pack('>I', 3600)
        modification_time = struct.pack('>I', 3600)
        timescale = struct.pack('>I', 1000)
        duration = struct.pack('>I', 3000)
        playback_speed = struct.pack('>i', 0x00010000)  # 1.0x
        volume = struct.pack('>H', 0x0100)  # 1.0
        reserved = b'\x00' * 10
        matrix = struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
        preview_time = struct.pack('>I', 0)
        preview_duration = struct.pack('>I', 0)
        next_track_id = struct.pack('>I', 2)
        
        box_data = (version_flags + creation_time + modification_time + timescale +
                   duration + playback_speed + volume + reserved + matrix +
                   preview_time + preview_duration + next_track_id)
        
        box_size = 8 + len(box_data)
        box = MP4BoxWriter.write_box_header('mvhd', box_size)
        return box + box_data
    
    @staticmethod
    def create_mdhd_box():
        """Create Media Header Box."""
        version_flags = struct.pack('>I', 0)
        creation_time = struct.pack('>I', 3600)
        modification_time = struct.pack('>I', 3600)
        timescale = struct.pack('>I', 1000)
        duration = struct.pack('>I', 3000)
        language = struct.pack('>H', 0x55C4)  # "und" (undetermined)
        quality = struct.pack('>H', 0)
        
        box_data = version_flags + creation_time + modification_time + timescale + duration + language + quality
        box_size = 8 + len(box_data)
        box = MP4BoxWriter.write_box_header('mdhd', box_size)
        return box + box_data
    
    @staticmethod
    def create_hdlr_box(handler_type='vide'):
        """Create Handler Reference Box."""
        version_flags = struct.pack('>I', 0)
        pre_defined = struct.pack('>I', 0)
        handler_type_code = handler_type.encode('ascii')
        reserved = b'\x00' * 12
        name = b'VideoHandler\x00'
        
        box_data = version_flags + pre_defined + handler_type_code + reserved + name
        box_size = 8 + len(box_data)
        box = MP4BoxWriter.write_box_header('hdlr', box_size)
        return box + box_data
    
    @staticmethod
    def create_vmhd_box():
        """Create Video Media Header Box."""
        version_flags = struct.pack('>I', 0)
        graphics_mode = struct.pack('>H', 0)
        opcolor = struct.pack('>HHH', 0, 0, 0)
        
        box_data = version_flags + graphics_mode + opcolor
        box_size = 8 + len(box_data)
        box = MP4BoxWriter.write_box_header('vmhd', box_size)
        return box + box_data
    
    @staticmethod
    def create_smhd_box():
        """Create Audio Media Header Box."""
        version_flags = struct.pack('>I', 0)
        balance = struct.pack('>h', 0)
        reserved = struct.pack('>H', 0)
        
        box_data = version_flags + balance + reserved
        box_size = 8 + len(box_data)
        box = MP4BoxWriter.write_box_header('smhd', box_size)
        return box + box_data
    
    @staticmethod
    def create_dinf_box():
        """Create Data Information Box with dref."""
        dref_version_flags = struct.pack('>I', 0)
        dref_entry_count = struct.pack('>I', 1)
        
        # Self-referencing data reference
        url_box_data = struct.pack('>I', 1)  # version=0, flags=1 (self-reference)
        url_box_size = 8 + len(url_box_data)
        url_box = struct.pack('>I4s', url_box_size, b'url ')
        url_box += url_box_data
        
        dref_data = dref_version_flags + dref_entry_count + url_box
        dref_size = 8 + len(dref_data)
        dref_box = struct.pack('>I4s', dref_size, b'dref')
        dref_box += dref_data
        
        dinf_size = 8 + dref_size
        dinf_box = struct.pack('>I4s', dinf_size, b'dinf')
        return dinf_box + dref_box
    
    @staticmethod
    def create_stbl_box():
        """Create Sample Table Box (minimal)."""
        # stsd (sample description)
        stsd_version_flags = struct.pack('>I', 0)
        stsd_entry_count = struct.pack('>I', 0)
        stsd_data = stsd_version_flags + stsd_entry_count
        stsd_size = 8 + len(stsd_data)
        stsd_box = struct.pack('>I4s', stsd_size, b'stsd') + stsd_data
        
        # stts (time to sample)
        stts_version_flags = struct.pack('>I', 0)
        stts_entry_count = struct.pack('>I', 0)
        stts_data = stts_version_flags + stts_entry_count
        stts_size = 8 + len(stts_data)
        stts_box = struct.pack('>I4s', stts_size, b'stts') + stts_data
        
        # stsc (sample to chunk)
        stsc_version_flags = struct.pack('>I', 0)
        stsc_entry_count = struct.pack('>I', 0)
        stsc_data = stsc_version_flags + stsc_entry_count
        stsc_size = 8 + len(stsc_data)
        stsc_box = struct.pack('>I4s', stsc_size, b'stsc') + stsc_data
        
        # stsz (sample size)
        stsz_version_flags = struct.pack('>I', 0)
        stsz_sample_size = struct.pack('>I', 0)
        stsz_sample_count = struct.pack('>I', 0)
        stsz_data = stsz_version_flags + stsz_sample_size + stsz_sample_count
        stsz_size = 8 + len(stsz_data)
        stsz_box = struct.pack('>I4s', stsz_size, b'stsz') + stsz_data
        
        # stco (chunk offset)
        stco_version_flags = struct.pack('>I', 0)
        stco_entry_count = struct.pack('>I', 0)
        stco_data = stco_version_flags + stco_entry_count
        stco_size = 8 + len(stco_data)
        stco_box = struct.pack('>I4s', stco_size, b'stco') + stco_data
        
        stbl_data = stsd_box + stts_box + stsc_box + stsz_box + stco_box
        stbl_size = 8 + len(stbl_data)
        stbl_box = struct.pack('>I4s', stbl_size, b'stbl')
        return stbl_box + stbl_data
    
    @staticmethod
    def create_minf_box(handler_type='vide'):
        """Create Media Information Box."""
        if handler_type == 'vide':
            media_header = MP4BoxWriter.create_vmhd_box()
        else:
            media_header = MP4BoxWriter.create_smhd_box()
        
        dinf = MP4BoxWriter.create_dinf_box()
        stbl = MP4BoxWriter.create_stbl_box()
        
        minf_data = media_header + dinf + stbl
        minf_size = 8 + len(minf_data)
        minf_box = struct.pack('>I4s', minf_size, b'minf')
        return minf_box + minf_data
    
    @staticmethod
    def create_mdia_box(handler_type='vide'):
        """Create Media Box."""
        mdhd = MP4BoxWriter.create_mdhd_box()
        hdlr = MP4BoxWriter.create_hdlr_box(handler_type)
        minf = MP4BoxWriter.create_minf_box(handler_type)
        
        mdia_data = mdhd + hdlr + minf
        mdia_size = 8 + len(mdia_data)
        mdia_box = struct.pack('>I4s', mdia_size, b'mdia')
        return mdia_box + mdia_data
    
    @staticmethod
    def create_tkhd_box():
        """Create Track Header Box."""
        version_flags = struct.pack('>I', 0x0000000F)  # version=0, flags=15
        creation_time = struct.pack('>I', 3600)
        modification_time = struct.pack('>I', 3600)
        track_id = struct.pack('>I', 1)
        reserved1 = struct.pack('>I', 0)
        duration = struct.pack('>I', 3000)
        reserved2 = struct.pack('>II', 0, 0)
        layer = struct.pack('>H', 0)
        alternate_group = struct.pack('>H', 0)
        volume = struct.pack('>H', 0x0100)
        reserved3 = struct.pack('>H', 0)
        matrix = struct.pack('>9i', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
        width = struct.pack('>I', 0x04800000)  # 320 in 16.16 fixed point
        height = struct.pack('>I', 0x03C00000)  # 240 in 16.16 fixed point
        
        box_data = (version_flags + creation_time + modification_time + track_id +
                   reserved1 + duration + reserved2 + layer + alternate_group +
                   volume + reserved3 + matrix + width + height)
        
        box_size = 8 + len(box_data)
        box = struct.pack('>I4s', box_size, b'tkhd')
        return box + box_data
    
    @staticmethod
    def create_trak_box(duplicate_mdia=False):
        """Create Track Box, optionally with duplicate mdia."""
        tkhd = MP4BoxWriter.create_tkhd_box()
        mdia1 = MP4BoxWriter.create_mdia_box('vide')
        
        trak_data = tkhd + mdia1
        
        if duplicate_mdia:
            # Add a duplicate mdia box AFTER the first complete mdia
            mdia2 = MP4BoxWriter.create_mdia_box('vide')
            trak_data += mdia2
        
        trak_size = 8 + len(trak_data)
        trak_box = struct.pack('>I4s', trak_size, b'trak')
        return trak_box + trak_data
    
    @staticmethod
    def create_moov_box(duplicate_mdia=False):
        """Create Movie Box."""
        mvhd = MP4BoxWriter.create_mvhd_box()
        trak = MP4BoxWriter.create_trak_box(duplicate_mdia)
        
        moov_data = mvhd + trak
        moov_size = 8 + len(moov_data)
        moov_box = struct.pack('>I4s', moov_size, b'moov')
        return moov_box + moov_data


def generate_mp4_with_duplicate_minf(output_file):
    """Generate MP4 with duplicate minf boxes inside a single mdia.
    
    Structure: mdia -> [mdhd, hdlr, minf (vmhd->dinf->stbl), minf (smhd->dinf->stbl)]
    The second minf comes AFTER stbl of the first minf.
    """
    print(f"[*] Generating MP4 with duplicate minf boxes: {output_file}")
    
    # Create base structure
    ftyp = MP4BoxWriter.create_ftyp_box()
    
    # Manually create trak with duplicate minf boxes positioned after stbl
    tkhd = MP4BoxWriter.create_tkhd_box()
    
    # Create mdia with duplicate minf boxes
    mdhd = MP4BoxWriter.create_mdhd_box()
    hdlr = MP4BoxWriter.create_hdlr_box('vide')
    
    # First minf box (video)
    minf1 = MP4BoxWriter.create_minf_box('vide')
    
    # Second minf box (audio) - positioned AFTER stbl of first minf
    minf2 = MP4BoxWriter.create_minf_box('soun')
    
    # Build mdia: mdhd -> hdlr -> minf1 (complete) -> minf2 (complete)
    mdia_data = mdhd + hdlr + minf1 + minf2
    mdia_size = 8 + len(mdia_data)
    mdia_box = struct.pack('>I4s', mdia_size, b'mdia')
    mdia = mdia_box + mdia_data
    
    trak_data = tkhd + mdia
    trak_size = 8 + len(trak_data)
    trak_box = struct.pack('>I4s', trak_size, b'trak')
    trak = trak_box + trak_data
    
    mvhd = MP4BoxWriter.create_mvhd_box()
    moov_data = mvhd + trak
    moov_size = 8 + len(moov_data)
    moov_box = struct.pack('>I4s', moov_size, b'moov')
    moov = moov_box + moov_data
    
    # Combine all boxes
    mp4_data = ftyp + moov
    
    # Write to file
    with open(output_file, 'wb') as f:
        f.write(mp4_data)
    
    print(f"[+] Created: {output_file} ({len(mp4_data)} bytes)")
    print(f"    Structure: ftyp -> moov -> trak -> mdia -> [mdhd, hdlr, minf(vmhd+dinf+stbl), minf(smhd+dinf+stbl)]")
    print(f"    Issue: Two minf boxes in single mdia (second minf positioned AFTER stbl)")


def generate_mp4_with_duplicate_mdia(output_file):
    """Generate MP4 with duplicate mdia boxes inside a single trak.
    
    Structure: trak -> [tkhd, mdia (complete mdhd+hdlr+minf+stbl), mdia (complete mdhd+hdlr+minf+stbl)]
    The second mdia comes AFTER stbl of the first mdia.
    """
    print(f"[*] Generating MP4 with duplicate mdia boxes: {output_file}")
    
    ftyp = MP4BoxWriter.create_ftyp_box()
    moov = MP4BoxWriter.create_moov_box(duplicate_mdia=True)
    
    mp4_data = ftyp + moov
    
    with open(output_file, 'wb') as f:
        f.write(mp4_data)
    
    print(f"[+] Created: {output_file} ({len(mp4_data)} bytes)")
    print(f"    Structure: ftyp -> moov -> trak -> [tkhd, mdia(mdhd+hdlr+minf+stbl), mdia(mdhd+hdlr+minf+stbl)]")
    print(f"    Issue: Two mdia boxes in single trak (second mdia positioned AFTER stbl of first mdia)")


def main():
    """Generate test MP4 files."""
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 80)
    print("MP4 Duplicate Box Generator")
    print("=" * 80)
    print()
    
    # Generate both types
    mp4_minf_file = os.path.join(output_dir, 'mp4_with_duplicate_minf.mp4')
    generate_mp4_with_duplicate_minf(mp4_minf_file)
    print()
    
    mp4_mdia_file = os.path.join(output_dir, 'mp4_with_duplicate_mdia.mp4')
    generate_mp4_with_duplicate_mdia(mp4_mdia_file)
    print()
    
    print("=" * 80)
    print("Generated files:")
    print(f"  - {mp4_minf_file}")
    print(f"  - {mp4_mdia_file}")
    print()
    print("These files have intentional structural violations:")
    print("  1. Duplicate minf: Multiple minf boxes in one mdia (after stbl)")
    print("  2. Duplicate mdia: Multiple mdia boxes in one trak (after stbl)")
    print()
    print("Use with parsers/validators to test robustness:")
    print("  ffprobe -show_boxes <file>")
    print("  mp4dump <file>")
    print("=" * 80)


if __name__ == '__main__':
    main()
