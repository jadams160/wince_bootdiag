#!/usr/bin/env python3
"""
wince_boot_diag.py
==================
Windows CE Compact Flash image boot diagnostics.

Analyses a raw .img (dd) file for common x86 bootloader and CE kernel
boot failures. Covers:
  - MBR / partition table
  - VBR (Volume Boot Record) / FAT BPB
  - FAT filesystem health (dirty flag, lost clusters, FAT chain integrity)
  - EBOOT / OEM bootloader detection and signature check
  - NK.BIN / NK.NB0 location and CE ROM image structure validation
  - XIP record checksums
  - Entropy / blank-sector analysis on critical regions

Usage:
    python3 wince_boot_diag.py <image.img> [--verbose] [--dump-sectors N]

Requires only the Python standard library.
"""

import sys
import os
import struct
import argparse
import hashlib
from dataclasses import dataclass, field
from typing import Optional, List, Tuple

# ---------------------------------------------------------------------------
# Colour helpers (fall back gracefully on Windows)
# ---------------------------------------------------------------------------
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
except Exception:
    pass

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def ok(msg):    print(f"  {GREEN}[OK]{RESET}    {msg}")
def warn(msg):  print(f"  {YELLOW}[WARN]{RESET}  {msg}")
def err(msg):   print(f"  {RED}[FAIL]{RESET}  {msg}")
def info(msg):  print(f"  {CYAN}[INFO]{RESET}  {msg}")
def hdr(msg):   print(f"\n{BOLD}{CYAN}{'='*60}{RESET}\n{BOLD} {msg}{RESET}\n{'='*60}")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SECTOR_SIZE        = 512
CE_ROM_SIGNATURE   = b'B000FF\n'          # NK.BIN plain-binary signature
CE_ROMHDR_MAGIC    = 0x43454345           # 'CECE' — ROM header magic (some OEMs)
EBOOT_SIGNATURES   = [
    b'EBOOT',
    b'WinCE',
    b'Windows CE',
    b'CEBOOT',
    b'BOOTLDR',
    b'BLDR',
    b'Loading',
    b'Booting',
]
NK_FILENAMES       = [
    'NK.BIN', 'NK.NB0', 'NK.BIN.GZ',
    'IMGFLASH.BIN', 'IMGFLASH.NB0',
    'NKNOCOMP.BIN',
]
FAT_DIRTY_MASK16   = 0x8000
FAT_DIRTY_MASK32   = 0x08000000

# ---------------------------------------------------------------------------
# Result accumulator
# ---------------------------------------------------------------------------
@dataclass
class DiagResult:
    issues: List[Tuple[str, str]] = field(default_factory=list)   # (severity, msg)

    def add(self, severity: str, msg: str):
        self.issues.append((severity, msg))
        if severity == 'ok':   ok(msg)
        elif severity == 'warn': warn(msg)
        elif severity == 'err':  err(msg)
        else:                   info(msg)

    def summary(self):
        errors   = sum(1 for s, _ in self.issues if s == 'err')
        warnings = sum(1 for s, _ in self.issues if s == 'warn')
        hdr("DIAGNOSIS SUMMARY")
        if errors == 0 and warnings == 0:
            print(f"  {GREEN}No issues found.{RESET}")
        else:
            if errors:
                print(f"  {RED}{errors} ERROR(S) — likely boot-blocking{RESET}")
            if warnings:
                print(f"  {YELLOW}{warnings} WARNING(S) — potential intermittent failures{RESET}")
        print()
        print("  Likely boot-failure causes (in probability order):")
        for i, (sev, msg) in enumerate(self.issues, 1):
            mark = "✗" if sev == 'err' else ("△" if sev == 'warn' else "·")
            print(f"    {i:>2}. [{mark}] {msg}")

# ---------------------------------------------------------------------------
# Low-level image helpers
# ---------------------------------------------------------------------------
class ImageFile:
    def __init__(self, path: str):
        self.path = path
        self.size = os.path.getsize(path)
        self._f   = open(path, 'rb')

    def close(self):
        self._f.close()

    def read_sector(self, lba: int, count: int = 1) -> bytes:
        offset = lba * SECTOR_SIZE
        if offset + count * SECTOR_SIZE > self.size:
            return b''
        self._f.seek(offset)
        return self._f.read(count * SECTOR_SIZE)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset + length > self.size:
            return b''
        self._f.seek(offset)
        return self._f.read(length)

    def sector_entropy(self, lba: int) -> float:
        """Shannon entropy of one sector (0=uniform, 8=random)."""
        data = self.read_sector(lba)
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        import math
        entropy = 0.0
        n = len(data)
        for c in counts:
            if c:
                p = c / n
                entropy -= p * math.log2(p)
        return entropy

    def is_blank(self, lba: int) -> bool:
        data = self.read_sector(lba)
        return all(b == 0x00 for b in data) or all(b == 0xFF for b in data)

# ---------------------------------------------------------------------------
# MBR / Partition table
# ---------------------------------------------------------------------------
@dataclass
class Partition:
    index:      int
    status:     int
    part_type:  int
    lba_start:  int
    lba_size:   int

MBR_SIGNATURE = 0xAA55

FAT_TYPES = {
    0x01: 'FAT12',
    0x04: 'FAT16 <32M',
    0x06: 'FAT16',
    0x0B: 'FAT32',
    0x0C: 'FAT32 LBA',
    0x0E: 'FAT16 LBA',
    0x0F: 'Extended LBA',
    0x05: 'Extended',
    0x07: 'NTFS/exFAT',
    0xCE: 'CE TFAT',      # some OEM CE images use this
}

def parse_mbr(img: ImageFile, res: DiagResult) -> List[Partition]:
    hdr("1. MBR & PARTITION TABLE")
    data = img.read_sector(0)
    if len(data) < 512:
        res.add('err', 'Image too small to contain an MBR')
        return []

    sig = struct.unpack_from('<H', data, 510)[0]
    if sig != MBR_SIGNATURE:
        res.add('err', f'MBR signature invalid: 0x{sig:04X} (expected 0xAA55)')
    else:
        res.add('ok', f'MBR signature valid (0xAA55)')

    # Check MBR bootstrap entropy — blank/zero code is suspicious
    mbr_code = data[:446]
    if all(b == 0 for b in mbr_code):
        res.add('warn', 'MBR bootstrap code is all zeros — bootloader may not be installed in MBR')
    elif all(b == 0xFF for b in mbr_code):
        res.add('err', 'MBR bootstrap code is all 0xFF — CF card may be erased/corrupt')
    else:
        res.add('ok', 'MBR bootstrap code appears populated')

    partitions = []
    for i in range(4):
        off = 446 + i * 16
        pe = data[off:off+16]
        status, _, _, _, ptype, _, lba_start, lba_size = struct.unpack_from('<B3sB3sII', pe)
        # Fix: unpack correctly
        status   = pe[0]
        ptype    = pe[4]
        lba_start = struct.unpack_from('<I', pe, 8)[0]
        lba_size  = struct.unpack_from('<I', pe, 12)[0]

        if lba_size == 0:
            continue
        p = Partition(i+1, status, ptype, lba_start, lba_size)
        partitions.append(p)
        type_name = FAT_TYPES.get(ptype, f'Unknown (0x{ptype:02X})')
        bootable  = ' [BOOTABLE]' if status == 0x80 else ''
        info(f'Partition {i+1}: type={type_name}, LBA {lba_start}–{lba_start+lba_size-1} '
             f'({lba_size*512//1024}KB){bootable}')

        if status not in (0x00, 0x80):
            res.add('warn', f'Partition {i+1} has non-standard status byte 0x{status:02X}')

    if not partitions:
        res.add('err', 'No partitions found in MBR partition table')
    else:
        bootable = [p for p in partitions if p.status == 0x80]
        if not bootable:
            res.add('warn', 'No partition marked as bootable (0x80) — BIOS may refuse to boot')
        else:
            res.add('ok', f'Partition {bootable[0].index} is marked bootable')

    return partitions

# ---------------------------------------------------------------------------
# BPB / FAT structures
# ---------------------------------------------------------------------------
@dataclass
class BPB:
    bytes_per_sector:   int
    sectors_per_cluster: int
    reserved_sectors:   int
    num_fats:           int
    root_entry_count:   int
    total_sectors_16:   int
    media_type:         int
    fat_size_16:        int
    total_sectors_32:   int
    fat_size_32:        int
    root_cluster:       int
    fat_type:           str   # 'FAT12','FAT16','FAT32'
    fat_start_lba:      int
    root_dir_lba:       int
    data_start_lba:     int
    part_start_lba:     int
    volume_label:       str
    oem_name:           str

def parse_bpb(img: ImageFile, part: Partition, res: DiagResult) -> Optional[BPB]:
    hdr(f"2. VBR / FAT BPB (Partition {part.index})")
    vbr = img.read_sector(part.lba_start)
    if len(vbr) < 512:
        res.add('err', 'Could not read VBR sector')
        return None

    sig = struct.unpack_from('<H', vbr, 510)[0]
    if sig != 0xAA55:
        res.add('err', f'VBR signature invalid: 0x{sig:04X}')
        return None
    else:
        res.add('ok', 'VBR signature valid (0xAA55)')

    oem = vbr[3:11].decode('ascii', errors='replace').strip()
    info(f'OEM name: "{oem}"')

    bps  = struct.unpack_from('<H', vbr, 11)[0]
    spc  = vbr[13]
    rsvd = struct.unpack_from('<H', vbr, 14)[0]
    nfat = vbr[16]
    rec  = struct.unpack_from('<H', vbr, 17)[0]
    ts16 = struct.unpack_from('<H', vbr, 19)[0]
    med  = vbr[21]
    fs16 = struct.unpack_from('<H', vbr, 22)[0]
    ts32 = struct.unpack_from('<I', vbr, 32)[0]

    if bps != 512:
        res.add('warn', f'Bytes per sector = {bps} (non-standard, expected 512)')
    if spc == 0:
        res.add('err', 'Sectors per cluster = 0 — corrupt BPB')
        return None

    # Determine FAT type
    fat_size_32 = 0
    root_cluster = 2
    if fs16 == 0:
        fat_size_32   = struct.unpack_from('<I', vbr, 36)[0]
        root_cluster  = struct.unpack_from('<I', vbr, 44)[0]
        fat_type      = 'FAT32'
        vol_label_off = 71
    else:
        fat_size_32  = fs16
        fat_type     = 'FAT16'  # or FAT12, determined below
        vol_label_off= 43

    total_sectors = ts32 if ts16 == 0 else ts16
    fat_start     = part.lba_start + rsvd
    root_dir_lba  = fat_start + nfat * fat_size_32
    data_start    = root_dir_lba + (rec * 32 + bps - 1) // bps
    data_clusters = (total_sectors - data_start + part.lba_start) // spc

    if fat_type == 'FAT16' and data_clusters < 4085:
        fat_type = 'FAT12'

    try:
        vol_label = vbr[vol_label_off:vol_label_off+11].decode('ascii', errors='replace').strip()
    except Exception:
        vol_label = '(unreadable)'

    info(f'FAT type: {fat_type}, Cluster size: {spc * bps} bytes')
    info(f'Volume label: "{vol_label}"')
    info(f'FAT start LBA: {fat_start}, Root dir LBA: {root_dir_lba}, Data start LBA: {data_start}')
    info(f'Total sectors: {total_sectors}, Data clusters: {data_clusters}')

    if med not in (0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
        res.add('warn', f'Media type byte 0x{med:02X} is non-standard')

    b = BPB(bps, spc, rsvd, nfat, rec, ts16, med, fs16, ts32, fat_size_32,
            root_cluster, fat_type, fat_start, root_dir_lba, data_start,
            part.lba_start, vol_label, oem)
    return b

# ---------------------------------------------------------------------------
# FAT health check
# ---------------------------------------------------------------------------
def check_fat(img: ImageFile, bpb: BPB, res: DiagResult):
    hdr("3. FAT HEALTH CHECK")

    # Read FAT1
    fat_bytes = bpb.fat_size_32 * SECTOR_SIZE
    fat_data  = img.read_at(bpb.fat_start_lba * SECTOR_SIZE, fat_bytes)
    if not fat_data:
        res.add('err', 'Could not read FAT region')
        return

    # Dirty bit check
    if bpb.fat_type == 'FAT32':
        fat1_entry = struct.unpack_from('<I', fat_data, 4)[0]
        dirty = not bool(fat1_entry & FAT_DIRTY_MASK32)
    elif bpb.fat_type == 'FAT16':
        fat1_entry = struct.unpack_from('<H', fat_data, 2)[0]
        dirty = not bool(fat1_entry & FAT_DIRTY_MASK16)
    else:
        dirty = False  # FAT12 has no dirty bit

    if dirty:
        res.add('warn', 'FAT dirty bit is SET — filesystem was not cleanly unmounted (TFAT corruption possible)')
    else:
        res.add('ok', 'FAT dirty bit clear (clean unmount)')

    # Compare FAT1 and FAT2
    if bpb.num_fats >= 2:
        fat2_start = bpb.fat_start_lba + bpb.fat_size_32
        fat2_data  = img.read_at(fat2_start * SECTOR_SIZE, fat_bytes)
        if fat_data != fat2_data:
            diffs = sum(1 for a, b in zip(fat_data, fat2_data) if a != b)
            res.add('warn', f'FAT1 and FAT2 differ by {diffs} bytes — possible incomplete write / TFAT inconsistency')
        else:
            res.add('ok', 'FAT1 and FAT2 are identical')
    else:
        res.add('warn', 'Only one FAT copy present — no redundancy')

    # Scan for obviously corrupt FAT entries (0x01 is illegal in FAT16/32)
    if bpb.fat_type in ('FAT16', 'FAT32'):
        entry_size = 4 if bpb.fat_type == 'FAT32' else 2
        fmt        = '<I' if bpb.fat_type == 'FAT32' else '<H'
        eoc        = 0x0FFFFFF8 if bpb.fat_type == 'FAT32' else 0xFFF8
        bad_count  = 0
        n_entries  = min(len(fat_data) // entry_size, 65536)
        for i in range(2, n_entries):
            val = struct.unpack_from(fmt, fat_data, i * entry_size)[0]
            if bpb.fat_type == 'FAT32':
                val &= 0x0FFFFFFF
            if val == 1:   # cluster 1 is always illegal as a next-pointer
                bad_count += 1
        if bad_count:
            res.add('warn', f'{bad_count} illegal FAT chain entries found (value=1) — possible corruption')
        else:
            res.add('ok', 'No illegal FAT chain entries found')

# ---------------------------------------------------------------------------
# Root directory walk + NK.BIN location
# ---------------------------------------------------------------------------
@dataclass
class DirEntry:
    name:      str
    attr:      int
    size:      int
    start_cluster: int
    is_dir:    bool

def read_fat_chain(fat_data: bytes, start: int, fat_type: str) -> List[int]:
    clusters = []
    current  = start
    visited  = set()
    if fat_type == 'FAT32':
        eoc = 0x0FFFFFF8
        fmt = '<I'
        sz  = 4
        mask= 0x0FFFFFFF
    else:
        eoc = 0xFFF8
        fmt = '<H'
        sz  = 2
        mask= 0xFFFF

    while True:
        if current in visited or current < 2:
            break
        clusters.append(current)
        visited.add(current)
        offset = current * sz
        if offset + sz > len(fat_data):
            break
        nxt = struct.unpack_from(fmt, fat_data, offset)[0] & mask
        if nxt >= (eoc & mask):
            break
        current = nxt
    return clusters

def parse_dir_sector(data: bytes) -> List[DirEntry]:
    entries = []
    for i in range(len(data) // 32):
        e = data[i*32:(i+1)*32]
        if e[0] == 0x00:
            break
        if e[0] == 0xE5:
            continue  # deleted
        attr = e[11]
        if attr == 0x0F:
            continue  # LFN entry
        raw_name = e[0:8].decode('ascii', errors='replace').rstrip()
        raw_ext  = e[8:11].decode('ascii', errors='replace').rstrip()
        name     = raw_name + ('.' + raw_ext if raw_ext else '')
        size     = struct.unpack_from('<I', e, 28)[0]
        hi       = struct.unpack_from('<H', e, 20)[0]
        lo       = struct.unpack_from('<H', e, 26)[0]
        cluster  = (hi << 16) | lo
        is_dir   = bool(attr & 0x10)
        entries.append(DirEntry(name, attr, size, cluster, is_dir))
    return entries

def find_nk_bin(img: ImageFile, bpb: BPB, res: DiagResult) -> Optional[Tuple[DirEntry, int]]:
    hdr("4. ROOT DIRECTORY & NK.BIN LOCATION")

    fat_bytes = bpb.fat_size_32 * SECTOR_SIZE
    fat_data  = img.read_at(bpb.fat_start_lba * SECTOR_SIZE, fat_bytes)

    def cluster_to_lba(cluster):
        return bpb.data_start_lba + (cluster - 2) * bpb.sectors_per_cluster

    # Read root directory
    all_entries = []
    if bpb.fat_type == 'FAT32':
        # FAT32: root dir is a cluster chain
        clusters = read_fat_chain(fat_data, bpb.root_cluster, bpb.fat_type)
        for c in clusters:
            lba  = cluster_to_lba(c)
            data = img.read_sector(lba, bpb.sectors_per_cluster)
            all_entries.extend(parse_dir_sector(data))
    else:
        # FAT12/16: fixed root dir
        root_size = bpb.root_entry_count * 32
        data = img.read_at(bpb.root_dir_lba * SECTOR_SIZE, root_size)
        all_entries = parse_dir_sector(data)

    if not all_entries:
        res.add('warn', 'Root directory is empty or unreadable')
        return None

    info(f'Root directory entries found: {len(all_entries)}')
    for e in all_entries:
        tag = '[DIR]' if e.is_dir else f'{e.size//1024}KB'
        info(f'  {e.name:<20} {tag}')

    # Find NK.BIN or equivalent
    nk_entry = None
    for e in all_entries:
        if e.name.upper() in NK_FILENAMES:
            nk_entry = e
            break

    if not nk_entry:
        # Try sub-directories one level deep
        for e in all_entries:
            if e.is_dir and e.start_cluster >= 2:
                clusters = read_fat_chain(fat_data, e.start_cluster, bpb.fat_type)
                for c in clusters:
                    lba  = cluster_to_lba(c)
                    data = img.read_sector(lba, bpb.sectors_per_cluster)
                    sub  = parse_dir_sector(data)
                    for se in sub:
                        if se.name.upper() in NK_FILENAMES:
                            nk_entry = se
                            info(f'Found {se.name} in subdirectory {e.name}')
                            break
                if nk_entry:
                    break

    if not nk_entry:
        res.add('err', 'NK.BIN / NK.NB0 / IMGFLASH.BIN not found in filesystem')
        return None

    res.add('ok', f'Found CE kernel image: {nk_entry.name} ({nk_entry.size//1024} KB, cluster {nk_entry.start_cluster})')

    # Check FAT chain for NK.BIN
    if nk_entry.start_cluster >= 2:
        chain = read_fat_chain(fat_data, nk_entry.start_cluster, bpb.fat_type)
        expected_clusters = (nk_entry.size + bpb.sectors_per_cluster * SECTOR_SIZE - 1) \
                            // (bpb.sectors_per_cluster * SECTOR_SIZE)
        info(f'NK.BIN FAT chain length: {len(chain)} clusters (expected ~{expected_clusters})')
        if len(chain) < expected_clusters:
            res.add('err', f'NK.BIN FAT chain truncated: {len(chain)} clusters but file size implies {expected_clusters}')
        elif len(chain) > expected_clusters + 1:
            res.add('warn', f'NK.BIN FAT chain longer than expected — possible phantom clusters')
        else:
            res.add('ok', 'NK.BIN FAT chain length matches file size')

        # Check for blank/erased clusters in NK.BIN
        blank_count = 0
        for c in chain[:min(len(chain), 64)]:  # check first 64 clusters
            lba = cluster_to_lba(c)
            if img.is_blank(lba):
                blank_count += 1
        if blank_count:
            res.add('err', f'{blank_count} blank/erased sectors in NK.BIN data area — CF read failure / incomplete write')
        else:
            res.add('ok', 'No blank sectors detected in first 64 clusters of NK.BIN')

        # Return file's LBA offset for further analysis
        if chain:
            nk_lba = cluster_to_lba(chain[0])
            return nk_entry, nk_lba

    return nk_entry, None

# ---------------------------------------------------------------------------
# CE ROM image (NK.BIN) structure validation
# ---------------------------------------------------------------------------
CE_ROMHDR_SIZE   = 72
ROM_SIGNATURE    = b'B000FF\n'  # 7 bytes at start of NK.BIN

# NK.BIN plain format:
#  Offset 0x00: ROM_SIGNATURE (7 bytes) + 1 byte reserved = 8 bytes
#  Then: ROMHDR at fixed physical address (referenced in header records)
#
# NK.NB0 (raw binary) has no header — it's loaded at a fixed address.
# EBOOT typically validates a checksum in the TOC.

def validate_nkbin(img: ImageFile, nk_entry: DirEntry, nk_lba: int, bpb: BPB, res: DiagResult):
    hdr("5. CE ROM IMAGE (NK.BIN) STRUCTURE VALIDATION")

    if nk_lba is None:
        res.add('warn', 'Cannot validate NK.BIN content — LBA unknown')
        return

    # Read first 512 bytes of NK.BIN
    header_data = img.read_sector(nk_lba, 1)
    if not header_data:
        res.add('err', 'Could not read NK.BIN first sector')
        return

    # Check NK.BIN signature
    if header_data[:7] == ROM_SIGNATURE:
        res.add('ok', 'NK.BIN ROM signature present (B000FF)')
        parse_nkbin_records(img, nk_entry, nk_lba, bpb, res)
    elif header_data[:4] == b'\x00\x00\x00\x00':
        res.add('err', 'NK.BIN starts with zeros — file is blank or not written')
    elif header_data[:4] == b'\xFF\xFF\xFF\xFF':
        res.add('err', 'NK.BIN starts with 0xFF — CF sector erased, kernel image missing')
    else:
        # May be NB0 (raw) or a compressed image
        entropy = sum(header_data) / (len(header_data) * 255)
        if entropy > 0.8:
            res.add('warn', 'NK.BIN has no standard signature — may be NB0 (raw) or compressed. Skipping deep parse.')
        else:
            res.add('warn', f'NK.BIN signature not recognised (first bytes: {header_data[:8].hex()}) — possibly custom OEM format')
        info(f'First 16 bytes: {header_data[:16].hex(" ")}')

def parse_nkbin_records(img: ImageFile, nk_entry: DirEntry, nk_lba: int,
                        bpb: BPB, res: DiagResult):
    """
    NK.BIN format (plain binary, no compression):
      [7]  signature: B000FF\n
      [1]  reserved
      [4]  image start physical address
      [4]  image length
      Then a sequence of records:
        [4] record physical address (0 = end marker)
        [4] record length
        [4] record checksum (sum of all DWORD values in the record data)
        [N] record data
    """
    fat_bytes = bpb.fat_size_32 * SECTOR_SIZE
    fat_data  = img.read_at(bpb.fat_start_lba * SECTOR_SIZE, fat_bytes)

    def cluster_to_lba(c):
        return bpb.data_start_lba + (c - 2) * bpb.sectors_per_cluster

    # Rebuild the full NK.BIN byte stream from FAT chain
    chain = read_fat_chain(fat_data, nk_entry.start_cluster, bpb.fat_type)
    cluster_bytes = bpb.sectors_per_cluster * SECTOR_SIZE
    max_read_clusters = min(len(chain), 4096)  # cap at 16MB to avoid huge reads

    info(f'Reading {max_read_clusters}/{len(chain)} clusters for NK.BIN analysis...')
    nkbin_data = bytearray()
    for c in chain[:max_read_clusters]:
        lba  = cluster_to_lba(c)
        data = img.read_sector(lba, bpb.sectors_per_cluster)
        nkbin_data.extend(data)
    nkbin_data = bytes(nkbin_data[:nk_entry.size])

    if len(nkbin_data) < 16:
        res.add('err', 'NK.BIN too short to contain valid ROM image records')
        return

    # Parse header
    img_start  = struct.unpack_from('<I', nkbin_data,  8)[0]
    img_length = struct.unpack_from('<I', nkbin_data, 12)[0]
    info(f'ROM image physical start: 0x{img_start:08X}, length: 0x{img_length:08X} ({img_length//1024} KB)')

    if img_length == 0 or img_length > 128 * 1024 * 1024:
        res.add('warn', f'ROM image length {img_length} looks suspicious')

    # Walk records
    offset       = 16
    rec_count    = 0
    bad_checksum = 0
    blank_recs   = 0
    total_data   = 0

    while offset + 12 <= len(nkbin_data):
        rec_addr = struct.unpack_from('<I', nkbin_data, offset)[0]
        rec_len  = struct.unpack_from('<I', nkbin_data, offset + 4)[0]
        rec_csum = struct.unpack_from('<I', nkbin_data, offset + 8)[0]
        offset  += 12

        if rec_addr == 0:
            # End of records — rec_len is the entry point address
            info(f'ROM image entry point: 0x{rec_len:08X}')
            break

        if rec_len == 0 or rec_len > img_length:
            res.add('warn', f'Record at 0x{rec_addr:08X} has suspicious length {rec_len}')
            break

        rec_data = nkbin_data[offset:offset + rec_len]
        offset  += rec_len
        rec_count += 1
        total_data += rec_len

        if len(rec_data) < rec_len:
            res.add('err', f'Record at 0x{rec_addr:08X} truncated ({len(rec_data)}/{rec_len} bytes) — NK.BIN incomplete')
            break

        # Verify checksum: simple sum of all DWORD values
        calc_csum = 0
        for i in range(0, len(rec_data) - 3, 4):
            calc_csum = (calc_csum + struct.unpack_from('<I', rec_data, i)[0]) & 0xFFFFFFFF

        if calc_csum != rec_csum:
            bad_checksum += 1
            if bad_checksum <= 3:  # don't spam
                res.add('err', f'Record 0x{rec_addr:08X} checksum MISMATCH: stored=0x{rec_csum:08X} calc=0x{calc_csum:08X}')

        # Check for blank record data
        if all(b == 0xFF for b in rec_data) or all(b == 0x00 for b in rec_data):
            blank_recs += 1

        if rec_count > 4096:
            res.add('warn', 'Exceeded 4096 NK.BIN records — stopping early')
            break

    info(f'NK.BIN records parsed: {rec_count}, total data: {total_data//1024} KB')

    if bad_checksum == 0:
        res.add('ok', f'All {rec_count} NK.BIN record checksums verified correctly')
    else:
        res.add('err', f'{bad_checksum} NK.BIN record checksum failures — EBOOT will refuse to boot this image')

    if blank_recs:
        res.add('warn', f'{blank_recs} NK.BIN records contain only 0x00 or 0xFF — possible partial write')

# ---------------------------------------------------------------------------
# EBOOT / bootloader detection
# ---------------------------------------------------------------------------
def find_eboot(img: ImageFile, partitions: List[Partition], bpb: Optional[BPB], res: DiagResult):
    hdr("6. EBOOT / BOOTLOADER DETECTION")

    # Locations to scan: MBR code, VBR code, first few sectors of partition,
    # and known EBOOT filenames in filesystem
    scan_lbas = [0, 1, 2, 3]
    if partitions:
        p = partitions[0]
        scan_lbas += list(range(p.lba_start, min(p.lba_start + 64, p.lba_start + p.lba_size)))

    found_strings = {}
    for lba in scan_lbas:
        data = img.read_sector(lba)
        if not data:
            continue
        for sig in EBOOT_SIGNATURES:
            if sig in data:
                if sig not in found_strings:
                    found_strings[sig] = lba
                    info(f'Bootloader string "{sig.decode("ascii","replace")}" found at LBA {lba}')

    if found_strings:
        res.add('ok', f'Bootloader strings detected in {len(found_strings)} location(s)')
    else:
        res.add('warn', 'No known bootloader strings found in first 64 sectors — EBOOT may be in filesystem or custom')

    # Look for EBOOT.BIN / EBOOT.NB0 in root dir listing already done
    eboot_names = ['EBOOT.BIN', 'EBOOT.NB0', 'BOOT.BIN', 'BOOTLDR.BIN', 'WINCE.BIN', 'BL.BIN']
    info('(Check root directory listing above for EBOOT.BIN / EBOOT.NB0)')

    # Check VBR entropy — low entropy = not installed
    if partitions:
        vbr_code = img.read_sector(partitions[0].lba_start)[:448]
        if vbr_code and all(b == 0 for b in vbr_code[3:]):
            res.add('warn', 'VBR bootstrap code is empty after OEM name — stage-2 loader not installed in VBR')
        elif vbr_code:
            res.add('ok', 'VBR bootstrap code appears populated')

# ---------------------------------------------------------------------------
# Sector entropy scan (critical regions)
# ---------------------------------------------------------------------------
def entropy_scan(img: ImageFile, partitions: List[Partition], res: DiagResult):
    hdr("7. CRITICAL SECTOR ENTROPY SCAN")
    import math

    def sector_summary(lba: int, label: str):
        data = img.read_sector(lba)
        if not data:
            info(f'{label} (LBA {lba}): unreadable')
            return
        counts = [0]*256
        for b in data: counts[b] += 1
        ent = 0.0
        for c in counts:
            if c:
                p = c/512
                ent -= p*math.log2(p)
        zeros = counts[0]
        ones  = counts[255]
        flag = ''
        if ent < 0.5:
            flag = f'{RED}[BLANK/SUSPICIOUS]{RESET}'
        elif ent > 7.5:
            flag = f'{CYAN}[HIGH ENTROPY/COMPRESSED]{RESET}'
        print(f'    LBA {lba:6d}  {label:<25}  entropy={ent:.2f}  zeros={zeros:3d}  0xFF={ones:3d}  {flag}')
        return ent

    sector_summary(0, 'MBR')
    if partitions:
        p = partitions[0]
        sector_summary(p.lba_start,     'VBR (partition start)')
        sector_summary(p.lba_start + 1, 'VBR+1')
        sector_summary(p.lba_start + 2, 'VBR+2')

    # Scan first 32 sectors of image
    print(f'\n  First 32 sectors:')
    for lba in range(32):
        sector_summary(lba, f'sector {lba}')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description='Windows CE CF image boot diagnostics')
    ap.add_argument('image', help='Path to .img file')
    ap.add_argument('--verbose', '-v', action='store_true', help='Extra detail')
    ap.add_argument('--entropy-scan', action='store_true', help='Full critical-sector entropy scan')
    args = ap.parse_args()

    if not os.path.exists(args.image):
        print(f'{RED}Error: file not found: {args.image}{RESET}')
        sys.exit(1)

    img = ImageFile(args.image)
    res = DiagResult()

    print(f'\n{BOLD}Windows CE CF Image Boot Diagnostics{RESET}')
    print(f'Image: {args.image}  ({img.size//1024//1024} MB, {img.size//512} sectors)\n')

    # Run all checks
    partitions = parse_mbr(img, res)

    bpb = None
    if partitions:
        boot_part = next((p for p in partitions if p.status == 0x80), partitions[0])
        bpb = parse_bpb(img, boot_part, res)

    if bpb:
        check_fat(img, bpb, res)
        result = find_nk_bin(img, bpb, res)
        if result:
            nk_entry, nk_lba = result
            validate_nkbin(img, nk_entry, nk_lba, bpb, res)

    find_eboot(img, partitions, bpb, res)

    if args.entropy_scan:
        entropy_scan(img, partitions, res)

    img.close()
    res.summary()

if __name__ == '__main__':
    main()
