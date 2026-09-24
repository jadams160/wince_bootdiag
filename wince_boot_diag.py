#!/usr/bin/env python3
"""
wince_boot_diag.py
==================
Windows CE Compact Flash image boot diagnostics and repair.

Analyses a raw (dd) image of an x86 Windows CE CF card for common bootloader,
filesystem and kernel-image faults, and can optionally write a repaired COPY
of the image. The input image is never modified.

Diagnostics:
  1. MBR / partition table (or superfloppy layout)
  2. VBR / FAT BPB, with FAT32 backup boot sector fallback
  3. FAT health: clean-shutdown bit, FAT copy comparison, illegal entries
  4. Root directory, bootloader files and kernel image (NK.BIN etc.)
  5. Cluster chains, lost/cross-linked clusters, FAT copy selection, FSInfo
  6. Kernel image structure: BIN records and checksums
  7. Bootloader string detection
  8. Critical-sector entropy scan (optional)

Repairs (with --repair):
  applied automatically when the fault is detected:
    - restore the MBR 0xAA55 signature (only if a valid FAT volume is found)
    - make the boot partition the single active partition
    - restore a damaged FAT32 boot sector from its backup copy
    - synchronise all FAT copies from the most consistent copy
    - set the FAT clean-shutdown bit
    - recompute the FAT32 FSInfo free-cluster count
  applied only on request:
    --fix-illegal-fat     terminate FAT chains at illegal entries
    --free-lost-clusters  mark orphaned (lost) clusters free
    --replace-nk FILE     write a known-good kernel image into the filesystem
    --mbr-code-from IMG   copy MBR boot code from a known-good reference image
    --vbr-code-from IMG   copy VBR boot code from a known-good reference image

Usage:
    python3 wince_boot_diag.py image.img [--entropy-scan] [-v]
    python3 wince_boot_diag.py image.img --repair [--dry-run] [-o out.img] [...]

Requires only the Python standard library (Python 3.7+).
"""

import argparse
import hashlib
import os
import shutil
import string
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

import math

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
RESET = RED = YELLOW = GREEN = CYAN = BOLD = ''


def setup_colour(enabled: bool):
    global RESET, RED, YELLOW, GREEN, CYAN, BOLD
    if not enabled:
        RESET = RED = YELLOW = GREEN = CYAN = BOLD = ''
        return
    if os.name == 'nt':
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
        except Exception:
            pass
    RESET, RED, YELLOW, GREEN, CYAN, BOLD = (
        '\033[0m', '\033[91m', '\033[93m', '\033[92m', '\033[96m', '\033[1m')


def ok(msg):   print(f"  {GREEN}[OK]{RESET}    {msg}")
def warn(msg): print(f"  {YELLOW}[WARN]{RESET}  {msg}")
def err(msg):  print(f"  {RED}[FAIL]{RESET}  {msg}")
def info(msg): print(f"  {CYAN}[INFO]{RESET}  {msg}")
def hdr(msg):  print(f"\n{BOLD}{CYAN}{'=' * 64}{RESET}\n{BOLD} {msg}{RESET}\n{'=' * 64}")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SECTOR_SIZE = 512
BIN_SIGNATURE = b'B000FF\n'     # 7-byte sync at the start of a BIN-format image
BIN_HEADER_SIZE = 15            # sync (7) + image start (4) + image length (4)
MAX_NK_READ = 512 * 1024 * 1024

BOOTLOADER_STRINGS = [b'EBOOT', b'WinCE', b'Windows CE', b'CEBOOT',
                      b'BOOTLDR', b'BLDR', b'Loading', b'Booting']
NK_FILENAMES = ['NK.BIN', 'NK.NB0', 'IMGFLASH.BIN', 'IMGFLASH.NB0', 'NKNOCOMP.BIN']
LOADER_FILENAMES = ['BLDR', 'EBOOT.BIN', 'EBOOT.NB0', 'BOOT.BIN',
                    'BOOTLDR.BIN', 'WINCE.BIN', 'BL.BIN']

PART_TYPES = {
    0x01: 'FAT12', 0x04: 'FAT16 <32M', 0x05: 'Extended', 0x06: 'FAT16',
    0x07: 'NTFS/exFAT', 0x0B: 'FAT32', 0x0C: 'FAT32 LBA', 0x0E: 'FAT16 LBA',
    0x0F: 'Extended LBA',
}
FAT_PARTITION_TYPES = {0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E}

FSINFO_LEAD, FSINFO_STRUCT, FSINFO_TRAIL = 0x41615252, 0x61417272, 0xAA550000

CHAIN_MSG = {
    'loop': 'chain loops back on itself',
    'free_in_chain': 'chain runs into a free cluster',
    'bad_cluster': 'chain runs into a cluster marked bad',
    'illegal': 'chain contains the illegal value 1',
    'out_of_range': 'chain points outside the volume',
    'bad_start': 'start cluster is invalid',
}


# ---------------------------------------------------------------------------
# Result accumulator
# ---------------------------------------------------------------------------
@dataclass
class DiagResult:
    issues: List[Tuple[str, str]] = field(default_factory=list)

    def add(self, severity: str, msg: str):
        self.issues.append((severity, msg))
        {'ok': ok, 'warn': warn, 'err': err}.get(severity, info)(msg)

    @property
    def errors(self) -> int:
        return sum(1 for s, _ in self.issues if s == 'err')

    @property
    def warnings(self) -> int:
        return sum(1 for s, _ in self.issues if s == 'warn')

    def summary(self, title: str = 'DIAGNOSIS SUMMARY'):
        hdr(title)
        if not self.errors and not self.warnings:
            print(f"  {GREEN}No issues found.{RESET}\n")
            return
        if self.errors:
            print(f"  {RED}{self.errors} ERROR(S): likely boot-blocking{RESET}")
        if self.warnings:
            print(f"  {YELLOW}{self.warnings} WARNING(S): potential or intermittent problems{RESET}")
        print("\n  Findings, in the order the checks ran (start with the first error):")
        n = 0
        for sev, msg in self.issues:
            if sev in ('err', 'warn'):
                n += 1
                mark = 'x' if sev == 'err' else '!'
                print(f"    {n:>2}. [{mark}] {msg}")
        print()


# ---------------------------------------------------------------------------
# Image access
# ---------------------------------------------------------------------------
class ImageFile:
    def __init__(self, path: str, writable: bool = False):
        self.path = path
        self.writable = writable
        self.size = os.path.getsize(path)
        self._f = open(path, 'r+b' if writable else 'rb')

    @property
    def sectors(self) -> int:
        return self.size // SECTOR_SIZE

    def close(self):
        if self._f.closed:
            return
        if self.writable:
            self._f.flush()
            os.fsync(self._f.fileno())
        self._f.close()

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            return b''
        self._f.seek(offset)
        return self._f.read(length)

    def read_sector(self, lba: int, count: int = 1) -> bytes:
        return self.read_at(lba * SECTOR_SIZE, count * SECTOR_SIZE)

    def write_at(self, offset: int, data: bytes):
        if not self.writable:
            raise IOError('image opened read-only')
        if offset < 0 or offset + len(data) > self.size:
            raise ValueError(f'write at 0x{offset:X} (+{len(data)}) is beyond the end of the image')
        self._f.seek(offset)
        self._f.write(data)


def is_blank(data: bytes) -> bool:
    return bool(data) and (data.strip(b'\x00') == b'' or data.strip(b'\xff') == b'')


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Partition / BPB structures
# ---------------------------------------------------------------------------
@dataclass
class Partition:
    index: int          # 1-4, or 0 for a superfloppy (whole-disk) volume
    status: int
    part_type: int
    lba_start: int
    lba_size: int


@dataclass
class BPB:
    oem_name: str
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entry_count: int
    total_sectors: int
    media_type: int
    fat_size: int
    root_cluster: int
    fsinfo_sector: int
    backup_boot_sector: int
    fat_type: str
    volume_label: str
    part_start_lba: int
    fat_start_lba: int
    root_dir_lba: int
    data_start_lba: int
    data_clusters: int

    @property
    def cluster_bytes(self) -> int:
        return self.sectors_per_cluster * SECTOR_SIZE

    @property
    def max_cluster(self) -> int:
        return self.data_clusters + 1

    @property
    def code_offset(self) -> int:
        """Offset where boot code starts (after the BPB) in the boot sector."""
        return 90 if self.fat_type == 'FAT32' else 62

    def cluster_lba(self, cluster: int) -> int:
        return self.data_start_lba + (cluster - 2) * self.sectors_per_cluster

    def fat_lba(self, copy_index: int) -> int:
        return self.fat_start_lba + copy_index * self.fat_size


def decode_bpb(sector: bytes, part_lba: int) -> Tuple[Optional[BPB], str]:
    """Decode and sanity-check a FAT boot sector. Returns (BPB, '') or (None, reason)."""
    if len(sector) < SECTOR_SIZE:
        return None, 'sector unreadable'
    sig = struct.unpack_from('<H', sector, 510)[0]
    if sig != 0xAA55:
        return None, f'boot signature 0x{sig:04X} (expected 0xAA55)'
    bps = struct.unpack_from('<H', sector, 11)[0]
    spc = sector[13]
    rsvd = struct.unpack_from('<H', sector, 14)[0]
    nfat = sector[16]
    rec = struct.unpack_from('<H', sector, 17)[0]
    ts16 = struct.unpack_from('<H', sector, 19)[0]
    media = sector[21]
    fs16 = struct.unpack_from('<H', sector, 22)[0]
    ts32 = struct.unpack_from('<I', sector, 32)[0]

    if bps != SECTOR_SIZE:
        return None, f'bytes per sector = {bps} (only 512 is supported)'
    if spc == 0 or spc & (spc - 1):
        return None, f'sectors per cluster = {spc} (must be a power of two)'
    if rsvd == 0:
        return None, 'reserved sector count is 0'
    if nfat == 0:
        return None, 'number of FATs is 0'
    total = ts16 if ts16 else ts32
    if total == 0:
        return None, 'total sector count is 0'

    if fs16:
        fat_size, root_cluster, fsinfo, backup, label_off = fs16, 0, 0, 0, 43
    else:
        fat_size = struct.unpack_from('<I', sector, 36)[0]
        root_cluster = struct.unpack_from('<I', sector, 44)[0]
        fsinfo = struct.unpack_from('<H', sector, 48)[0]
        backup = struct.unpack_from('<H', sector, 50)[0]
        label_off = 71
    if fat_size == 0:
        return None, 'FAT size is 0'

    root_dir_sectors = (rec * 32 + bps - 1) // bps
    data_sectors = total - (rsvd + nfat * fat_size + root_dir_sectors)
    if data_sectors <= 0:
        return None, 'BPB geometry is inconsistent (no room for data area)'
    clusters = data_sectors // spc
    if fs16 == 0:
        fat_type = 'FAT32'
    else:
        fat_type = 'FAT12' if clusters < 4085 else 'FAT16'
        if clusters >= 65525:
            return None, 'FAT12/16 layout with too many clusters (inconsistent BPB)'
    if fat_type == 'FAT32' and root_cluster < 2:
        return None, f'FAT32 root cluster = {root_cluster}'

    fat_start = part_lba + rsvd
    root_lba = fat_start + nfat * fat_size
    data_start = root_lba + root_dir_sectors
    return BPB(
        oem_name=sector[3:11].decode('ascii', errors='replace').strip(),
        bytes_per_sector=bps, sectors_per_cluster=spc, reserved_sectors=rsvd,
        num_fats=nfat, root_entry_count=rec, total_sectors=total, media_type=media,
        fat_size=fat_size, root_cluster=root_cluster, fsinfo_sector=fsinfo,
        backup_boot_sector=backup, fat_type=fat_type,
        volume_label=sector[label_off:label_off + 11].decode('ascii', errors='replace').strip(),
        part_start_lba=part_lba, fat_start_lba=fat_start, root_dir_lba=root_lba,
        data_start_lba=data_start, data_clusters=clusters,
    ), ''


def expected_clusters(size: int, bpb: BPB) -> int:
    return (size + bpb.cluster_bytes - 1) // bpb.cluster_bytes


# ---------------------------------------------------------------------------
# FAT table
# ---------------------------------------------------------------------------
class FatTable:
    PARAMS = {
        'FAT12': (0xFF8, 0xFFF, 0xFF7, None, None),
        'FAT16': (0xFFF8, 0xFFFF, 0xFFF7, 0x8000, 0x4000),
        'FAT32': (0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFF7, 0x08000000, 0x04000000),
    }

    def __init__(self, data: bytes, fat_type: str, max_cluster: int):
        self.data = bytearray(data)
        self.fat_type = fat_type
        (self.eoc_min, self.eoc, self.bad,
         self.clean_mask, self.herr_mask) = self.PARAMS[fat_type]
        if fat_type == 'FAT12':
            capacity = len(data) * 2 // 3
        elif fat_type == 'FAT16':
            capacity = len(data) // 2
        else:
            capacity = len(data) // 4
        self.max_cluster = min(max_cluster, capacity - 1)

    def copy(self) -> 'FatTable':
        return FatTable(bytes(self.data), self.fat_type, self.max_cluster)

    def get(self, n: int) -> int:
        if self.fat_type == 'FAT12':
            off = n + (n >> 1)
            v = self.data[off] | (self.data[off + 1] << 8)
            return v >> 4 if n & 1 else v & 0xFFF
        if self.fat_type == 'FAT16':
            return struct.unpack_from('<H', self.data, n * 2)[0]
        return struct.unpack_from('<I', self.data, n * 4)[0] & 0x0FFFFFFF

    def set(self, n: int, val: int):
        if self.fat_type == 'FAT12':
            off = n + (n >> 1)
            v = self.data[off] | (self.data[off + 1] << 8)
            v = (v & 0x000F) | ((val & 0xFFF) << 4) if n & 1 else (v & 0xF000) | (val & 0xFFF)
            self.data[off] = v & 0xFF
            self.data[off + 1] = v >> 8
        elif self.fat_type == 'FAT16':
            struct.pack_into('<H', self.data, n * 2, val & 0xFFFF)
        else:
            old = struct.unpack_from('<I', self.data, n * 4)[0]
            struct.pack_into('<I', self.data, n * 4, (old & 0xF0000000) | (val & 0x0FFFFFFF))

    def values(self) -> List[int]:
        m = self.max_cluster + 1
        if self.fat_type == 'FAT16':
            return list(struct.unpack_from(f'<{m}H', self.data, 0))
        if self.fat_type == 'FAT32':
            return [v & 0x0FFFFFFF for v in struct.unpack_from(f'<{m}I', self.data, 0)]
        return [self.get(n) for n in range(m)]

    def chain(self, start: int) -> Tuple[List[int], str]:
        if start < 2 or start > self.max_cluster:
            return [], 'bad_start'
        clusters, seen, cur = [], set(), start
        while True:
            if cur in seen:
                return clusters, 'loop'
            clusters.append(cur)
            seen.add(cur)
            nxt = self.get(cur)
            if nxt >= self.eoc_min:
                return clusters, 'ok'
            if nxt == 0:
                return clusters, 'free_in_chain'
            if nxt == self.bad:
                return clusters, 'bad_cluster'
            if nxt == 1:
                return clusters, 'illegal'
            if nxt > self.max_cluster:
                return clusters, 'out_of_range'
            cur = nxt

    def illegal_entries(self) -> List[int]:
        vals = self.values()
        return [n for n in range(2, len(vals))
                if vals[n] == 1 or self.max_cluster < vals[n] < self.bad]

    def free_list(self) -> List[int]:
        vals = self.values()
        return [n for n in range(2, len(vals)) if vals[n] == 0]

    def count_free(self) -> int:
        return len(self.free_list())

    def allocate(self, need: int) -> Tuple[Optional[List[int]], bool]:
        """Return (clusters, contiguous). Prefers a single contiguous run."""
        free = self.free_list()
        if len(free) < need:
            return None, False
        run_start = 0
        for i in range(1, len(free) + 1):
            if i - run_start >= need:
                return free[run_start:run_start + need], True
            if i < len(free) and free[i] != free[i - 1] + 1:
                run_start = i
        return free[:need], False

    def clean_flag(self) -> Optional[bool]:
        return None if self.clean_mask is None else bool(self.get(1) & self.clean_mask)

    def hard_error_flag(self) -> bool:
        return False if self.herr_mask is None else not (self.get(1) & self.herr_mask)

    def set_clean(self):
        if self.clean_mask is not None:
            self.set(1, self.get(1) | self.clean_mask)


def fragments(chain: List[int]) -> int:
    return 0 if not chain else 1 + sum(1 for a, b in zip(chain, chain[1:]) if b != a + 1)


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
@dataclass
class DirEntry:
    name: str
    attr: int
    size: int
    start_cluster: int
    is_dir: bool
    offset: int          # absolute byte offset of the 32-byte entry in the image


def read_directory(img: ImageFile, bpb: BPB, fat: FatTable,
                   start_cluster: Optional[int] = None) -> Tuple[List[DirEntry], List[int]]:
    """Read a directory. start_cluster=None means the root directory.
    Returns (entries, offsets of free slots)."""
    if start_cluster is None and bpb.fat_type != 'FAT32':
        regions = [(bpb.root_dir_lba * SECTOR_SIZE, bpb.root_entry_count * 32)]
    else:
        start = bpb.root_cluster if start_cluster is None else start_cluster
        clusters, _ = fat.chain(start)
        regions = [(bpb.cluster_lba(c) * SECTOR_SIZE, bpb.cluster_bytes) for c in clusters]

    entries, free, ended = [], [], False
    for off, length in regions:
        data = img.read_at(off, length)
        for i in range(len(data) // 32):
            eoff = off + i * 32
            e = data[i * 32:(i + 1) * 32]
            if ended or e[0] == 0x00:
                ended = True
                free.append(eoff)
                continue
            if e[0] == 0xE5:
                free.append(eoff)
                continue
            attr = e[11]
            if attr == 0x0F or attr & 0x08:     # LFN entry or volume label
                continue
            raw = bytearray(e[0:11])
            if raw[0] == 0x05:
                raw[0] = 0xE5
            base = raw[0:8].decode('ascii', errors='replace').rstrip()
            ext = raw[8:11].decode('ascii', errors='replace').rstrip()
            name = base + ('.' + ext if ext else '')
            if name in ('.', '..'):
                continue
            hi = struct.unpack_from('<H', e, 20)[0] if bpb.fat_type == 'FAT32' else 0
            lo = struct.unpack_from('<H', e, 26)[0]
            entries.append(DirEntry(name, attr, struct.unpack_from('<I', e, 28)[0],
                                    (hi << 16) | lo, bool(attr & 0x10), eoff))
    return entries, free


def to_83(name: str) -> Optional[bytes]:
    allowed = set(string.ascii_uppercase + string.digits + "!#$%&'()-@^_`{}~")
    name = name.upper()
    base, ext = name.rsplit('.', 1) if '.' in name else (name, '')
    if not base or len(base) > 8 or len(ext) > 3 or any(c not in allowed for c in base + ext):
        return None
    return base.ljust(8).encode('ascii') + ext.ljust(3).encode('ascii')


def fat_timestamp() -> Tuple[int, int]:
    t = time.localtime()
    ftime = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    fdate = ((max(t.tm_year, 1980) - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    return ftime, fdate


# ---------------------------------------------------------------------------
# BIN-format kernel image
# ---------------------------------------------------------------------------
@dataclass
class BinReport:
    image_start: int = 0
    image_length: int = 0
    records: int = 0
    total_data: int = 0
    bad: List[Tuple[int, int, int]] = field(default_factory=list)   # (addr, stored, calc)
    blank_records: int = 0
    out_of_range: int = 0
    entry_point: Optional[int] = None
    trailing: int = 0
    fatal: str = ''


def check_bin_bytes(data: bytes) -> BinReport:
    """
    Walk a BIN-format image:
      [7] sync bytes 'B000FF\\n'   [4] image start   [4] image length
      records: [4] address  [4] length  [4] checksum  [length] data
      checksum = 32-bit sum of the record's data bytes
      terminator: address 0, length field = entry point, checksum 0
    """
    r = BinReport()
    if data[:7] != BIN_SIGNATURE or len(data) < BIN_HEADER_SIZE:
        r.fatal = 'missing BIN sync bytes or header'
        return r
    r.image_start, r.image_length = struct.unpack_from('<II', data, 7)
    off = BIN_HEADER_SIZE
    while True:
        if off + 12 > len(data):
            r.fatal = 'image ends without a terminator record (file truncated)'
            break
        addr, length, csum = struct.unpack_from('<III', data, off)
        off += 12
        if addr == 0:
            r.entry_point = length
            break
        if off + length > len(data):
            r.fatal = (f'record at 0x{addr:08X} truncated '
                       f'({len(data) - off} of {length} bytes present)')
            break
        rec = data[off:off + length]
        off += length
        r.records += 1
        r.total_data += length
        calc = sum(rec) & 0xFFFFFFFF
        if calc != csum:
            r.bad.append((addr, csum, calc))
        if is_blank(rec):
            r.blank_records += 1
        if r.image_length and not (r.image_start <= addr and
                                   addr + length <= r.image_start + r.image_length):
            r.out_of_range += 1
    r.trailing = max(0, len(data) - off)
    return r


# ---------------------------------------------------------------------------
# Analysis context
# ---------------------------------------------------------------------------
@dataclass
class Ctx:
    img: ImageFile
    res: DiagResult
    args: argparse.Namespace
    mbr: bytes = b''
    superfloppy: bool = False
    mbr_sig_ok: bool = True
    mbr_code_state: str = 'ok'          # ok / zero / ff
    partitions: List[Partition] = field(default_factory=list)
    boot_part: Optional[Partition] = None
    active_fix_needed: bool = False
    bpb: Optional[BPB] = None
    vbr_restore_from_backup: bool = False
    vbr_code_blank: bool = False
    fats: List[FatTable] = field(default_factory=list)
    fat_illegal: List[List[int]] = field(default_factory=list)
    clean: List[Optional[bool]] = field(default_factory=list)
    fats_differ: bool = False
    preferred_fat: int = 0
    root_entries: List[DirEntry] = field(default_factory=list)
    root_free: List[int] = field(default_factory=list)
    loader_files: List[DirEntry] = field(default_factory=list)
    nk: Optional[DirEntry] = None
    nk_in_root: bool = True
    nk_chain: List[int] = field(default_factory=list)
    nk_data: Optional[bytes] = None
    nk_issue: bool = False
    lost_clusters: List[int] = field(default_factory=list)
    cross_linked: int = 0
    fsinfo_valid: bool = False
    fsinfo_mismatch: bool = False


# ---------------------------------------------------------------------------
# 1. MBR
# ---------------------------------------------------------------------------
def check_mbr(ctx: Ctx):
    hdr('1. MBR & PARTITION TABLE')
    img, res = ctx.img, ctx.res
    data = img.read_sector(0)
    if len(data) < SECTOR_SIZE:
        res.add('err', 'Image too small to contain an MBR')
        return
    ctx.mbr = data

    bpb0, _ = decode_bpb(data, 0)
    if bpb0 is not None and data[0] in (0xEB, 0xE9):
        ctx.superfloppy = True
        info('Sector 0 is a FAT boot sector: no partition table (superfloppy layout)')
        res.add('ok', 'Volume starts at LBA 0; the BIOS runs the VBR boot code directly')
        ctx.boot_part = Partition(0, 0x80, 0, 0, img.sectors)
        return

    sig = struct.unpack_from('<H', data, 510)[0]
    if sig != 0xAA55:
        ctx.mbr_sig_ok = False
        res.add('err', f'MBR signature invalid: 0x{sig:04X} (expected 0xAA55); BIOS will not boot the card')
    else:
        res.add('ok', 'MBR signature valid (0xAA55)')

    code = data[:440]
    if code.strip(b'\x00') == b'':
        ctx.mbr_code_state = 'zero'
        res.add('err', 'MBR boot code is all zeros; a standard BIOS has nothing to run')
    elif code.strip(b'\xff') == b'':
        ctx.mbr_code_state = 'ff'
        res.add('err', 'MBR boot code is all 0xFF; card erased or sector unreadable')
    else:
        res.add('ok', 'MBR boot code appears populated')

    for i in range(4):
        pe = data[446 + i * 16:462 + i * 16]
        status, ptype = pe[0], pe[4]
        start, size = struct.unpack_from('<II', pe, 8)
        if ptype == 0 or size == 0:
            continue
        p = Partition(i + 1, status, ptype, start, size)
        ctx.partitions.append(p)
        tname = PART_TYPES.get(ptype, f'unknown (0x{ptype:02X})')
        active = ' [ACTIVE]' if status == 0x80 else ''
        info(f'Partition {p.index}: type={tname}, LBA {start}-{start + size - 1} '
             f'({size * SECTOR_SIZE // 1024} KB){active}')
        if status not in (0x00, 0x80):
            res.add('warn', f'Partition {p.index} has non-standard status byte 0x{status:02X}')
        if start == 0:
            res.add('err', f'Partition {p.index} starts at LBA 0 and overlaps the MBR')
        if start + size > img.sectors:
            res.add('err', f'Partition {p.index} ends at LBA {start + size - 1} but the image has only '
                           f'{img.sectors} sectors (truncated image, or imaged from a smaller device)')

    if not ctx.partitions:
        res.add('err', 'No partitions found in the MBR partition table')
        return

    active = [p for p in ctx.partitions if p.status == 0x80]
    if not active:
        ctx.active_fix_needed = True
        res.add('err', 'No partition is marked active (0x80); standard MBR code will not boot')
    elif len(active) > 1:
        ctx.active_fix_needed = True
        res.add('err', f'{len(active)} partitions are marked active; standard MBR code rejects this')
    else:
        res.add('ok', f'Partition {active[0].index} is the active partition')

    ctx.boot_part = (active[0] if active else
                     next((p for p in ctx.partitions if p.part_type in FAT_PARTITION_TYPES),
                          ctx.partitions[0]))


# ---------------------------------------------------------------------------
# 2. VBR / BPB
# ---------------------------------------------------------------------------
def check_vbr(ctx: Ctx):
    img, res, p = ctx.img, ctx.res, ctx.boot_part
    hdr(f"2. VBR / FAT BPB ({'whole disk' if ctx.superfloppy else f'partition {p.index}'})")

    sector = img.read_sector(p.lba_start)
    bpb, why = decode_bpb(sector, p.lba_start)
    if bpb:
        res.add('ok', 'Boot sector signature and BPB valid')
    else:
        res.add('err', f'Boot sector at LBA {p.lba_start} is invalid: {why}')
        backup = img.read_sector(p.lba_start + 6)
        bbpb, _ = decode_bpb(backup, p.lba_start)
        if bbpb is None or bbpb.fat_type != 'FAT32':
            return
        ctx.vbr_restore_from_backup = True
        res.add('warn', 'A valid FAT32 backup boot sector exists at partition sector 6; '
                        'the primary can be restored with --repair')
        bpb, sector = bbpb, backup
    ctx.bpb = bpb

    info(f'OEM name: "{bpb.oem_name}", volume label: "{bpb.volume_label}"')
    info(f'FAT type: {bpb.fat_type}, cluster size: {bpb.cluster_bytes} bytes, '
         f'{bpb.num_fats} FAT(s) of {bpb.fat_size} sectors')
    info(f'FAT start LBA {bpb.fat_start_lba}, root dir LBA {bpb.root_dir_lba}, '
         f'data start LBA {bpb.data_start_lba}')
    info(f'Total sectors: {bpb.total_sectors}, data clusters: {bpb.data_clusters}')

    if sector[0] not in (0xEB, 0xE9):
        res.add('warn', f'Boot sector does not start with a jump instruction (0x{sector[0]:02X})')
    if bpb.media_type not in (0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
        res.add('warn', f'Media type byte 0x{bpb.media_type:02X} is non-standard')
    if not ctx.superfloppy and bpb.total_sectors > p.lba_size:
        res.add('warn', f'Filesystem claims {bpb.total_sectors} sectors but the partition '
                        f'holds only {p.lba_size}')
    if p.lba_start + bpb.total_sectors > img.sectors:
        res.add('err', 'Filesystem extends past the end of the image (image truncated)')

    code = sector[bpb.code_offset:510]
    if is_blank(code):
        ctx.vbr_code_blank = True
        res.add('err', 'VBR boot code area is empty; the stage-2 loader is not installed')
    else:
        res.add('ok', 'VBR boot code appears populated')


# ---------------------------------------------------------------------------
# 3. FAT health
# ---------------------------------------------------------------------------
def check_fat(ctx: Ctx):
    hdr('3. FAT HEALTH CHECK')
    img, res, bpb = ctx.img, ctx.res, ctx.bpb
    nbytes = bpb.fat_size * SECTOR_SIZE

    for i in range(bpb.num_fats):
        d = img.read_at(bpb.fat_lba(i) * SECTOR_SIZE, nbytes)
        if not d:
            res.add('err', f'FAT{i + 1} region is beyond the end of the image')
            ctx.fats = []
            return
        ctx.fats.append(FatTable(d, bpb.fat_type, bpb.max_cluster))

    f0 = ctx.fats[0]
    if f0.max_cluster < bpb.max_cluster:
        res.add('warn', f'FAT is too small for the cluster count ({f0.max_cluster - 1} of '
                        f'{bpb.data_clusters} clusters addressable)')
    if f0.get(0) & 0xFF != bpb.media_type:
        res.add('warn', f'FAT[0] media byte 0x{f0.get(0) & 0xFF:02X} does not match BPB '
                        f'media byte 0x{bpb.media_type:02X}')

    ctx.clean = [f.clean_flag() for f in ctx.fats]
    if bpb.fat_type == 'FAT12':
        info('FAT12 has no clean-shutdown bit')
    else:
        unclean = [i + 1 for i, c in enumerate(ctx.clean) if c is False]
        if unclean:
            res.add('warn', f'Clean-shutdown bit not set in FAT{"/FAT".join(map(str, unclean))}; '
                            'volume was not cleanly dismounted (power loss during a write?)')
        else:
            res.add('ok', 'Clean-shutdown bit set (volume was cleanly dismounted)')
        if any(f.hard_error_flag() for f in ctx.fats):
            res.add('warn', 'Hard-error bit set: the OS recorded disk I/O errors on this volume')

    if bpb.num_fats >= 2:
        diff_sectors = set()
        for f in ctx.fats[1:]:
            for s in range(bpb.fat_size):
                a = slice(s * SECTOR_SIZE, (s + 1) * SECTOR_SIZE)
                if f.data[a] != f0.data[a]:
                    diff_sectors.add(s)
        if diff_sectors:
            ctx.fats_differ = True
            res.add('warn', f'FAT copies differ in {len(diff_sectors)} sector(s); '
                            'interrupted write or uncommitted TFAT transaction')
        else:
            res.add('ok', 'All FAT copies are identical')
    else:
        res.add('warn', 'Only one FAT copy present (no redundancy)')

    ctx.fat_illegal = [f.illegal_entries() for f in ctx.fats]
    if any(ctx.fat_illegal):
        for i, ill in enumerate(ctx.fat_illegal):
            if ill:
                res.add('warn', f'FAT{i + 1}: {len(ill)} illegal chain entr{"y" if len(ill) == 1 else "ies"} '
                                '(next-cluster value 1 or outside the volume)')
    else:
        res.add('ok', 'No illegal FAT chain entries found')


# ---------------------------------------------------------------------------
# 4. Root directory, loader files, kernel image
# ---------------------------------------------------------------------------
def find_files(ctx: Ctx):
    hdr('4. ROOT DIRECTORY & BOOT FILES')
    img, res, bpb = ctx.img, ctx.res, ctx.bpb
    fat = ctx.fats[0]

    entries, free = read_directory(img, bpb, fat)
    ctx.root_entries, ctx.root_free = entries, free
    if not entries:
        res.add('warn', 'Root directory is empty or unreadable')
    else:
        info(f'Root directory entries: {len(entries)}')
        for e in entries:
            tag = '[DIR]' if e.is_dir else f'{e.size // 1024} KB'
            info(f'  {e.name:<14} {tag}')

    ctx.loader_files = [e for e in entries if not e.is_dir and e.name.upper() in LOADER_FILENAMES]

    for e in entries:
        if not e.is_dir and e.name.upper() in NK_FILENAMES:
            ctx.nk = e
            break
    if not ctx.nk:
        for d in entries:
            if not d.is_dir or d.start_cluster < 2:
                continue
            sub, _ = read_directory(img, bpb, fat, d.start_cluster)
            hit = next((e for e in sub if not e.is_dir and e.name.upper() in NK_FILENAMES), None)
            if hit:
                ctx.nk, ctx.nk_in_root = hit, False
                info(f'Found {hit.name} in subdirectory {d.name} '
                     '(loaders normally expect the kernel in the root directory)')
                break

    if not ctx.nk:
        ctx.nk_issue = True
        res.add('err', f'No kernel image ({", ".join(NK_FILENAMES)}) found in the filesystem')
    else:
        res.add('ok', f'Found kernel image {ctx.nk.name} ({ctx.nk.size // 1024} KB, '
                      f'start cluster {ctx.nk.start_cluster})')


def walk_allocation(img: ImageFile, bpb: BPB, fat: FatTable) -> Tuple[List[int], int]:
    """Walk the whole directory tree. Returns (lost clusters, cross-linked cluster count)."""
    refs = Counter()
    seen_dirs = set()
    if bpb.fat_type == 'FAT32':
        refs.update(fat.chain(bpb.root_cluster)[0])
    pending = [None]
    while pending:
        start = pending.pop()
        entries, _ = read_directory(img, bpb, fat, start)
        for e in entries:
            if e.start_cluster < 2 or e.start_cluster > fat.max_cluster:
                continue
            chain, _ = fat.chain(e.start_cluster)
            if e.is_dir:
                if e.start_cluster in seen_dirs:
                    continue
                seen_dirs.add(e.start_cluster)
                if len(seen_dirs) < 10000:
                    pending.append(e.start_cluster)
            else:
                chain = chain[:max(1, expected_clusters(e.size, bpb))] if e.size else chain
            refs.update(chain)
    vals = fat.values()
    lost = [n for n in range(2, len(vals)) if vals[n] not in (0, fat.bad) and n not in refs]
    cross = sum(1 for c in refs.values() if c > 1)
    return lost, cross


# ---------------------------------------------------------------------------
# 5. Cluster chains, FAT copy selection, FSInfo
# ---------------------------------------------------------------------------
def check_chains(ctx: Ctx):
    hdr('5. CLUSTER CHAINS & ALLOCATION')
    img, res, bpb, args = ctx.img, ctx.res, ctx.bpb, ctx.args
    nk = ctx.nk

    scores = []
    for i, f in enumerate(ctx.fats):
        s = -10 * len(ctx.fat_illegal[i])
        if bpb.fat_type == 'FAT32' and f.chain(bpb.root_cluster)[1] == 'ok':
            s += 50
        if nk and nk.start_cluster >= 2:
            ch, st = f.chain(nk.start_cluster)
            if st == 'ok' and len(ch) == expected_clusters(nk.size, bpb):
                s += 100
        scores.append(s)

    if args.fat_source:
        idx = args.fat_source - 1
        if idx >= len(ctx.fats):
            res.add('warn', f'--fat-source {args.fat_source} requested but the volume has '
                            f'{len(ctx.fats)} FAT(s); using FAT1')
            idx = 0
        else:
            info(f'Using FAT{idx + 1} as the reference copy (--fat-source)')
    else:
        idx = max(range(len(scores)), key=lambda i: (scores[i], -i))
        if ctx.fats_differ:
            info(f'FAT copies differ; using FAT{idx + 1} as the reference copy (consistency scores: '
                 + ', '.join(f'FAT{i + 1}={s}' for i, s in enumerate(scores))
                 + '). Override with --fat-source.')
    ctx.preferred_fat = idx
    f = ctx.fats[idx]

    free = f.count_free()
    info(f'Clusters: {bpb.data_clusters} total, {free} free')

    ctx.lost_clusters, ctx.cross_linked = walk_allocation(img, bpb, f)
    if ctx.lost_clusters:
        res.add('warn', f'{len(ctx.lost_clusters)} lost cluster(s): allocated in the FAT but not part '
                        'of any file or directory')
    if ctx.cross_linked:
        res.add('warn', f'{ctx.cross_linked} cross-linked cluster(s) shared by more than one file')
    if not ctx.lost_clusters and not ctx.cross_linked:
        res.add('ok', 'No lost or cross-linked clusters')

    if bpb.fat_type == 'FAT32':
        _, st = f.chain(bpb.root_cluster)
        if st != 'ok':
            res.add('err', f'Root directory cluster chain is broken: {CHAIN_MSG[st]}')
        else:
            res.add('ok', 'Root directory cluster chain intact')

    if nk:
        need = expected_clusters(nk.size, bpb)
        if nk.size == 0:
            ctx.nk_issue = True
            res.add('err', f'{nk.name} is zero bytes long')
        elif nk.start_cluster < 2 or nk.start_cluster > f.max_cluster:
            ctx.nk_issue = True
            res.add('err', f'{nk.name} has an invalid start cluster ({nk.start_cluster})')
        else:
            chain, st = f.chain(nk.start_cluster)
            ctx.nk_chain = chain
            info(f'{nk.name} chain: {len(chain)} cluster(s), file size needs {need}, '
                 f'{fragments(chain)} fragment(s)')
            if st != 'ok':
                ctx.nk_issue = True
                res.add('err', f'{nk.name} cluster chain broken after {len(chain)} cluster(s): {CHAIN_MSG[st]}')
            if len(chain) < need:
                ctx.nk_issue = True
                res.add('err', f'{nk.name} chain truncated: {len(chain)} cluster(s) but the file size needs {need}')
            elif len(chain) > need:
                res.add('warn', f'{nk.name} chain is {len(chain) - need} cluster(s) longer than its size requires')
            elif st == 'ok':
                res.add('ok', f'{nk.name} chain length matches its file size')

            zero = ff = unreadable = 0
            parts = []
            for c in chain[:need]:
                d = img.read_sector(bpb.cluster_lba(c), bpb.sectors_per_cluster)
                if not d:
                    unreadable += 1
                    continue
                parts.append(d)
                if d.strip(b'\x00') == b'':
                    zero += 1
                elif d.strip(b'\xff') == b'':
                    ff += 1
            if unreadable:
                ctx.nk_issue = True
                res.add('err', f'{unreadable} cluster(s) of {nk.name} lie beyond the end of the image')
            if ff:
                res.add('warn', f'{ff} cluster(s) of {nk.name} are entirely 0xFF (erased or never written)')
            if zero:
                info(f'{zero} cluster(s) of {nk.name} are entirely 0x00 (can be normal; sectors that '
                     'failed to read during imaging with conv=sync also appear as zeros)')
            if not unreadable and nk.size <= MAX_NK_READ:
                ctx.nk_data = b''.join(parts)[:nk.size]

    if bpb.fat_type == 'FAT32':
        fs = bpb.fsinfo_sector
        if fs in (0, 0xFFFF):
            info('No FSInfo sector')
        else:
            s = img.read_sector(bpb.part_start_lba + fs)
            if (len(s) == SECTOR_SIZE and struct.unpack_from('<I', s, 0)[0] == FSINFO_LEAD
                    and struct.unpack_from('<I', s, 484)[0] == FSINFO_STRUCT
                    and struct.unpack_from('<I', s, 508)[0] == FSINFO_TRAIL):
                ctx.fsinfo_valid = True
                recorded = struct.unpack_from('<I', s, 488)[0]
                if recorded == 0xFFFFFFFF:
                    info('FSInfo free-cluster count not recorded')
                elif recorded != free:
                    ctx.fsinfo_mismatch = True
                    res.add('warn', f'FSInfo free-cluster count is {recorded}, actual is {free}')
                else:
                    res.add('ok', 'FSInfo free-cluster count is correct')
            else:
                res.add('warn', 'FSInfo sector signatures are invalid')


# ---------------------------------------------------------------------------
# 6. Kernel image structure
# ---------------------------------------------------------------------------
def report_bin(ctx: Ctx, rep: BinReport, name: str):
    res, verbose = ctx.res, ctx.args.verbose
    info(f'Image start 0x{rep.image_start:08X}, length 0x{rep.image_length:08X} '
         f'({rep.image_length // 1024} KB)')
    if rep.image_length == 0 or rep.image_length > 256 * 1024 * 1024:
        res.add('warn', f'Image length header value 0x{rep.image_length:08X} looks implausible')
    info(f'Records: {rep.records}, record data: {rep.total_data // 1024} KB')

    if rep.fatal:
        ctx.nk_issue = True
        res.add('err', f'{name}: {rep.fatal}')
    if rep.bad:
        ctx.nk_issue = True
        res.add('err', f'{len(rep.bad)} record checksum failure(s) in {name}; '
                       'the bootloader will reject this image')
        for addr, stored, calc in rep.bad if verbose else rep.bad[:3]:
            info(f'  record 0x{addr:08X}: stored 0x{stored:08X}, calculated 0x{calc:08X}')
        if not verbose and len(rep.bad) > 3:
            info(f'  ... {len(rep.bad) - 3} more (use -v to list all)')
    elif rep.records:
        res.add('ok', f'All {rep.records} record checksums valid')
    if rep.blank_records:
        res.add('warn', f'{rep.blank_records} record(s) contain only 0x00 or 0xFF (possible partial write)')
    if rep.out_of_range:
        res.add('warn', f'{rep.out_of_range} record(s) fall outside the image address range in the header')
    if rep.entry_point is not None:
        info(f'Entry point: 0x{rep.entry_point:08X}')
        if rep.image_length and not (rep.image_start <= rep.entry_point < rep.image_start + rep.image_length):
            res.add('warn', 'Entry point lies outside the image address range')
    if rep.trailing:
        info(f'{rep.trailing} byte(s) after the terminator record')


def validate_nk(ctx: Ctx):
    hdr('6. KERNEL IMAGE STRUCTURE')
    res, nk, data = ctx.res, ctx.nk, ctx.nk_data
    if data is None:
        res.add('warn', f'{nk.name} content not analysed (too large, or chain incomplete)')
        return
    head = data[:SECTOR_SIZE]
    is_nb0 = nk.name.upper().endswith('.NB0')

    if data[:7] == BIN_SIGNATURE:
        res.add('ok', f'{nk.name} has BIN-format sync bytes (B000FF)')
        if is_nb0:
            res.add('warn', f'{nk.name} is named .NB0 but contains a BIN-format image')
        report_bin(ctx, check_bin_bytes(data), nk.name)
    elif head.strip(b'\x00') == b'':
        ctx.nk_issue = True
        res.add('err', f'{nk.name} starts with zeros; file is blank or was not written')
    elif head.strip(b'\xff') == b'':
        ctx.nk_issue = True
        res.add('err', f'{nk.name} starts with 0xFF; data erased, kernel image missing')
    elif is_nb0:
        info(f'{nk.name} is a raw NB0 image: no record structure or checksums to verify')
    else:
        res.add('warn', f'{nk.name} has no BIN sync bytes; it may be compressed or an OEM format')
        info(f'First 16 bytes: {data[:16].hex(" ")}')


# ---------------------------------------------------------------------------
# 7. Bootloader detection
# ---------------------------------------------------------------------------
def check_bootloader(ctx: Ctx):
    hdr('7. BOOTLOADER DETECTION')
    img, res = ctx.img, ctx.res
    lbas = list(range(4))
    if ctx.boot_part:
        p = ctx.boot_part
        lbas += range(p.lba_start, min(p.lba_start + 64, p.lba_start + p.lba_size))
    found = {}
    for lba in dict.fromkeys(lbas):
        data = img.read_sector(lba)
        for sig in BOOTLOADER_STRINGS:
            if data and sig in data and sig not in found:
                found[sig] = lba
                info(f'Loader string "{sig.decode("ascii")}" at LBA {lba}')
    if found:
        res.add('ok', f'Loader strings found at {len(set(found.values()))} sector(s)')
    else:
        info('No known loader strings in the boot sectors (heuristic only)')

    if ctx.bpb is not None and ctx.fats:
        if ctx.loader_files:
            for e in ctx.loader_files:
                res.add('ok', f'Bootloader file in root directory: {e.name} ({e.size // 1024} KB)')
        else:
            res.add('warn', 'No bootloader file (' + ', '.join(LOADER_FILENAMES) +
                            ') in the root directory; expected if the VBR loads a file such as BLDR')


# ---------------------------------------------------------------------------
# 8. Entropy scan
# ---------------------------------------------------------------------------
def entropy_scan(ctx: Ctx):
    hdr('8. CRITICAL SECTOR ENTROPY SCAN')
    img = ctx.img

    def line(lba: int, label: str):
        data = img.read_sector(lba)
        if not data:
            print(f'    LBA {lba:6d}  {label:<25}  unreadable')
            return
        ent = shannon_entropy(data)
        flag = ''
        if ent < 0.5:
            flag = f'{RED}[BLANK/SUSPICIOUS]{RESET}'
        elif ent > 7.5:
            flag = f'{CYAN}[HIGH ENTROPY/COMPRESSED]{RESET}'
        print(f'    LBA {lba:6d}  {label:<25}  entropy={ent:.2f}  '
              f'zeros={data.count(0):3d}  0xFF={data.count(255):3d}  {flag}')

    line(0, 'MBR')
    if ctx.boot_part and not ctx.superfloppy:
        p = ctx.boot_part
        for k, label in enumerate(['VBR (partition start)', 'VBR+1', 'VBR+2']):
            line(p.lba_start + k, label)
    print('\n  First 32 sectors:')
    for lba in range(32):
        line(lba, f'sector {lba}')


# ---------------------------------------------------------------------------
# Analysis driver
# ---------------------------------------------------------------------------
def analyse(path: str, args: argparse.Namespace) -> Ctx:
    img = ImageFile(path)
    ctx = Ctx(img=img, res=DiagResult(), args=args)
    print(f'\n{BOLD}Windows CE CF Image Boot Diagnostics{RESET}')
    print(f'Image: {path}  ({img.size / 1048576:.1f} MB, {img.sectors} sectors)')
    if img.size % SECTOR_SIZE:
        ctx.res.add('warn', f'Image size is not a multiple of 512 bytes '
                            f'({img.size % SECTOR_SIZE} extra bytes); incomplete read?')
    try:
        check_mbr(ctx)
        if ctx.boot_part:
            check_vbr(ctx)
        if ctx.bpb:
            check_fat(ctx)
            if ctx.fats:
                find_files(ctx)
                check_chains(ctx)
                if ctx.nk and ctx.nk_chain:
                    validate_nk(ctx)
        check_bootloader(ctx)
        if args.entropy_scan:
            entropy_scan(ctx)
    finally:
        img.close()
    return ctx


# ---------------------------------------------------------------------------
# Repair
# ---------------------------------------------------------------------------
@dataclass
class RepairAction:
    title: str
    detail: str
    requested: bool
    apply: Callable[['RepairSession'], None]


@dataclass
class RepairPlan:
    actions: List[RepairAction] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)
    unfixable: List[str] = field(default_factory=list)


class RepairSession:
    def __init__(self, ctx: Ctx, img: ImageFile):
        self.ctx = ctx
        self.img = img
        self.bpb = ctx.bpb
        self.fat = ctx.fats[ctx.preferred_fat].copy() if ctx.fats else None
        self.log: List[str] = []

    def write(self, offset: int, data: bytes, why: str, quiet: bool = False):
        old = self.img.read_at(offset, len(data))
        if old == data:
            return False
        self.img.write_at(offset, data)
        if not quiet:
            self.log.append(f'{why}: offset 0x{offset:X}, {len(data)} bytes')
        return True

    def write_sector(self, lba: int, data: bytes, why: str):
        self.write(lba * SECTOR_SIZE, data, f'{why} (LBA {lba})')


def load_reference(path: str) -> Tuple[Optional[bytes], Optional[bytes], Optional[BPB], str]:
    """Return (mbr, vbr, vbr_bpb, error) from a known-good reference image."""
    if not os.path.isfile(path):
        return None, None, None, f'file not found: {path}'
    ref = ImageFile(path)
    try:
        s0 = ref.read_sector(0)
        if len(s0) < SECTOR_SIZE:
            return None, None, None, 'reference image is too small'
        bpb0, _ = decode_bpb(s0, 0)
        if bpb0 is not None and s0[0] in (0xEB, 0xE9):
            return None, s0, bpb0, ''
        mbr = s0 if struct.unpack_from('<H', s0, 510)[0] == 0xAA55 else None
        parts = []
        for i in range(4):
            pe = s0[446 + i * 16:462 + i * 16]
            start, size = struct.unpack_from('<II', pe, 8)
            if pe[4] and size:
                parts.append((pe[0], start))
        if not parts:
            return mbr, None, None, ''
        start = next((s for st, s in parts if st == 0x80), parts[0][1])
        vbr = ref.read_sector(start)
        vbpb, _ = decode_bpb(vbr, start)
        return mbr, (vbr if vbpb else None), vbpb, ''
    finally:
        ref.close()


def plan_repairs(ctx: Ctx, args: argparse.Namespace) -> RepairPlan:
    plan = RepairPlan()
    bpb = ctx.bpb
    fat_edits = False

    # --- MBR signature -----------------------------------------------------
    if ctx.mbr and not ctx.superfloppy and not ctx.mbr_sig_ok:
        if bpb is not None:
            def fix_sig(s: RepairSession):
                sec = bytearray(s.img.read_sector(0))
                sec[510:512] = b'\x55\xAA'
                s.write_sector(0, bytes(sec), 'MBR signature')
            plan.actions.append(RepairAction(
                'Restore MBR signature 0xAA55',
                f'partition {ctx.boot_part.index} holds a valid {bpb.fat_type} volume', False, fix_sig))
        else:
            plan.unfixable.append('MBR signature is invalid and no valid FAT volume was found behind '
                                  'the partition table, so the table cannot be trusted')

    # --- MBR boot code -----------------------------------------------------
    if args.mbr_code_from:
        mbr, _, _, e = load_reference(args.mbr_code_from)
        if e:
            plan.blocked.append(f'--mbr-code-from: {e}')
        elif ctx.superfloppy:
            plan.blocked.append('--mbr-code-from: this image has no MBR (superfloppy layout)')
        elif mbr is None or is_blank(mbr[:440]):
            plan.blocked.append('--mbr-code-from: reference image has no valid, populated MBR')
        else:
            def fix_mbr_code(s: RepairSession, ref=mbr):
                sec = bytearray(s.img.read_sector(0))
                sec[0:440] = ref[0:440]
                sec[510:512] = b'\x55\xAA'
                s.write_sector(0, bytes(sec), 'MBR boot code from reference')
            plan.actions.append(RepairAction(
                'Copy MBR boot code from reference image',
                f'{args.mbr_code_from}: bytes 0-439; partition table and disk signature kept',
                True, fix_mbr_code))
    elif ctx.mbr_code_state != 'ok' and not ctx.superfloppy:
        plan.unfixable.append('MBR boot code is missing: supply a known-good image from the same '
                              'hardware with --mbr-code-from')

    # --- Active partition --------------------------------------------------
    if ctx.active_fix_needed and ctx.boot_part and bpb is not None:
        idx = ctx.boot_part.index

        def fix_active(s: RepairSession, idx=idx):
            sec = bytearray(s.img.read_sector(0))
            for i in range(4):
                sec[446 + i * 16] = 0x80 if i + 1 == idx else 0x00
            s.write_sector(0, bytes(sec), 'partition active flags')
        plan.actions.append(RepairAction(
            f'Make partition {idx} the only active partition',
            'sets its status byte to 0x80 and clears the others', False, fix_active))

    # --- VBR from FAT32 backup ---------------------------------------------
    if ctx.vbr_restore_from_backup:
        plba = ctx.boot_part.lba_start

        def fix_vbr_backup(s: RepairSession, plba=plba):
            for k in range(3):
                cur = s.img.read_sector(plba + k)
                if (k == s.bpb.fsinfo_sector and len(cur) == SECTOR_SIZE
                        and struct.unpack_from('<I', cur, 0)[0] == FSINFO_LEAD):
                    continue    # keep a valid primary FSInfo; the backup copy is usually stale
                s.write_sector(plba + k, s.img.read_sector(plba + 6 + k), 'boot sector from FAT32 backup')
        plan.actions.append(RepairAction(
            'Restore FAT32 boot sectors from backup',
            'copies partition sectors 6-8 over sectors 0-2 (a valid FSInfo sector is kept)',
            False, fix_vbr_backup))

    # --- VBR boot code -----------------------------------------------------
    if args.vbr_code_from:
        _, vbr, vbpb, e = load_reference(args.vbr_code_from)
        if e:
            plan.blocked.append(f'--vbr-code-from: {e}')
        elif bpb is None:
            plan.blocked.append('--vbr-code-from: no valid FAT volume in this image to patch')
        elif vbr is None or vbpb is None:
            plan.blocked.append('--vbr-code-from: reference image has no valid FAT boot sector')
        elif vbpb.fat_type != bpb.fat_type:
            plan.blocked.append(f'--vbr-code-from: reference volume is {vbpb.fat_type}, '
                                f'this volume is {bpb.fat_type}; boot code is not interchangeable')
        elif is_blank(vbr[vbpb.code_offset:510]):
            plan.blocked.append('--vbr-code-from: reference boot sector has no boot code')
        else:
            plba, co = ctx.boot_part.lba_start, bpb.code_offset
            targets = [plba]
            if bpb.fat_type == 'FAT32' and bpb.backup_boot_sector not in (0, 0xFFFF):
                targets.append(plba + bpb.backup_boot_sector)

            def fix_vbr_code(s: RepairSession, ref=vbr, targets=targets, co=co):
                for lba in targets:
                    sec = bytearray(s.img.read_sector(lba))
                    if decode_bpb(bytes(sec), plba)[0] is None:
                        continue
                    sec[0:3] = ref[0:3]
                    sec[co:510] = ref[co:510]
                    sec[510:512] = b'\x55\xAA'
                    s.write_sector(lba, bytes(sec), 'VBR boot code from reference')
            detail = f'{args.vbr_code_from}: jump + bytes {co}-509; this volume\'s BPB kept'
            if bpb.fat_type == 'FAT32':
                detail += ' (single sector only; loaders that use extra reserved sectors are not copied)'
            plan.actions.append(RepairAction('Copy VBR boot code from reference image', detail,
                                             True, fix_vbr_code))
    elif ctx.vbr_code_blank:
        plan.unfixable.append('VBR boot code is missing: supply a known-good image from the same '
                              'hardware with --vbr-code-from')

    if bpb is None or not ctx.fats:
        if bpb is None:
            plan.unfixable.append('No valid FAT volume: filesystem-level repairs are not possible')
        for opt, flag in (('--replace-nk', args.replace_nk), ('--fix-illegal-fat', args.fix_illegal_fat),
                          ('--free-lost-clusters', args.free_lost_clusters)):
            if flag:
                plan.blocked.append(f'{opt}: no usable FAT volume in this image')
        return plan

    pref = ctx.fats[ctx.preferred_fat]

    # --- Illegal FAT entries -----------------------------------------------
    illegal = ctx.fat_illegal[ctx.preferred_fat]
    if args.fix_illegal_fat:
        if illegal:
            fat_edits = True

            def fix_illegal(s: RepairSession, clusters=list(illegal)):
                for c in clusters:
                    s.fat.set(c, s.fat.eoc)
                s.log.append(f'terminated {len(clusters)} chain(s) at illegal FAT entries')
            plan.actions.append(RepairAction(
                f'Terminate {len(illegal)} broken FAT chain(s)',
                'illegal next-cluster values become end-of-chain; affected files are truncated, '
                'not recovered (the cut-off clusters become lost clusters)', True, fix_illegal))
        else:
            info('--fix-illegal-fat: the reference FAT has no illegal entries; nothing to do')
    elif illegal:
        plan.unfixable.append(f'{len(illegal)} illegal FAT entries: use --fix-illegal-fat to terminate '
                              'those chains (affected files are truncated)')

    # --- Lost clusters ------------------------------------------------------
    if args.free_lost_clusters:
        if ctx.lost_clusters:
            fat_edits = True

            def fix_lost(s: RepairSession, clusters=list(ctx.lost_clusters)):
                for c in clusters:
                    s.fat.set(c, 0)
                s.log.append(f'freed {len(clusters)} lost cluster(s)')
            plan.actions.append(RepairAction(
                f'Free {len(ctx.lost_clusters)} lost cluster(s)',
                'marks them free; any orphaned data in them is discarded', True, fix_lost))
        else:
            info('--free-lost-clusters: no lost clusters; nothing to do')
    elif ctx.lost_clusters:
        plan.unfixable.append(f'{len(ctx.lost_clusters)} lost cluster(s): use --free-lost-clusters to '
                              'reclaim the space (orphaned data is discarded)')
    if ctx.cross_linked:
        plan.unfixable.append(f'{ctx.cross_linked} cross-linked cluster(s): not repaired automatically; '
                              'run chkdsk or fsck.fat on a further copy if they affect needed files')

    # --- Kernel image replacement ------------------------------------------
    if args.replace_nk:
        action, why = plan_replace_nk(ctx, args, pref)
        if action:
            plan.actions.append(action)
            fat_edits = True
        else:
            plan.blocked.append(f'--replace-nk: {why}')
    elif ctx.nk_issue:
        plan.unfixable.append('Kernel image is missing or damaged: its contents cannot be rebuilt; '
                              'write a known-good copy with --replace-nk')

    # --- Clean-shutdown bit --------------------------------------------------
    if pref.clean_flag() is False or (ctx.fats_differ and any(c is False for c in ctx.clean)):
        fat_edits = True

        def fix_clean(s: RepairSession):
            s.fat.set_clean()
            s.log.append('set clean-shutdown bit in FAT entry 1')
        plan.actions.append(RepairAction('Set the FAT clean-shutdown bit',
                                         'marks the volume as cleanly dismounted', False, fix_clean))

    # --- Write FAT copies ----------------------------------------------------
    if ctx.fats_differ or fat_edits:
        src = f'FAT{ctx.preferred_fat + 1}'
        title = (f'Synchronise all FAT copies from {src}' if ctx.fats_differ
                 else 'Write updated FAT to all copies')

        def flush(s: RepairSession):
            nbytes = s.bpb.fat_size * SECTOR_SIZE
            data = bytes(s.fat.data[:nbytes])
            for i in range(s.bpb.num_fats):
                base = s.bpb.fat_lba(i)
                changed = 0
                for k in range(s.bpb.fat_size):
                    chunk = data[k * SECTOR_SIZE:(k + 1) * SECTOR_SIZE]
                    if s.write((base + k) * SECTOR_SIZE, chunk, '', quiet=True):
                        changed += 1
                if changed:
                    s.log.append(f'FAT{i + 1}: {changed} sector(s) rewritten')
        plan.actions.append(RepairAction(
            title, f'{bpb.num_fats} cop{"y" if bpb.num_fats == 1 else "ies"} of {bpb.fat_size} sectors',
            False, flush))

    # --- FSInfo ----------------------------------------------------------------
    if bpb.fat_type == 'FAT32' and (ctx.fsinfo_valid or ctx.vbr_restore_from_backup) and (
            ctx.fsinfo_mismatch or fat_edits or ctx.vbr_restore_from_backup):
        def fix_fsinfo(s: RepairSession):
            free = s.fat.free_list()
            lbas = [s.bpb.part_start_lba + s.bpb.fsinfo_sector]
            if s.bpb.backup_boot_sector not in (0, 0xFFFF):
                lbas.append(s.bpb.part_start_lba + s.bpb.backup_boot_sector + s.bpb.fsinfo_sector)
            for lba in lbas:
                sec = bytearray(s.img.read_sector(lba))
                if len(sec) != SECTOR_SIZE or struct.unpack_from('<I', sec, 0)[0] != FSINFO_LEAD:
                    continue
                struct.pack_into('<II', sec, 488, len(free), free[0] if free else 0xFFFFFFFF)
                s.write_sector(lba, bytes(sec), 'FSInfo free count')
        plan.actions.append(RepairAction('Update FAT32 FSInfo free-cluster count',
                                         'recomputed from the repaired FAT', False, fix_fsinfo))

    return plan


def plan_replace_nk(ctx: Ctx, args: argparse.Namespace,
                    pref: FatTable) -> Tuple[Optional[RepairAction], str]:
    path = args.replace_nk
    if not os.path.isfile(path):
        return None, f'file not found: {path}'
    with open(path, 'rb') as fh:
        data = fh.read()
    if not data:
        return None, 'replacement file is empty'

    notes = []
    if data[:7] == BIN_SIGNATURE:
        rep = check_bin_bytes(data)
        problems = []
        if rep.fatal:
            problems.append(rep.fatal)
        if rep.bad:
            problems.append(f'{len(rep.bad)} record checksum failure(s)')
        if problems and not args.force:
            return None, ('the replacement image fails its own validation (' + '; '.join(problems) +
                          '). Use --force to write it anyway')
        notes.append(f'BIN image, {rep.records} records, '
                     + ('checksums valid' if not problems else 'VALIDATION FAILED (--force)'))
    else:
        notes.append('not BIN format (raw/NB0), cannot be validated')

    bpb = ctx.bpb
    need = expected_clusters(len(data), bpb)
    old = list(dict.fromkeys(ctx.nk_chain)) if ctx.nk else []
    available = pref.count_free() + len(old)
    if need > available:
        return None, (f'needs {need} clusters but only {available} are available '
                      f'({need * bpb.cluster_bytes // 1024} KB required)')

    if ctx.nk:
        target, name83 = ctx.nk, None
        is_bin = data[:7] == BIN_SIGNATURE
        if is_bin != (not ctx.nk.name.upper().endswith('.NB0')):
            notes.append(f'WARNING: content format does not match the name {ctx.nk.name}')
        desc = f'replaces {ctx.nk.name} ({ctx.nk.size // 1024} KB -> {len(data) // 1024} KB)'
    else:
        name = args.nk_name or 'NK.BIN'
        name83 = to_83(name)
        if name83 is None:
            return None, f'"{name}" is not a valid 8.3 file name'
        if not ctx.root_free:
            return None, 'no free entry in the root directory'
        target = None
        desc = f'creates {name.upper()} in the root directory'

    def apply(s: RepairSession, data=data, old=old, target=target, name83=name83):
        f, b = s.fat, s.bpb
        for c in old:
            f.set(c, 0)
        clusters, contiguous = f.allocate(need)
        if clusters is None:
            raise RuntimeError('cluster allocation failed')
        for i, c in enumerate(clusters):
            f.set(c, clusters[i + 1] if i + 1 < len(clusters) else f.eoc)
        cb = b.cluster_bytes
        for i, c in enumerate(clusters):
            chunk = data[i * cb:(i + 1) * cb].ljust(cb, b'\x00')
            s.img.write_at(b.cluster_lba(c) * SECTOR_SIZE, chunk)
        s.log.append(f'kernel image: {len(data)} bytes written to {len(clusters)} cluster(s) '
                     f'starting at {clusters[0]}' + ('' if contiguous else ' (fragmented)'))
        if not contiguous:
            warn('No contiguous free run was large enough; the kernel image was written fragmented')

        ftime, fdate = fat_timestamp()
        if target:
            off = target.offset
            e = bytearray(s.img.read_at(off, 32))
        else:
            off = s.ctx.root_free[0]
            e = bytearray(32)
            e[0:11] = name83
            e[11] = 0x20
            struct.pack_into('<HHH', e, 14, ftime, fdate, fdate)
        hi = (clusters[0] >> 16) & 0xFFFF if b.fat_type == 'FAT32' else 0
        struct.pack_into('<H', e, 20, hi)
        struct.pack_into('<HH', e, 22, ftime, fdate)
        struct.pack_into('<H', e, 26, clusters[0] & 0xFFFF)
        struct.pack_into('<I', e, 28, len(data))
        s.write(off, bytes(e), 'kernel image directory entry')

    detail = f'{path}: {desc}; ' + '; '.join(notes)
    return RepairAction('Write replacement kernel image', detail, True, apply), ''


def print_plan(plan: RepairPlan, output: str):
    hdr('REPAIR PLAN')
    if plan.actions:
        print(f'  Repairs to apply (written to a copy: {output}):')
        for i, a in enumerate(plan.actions, 1):
            tag = 'requested' if a.requested else 'auto'
            print(f'    {i}. [{tag}] {a.title}')
            print(f'       {a.detail}')
    else:
        print('  No repairs are available for the problems found.')
    if plan.blocked:
        print(f'\n  {RED}Requested repairs that cannot be performed:{RESET}')
        for b in plan.blocked:
            print(f'    - {b}')
    if plan.unfixable:
        print(f'\n  {YELLOW}Problems these repairs will not fix:{RESET}')
        for u in plan.unfixable:
            print(f'    - {u}')
    print()


def default_output(path: str) -> str:
    base, ext = os.path.splitext(path)
    return f'{base}.repaired{ext or ".img"}'


def run_repair(ctx: Ctx, args: argparse.Namespace) -> int:
    output = args.output or default_output(args.image)
    plan = plan_repairs(ctx, args)
    print_plan(plan, output)

    if plan.blocked:
        print(f'  {RED}Nothing written: fix the options above and run again.{RESET}\n')
        return 1
    if not plan.actions:
        return 2 if ctx.res.errors else 0
    if args.dry_run:
        print('  Dry run: no changes written.\n')
        return 2 if ctx.res.errors else 0

    if os.path.abspath(output) == os.path.abspath(args.image) or (
            os.path.exists(output) and os.path.samefile(output, args.image)):
        print(f'{RED}Error: the output must be a different file from the input image.{RESET}')
        return 1
    if os.path.exists(output) and not args.overwrite:
        print(f'{RED}Error: {output} already exists (use --overwrite to replace it).{RESET}')
        return 1
    out_dir = os.path.dirname(os.path.abspath(output))
    if shutil.disk_usage(out_dir).free < os.path.getsize(args.image) + (1 << 20):
        print(f'{RED}Error: not enough free space in {out_dir} for a copy of the image.{RESET}')
        return 1

    if not args.yes:
        if not sys.stdin.isatty():
            print('Not running interactively: add --yes to apply the repairs.')
            return 1
        if input(f'  Apply {len(plan.actions)} repair(s) to a copy at {output}? [y/N] ').strip().lower() != 'y':
            print('  Cancelled.')
            return 1

    print(f'\n  Copying image to {output} ...')
    shutil.copyfile(args.image, output)
    out = ImageFile(output, writable=True)
    session = RepairSession(ctx, out)
    failed = None
    try:
        for a in plan.actions:
            print(f'  -> {a.title}')
            a.apply(session)
    except Exception as e:
        failed = f'{a.title}: {e}'
    finally:
        out.close()

    log_path = output + '.repair.log'
    with open(log_path, 'w', encoding='utf-8') as lf:
        lf.write(f'wince_boot_diag repair log  {time.strftime("%Y-%m-%d %H:%M:%S")}\n')
        lf.write(f'input:  {os.path.abspath(args.image)}\n  sha256 {sha256_file(args.image)}\n')
        lf.write(f'output: {os.path.abspath(output)}\n  sha256 {sha256_file(output)}\n\n')
        for a in plan.actions:
            lf.write(f'action: {a.title} -- {a.detail}\n')
        lf.write('\nwrites:\n')
        for line in session.log:
            lf.write(f'  {line}\n')
        if failed:
            lf.write(f'\nFAILED: {failed}\n')

    if failed:
        print(f'\n  {RED}Repair failed: {failed}{RESET}')
        print(f'  {RED}{output} is incomplete and should be deleted. The input image is unchanged.{RESET}')
        return 1

    print(f'  Repair log: {log_path}')
    print(f'\n{BOLD}Re-checking the repaired image...{RESET}')
    verify = analyse(output, args)
    verify.res.summary('POST-REPAIR VERIFICATION')
    return 2 if verify.res.errors else 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description='Windows CE CF image boot diagnostics and repair. '
                    'Repairs are always written to a copy; the input image is never modified.')
    ap.add_argument('image', help='path to the raw .img file')
    ap.add_argument('-v', '--verbose', action='store_true', help='list every checksum failure')
    ap.add_argument('--entropy-scan', action='store_true', help='add the critical-sector entropy report')
    ap.add_argument('--no-colour', '--no-color', action='store_true', help='disable coloured output')
    ap.add_argument('--fat-source', type=int, choices=(1, 2),
                    help='FAT copy to treat as authoritative (default: most consistent copy)')

    rp = ap.add_argument_group('repair')
    rp.add_argument('--repair', action='store_true', help='plan and apply repairs to a copy of the image')
    rp.add_argument('-o', '--output', help='repaired image path (default: <image>.repaired.img)')
    rp.add_argument('--dry-run', action='store_true', help='show the repair plan without writing anything')
    rp.add_argument('-y', '--yes', action='store_true', help='apply without asking for confirmation')
    rp.add_argument('--overwrite', action='store_true', help='replace an existing output file')
    rp.add_argument('--fix-illegal-fat', action='store_true',
                    help='terminate FAT chains at illegal entries (affected files are truncated)')
    rp.add_argument('--free-lost-clusters', action='store_true',
                    help='mark lost (orphaned) clusters free; their data is discarded')
    rp.add_argument('--replace-nk', metavar='FILE', help='write a known-good kernel image into the filesystem')
    rp.add_argument('--nk-name', metavar='NAME',
                    help='file name to create if no kernel image exists (default: NK.BIN)')
    rp.add_argument('--mbr-code-from', metavar='IMG', help='copy MBR boot code from a reference image')
    rp.add_argument('--vbr-code-from', metavar='IMG', help='copy VBR boot code from a reference image')
    rp.add_argument('--force', action='store_true',
                    help='write a --replace-nk image even if it fails validation')
    args = ap.parse_args(argv)

    repair_only = [args.output, args.dry_run, args.yes, args.overwrite, args.fix_illegal_fat,
                   args.free_lost_clusters,
                   args.replace_nk, args.nk_name, args.mbr_code_from, args.vbr_code_from, args.force]
    if not args.repair and any(repair_only):
        ap.error('repair options require --repair')
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_colour(not args.no_colour and sys.stdout.isatty())
    if not os.path.isfile(args.image):
        print(f'{RED}Error: file not found: {args.image}{RESET}')
        return 1
    ctx = analyse(args.image, args)
    ctx.res.summary()
    if args.repair:
        return run_repair(ctx, args)
    return 2 if ctx.res.errors else 0


if __name__ == '__main__':
    sys.exit(main())
