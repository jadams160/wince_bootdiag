#!/usr/bin/env python3
"""
fat32_demo.py
=============
Builds a small FAT32 disk image byte by byte, without mkfs or any external
tool, to show exactly what a FAT32 driver writes to a block device.

It produces three images:

  fat32_1_two_files.img     HELLO.TXT and WORLD.TXT written one after another
  fat32_2_grown.img         HELLO.TXT grown past one cluster, so it fragments
  fat32_3_defragmented.img  clusters moved so each file is contiguous again

and prints hex dumps of the structures involved, the individual steps of the
defragmentation, and a byte-level diff between the stages.

Usage:
    python3 fat32_demo.py [--outdir DIR] [--quiet]

The images are "superfloppy" volumes (no partition table): the FAT32 boot
sector is sector 0. Linux mounts them directly (sudo mount -o loop IMG /mnt),
mtools reads them (mdir -i IMG ::), and fsck.fat -n IMG checks them.

All timestamps and the volume ID are fixed, so every run produces
byte-identical images. Standard library only; Python 3.7+.
"""

import argparse
import copy
import os
import struct

# ---------------------------------------------------------------------------
# Volume geometry
# ---------------------------------------------------------------------------
SECTOR = 512
TOTAL_SECTORS = 69632          # 34 MiB: small, but above the FAT32 minimum cluster count
RESERVED_SECTORS = 32
NUM_FATS = 2
SECTORS_PER_CLUSTER = 1        # 512-byte clusters keep the example small
ROOT_CLUSTER = 2
FSINFO_SECTOR = 1
BACKUP_BOOT_SECTOR = 6
MEDIA = 0xF8                   # fixed disk
VOLUME_ID = 0x1234ABCD
VOLUME_LABEL = b'DEMO       '
FAT32_MIN_CLUSTERS = 65525     # fewer clusters than this and a driver treats it as FAT16

EOC = 0x0FFFFFFF               # end-of-chain marker
ATTR_ARCHIVE = 0x20
ATTR_VOLUME_ID = 0x08

CREATED = (2026, 1, 15, 9, 30, 0)
GROWN = (2026, 1, 15, 9, 45, 10)

HELLO_TEXT = b'Hello, world!\n'
WORLD_TEXT = b'This is the second file.\n'
HELLO_EXTRA = b''.join(b'Line %02d: HELLO.TXT keeps growing.\n' % i for i in range(1, 21))


def fat_time(h: int, m: int, s: int) -> int:
    return (h << 11) | (m << 5) | (s // 2)


def fat_date(y: int, mo: int, d: int) -> int:
    return ((y - 1980) << 9) | (mo << 5) | d


def to_83(name: str) -> bytes:
    base, ext = name.upper().split('.')
    return base.ljust(8).encode('ascii') + ext.ljust(3).encode('ascii')


def compute_fat_size():
    """Smallest FAT (in sectors) that can hold an entry for every cluster."""
    fat = 1
    while True:
        clusters = (TOTAL_SECTORS - RESERVED_SECTORS - NUM_FATS * fat) // SECTORS_PER_CLUSTER
        if (clusters + 2) * 4 <= fat * SECTOR:
            return fat, clusters
        fat += 1


# ---------------------------------------------------------------------------
# The image
# ---------------------------------------------------------------------------
class Fat32Image:
    def __init__(self):
        self.fat_size, self.clusters = compute_fat_size()
        assert self.clusters >= FAT32_MIN_CLUSTERS
        self.buf = bytearray(TOTAL_SECTORS * SECTOR)
        self.fat = [0] * (self.clusters + 2)     # in-memory FAT; flush() writes both copies
        self.last_alloc = ROOT_CLUSTER
        self._format()

    # --- geometry ---------------------------------------------------------
    @property
    def cluster_bytes(self) -> int:
        return SECTORS_PER_CLUSTER * SECTOR

    @property
    def data_lba(self) -> int:
        return RESERVED_SECTORS + NUM_FATS * self.fat_size

    def fat_lba(self, copy_index: int) -> int:
        return RESERVED_SECTORS + copy_index * self.fat_size

    def cluster_offset(self, c: int) -> int:
        return (self.data_lba + (c - 2) * SECTORS_PER_CLUSTER) * SECTOR

    def clone(self) -> 'Fat32Image':
        return copy.deepcopy(self)

    # --- formatting -------------------------------------------------------
    def _format(self):
        bs = bytearray(SECTOR)
        bs[0:3] = b'\xEB\x58\x90'                 # JMP +0x58 to offset 0x5A, NOP
        bs[3:11] = b'MSWIN4.1'                    # OEM name
        struct.pack_into('<HBHBHHBHHHII', bs, 11,
                         SECTOR,                  # 0x0B bytes per sector
                         SECTORS_PER_CLUSTER,     # 0x0D sectors per cluster
                         RESERVED_SECTORS,        # 0x0E reserved sectors
                         NUM_FATS,                # 0x10 number of FATs
                         0,                       # 0x11 root entries (0 on FAT32)
                         0,                       # 0x13 16-bit total sectors (0 on FAT32)
                         MEDIA,                   # 0x15 media descriptor
                         0,                       # 0x16 16-bit FAT size (0 on FAT32)
                         63, 255,                 # 0x18 sectors/track, 0x1A heads (CHS legacy)
                         0,                       # 0x1C hidden sectors (none: no partition table)
                         TOTAL_SECTORS)           # 0x20 32-bit total sectors
        struct.pack_into('<IHHIHH', bs, 36,
                         self.fat_size,           # 0x24 sectors per FAT
                         0,                       # 0x28 flags: FAT copies mirrored
                         0,                       # 0x2A version 0.0
                         ROOT_CLUSTER,            # 0x2C root directory cluster
                         FSINFO_SECTOR,           # 0x30 FSInfo sector
                         BACKUP_BOOT_SECTOR)      # 0x32 backup boot sector
        bs[64] = 0x80                             # 0x40 BIOS drive number
        bs[66] = 0x29                             # 0x42 extended boot signature
        struct.pack_into('<I', bs, 67, VOLUME_ID)  # 0x43 volume serial number
        bs[71:82] = VOLUME_LABEL                  # 0x47 volume label
        bs[82:90] = b'FAT32   '                   # 0x52 file system type (informational only)
        bs[90:92] = b'\xEB\xFE'                   # 0x5A boot code: jump to self (not bootable)
        bs[510:512] = b'\x55\xAA'                 # boot signature
        self._write_sector(0, bs)
        self._write_sector(BACKUP_BOOT_SECTOR, bs)

        self.fat[0] = 0x0FFFFF00 | MEDIA          # entry 0: media byte
        self.fat[1] = EOC                         # entry 1: EOC; clean + no-error bits set
        self.fat[2] = EOC                         # root directory: a one-cluster chain

        self.buf[self.cluster_offset(ROOT_CLUSTER):self.cluster_offset(ROOT_CLUSTER) + 32] = \
            self.dir_entry(VOLUME_LABEL, ATTR_VOLUME_ID, 0, 0, CREATED)
        self.flush()

    def _write_sector(self, lba: int, data: bytes):
        self.buf[lba * SECTOR:(lba + 1) * SECTOR] = data

    def flush(self):
        """Write both FAT copies and both FSInfo sectors from the in-memory state."""
        fat_bytes = struct.pack(f'<{len(self.fat)}I', *self.fat).ljust(self.fat_size * SECTOR, b'\x00')
        for i in range(NUM_FATS):
            start = self.fat_lba(i) * SECTOR
            self.buf[start:start + len(fat_bytes)] = fat_bytes
        fs = bytearray(SECTOR)
        struct.pack_into('<I', fs, 0, 0x41615252)          # "RRaA" lead signature
        struct.pack_into('<I', fs, 484, 0x61417272)        # "rrAa" structure signature
        struct.pack_into('<I', fs, 488, self.fat[2:].count(0))  # free cluster count
        struct.pack_into('<I', fs, 492, self.last_alloc)   # next-free hint
        struct.pack_into('<I', fs, 508, 0xAA550000)        # trail signature
        self._write_sector(FSINFO_SECTOR, fs)
        self._write_sector(BACKUP_BOOT_SECTOR + FSINFO_SECTOR, fs)

    # --- directory entries -------------------------------------------------
    @staticmethod
    def dir_entry(name83: bytes, attr: int, start: int, size: int, ts) -> bytes:
        t, d = fat_time(*ts[3:]), fat_date(*ts[:3])
        e = bytearray(32)
        e[0:11] = name83
        e[11] = attr
        struct.pack_into('<HHH', e, 14, t, d, d)   # created time, created date, accessed date
        struct.pack_into('<H', e, 20, start >> 16)  # first cluster, high 16 bits
        struct.pack_into('<HH', e, 22, t, d)       # modified time, modified date
        struct.pack_into('<H', e, 26, start & 0xFFFF)  # first cluster, low 16 bits
        struct.pack_into('<I', e, 28, size)        # file size in bytes
        return bytes(e)

    def root_slots(self):
        base = self.cluster_offset(ROOT_CLUSTER)
        return [base + i * 32 for i in range(self.cluster_bytes // 32)]

    def files(self):
        """(name, entry offset) for each file in the root, in directory order."""
        out = []
        for off in self.root_slots():
            first, attr = self.buf[off], self.buf[off + 11]
            if first == 0x00:
                break
            if first == 0xE5 or attr & ATTR_VOLUME_ID:
                continue
            name = self.buf[off:off + 8].decode().rstrip() + '.' + self.buf[off + 8:off + 11].decode().rstrip()
            out.append((name, off))
        return out

    def entry_offset(self, name: str) -> int:
        return next(off for n, off in self.files() if n == name)

    def entry_start(self, off: int) -> int:
        hi, = struct.unpack_from('<H', self.buf, off + 20)
        lo, = struct.unpack_from('<H', self.buf, off + 26)
        return (hi << 16) | lo

    def set_entry_start(self, off: int, cluster: int):
        struct.pack_into('<H', self.buf, off + 20, cluster >> 16)
        struct.pack_into('<H', self.buf, off + 26, cluster & 0xFFFF)

    # --- clusters ------------------------------------------------------------
    def chain(self, start: int):
        out = [start]
        while self.fat[out[-1]] < 0x0FFFFFF8:
            out.append(self.fat[out[-1]])
        return out

    def allocate(self, n: int):
        """Take n free clusters, searching from just after the last one allocated,
        the way the FSInfo next-free hint is meant to be used."""
        found, c = [], self.last_alloc + 1
        while len(found) < n:
            if c > self.clusters + 1:
                c = 2
            if self.fat[c] == 0:
                found.append(c)
            c += 1
        self.last_alloc = found[-1]
        return found

    def first_free(self, start: int) -> int:
        return next(c for c in range(start, self.clusters + 2) if self.fat[c] == 0)

    def write_chain(self, clusters, data: bytes):
        cb = self.cluster_bytes
        for i, c in enumerate(clusters):
            off = self.cluster_offset(c)
            self.buf[off:off + cb] = data[i * cb:(i + 1) * cb].ljust(cb, b'\x00')

    def read_file(self, name: str) -> bytes:
        off = self.entry_offset(name)
        size, = struct.unpack_from('<I', self.buf, off + 28)
        data = b''.join(bytes(self.buf[self.cluster_offset(c):self.cluster_offset(c) + self.cluster_bytes])
                        for c in self.chain(self.entry_start(off)))
        return data[:size]

    # --- file operations -------------------------------------------------------
    def create_file(self, name: str, data: bytes, ts):
        n = -(-len(data) // self.cluster_bytes)
        clusters = self.allocate(n)
        for a, b in zip(clusters, clusters[1:]):
            self.fat[a] = b
        self.fat[clusters[-1]] = EOC
        self.write_chain(clusters, data)
        slot = next(off for off in self.root_slots() if self.buf[off] in (0x00, 0xE5))
        self.buf[slot:slot + 32] = self.dir_entry(to_83(name), ATTR_ARCHIVE, clusters[0], len(data), ts)
        self.flush()

    def append(self, name: str, extra: bytes, ts):
        off = self.entry_offset(name)
        data = self.read_file(name) + extra
        chain = self.chain(self.entry_start(off))
        need = -(-len(data) // self.cluster_bytes)
        if need > len(chain):
            new = self.allocate(need - len(chain))
            self.fat[chain[-1]] = new[0]              # old end-of-chain now points onward
            for a, b in zip(new, new[1:]):
                self.fat[a] = b
            self.fat[new[-1]] = EOC
            chain += new
        self.write_chain(chain, data)
        t, d = fat_time(*ts[3:]), fat_date(*ts[:3])
        struct.pack_into('<H', self.buf, off + 18, d)          # accessed date
        struct.pack_into('<HH', self.buf, off + 22, t, d)      # modified time and date
        struct.pack_into('<I', self.buf, off + 28, len(data))  # new size
        self.flush()

    def owner_of(self, cluster: int):
        for name, off in self.files():
            ch = self.chain(self.entry_start(off))
            if cluster in ch:
                i = ch.index(cluster)
                return name, off, i, (ch[i - 1] if i else None)
        raise ValueError(f'cluster {cluster} belongs to no file')

    def move_cluster(self, src: int, dst: int, log):
        """Move one cluster in the order that keeps the volume consistent if
        power fails between any two steps: copy, link in, then free."""
        assert self.fat[dst] == 0
        name, off, idx, prev = self.owner_of(src)
        cb = self.cluster_bytes
        s, d = self.cluster_offset(src), self.cluster_offset(dst)
        self.buf[d:d + cb] = self.buf[s:s + cb]
        log.append(f'copy the data in cluster {src} to cluster {dst} ({name}, its cluster #{idx + 1})')
        self.fat[dst] = self.fat[src]
        log.append(f'FAT[{dst}] = {fmt_entry(self.fat[dst])}')
        if prev is None:
            self.set_entry_start(off, dst)
            log.append(f'{name} directory entry: first cluster {src} -> {dst}')
        else:
            self.fat[prev] = dst
            log.append(f'FAT[{prev}] = {dst} (was {src})')
        self.fat[src] = 0
        log.append(f'FAT[{src}] = 0 (free; the old data stays in the cluster)')

    def defragment(self, log):
        """Lay files out contiguously, in directory order, right after the root."""
        files = self.files()
        planned_end = ROOT_CLUSTER + 1 + sum(len(self.chain(self.entry_start(o))) for _, o in files)
        target = ROOT_CLUSTER + 1
        for name, off in files:
            i = 0
            while True:
                ch = self.chain(self.entry_start(off))
                if i >= len(ch):
                    break
                if ch[i] != target:
                    if self.fat[target] != 0:
                        scratch = self.first_free(planned_end)
                        occupant = self.owner_of(target)[0]
                        log.append(f'# Cluster {target} is needed for {name} but holds {occupant}; '
                                   f'move it out of the way to free cluster {scratch}')
                        self.move_cluster(target, scratch, log)
                        ch = self.chain(self.entry_start(off))
                    log.append(f'# Move {name} cluster #{i + 1} from {ch[i]} to {target}')
                    self.move_cluster(ch[i], target, log)
                target += 1
                i += 1
        self.last_alloc = target - 1
        self.flush()

    # --- description -------------------------------------------------------------
    def region(self, off: int) -> str:
        lba = off // SECTOR
        names = {0: 'boot sector', FSINFO_SECTOR: 'FSInfo sector',
                 BACKUP_BOOT_SECTOR: 'backup boot sector',
                 BACKUP_BOOT_SECTOR + FSINFO_SECTOR: 'backup FSInfo sector'}
        if lba in names:
            return names[lba]
        if lba < RESERVED_SECTORS:
            return 'reserved area'
        for i in range(NUM_FATS):
            if self.fat_lba(i) <= lba < self.fat_lba(i) + self.fat_size:
                first = (off - self.fat_lba(i) * SECTOR) // 4
                return f'FAT{i + 1}, entries {first}-{first + 3}'
        c = (lba - self.data_lba) // SECTORS_PER_CLUSTER + 2
        return f'cluster {c}' + (' (root directory)' if c == ROOT_CLUSTER else ' (file data)')


def fmt_entry(v: int) -> str:
    return 'EOC (0x0FFFFFFF)' if v >= 0x0FFFFFF8 else ('0 (free)' if v == 0 else str(v))


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def hexdump(buf: bytes, start: int, length: int, squeeze: bool = True):
    prev, starred = None, False
    for off in range(start, start + length, 16):
        line = bytes(buf[off:off + 16])
        if squeeze and line == prev and off + 16 < start + length:
            if not starred:
                print('*')
                starred = True
            continue
        prev, starred = line, False
        hx = ' '.join(f'{b:02x}' for b in line[:8]) + '  ' + ' '.join(f'{b:02x}' for b in line[8:])
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line)
        print(f'{off:08x}  {hx}  |{asc}|')


def show_layout(img: Fat32Image):
    rows = [('sector 0', 'boot sector (byte 0x0)'),
            (f'sector {FSINFO_SECTOR}', 'FSInfo'),
            (f'sectors {BACKUP_BOOT_SECTOR}-{BACKUP_BOOT_SECTOR + 1}', 'backup boot sector and FSInfo')]
    for i in range(NUM_FATS):
        a = img.fat_lba(i)
        rows.append((f'sectors {a}-{a + img.fat_size - 1}', f'FAT{i + 1} (byte 0x{a * SECTOR:x})'))
    rows.append((f'sector {img.data_lba}', f'cluster 2, root directory (byte 0x{img.data_lba * SECTOR:x})'))
    print('Layout:')
    for where, what in rows:
        print(f'  {where:<18} {what}')
    print(f'  data clusters: {img.clusters}, cluster size {img.cluster_bytes} bytes')


def show_state(img: Fat32Image):
    print('Files:')
    for name, off in img.files():
        size, = struct.unpack_from('<I', img.buf, off + 28)
        print(f'  {name:<10} {size:4d} bytes, clusters {img.chain(img.entry_start(off))}')
    print('\nFAT1, entries 0-7:')
    hexdump(img.buf, img.fat_lba(0) * SECTOR, 32, squeeze=False)
    print('\nRoot directory (cluster 2), first four entries:')
    hexdump(img.buf, img.cluster_offset(ROOT_CLUSTER), 128, squeeze=False)
    print('\nFSInfo counters (offset 0x1E8 in sector 1):')
    hexdump(img.buf, FSINFO_SECTOR * SECTOR + 0x1E0, 16, squeeze=False)
    print('\nData clusters 3-6, first 32 bytes of each:')
    for c in range(3, 7):
        print(f'cluster {c}:')
        hexdump(img.buf, img.cluster_offset(c), 32, squeeze=False)


def show_diff(old: Fat32Image, new: Fat32Image):
    for lba in range(TOTAL_SECTORS):
        a = old.buf[lba * SECTOR:(lba + 1) * SECTOR]
        b = new.buf[lba * SECTOR:(lba + 1) * SECTOR]
        if a == b:
            continue
        for k in range(0, SECTOR, 16):
            o = lba * SECTOR + k
            if a[k:k + 16] != b[k:k + 16]:
                print(f'  0x{o:08x}  {new.region(o)}')
                print('    before: ' + a[k:k + 16].hex(' '))
                print('    after:  ' + b[k:k + 16].hex(' '))


def banner(text: str):
    print('\n' + '=' * 78 + '\n' + text + '\n' + '=' * 78)


def main():
    ap = argparse.ArgumentParser(description='Build and explain a small FAT32 image.')
    ap.add_argument('--outdir', default='.', help='directory for the .img files (default: current)')
    ap.add_argument('--quiet', action='store_true', help='only write the images')
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # Stage 1: format, then create two files
    s1 = Fat32Image()
    s1.create_file('HELLO.TXT', HELLO_TEXT, CREATED)
    s1.create_file('WORLD.TXT', WORLD_TEXT, CREATED)

    # Stage 2: grow HELLO.TXT past one cluster
    s2 = s1.clone()
    s2.append('HELLO.TXT', HELLO_EXTRA, GROWN)

    # Stage 3: defragment
    s3 = s2.clone()
    steps = []
    s3.defragment(steps)

    for img, fname in ((s1, 'fat32_1_two_files.img'), (s2, 'fat32_2_grown.img'),
                       (s3, 'fat32_3_defragmented.img')):
        with open(os.path.join(args.outdir, fname), 'wb') as f:
            f.write(img.buf)

    assert s3.read_file('HELLO.TXT') == HELLO_TEXT + HELLO_EXTRA
    assert s3.read_file('WORLD.TXT') == WORLD_TEXT
    if args.quiet:
        return

    banner('STAGE 1: two files (fat32_1_two_files.img)')
    show_layout(s1)
    print('\nBoot sector, bytes 0x00-0x5F and 0x1F0-0x1FF:')
    hexdump(s1.buf, 0, 0x60, squeeze=False)
    print('...')
    hexdump(s1.buf, 0x1F0, 16, squeeze=False)
    print()
    show_state(s1)

    banner('STAGE 2: HELLO.TXT grown (fat32_2_grown.img)')
    show_state(s2)
    print('\nBytes changed from stage 1:')
    show_diff(s1, s2)

    banner('STAGE 3: defragmented (fat32_3_defragmented.img)')
    print('Steps:')
    for s in steps:
        print(('' if s.startswith('#') else '    ') + s)
    print()
    show_state(s3)
    print('\nBytes changed from stage 2:')
    show_diff(s2, s3)
    print(f'\nImages written to {os.path.abspath(args.outdir)}')


if __name__ == '__main__':
    main()
