# FAT32, byte by byte

This walkthrough builds a FAT32 volume from nothing, writes two small text files to it, grows one of them until it fragments, and then defragments the volume. At every step it shows the actual bytes that land on the block device.

Every hex dump here is real output from the companion script, `fat32_demo.py`, which writes the three disk images described below. Run it yourself and you will get byte-identical images, because the timestamps and volume serial number are fixed:

```bash
python3 fat32_demo.py --outdir images > walkthrough.txt
```

The images are ordinary FAT32 volumes. They pass `fsck.fat -n` cleanly, `mdir -i fat32_1_two_files.img ::` lists them, and Linux will mount them with `sudo mount -o loop`.

A note on `.img` versus `.iso`: an `.iso` file is an ISO 9660 image, the file system used on CDs and DVDs, which is a different format entirely. A raw copy of a FAT32 block device is conventionally named `.img`.

## Reading the dumps

Each dump line shows the byte offset from the start of the device, sixteen bytes in hex, and the same bytes as ASCII (non-printable bytes appear as dots):

```
0008a200  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a 00 00  |Hello, world!...|
```

All multi-byte numbers in FAT32 are **little-endian**: the least significant byte comes first. So the four bytes `00 10 01 00` are the number `0x00011000`, and `18 02 00 00` is `0x00000218`. This trips everyone up at first, so every value below is decoded for you.

## The big picture

A block device is just a long run of 512-byte sectors, numbered from 0 (the logical block address, or LBA). FAT32 divides it into four regions:

| Region | Sectors in this image | Byte offset | Holds |
|---|---|---|---|
| Reserved area | 0-31 | `0x0` | Boot sector, FSInfo, backup copies |
| FAT 1 | 32-567 | `0x4000` | The file allocation table |
| FAT 2 | 568-1103 | `0x47000` | An identical copy of FAT 1 |
| Data area | 1104 onward | `0x8A000` | Clusters holding directories and file contents |

The data area is divided into **clusters**, the unit of allocation: a file always occupies whole clusters. Clusters are numbered from **2** (numbers 0 and 1 are reserved, for reasons covered below). In this image a cluster is one 512-byte sector, so cluster *N* starts at byte:

```
0x8A000 + (N - 2) × 0x200
```

That puts cluster 2 at `0x8A000`, cluster 3 at `0x8A200`, cluster 4 at `0x8A400`, and so on. Real volumes use larger clusters (4 KB to 32 KB); one sector per cluster keeps this example small enough to read.

The core idea of FAT is that **a file's clusters form a linked list, and the links are stored in the FAT, not in the clusters themselves.** The FAT is an array with one 32-bit entry per cluster. The entry for cluster *N* holds the number of the *next* cluster in the same file, or a special end-of-chain marker. A directory entry records only the file's *first* cluster; the FAT supplies the rest.

There are no inodes. Everything the file system knows about a file is split between its 32-byte directory entry (name, size, timestamps, first cluster) and its chain of FAT entries.

## Stage 1: format, then write two files

### The boot sector (sector 0)

The boot sector is the first thing any FAT driver reads. It describes the geometry of everything else:

```
00000000  eb 58 90 4d 53 57 49 4e  34 2e 31 00 02 01 20 00  |.X.MSWIN4.1... .|
00000010  02 00 00 00 00 f8 00 00  3f 00 ff 00 00 00 00 00  |........?.......|
00000020  00 10 01 00 18 02 00 00  00 00 00 00 02 00 00 00  |................|
00000030  01 00 06 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000040  80 00 29 cd ab 34 12 44  45 4d 4f 20 20 20 20 20  |..)..4.DEMO     |
00000050  20 20 46 41 54 33 32 20  20 20 eb fe 00 00 00 00  |  FAT32   ......|
...
000001f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 55 aa  |..............U.|
```

The first part is the **BIOS Parameter Block** (BPB):

| Offset | Bytes | Value | Meaning |
|---|---|---|---|
| `0x00` | `eb 58 90` | | x86 jump over the BPB to the boot code at `0x5A`, then a NOP |
| `0x03` | `4d 53 ... 31` | `MSWIN4.1` | OEM name; purely informational |
| `0x0B` | `00 02` | 512 | Bytes per sector |
| `0x0D` | `01` | 1 | Sectors per cluster |
| `0x0E` | `20 00` | 32 | Reserved sectors: the FAT starts at sector 32 |
| `0x10` | `02` | 2 | Number of FAT copies |
| `0x11` | `00 00` | 0 | Root directory entries: always 0 on FAT32 |
| `0x13` | `00 00` | 0 | 16-bit total sectors: 0 means "use the 32-bit field" |
| `0x15` | `f8` | `0xF8` | Media descriptor: fixed disk |
| `0x16` | `00 00` | 0 | 16-bit FAT size: 0 means "this is FAT32, see `0x24`" |
| `0x18` | `3f 00` / `ff 00` | 63 / 255 | Sectors per track and heads, legacy CHS values |
| `0x1C` | `00 00 00 00` | 0 | Hidden sectors before the volume (no partition table here) |
| `0x20` | `00 10 01 00` | 69,632 | Total sectors (34 MiB) |

Then the FAT32-specific fields:

| Offset | Bytes | Value | Meaning |
|---|---|---|---|
| `0x24` | `18 02 00 00` | 536 | Sectors per FAT |
| `0x28` | `00 00` | 0 | Flags: all FAT copies are kept identical |
| `0x2A` | `00 00` | 0.0 | File system version |
| `0x2C` | `02 00 00 00` | 2 | Cluster where the root directory starts |
| `0x30` | `01 00` | 1 | Sector holding the FSInfo structure |
| `0x32` | `06 00` | 6 | Sector holding the backup boot sector |
| `0x40` | `80` | | BIOS drive number |
| `0x42` | `29` | | Signature: the next three fields are present |
| `0x43` | `cd ab 34 12` | `1234-ABCD` | Volume serial number |
| `0x47` | `44 45 4d 4f 20 ...` | `DEMO` | Volume label, padded to 11 bytes with spaces |
| `0x52` | `46 41 54 33 32 20 20 20` | `FAT32` | Informational only; drivers must not trust it |
| `0x5A` | `eb fe` | | Boot code: an infinite loop, since this volume is not bootable |
| `0x1FE` | `55 aa` | | Boot signature |

From these numbers a driver computes the whole layout:

```
FAT 1 starts at   reserved                       = 32
FAT 2 starts at   32 + 536                       = 568
Data starts at    32 + 2 × 536                   = 1104
Data clusters     (69632 − 1104) ÷ 1             = 68,528
```

The cluster count is what actually makes this FAT32. The `FAT32` text at `0x52` is ignored; a driver decides the FAT type purely from the number of clusters, and anything with 65,525 or more is FAT32. That is why this image is 34 MiB even though it holds only 39 bytes of text: a smaller volume with 512-byte clusters would legally be FAT16.

A copy of the boot sector sits at sector 6, so a damaged sector 0 can be recovered.

### The FSInfo sector (sector 1)

FSInfo is a small cache so the driver doesn't have to scan the whole FAT to answer "how much space is free?". The interesting part is near the end:

```
000003e0  00 00 00 00 72 72 41 61  ad 0b 01 00 04 00 00 00  |....rrAa........|
```

`72 72 41 61` (`rrAa`) is a signature. The next four bytes, `ad 0b 01 00`, are the free cluster count: 68,525 (68,528 clusters minus the three in use). The last four, `04 00 00 00`, are a hint: the most recently allocated cluster, 4, where the next search for free space should begin. Both values are advisory; `chkdsk` and `fsck.fat` recompute them and overwrite them if they are wrong.

### The FAT

Here are the first eight entries of FAT 1, four bytes each:

```
00004000  f8 ff ff 0f ff ff ff 0f  ff ff ff 0f ff ff ff 0f  |................|
00004010  ff ff ff 0f 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

| Entry | Offset | Bytes | Value | Meaning |
|---|---|---|---|---|
| 0 | `0x4000` | `f8 ff ff 0f` | `0x0FFFFFF8` | Reserved; low byte repeats the media descriptor `F8` |
| 1 | `0x4004` | `ff ff ff 0f` | `0x0FFFFFFF` | Reserved; two flag bits here record a clean dismount and no disk errors |
| 2 | `0x4008` | `ff ff ff 0f` | end of chain | Root directory occupies cluster 2 only |
| 3 | `0x400C` | `ff ff ff 0f` | end of chain | HELLO.TXT occupies cluster 3 only |
| 4 | `0x4010` | `ff ff ff 0f` | end of chain | WORLD.TXT occupies cluster 4 only |
| 5 | `0x4014` | `00 00 00 00` | 0 | Free |

The entry for cluster *N* is simply at `0x4000 + 4N`, which is why clusters 0 and 1 cannot hold data: their FAT slots are used for bookkeeping.

A FAT32 entry has only 28 usable bits. The top four are reserved, which is why the end-of-chain marker is `0x0FFFFFFF` rather than `0xFFFFFFFF`. Any value from `0x0FFFFFF8` up means "end of chain", `0x0FFFFFF7` marks a bad cluster, and 0 means free.

FAT 2 at `0x47000` contains exactly the same bytes.

### The root directory (cluster 2)

A directory is just a sequence of 32-byte entries stored in clusters, like a file whose contents happen to be entries. The root directory lives in cluster 2, at `0x8A000`:

```
0008a000  44 45 4d 4f 20 20 20 20  20 20 20 08 00 00 c0 4b  |DEMO       ....K|
0008a010  2f 5c 2f 5c 00 00 c0 4b  2f 5c 00 00 00 00 00 00  |/\/\...K/\......|
0008a020  48 45 4c 4c 4f 20 20 20  54 58 54 20 00 00 c0 4b  |HELLO   TXT ...K|
0008a030  2f 5c 2f 5c 00 00 c0 4b  2f 5c 03 00 0e 00 00 00  |/\/\...K/\......|
0008a040  57 4f 52 4c 44 20 20 20  54 58 54 20 00 00 c0 4b  |WORLD   TXT ...K|
0008a050  2f 5c 2f 5c 00 00 c0 4b  2f 5c 04 00 19 00 00 00  |/\/\...K/\......|
0008a060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

The first entry, `DEMO` with attribute `08`, is the volume label. The second is HELLO.TXT, decoded field by field:

| Offset in entry | Bytes | Value | Meaning |
|---|---|---|---|
| `0x00` | `48 45 4c 4c 4f 20 20 20` | `HELLO` | Name, padded to 8 characters with spaces |
| `0x08` | `54 58 54` | `TXT` | Extension, padded to 3 characters; the dot is not stored |
| `0x0B` | `20` | archive | Attribute bits: `01` read-only, `02` hidden, `04` system, `08` volume label, `10` directory, `20` archive |
| `0x0D` | `00` | | Creation time, hundredths of a second |
| `0x0E` | `c0 4b` | 09:30:00 | Creation time |
| `0x10` | `2f 5c` | 2026-01-15 | Creation date |
| `0x12` | `2f 5c` | 2026-01-15 | Last access date |
| `0x14` | `00 00` | 0 | First cluster, high 16 bits |
| `0x16` | `c0 4b` | 09:30:00 | Last modified time |
| `0x18` | `2f 5c` | 2026-01-15 | Last modified date |
| `0x1A` | `03 00` | 3 | First cluster, low 16 bits |
| `0x1C` | `0e 00 00 00` | 14 | File size in bytes |

The first cluster is split into two halves at `0x14` and `0x1A`. That's a leftover from FAT16, which had only a 16-bit field at `0x1A`; FAT32 added the high half in a previously unused slot.

Times and dates are packed into 16 bits each:

```
time 0x4BC0 = 01001 011110 00000    hours 9, minutes 30, seconds ÷ 2 = 0
date 0x5C2F = 0101110 0001 01111    years since 1980 = 46 (2026), month 1, day 15
```

Seconds are stored halved, which is why FAT timestamps only have two-second resolution.

WORLD.TXT's entry is the same shape: first cluster `04 00` (4) and size `19 00 00 00` (25 bytes). The entry at `0x8A060` starts with `00`, which means "end of directory"; a driver stops reading there. A deleted file's entry starts with `E5` instead.

Long file names are stored in extra entries (attribute `0F`) placed just before the short 8.3 entry. This example uses only 8.3 names to keep the entries readable.

### The data

The file contents sit in their clusters, padded with zeros to the end of the cluster:

```
cluster 3:
0008a200  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a 00 00  |Hello, world!...|
cluster 4:
0008a400  54 68 69 73 20 69 73 20  74 68 65 20 73 65 63 6f  |This is the seco|
0008a410  6e 64 20 66 69 6c 65 2e  0a 00 00 00 00 00 00 00  |nd file.........|
```

The padding is not part of the file. The size in the directory entry (14 bytes) tells the driver where the file really ends; the rest of the cluster is **slack space**.

### Reading HELLO.TXT, the way a driver does

1. Read the boot sector and compute where the FAT and data area are.
2. Read the root directory (cluster 2), scanning 32-byte entries for `HELLO   TXT`.
3. Take the first cluster (3) and size (14) from its entry.
4. Read cluster 3 at `0x8A200`.
5. Look up FAT entry 3 at `0x400C`: it is end-of-chain, so this was the last cluster.
6. Return the first 14 bytes.

## Stage 2: HELLO.TXT grows

Now we append twenty lines of text to HELLO.TXT, taking it from 14 bytes to 694. That no longer fits in one 512-byte cluster, so the driver needs a second one.

Cluster 4, directly after cluster 3, belongs to WORLD.TXT. The driver starts searching after the FSInfo hint (cluster 4), finds cluster 5 free, and takes it. HELLO.TXT is now **fragmented**: its chain is 3 → 5, with WORLD.TXT's cluster in between.

The script compares the two images sector by sector. Here is every byte that changed on the device, apart from the new text itself:

**FAT 1**, and the identical change in FAT 2 at `0x47000`:

```
  0x00004000  FAT1, entries 0-3
    before: f8 ff ff 0f ff ff ff 0f ff ff ff 0f ff ff ff 0f
    after:  f8 ff ff 0f ff ff ff 0f ff ff ff 0f 05 00 00 00
  0x00004010  FAT1, entries 4-7
    before: ff ff ff 0f 00 00 00 00 00 00 00 00 00 00 00 00
    after:  ff ff ff 0f ff ff ff 0f 00 00 00 00 00 00 00 00
```

Entry 3 changed from end-of-chain to `05 00 00 00`: "after cluster 3, go to cluster 5". Entry 5 changed from free to end-of-chain. Entry 4 is untouched; WORLD.TXT never knew anything happened.

**The HELLO.TXT directory entry**, second half:

```
  0x0008a030  cluster 2 (root directory)
    before: 2f 5c 2f 5c 00 00 c0 4b 2f 5c 03 00 0e 00 00 00
    after:  2f 5c 2f 5c 00 00 a5 4d 2f 5c 03 00 b6 02 00 00
```

The modified time went from `c0 4b` (09:30:00) to `a5 4d` (09:45:10), and the size from `0e 00 00 00` (14) to `b6 02 00 00` (694). The first cluster is still 3: growing a file never changes where it starts.

**FSInfo**, and its backup at `0xFE0`:

```
  0x000003e0  FSInfo sector
    before: 00 00 00 00 72 72 41 61 ad 0b 01 00 04 00 00 00
    after:  00 00 00 00 72 72 41 61 ac 0b 01 00 05 00 00 00
```

Free clusters dropped by one to 68,524 (`ac 0b 01 00`), and the hint moved to cluster 5.

**The data.** Cluster 3 now holds the first 512 bytes of the file, and cluster 5 holds the remaining 182:

```
cluster 3:
0008a200  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a 4c 69  |Hello, world!.Li|
0008a210  6e 65 20 30 31 3a 20 48  45 4c 4c 4f 2e 54 58 54  |ne 01: HELLO.TXT|
cluster 4:
0008a400  54 68 69 73 20 69 73 20  74 68 65 20 73 65 63 6f  |This is the seco|
cluster 5:
0008a600  70 73 20 67 72 6f 77 69  6e 67 2e 0a 4c 69 6e 65  |ps growing..Line|
0008a610  20 31 36 3a 20 48 45 4c  4c 4f 2e 54 58 54 20 6b  | 16: HELLO.TXT k|
```

The split falls mid-word (`kee` / `ps growing`). Clusters are raw storage; the file system has no idea where lines or words are.

### Why the order of writes matters

A driver can't write all of these bytes at once. If power fails partway through, the device holds whatever subset was written. A careful driver orders the writes so every intermediate state is at worst wasteful, never corrupt:

1. Mark cluster 5 as end-of-chain in the FAT, and write the new data into it. If power fails now, cluster 5 is allocated but nothing points to it: a **lost cluster**. `fsck` reclaims it and no file is harmed.
2. Link it in: FAT entry 3 = 5. If power fails now, the chain is two clusters long but the size still says 14 bytes. `fsck` reports that the chain is longer than the file and trims it.
3. Update the size in the directory entry.

Writing in the opposite order could leave a file whose chain runs into a free cluster that is later given to another file, which is real corruption.

## Stage 3: defragmenting

Fragmentation costs little on flash storage, but on a spinning disk every jump between non-adjacent clusters is a head seek. Some bootloaders also require their files to be contiguous, because they read a file as one run of sectors instead of following the FAT. Defragmenting rewrites the layout so each file's clusters are consecutive.

The goal here is the obvious layout: HELLO.TXT in clusters 3 and 4, WORLD.TXT in cluster 5. The difficulty is that cluster 4, which HELLO.TXT needs, is occupied by WORLD.TXT. You can't swap two clusters in place without a temporary location, so the defragmenter goes through a free cluster.

### Moving one cluster safely

Every move uses the same four steps, ordered so that a power failure at any point leaves a consistent file system:

1. **Copy** the data to a free destination cluster.
2. **Terminate or continue the chain at the destination**: copy the source's FAT entry into the destination's.
3. **Repoint** whatever referenced the source (either the directory entry, if it's the file's first cluster, or the previous cluster's FAT entry) to the destination.
4. **Free** the source cluster.

Until step 3, the old copy is still the live one and the new copy is just a lost cluster. After step 3, the new copy is live and the old one is lost until step 4 frees it. At no point does a file point at a free cluster or share a cluster with another file.

### The actual moves

This is the log the script prints while defragmenting:

```
# Cluster 4 is needed for HELLO.TXT but holds WORLD.TXT; move it out of the way to free cluster 6
    copy the data in cluster 4 to cluster 6 (WORLD.TXT, its cluster #1)
    FAT[6] = EOC (0x0FFFFFFF)
    WORLD.TXT directory entry: first cluster 4 -> 6
    FAT[4] = 0 (free; the old data stays in the cluster)
# Move HELLO.TXT cluster #2 from 5 to 4
    copy the data in cluster 5 to cluster 4 (HELLO.TXT, its cluster #2)
    FAT[4] = EOC (0x0FFFFFFF)
    FAT[3] = 4 (was 5)
    FAT[5] = 0 (free; the old data stays in the cluster)
# Move WORLD.TXT cluster #1 from 6 to 5
    copy the data in cluster 6 to cluster 5 (WORLD.TXT, its cluster #1)
    FAT[5] = EOC (0x0FFFFFFF)
    WORLD.TXT directory entry: first cluster 6 -> 5
    FAT[6] = 0 (free; the old data stays in the cluster)
```

Three moves, each with the four steps. Tracing the chains through it:

| After | HELLO.TXT | WORLD.TXT | Cluster 6 |
|---|---|---|---|
| Start (stage 2) | 3 → 5 | 4 | free |
| Move 1 | 3 → 5 | 6 | WORLD.TXT |
| Move 2 | 3 → 4 | 6 | WORLD.TXT |
| Move 3 | 3 → 4 | 5 | free |

The script applies these steps to its in-memory copy and then writes the final image, so it shows the logical order of the updates rather than individual disk writes. A real defragmenter hands each move to the file system driver (on Windows, through the `FSCTL_MOVE_FILE` control code), and the driver is responsible for issuing and flushing the writes in a safe order.

### The net change on the device

Comparing stage 2 with stage 3 shows a surprisingly small result for all that work:

```
  0x00004000  FAT1, entries 0-3
    before: f8 ff ff 0f ff ff ff 0f ff ff ff 0f 05 00 00 00
    after:  f8 ff ff 0f ff ff ff 0f ff ff ff 0f 04 00 00 00
  0x0008a050  cluster 2 (root directory)
    before: 2f 5c 2f 5c 00 00 c0 4b 2f 5c 04 00 19 00 00 00
    after:  2f 5c 2f 5c 00 00 c0 4b 2f 5c 05 00 19 00 00 00
```

FAT entry 3 now says "next is 4" instead of "next is 5", and WORLD.TXT's directory entry now says "starts at cluster 5" (`05 00` at `0x1A`) instead of 4. FAT 2 changed identically.

The FAT bytes for entries 4 and 5 are **identical** before and after:

```
00004010  ff ff ff 0f ff ff ff 0f  00 00 00 00 00 00 00 00  |................|
```

Both entries are end-of-chain in both images. But before, entry 4 ended WORLD.TXT and entry 5 ended HELLO.TXT; now it's the other way round. The FAT alone doesn't say which file owns a chain; that only becomes clear by starting from a directory entry and following the links. Comparing the before and after images also hides the intermediate writes, which is exactly where the crash-safety reasoning above matters.

HELLO.TXT's directory entry doesn't change at all: its first cluster is still 3, and neither its size nor its timestamps change, because moving clusters doesn't change the file's contents.

The data area shows the rest:

```
cluster 3:
0008a200  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a 4c 69  |Hello, world!.Li|
cluster 4:
0008a400  70 73 20 67 72 6f 77 69  6e 67 2e 0a 4c 69 6e 65  |ps growing..Line|
cluster 5:
0008a600  54 68 69 73 20 69 73 20  74 68 65 20 73 65 63 6f  |This is the seco|
cluster 6:
0008a800  54 68 69 73 20 69 73 20  74 68 65 20 73 65 63 6f  |This is the seco|
```

Cluster 6 is free again (FAT entry 6 is `00 00 00 00`), but it still holds a copy of WORLD.TXT from the temporary move. Freeing a cluster only changes its FAT entry; the data stays until something overwrites it. The same is true of deleted files, which is why undelete and forensic recovery tools work, and why deleting a file doesn't securely erase it.

### How real defragmenters decide the layout

This example uses the simplest possible policy: files in directory order, packed from cluster 3. Real tools make more choices:

- **Which files to place first.** Directories and frequently read files are often placed near the start of the volume.
- **Free-space consolidation.** Gathering the free clusters into one large run keeps future files from fragmenting as soon as they grow.
- **Leaving growth room.** A file that grows constantly, like a log, will fragment again immediately if it's packed tightly against its neighbour.
- **Using fewer moves.** Moving a small file out of the way can be cheaper than moving a large file into place. Real tools plan with the whole volume in mind rather than cluster by cluster.

Whatever the policy, every move comes down to the same bytes shown here: copy the data, update one FAT entry or directory entry to point at it, and set the old FAT entry to zero, applied to every FAT copy.

## What this example leaves out

- **Subdirectories.** A subdirectory is a cluster chain like any file, with attribute `10`, containing 32-byte entries. It begins with `.` (itself) and `..` (its parent) entries.
- **Long file names.** Extra entries with attribute `0F` hold the name in UTF-16 pieces, with a checksum linking them to the 8.3 entry.
- **Partition tables.** On a real disk the volume usually starts inside a partition, and every sector number above is offset by the partition's starting LBA. The boot sector's "hidden sectors" field records that offset.
- **Larger clusters.** With 4 KB clusters, everything works the same way; the only difference is that each FAT entry covers eight sectors, so the address arithmetic uses `(N − 2) × 8`.
- **TFAT.** Transaction-safe FAT, used by Windows CE, keeps the two FAT copies deliberately different during a write, and uses one as the committed state to recover from if power is lost.

## Files

- `fat32_demo.py` builds the three images and prints every dump shown here, plus the full byte diff between stages. It uses only the Python standard library.
- `fat32_1_two_files.img` is stage 1: HELLO.TXT in cluster 3, WORLD.TXT in cluster 4.
- `fat32_2_grown.img` is stage 2: HELLO.TXT grown and fragmented across clusters 3 and 5.
- `fat32_3_defragmented.img` is stage 3: HELLO.TXT in clusters 3-4, WORLD.TXT in cluster 5.

Useful commands for poking at the images:

```bash
xxd -s 0x8a000 -l 128 images/fat32_1_two_files.img    # root directory
xxd -s 0x4000 -l 32 images/fat32_2_grown.img           # first FAT entries
fsck.fat -nv images/fat32_2_grown.img                  # check it and show the geometry
mdir -i images/fat32_3_defragmented.img ::             # list files (mtools)
mtype -i images/fat32_3_defragmented.img ::HELLO.TXT   # read a file (mtools)
```
