# wince_boot_diag.py

Boot diagnostics for Windows CE Compact Flash images.

`wince_boot_diag.py` analyses a raw, sector-for-sector image (`dd`-style `.img`) of an x86 Windows CE CF card and reports the most common reasons such a card fails to boot: a damaged MBR or VBR, an unclean or inconsistent FAT, a missing or truncated kernel image, bad `NK.BIN` record checksums, and blank or erased sectors in critical regions.

It is read-only. The image file is opened in binary read mode and is never modified, so it is safe to run against the only copy of a field image (though working from a copy is still good practice).

## Requirements

- Python 3.7 or newer
- Standard library only; no third-party packages

Colour output uses ANSI escape codes. On Windows the script attempts to enable virtual-terminal processing automatically; if that fails the output still works, just with visible escape sequences.

## Usage

```bash
python3 wince_boot_diag.py <image.img> [--entropy-scan] [--verbose]
```

| Argument | Description |
|---|---|
| `image` | Path to the raw CF image file (required) |
| `--entropy-scan` | Adds the critical-sector entropy report (section 7) |
| `-v`, `--verbose` | Accepted but not currently used by any check |

### Creating an image

On Linux, with the CF card in a reader at `/dev/sdX`:

```bash
sudo dd if=/dev/sdX of=cf_card.img bs=512 conv=noerror,sync status=progress
```

`conv=noerror,sync` keeps going past unreadable sectors and pads them with zeros, which the tool will then report as blank regions. On Windows, tools such as Win32 Disk Imager or HDD Raw Copy produce equivalent raw images.

## What it checks

The checks run in order, and each later stage depends on the earlier ones succeeding (for example, no BPB means no FAT or `NK.BIN` checks).

**1. MBR and partition table.** Verifies the `0xAA55` boot signature, checks whether the 446-byte bootstrap area is populated, all zeros (no MBR loader) or all `0xFF` (erased card), lists the four primary partition entries, flags non-standard status bytes, and confirms a partition is marked active (`0x80`).

**2. VBR / FAT BPB.** Reads the volume boot record of the active partition (or the first partition if none is active), checks its signature, and decodes the BIOS Parameter Block: OEM name, sector and cluster size, reserved sectors, FAT count and size, volume label, and media descriptor. FAT12, FAT16 and FAT32 are distinguished by FAT size and cluster count.

**3. FAT health.** Checks the clean-shutdown bit in FAT entry 1 (FAT16 and FAT32), compares FAT1 and FAT2 byte-for-byte to catch incomplete or inconsistent TFAT writes, and scans chain entries for the illegal next-cluster value `1`.

**4. Root directory and kernel image location.** Lists the root directory and searches it, then one level of subdirectories, for a kernel image named `NK.BIN`, `NK.NB0`, `IMGFLASH.BIN`, `IMGFLASH.NB0` or `NKNOCOMP.BIN`. Once found, it compares the file's FAT chain length with its directory size (truncated or over-long chains) and checks the first 64 clusters for blank sectors.

**5. NK.BIN structure.** Checks for the `B000FF\n` BIN-format sync bytes. If present, the file is reassembled from its cluster chain (up to 4096 clusters), the image start address and length are decoded, and each record is walked and checksummed, reporting truncated records, checksum mismatches, all-`0x00`/`0xFF` records and the entry point. Files that start with zeros or `0xFF` are reported as unwritten; files with no recognised signature are reported as possibly NB0, compressed or an OEM format, with their first 16 bytes shown.

**6. EBOOT / bootloader detection.** Scans the first four sectors of the image and the first 64 sectors of the first partition for common loader strings (`EBOOT`, `WinCE`, `Windows CE`, `CEBOOT`, `BOOTLDR`, `BLDR`, `Loading`, `Booting`), and checks whether the VBR bootstrap code is populated.

**7. Critical-sector entropy scan** (`--entropy-scan` only). Prints Shannon entropy and counts of `0x00` and `0xFF` bytes for the MBR, the first three sectors of the partition, and sectors 0 to 31. Entropy below 0.5 is flagged as blank or suspicious; above 7.5 as high entropy (likely compressed data).

## Reading the output

Each finding is printed with a status tag:

| Tag | Meaning |
|---|---|
| `[OK]` | Check passed |
| `[INFO]` | Informational detail (addresses, sizes, listings) |
| `[WARN]` | Potential problem; may cause intermittent or conditional boot failure |
| `[FAIL]` | Likely boot-blocking problem |

A summary at the end counts errors and warnings and lists every finding with a marker: `✗` for errors, `△` for warnings, `·` for OK results. The findings appear in the order the checks ran, so the earliest failure in the list is usually the best place to start.

### Common results and what they usually mean

| Finding | Typical cause |
|---|---|
| MBR bootstrap all `0xFF` | Card erased or failed; nothing to boot |
| No partition marked bootable | BIOS finds no active partition |
| FAT1 and FAT2 differ, or clean-shutdown bit not set | Power lost during a write; TFAT transaction not completed |
| `NK.BIN` not found | Kernel image deleted, renamed, or stored where the loader expects it but this tool does not look |
| `NK.BIN` chain truncated or blank sectors | Incomplete copy, or CF wear / read failures |
| `NK.BIN` record checksum mismatch | Corrupted kernel data; the loader will normally refuse the image |

## Limitations

- Only the four primary MBR partitions are read; extended and logical partitions are listed but not followed.
- Only one partition is analysed: the active one, or the first if none is active.
- Cluster-chain reading assumes 16-bit or 32-bit FAT entries, so chain-based checks on FAT12 volumes are not reliable.
- Long file names are skipped; the kernel is matched on its 8.3 short name only, so `NK.BIN.GZ` in the name list will never match.
- Only one subdirectory level is searched for the kernel image.
- `NK.NB0` and compressed images are located and chain-checked but not structurally validated.
- `NK.BIN` analysis reads at most 4096 clusters and 4096 records.
- Bootloader detection is string matching on a limited sector range; a custom or stripped loader may not be detected, and a filesystem-based `EBOOT.BIN` is not searched for automatically (check the root directory listing in section 4).
- Sector size is assumed to be 512 bytes throughout.

## Exit status

The script exits with status 1 if the image file does not exist. Otherwise it exits with status 0 regardless of what it finds, so check the summary rather than the exit code when scripting.
