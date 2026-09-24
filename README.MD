# wince_boot_diag.py

Boot diagnostics and repair for Windows CE Compact Flash images.

`wince_boot_diag.py` analyses a raw, sector-for-sector image (`dd`-style `.img`) of an x86 Windows CE CF card and reports the most common reasons such a card fails to boot: a damaged MBR or VBR, missing boot code, an unclean or inconsistent FAT, broken cluster chains, a missing or truncated kernel image, and bad `NK.BIN` record checksums. With `--repair` it can fix many of these problems in a copy of the image.

**The input image is never modified.** Diagnostics open it read-only, and repairs are always written to a separate output file, together with a log of every change.

## Requirements

- Python 3.7 or newer
- Standard library only; no third-party packages

Colour output is used when writing to a terminal and disabled automatically when output is piped or redirected (or with `--no-colour`).

## Quick start

```bash
# Diagnose
python3 wince_boot_diag.py cf_card.img

# See what would be repaired, without writing anything
python3 wince_boot_diag.py cf_card.img --repair --dry-run

# Repair into cf_card.repaired.img, replacing the kernel with a known-good copy
python3 wince_boot_diag.py cf_card.img --repair --replace-nk /path/to/good/NK.BIN
```

After a repair, write the repaired image back to a card (preferably a new one; see below) with `dd` or an equivalent imaging tool.

### Creating an image

On Linux, with the CF card in a reader at `/dev/sdX`:

```bash
sudo dd if=/dev/sdX of=cf_card.img bs=512 conv=noerror,sync status=progress
```

`conv=noerror,sync` keeps going past unreadable sectors and pads them with zeros, which the tool will then report as blank regions. On Windows, Win32 Disk Imager or HDD Raw Copy produce equivalent raw images.

Always keep the original image unchanged as your baseline. If the card produced read errors while imaging, it is failing: write the repaired image to a new card rather than back to the old one.

## Options

| Option | Description |
|---|---|
| `image` | Path to the raw CF image (required) |
| `-v`, `--verbose` | List every NK.BIN checksum failure rather than the first three |
| `--entropy-scan` | Add the critical-sector entropy report (section 8) |
| `--no-colour` | Disable coloured output |
| `--fat-source {1,2}` | Treat this FAT copy as authoritative instead of choosing automatically |

Repair options (all require `--repair`):

| Option | Description |
|---|---|
| `--repair` | Plan repairs and apply them to a copy of the image |
| `-o`, `--output PATH` | Repaired image path (default: `<image>.repaired.img`) |
| `--dry-run` | Show the repair plan and exit without writing anything |
| `-y`, `--yes` | Apply without asking for confirmation (required when not run interactively) |
| `--overwrite` | Allow replacing an existing output file |
| `--fix-illegal-fat` | Terminate FAT chains at illegal entries |
| `--free-lost-clusters` | Mark orphaned clusters free |
| `--replace-nk FILE` | Write a known-good kernel image into the filesystem |
| `--nk-name NAME` | File name to create if the image has no kernel file (default `NK.BIN`) |
| `--mbr-code-from IMG` | Copy MBR boot code from a known-good reference image |
| `--vbr-code-from IMG` | Copy VBR boot code from a known-good reference image |
| `--force` | Write a `--replace-nk` file even if it fails its own validation |

## What it checks

The checks run in order, and later stages depend on earlier ones (no valid boot sector means no FAT or kernel checks).

**1. MBR and partition table.** Verifies the `0xAA55` signature and checks that the boot code area is populated rather than all zeros or all `0xFF`. It lists the primary partitions, flags partitions that extend past the end of the image, and confirms exactly one partition is active. Images with no partition table, where sector 0 is itself a FAT boot sector ("superfloppy" layout), are recognised and handled.

**2. VBR / FAT BPB.** Decodes and sanity-checks the boot sector of the active partition: geometry, FAT type (FAT12, FAT16 or FAT32, determined by cluster count), jump instruction, media byte, and whether the boot code area is populated. If a FAT32 boot sector is damaged but its backup copy (partition sector 6) is valid, analysis continues from the backup.

**3. FAT health.** Checks the clean-shutdown and hard-error bits (FAT16 and FAT32), compares all FAT copies sector by sector, verifies the media byte in FAT entry 0, and scans every entry for illegal next-cluster values.

**4. Root directory and boot files.** Lists the root directory, reports bootloader files (`BLDR`, `EBOOT.BIN` and similar), and locates the kernel image (`NK.BIN`, `NK.NB0`, `IMGFLASH.BIN`, `IMGFLASH.NB0` or `NKNOCOMP.BIN`) in the root or one subdirectory level.

**5. Cluster chains and allocation.** Chooses the FAT copy to trust (see below) and walks the whole directory tree to find lost clusters (allocated but belonging to no file) and cross-linked clusters (shared by two files). It checks the FAT32 root directory chain and the kernel's chain for loops, breaks, truncation and fragmentation, and flags kernel clusters that are entirely `0xFF` or beyond the end of the image. On FAT32 it verifies the FSInfo free-cluster count.

**6. Kernel image structure.** For BIN-format images (starting with the `B000FF` sync bytes) it decodes the header and walks every record, verifying each record's checksum (the 32-bit sum of its data bytes). It also reports truncated or blank records, records outside the declared address range, and the entry point. Blank, erased, NB0 and unrecognised formats are reported separately.

**7. Bootloader detection.** A heuristic scan of the boot sectors for common loader strings, and a check that a bootloader file exists in the root directory.

**8. Entropy scan** (`--entropy-scan` only). Shannon entropy and `0x00`/`0xFF` counts for the MBR, the first sectors of the partition and sectors 0 to 31.

### Which FAT copy is trusted

When the FAT copies differ, each copy is scored on internal consistency: illegal entries count against it, while an intact FAT32 root chain and a kernel chain matching its file size count in its favour. The best-scoring copy is used for analysis and for any repair, and the first copy wins a tie. On a TFAT volume the first FAT is normally the last committed state. If you know better, set `--fat-source` explicitly.

## Repairs

`--repair` builds a plan from the diagnosis, prints it, asks for confirmation, copies the image, applies the repairs to the copy, and then re-runs the full diagnosis on the repaired image. The plan has three parts: repairs to apply, requested repairs that cannot be performed (for example, a missing reference file), and detected problems that no repair addresses. If any requested repair cannot be performed, nothing is written.

### Applied automatically when the fault is found

| Repair | Condition and safeguard |
|---|---|
| Restore MBR `0xAA55` signature | Only if a valid FAT volume is found where the partition table points |
| Make the boot partition the only active one | When no partition, or more than one, is active |
| Restore FAT32 boot sectors from backup | When the primary is invalid and the backup at sector 6 is valid; a valid primary FSInfo sector is kept |
| Synchronise FAT copies | Copies the trusted FAT (see above) over the others |
| Set the clean-shutdown bit | When the trusted FAT shows an unclean dismount |
| Update FAT32 FSInfo free count | When it is wrong, or after any FAT change |

### Applied only on request

**`--replace-nk FILE`** writes a known-good kernel image into the filesystem. It is the only way to fix a kernel image with checksum failures, truncation or blank data, because the file has no redundancy to rebuild it from. A BIN-format replacement is validated first, and one that fails its own checksum validation is refused unless `--force` is given. The old file's clusters are freed and the new file is written into a contiguous run of clusters where possible, then its directory entry is updated. If the image has no kernel file at all, a new root directory entry is created (named `NK.BIN` unless `--nk-name` says otherwise). Use a file built for exactly this hardware and OS image.

**`--fix-illegal-fat`** replaces illegal FAT entries with end-of-chain markers. This stops the filesystem following corrupt pointers, but the affected file is truncated at that point, and the clusters after the break become lost clusters. It is usually combined with `--free-lost-clusters` and, if the kernel was affected, `--replace-nk`.

**`--free-lost-clusters`** marks orphaned clusters free to reclaim the space. Any data in them is discarded.

**`--mbr-code-from IMG`** copies bytes 0 to 439 of a reference image's MBR, keeping this image's disk signature and partition table. **`--vbr-code-from IMG`** copies the jump instruction and the boot code area of the reference image's boot sector, keeping this volume's BPB. For FAT32 it also updates the backup boot sector. The reference must have the same FAT type. Take reference images from a known-good card for the same hardware, since boot code is specific to the loader in use.

### Output

Next to the repaired image, a log file (`<output>.repair.log`) records the SHA-256 of the input and output images, each action applied, and every region written.

## Exit status

| Code | Meaning |
|---|---|
| 0 | No errors found (after repair: none remain) |
| 1 | Usage error, missing file, cancelled or blocked repair, or a repair that failed partway |
| 2 | Errors found (after repair: errors remain) |

If a repair fails partway, the output image is incomplete and should be deleted; the input image is unaffected.

## Limitations

- Sector size must be 512 bytes.
- Only the four primary MBR partitions are read, and only one volume (the active partition, or the first FAT partition) is analysed and repaired.
- Long file names are not decoded; files are matched on their 8.3 short names.
- The kernel image is searched for in the root and one subdirectory level; `--replace-nk` creates new entries in the root directory only.
- NB0 and compressed kernel images are located and chain-checked but not structurally validated.
- Cross-linked clusters are detected but not repaired. Freeing an old kernel chain assumes it is not cross-linked with another file.
- Boot code is copied from the first sector of the VBR only. FAT32 loaders that place code in additional reserved sectors are not handled.
- Bootloader string detection is heuristic.
- The tool repairs structure, not content: files other than the kernel image cannot be rebuilt, and repairs cannot compensate for a card that is physically failing.
