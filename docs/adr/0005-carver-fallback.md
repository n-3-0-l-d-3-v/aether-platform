# ADR 0005: A bounded extraction fallback when binwalk is absent

**Status:** accepted · **Date:** 2026-08-26

## Context

The specification says to reuse binwalk for unpacking and forbids rebuilding
analysis engines. It also sets a Phase 0 gate: "can unpack simple firmware
images with binwalk and inventory binaries."

binwalk is frequently not installed, and its extraction stack (sasquatch,
jefferson, ubi_reader) is particularly awkward on Windows. The development
machine for Phase 0 had neither binwalk nor Java, so a strict reading would have
left the firmware half of the gate undemonstrable.

## Decision

Prefer binwalk whenever it is on PATH. When it is not, fall back to a built-in
carver scoped to what the Python standard library already decodes — gzip, bzip2,
xz, zip, tar — plus cpio, which is a fixed-width ASCII header format and
ubiquitous in initramfs images.

Everything else is **identified and located but explicitly not unpacked**. A
squashfs image produces a `signature_hit` artifact recording its offset, and the
run reports:

> SquashFS filesystem, little endian at offset 0x4000 was located but not
> unpacked; install binwalk (and its extractors) to recover it

## Why this is not "rebuilding an engine"

Nothing here implements a decompressor or a filesystem driver. `zlib`, `bz2`,
`lzma`, `zipfile`, and `tarfile` are stdlib; the carver locates streams and
hands them over. cpio parsing is roughly forty lines of fixed-offset field
reading, and shelling out to an external tool for it would be the more fragile
choice, not the more principled one.

The line held: no squashfs implementation, no jffs2 implementation, no LZMA
variant hand-rolled to match some vendor's fork.

## Being honest about the gap

The failure mode this decision must avoid is a user believing an image was fully
unpacked when it was not. Three things prevent that:

- Unpackable-but-not-unpacked formats produce a warning naming the format, the
  offset, and the remedy.
- `aether doctor` states plainly that without binwalk only the stdlib formats
  are extracted.
- The adapter records which engine ran in provenance, so any inventory can be
  traced to what produced it.

## Safety

Archive members are attacker-controlled. Extraction goes through `safe_join`,
which rejects `../` traversal, absolute paths, and drive-letter escapes; a
`Budget` caps file count and total bytes; and a member whose name normalizes
away to nothing is refused rather than being written over the extraction root.
Signature validation runs decoders against short windows to reject coincidental
magic bytes — a three-byte gzip signature otherwise hits constantly in random
data.

## Consequences

- Firmware analysis works out of the box, at reduced depth, and says so.
- Two extraction paths to maintain. The interface is narrow — both return
  `(hits, entries, notes)` — and the adapter above them is identical either way.
- Real vendor firmware is overwhelmingly squashfs. Without binwalk, Aether will
  inventory the header and stop. That is the honest outcome, and it is reported
  rather than hidden.
