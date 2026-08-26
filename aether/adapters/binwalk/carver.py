"""Fallback signature scanner and extractor for firmware images.

binwalk is the right tool for this job and the adapter prefers it whenever it
is installed. This exists because it frequently is not - binwalk's own
extraction stack (sasquatch, jefferson, ubi_reader) is awkward on Windows in
particular - and a firmware platform that can do nothing at all without it is
not much of a platform.

Scope is deliberately narrow. Formats the Python standard library can already
decode (gzip, bzip2, xz, zip, tar) are extracted; cpio is parsed here because
it is trivial and ubiquitous in initramfs images. Everything else - squashfs,
jffs2, ubifs - is *identified and located* but not unpacked, and the adapter
says so rather than pretending otherwise.

Nothing here reimplements a decompressor.
"""

from __future__ import annotations

import bz2
import io
import lzma
import os
import posixpath
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from typing import Callable, Iterator

from aether.adapters.triage.formats import CONTAINER_SIGNATURES

#: Signatures short enough to collide with random data. A hit is only reported
#: when the candidate also survives a format-specific sanity check.
_NEEDS_VALIDATION = {"gzip", "lzma_alone", "jffs2_le", "ext_sb", "zip", "tar", "bzip2"}

#: Guardrails against a malformed or hostile image.
MAX_EXTRACTED_FILES = 4000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_SINGLE_FILE = 128 * 1024 * 1024


@dataclass(frozen=True)
class SignatureHit:
    """A magic-signature match at an offset inside an image."""

    signature: str
    offset: int
    format: str
    description: str
    size: int | None = None

    def to_data(self) -> dict[str, object]:
        data: dict[str, object] = {
            "signature": self.signature,
            "file_offset": self.offset,
            "description": self.description,
            "extractor": "aether-carver",
        }
        if self.size:
            data["size"] = self.size
        return data


@dataclass(frozen=True)
class ExtractedEntry:
    """One file recovered from an image, already written to disk."""

    path: str
    disk_path: str
    size: int
    #: Offset in the parent image the containing blob started at.
    source_offset: int
    #: Signature of the container it came out of.
    via: str


def scan(data: bytes, *, limit: int = 4096) -> list[SignatureHit]:
    """Find container signatures anywhere in ``data``.

    One pass per signature. That is O(signatures x size) and perfectly adequate
    at the scale Phase 0 targets; if it ever matters, an Aho-Corasick automaton
    over the same table is a drop-in replacement.
    """
    hits: list[SignatureHit] = []
    for name, magic, fmt, description in CONTAINER_SIGNATURES:
        if not magic:
            continue
        start = 0
        while len(hits) < limit:
            offset = data.find(magic, start)
            if offset < 0:
                break
            start = offset + 1
            if name == "tar":
                offset -= 257  # ustar magic sits inside the tar header
                if offset < 0:
                    continue
            elif name == "ext_sb":
                offset -= 1080
                if offset < 0:
                    continue
            if name in _NEEDS_VALIDATION and not _validate(name, data, offset):
                continue
            hits.append(SignatureHit(name, offset, fmt, description))
    hits.sort(key=lambda h: (h.offset, h.signature))
    return hits


def _validate(name: str, data: bytes, offset: int) -> bool:
    """Cheap format-specific confirmation for collision-prone signatures."""
    window = data[offset : offset + 4096]
    try:
        if name == "gzip":
            zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(window, 1024)
            return True
        if name == "bzip2":
            if not (0x31 <= data[offset + 3] <= 0x39):  # compression level 1-9
                return False
            bz2.BZ2Decompressor().decompress(window, 1024)
            return True
        if name == "lzma_alone":
            lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(window, 1024)
            return True
        if name == "zip":
            return len(data) - offset >= 30
        if name == "tar":
            return _tar_checksum_ok(data[offset : offset + 512])
        if name == "jffs2_le":
            node_type = struct.unpack_from("<H", data, offset + 2)[0]
            return node_type in (0xE001, 0xE002, 0x2003, 0x2004)
        if name == "ext_sb":
            block_size = struct.unpack_from("<I", data, offset - 1080 + 24)[0]
            return 0 <= block_size <= 6
    except Exception:  # noqa: BLE001
        # Every decoder signals "not my format" with a different exception type,
        # and several are private. Any failure to parse means the candidate was
        # a coincidence, which is exactly the answer validation exists to give.
        return False
    return True


def _tar_checksum_ok(header: bytes) -> bool:
    """Verify a tar header's stored checksum, the only reliable tar signal."""
    if len(header) < 512:
        return False
    try:
        stored = int(header[148:156].split(b"\x00")[0].strip() or b"-1", 8)
    except ValueError:
        return False
    blanked = header[:148] + b" " * 8 + header[156:]
    return stored in (sum(blanked), sum(bytearray(blanked)))


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def safe_join(root: str, member: str) -> str | None:
    """Resolve an archive member path under ``root``, or None if it escapes.

    Archive members are attacker-controlled. ``../../etc/cron.d/x`` inside a
    firmware image must not become a write outside the extraction directory.
    """
    cleaned = member.replace("\\", "/").lstrip("/")
    normalized = posixpath.normpath(cleaned)
    if normalized.startswith("../") or normalized == ".." or ":" in normalized[:2]:
        return None
    destination = os.path.normpath(os.path.join(root, *normalized.split("/")))
    if os.path.commonpath([os.path.abspath(root), os.path.abspath(destination)]) != os.path.abspath(
        root
    ):
        return None
    return destination


def _write(root: str, member: str, payload: bytes, budget: "Budget") -> str | None:
    destination = safe_join(root, member)
    if destination is None or not budget.allow(len(payload)):
        return None
    os.makedirs(os.path.dirname(destination) or root, exist_ok=True)
    with open(destination, "wb") as handle:
        handle.write(payload)
    return destination


class Budget:
    """Bounds on how much one extraction is permitted to produce."""

    def __init__(
        self,
        max_files: int = MAX_EXTRACTED_FILES,
        max_bytes: int = MAX_EXTRACTED_BYTES,
    ) -> None:
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.files = 0
        self.written = 0
        self.refused = 0

    def allow(self, size: int) -> bool:
        if size > MAX_SINGLE_FILE or self.files >= self.max_files:
            self.refused += 1
            return False
        if self.written + size > self.max_bytes:
            self.refused += 1
            return False
        self.files += 1
        self.written += size
        return True


def extract(
    data: bytes, hits: list[SignatureHit], out_dir: str, *, budget: Budget | None = None
) -> tuple[list[ExtractedEntry], list[str]]:
    """Extract what can be extracted; report what could not.

    Returns ``(entries, notes)``. ``notes`` records formats that were located
    but left packed, so a caller can tell the user precisely which tool would
    unlock the rest of the image.
    """
    budget = budget or Budget()
    entries: list[ExtractedEntry] = []
    notes: list[str] = []
    consumed: list[tuple[int, int]] = []

    handlers: dict[str, Callable[..., list[ExtractedEntry]]] = {
        "gzip": _extract_gzip,
        "bzip2": _extract_bzip2,
        "xz": _extract_xz,
        "zip": _extract_zip,
        "tar": _extract_tar,
        "cpio_newc": _extract_cpio,
        "cpio_crc": _extract_cpio,
        "cpio_odc": _extract_cpio,
    }

    for hit in hits:
        if any(start <= hit.offset < end for start, end in consumed):
            continue  # already inside something we unpacked
        handler = handlers.get(hit.signature)
        if handler is None:
            if hit.format in ("filesystem", "compressed", "archive"):
                notes.append(
                    f"{hit.description} at offset 0x{hit.offset:x} was located but not "
                    f"unpacked; install binwalk (and its extractors) to recover it"
                )
            continue
        try:
            produced = handler(data, hit, out_dir, budget)
        except Exception as exc:  # noqa: BLE001 - a bad blob must not abort the run
            notes.append(
                f"{hit.description} at offset 0x{hit.offset:x} failed to extract: "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        if produced:
            entries.extend(produced)
            end = max((e.source_offset for e in produced), default=hit.offset)
            consumed.append((hit.offset, max(end + 1, hit.offset + 1)))

    return entries, notes


def _decompress_stream(data: bytes, hit: SignatureHit) -> bytes:
    if hit.signature == "gzip":
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(
            data[hit.offset :], MAX_SINGLE_FILE
        )
    if hit.signature == "bzip2":
        return bz2.BZ2Decompressor().decompress(data[hit.offset :], MAX_SINGLE_FILE)
    if hit.signature == "xz":
        return lzma.LZMADecompressor().decompress(data[hit.offset :], MAX_SINGLE_FILE)
    raise ValueError(f"no stream decompressor for {hit.signature}")


def _extract_compressed(
    data: bytes, hit: SignatureHit, out_dir: str, budget: Budget, suffix: str
) -> list[ExtractedEntry]:
    """Decompress a stream and write it out under a synthetic name.

    The decompressed blob is written whole. Whether it is itself an archive is
    the caller's problem: the adapter re-scans every extracted file, so a
    gzip-wrapped cpio unpacks on the next pass.
    """
    payload = _decompress_stream(data, hit)
    if not payload:
        return []
    member = f"{hit.offset:08x}.{suffix}"
    destination = _write(out_dir, member, payload, budget)
    if destination is None:
        return []
    return [
        ExtractedEntry(
            path=member,
            disk_path=destination,
            size=len(payload),
            source_offset=hit.offset,
            via=hit.signature,
        )
    ]


def _extract_gzip(data, hit, out_dir, budget):  # type: ignore[no-untyped-def]
    return _extract_compressed(data, hit, out_dir, budget, "gunzipped")


def _extract_bzip2(data, hit, out_dir, budget):  # type: ignore[no-untyped-def]
    return _extract_compressed(data, hit, out_dir, budget, "bunzipped")


def _extract_xz(data, hit, out_dir, budget):  # type: ignore[no-untyped-def]
    return _extract_compressed(data, hit, out_dir, budget, "unxzed")


def _extract_zip(
    data: bytes, hit: SignatureHit, out_dir: str, budget: Budget
) -> list[ExtractedEntry]:
    entries: list[ExtractedEntry] = []
    with zipfile.ZipFile(io.BytesIO(data[hit.offset :])) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > MAX_SINGLE_FILE:
                continue
            payload = archive.read(info)
            destination = _write(out_dir, info.filename, payload, budget)
            if destination is None:
                continue
            entries.append(
                ExtractedEntry(
                    path=info.filename,
                    disk_path=destination,
                    size=len(payload),
                    source_offset=hit.offset,
                    via="zip",
                )
            )
    return entries


def _extract_tar(
    data: bytes, hit: SignatureHit, out_dir: str, budget: Budget
) -> list[ExtractedEntry]:
    entries: list[ExtractedEntry] = []
    with tarfile.open(fileobj=io.BytesIO(data[hit.offset :]), mode="r:") as archive:
        for member in archive:
            if not member.isfile() or member.size > MAX_SINGLE_FILE:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            payload = handle.read()
            destination = _write(out_dir, member.name, payload, budget)
            if destination is None:
                continue
            entries.append(
                ExtractedEntry(
                    path=member.name,
                    disk_path=destination,
                    size=len(payload),
                    source_offset=hit.offset,
                    via="tar",
                )
            )
    return entries


def _extract_cpio(
    data: bytes, hit: SignatureHit, out_dir: str, budget: Budget
) -> list[ExtractedEntry]:
    """Parse an ASCII cpio archive (the newc/crc/odc family).

    Ubiquitous in initramfs images and simple enough that shelling out to an
    external tool would be the more fragile choice.
    """
    entries: list[ExtractedEntry] = []
    for member, payload, offset in _iter_cpio(data, hit.offset):
        if member == "TRAILER!!!":
            break
        if not payload and member.endswith("/"):
            continue
        destination = _write(out_dir, member, payload, budget)
        if destination is None:
            continue
        entries.append(
            ExtractedEntry(
                path=member,
                disk_path=destination,
                size=len(payload),
                source_offset=offset,
                via="cpio",
            )
        )
    return entries


def _iter_cpio(data: bytes, start: int) -> Iterator[tuple[str, bytes, int]]:
    position = start
    is_odc = data[start : start + 6] == b"070707"
    while position + 110 <= len(data):
        magic = data[position : position + 6]
        if magic not in (b"070701", b"070702", b"070707"):
            return
        if is_odc:
            # Portable format: 76-byte header, octal fields.
            header = data[position : position + 76]
            try:
                name_size = int(header[59:65], 8)
                file_size = int(header[65:76], 8)
            except ValueError:
                return
            name_start = position + 76
            name = data[name_start : name_start + name_size].split(b"\x00")[0]
            data_start = name_start + name_size
            next_position = data_start + file_size
        else:
            header = data[position : position + 110]
            try:
                file_size = int(header[54:62], 16)
                name_size = int(header[94:102], 16)
            except ValueError:
                return
            name_start = position + 110
            name = data[name_start : name_start + name_size].split(b"\x00")[0]
            data_start = _round4(name_start + name_size)
            next_position = _round4(data_start + file_size)

        if file_size > MAX_SINGLE_FILE or data_start + file_size > len(data):
            return
        yield (
            name.decode("utf-8", "replace"),
            data[data_start : data_start + file_size],
            position,
        )
        if next_position <= position:
            return
        position = next_position


def _round4(value: int) -> int:
    return (value + 3) & ~3
