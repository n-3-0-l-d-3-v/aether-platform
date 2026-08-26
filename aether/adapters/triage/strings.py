"""String extraction from raw bytes.

Deliberately boring: runs of printable bytes, in ASCII and UTF-16LE. Ghidra
produces better-located strings once it has run (it knows which are referenced
from code and which section they live in), and its results converge onto the
same artifact ids when the address matches. This exists so that inventory and
firmware triage work before - or without - a full disassembly pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

#: Below this, hits are mostly noise; above it, real messages get missed.
DEFAULT_MIN_LENGTH = 6

#: Cap on how much of one file gets scanned, so a multi-gigabyte image cannot
#: stall an interactive command. Callers that want everything raise it.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ExtractedString:
    """One string literal and where in the file it was found."""

    text: str
    file_offset: int
    encoding: str

    def to_data(self) -> dict[str, object]:
        return {
            "text": self.text,
            "encoding": self.encoding,
            "file_offset": self.file_offset,
            "length": len(self.text),
        }


def _is_printable(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E or byte == 0x09


def iter_strings(
    data: bytes,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = 4096,
) -> Iterator[ExtractedString]:
    """Yield ASCII and UTF-16LE strings in ascending file offset order."""
    found = list(_iter_ascii(data, min_length, max_length))
    found.extend(_iter_utf16le(data, min_length, max_length))
    found.sort(key=lambda s: (s.file_offset, s.encoding))
    yield from found


def _iter_ascii(data: bytes, min_length: int, max_length: int) -> Iterator[ExtractedString]:
    start = -1
    for index, byte in enumerate(data):
        if _is_printable(byte):
            if start < 0:
                start = index
            elif index - start >= max_length:
                yield ExtractedString(
                    data[start:index].decode("ascii", "replace"), start, "ascii"
                )
                start = index
        else:
            if start >= 0 and index - start >= min_length:
                yield ExtractedString(
                    data[start:index].decode("ascii", "replace"), start, "ascii"
                )
            start = -1
    if start >= 0 and len(data) - start >= min_length:
        yield ExtractedString(data[start:].decode("ascii", "replace"), start, "ascii")


def _iter_utf16le(data: bytes, min_length: int, max_length: int) -> Iterator[ExtractedString]:
    """Find UTF-16LE runs: printable byte followed by a zero byte, repeated.

    Windows binaries keep most of their interesting text this way, so skipping
    it would blind triage on exactly the PE targets it is meant to inventory.
    """
    index = 0
    limit = len(data) - 1
    while index < limit:
        if _is_printable(data[index]) and data[index + 1] == 0:
            start = index
            characters: list[int] = []
            while (
                index < limit
                and _is_printable(data[index])
                and data[index + 1] == 0
                and len(characters) < max_length
            ):
                characters.append(data[index])
                index += 2
            if len(characters) >= min_length:
                yield ExtractedString(
                    bytes(characters).decode("ascii", "replace"), start, "utf16le"
                )
        else:
            index += 1


def extract_from_file(
    path: str,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> list[ExtractedString]:
    """Read a file (up to ``max_bytes``) and extract its strings."""
    with open(path, "rb") as handle:
        data = handle.read(max_bytes)
    return list(iter_strings(data, min_length=min_length))
