"""Small shared helpers: time, paths, and text sanitation.

Nothing here is clever. It exists so that timestamps and logical paths are
formatted identically everywhere, because both end up inside content hashes or
Git-tracked exports and inconsistency there is expensive to unwind later.
"""

from __future__ import annotations

import os
import posixpath
import unicodedata
from datetime import datetime, timezone

#: Characters that must never reach a JSON export un-escaped or a terminal
#: un-sanitized. Extracted strings routinely contain them.
_CONTROL = {c for c in range(0x20)} | {0x7F}


def utc_now() -> str:
    """Current UTC time as a stable ISO-8601 string ending in Z."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def logical_path(path: str, *, root: str | None = None) -> str:
    """Normalize a filesystem path into the project's logical path form.

    Always forward slashes, no drive letters, no leading separator, relative to
    ``root`` when the path is underneath it. Firmware paths and host paths then
    look the same in the graph, and a project exported on Windows diffs cleanly
    against one exported on Linux.
    """
    candidate = os.fspath(path)
    if root:
        try:
            candidate = os.path.relpath(os.path.abspath(candidate), os.path.abspath(root))
        except ValueError:
            # Different drives on Windows; fall back to the basename.
            candidate = os.path.basename(candidate)
    candidate = candidate.replace(os.sep, "/").replace("\\", "/")
    drive, rest = posixpath.splitdrive(candidate) if ":" in candidate[:2] else ("", candidate)
    rest = rest.lstrip("/")
    normalized = posixpath.normpath(rest) if rest else ""
    if normalized in (".", ""):
        normalized = posixpath.basename(candidate.rstrip("/")) or "unnamed"
    return normalized.lstrip("/")


def sanitize_text(value: str, *, limit: int | None = None) -> str:
    """Strip control characters and optionally truncate.

    Strings recovered from binaries are attacker-controlled. Anything that
    reaches a terminal, a JSON export, or an MCP response goes through here so
    a crafted string cannot inject escape sequences into a reviewer's console.
    """
    cleaned = "".join(
        ch for ch in value if ord(ch) not in _CONTROL or ch in ("\t", "\n")
    )
    cleaned = unicodedata.normalize("NFC", cleaned)
    if limit is not None and len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned


def redact(value: str, *, keep: int = 4, limit: int = 32) -> str:
    """Mask a secret-shaped string for display.

    Keeps a short prefix so a reviewer can correlate it with the raw evidence,
    and drops the rest. Claims carry this, never the full literal.
    """
    cleaned = sanitize_text(value, limit=limit)
    if len(cleaned) <= keep:
        return "*" * len(cleaned)
    return cleaned[:keep] + "*" * min(len(cleaned) - keep, limit - keep)


def human_size(num_bytes: int) -> str:
    """Format a byte count for CLI display."""
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024.0 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TiB"


def hex_addr(addr: int | None) -> str:
    """Render an address the way a reverse engineer expects to read it."""
    return "-" if addr is None else f"0x{addr:x}"
