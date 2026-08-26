"""Canonical serialization, hashing, and identifier minting.

Everything in Aether that needs an identity gets it from this module. Two
properties matter and are tested:

1. *Determinism*. Re-running the same analysis over the same bytes produces
   byte-identical records and therefore byte-identical IDs. This is what makes
   the exported graph diffable in Git: a re-analysis that discovered nothing
   new produces an empty diff.

2. *Content addressing*. An ID is a function of the thing's meaning, not of
   insertion order or wall-clock time. Two adapters that independently observe
   the same function at the same address mint the same artifact ID, so evidence
   converges instead of duplicating.

Volatile data (timestamps, absolute host paths, durations) is deliberately kept
out of every hashed payload and lives in the run ledger instead. See
docs/adr/0002-deterministic-ids.md.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

# Width of the hex digest carried in every ID. 16 bytes of BLAKE2b is 128 bits:
# far beyond collision risk for a per-project graph, and short enough to read.
_DIGEST_BYTES = 16

#: Confidence and other floats are rounded before hashing so that platform
#: float formatting differences can never change an ID.
FLOAT_PRECISION = 6

_ID_RE = re.compile(r"^[a-z]{3,4}_[0-9a-f]{32}$")


class CanonicalError(ValueError):
    """A value was not representable in canonical form."""


def _canonicalize(value: Any, *, path: str = "$") -> Any:
    """Recursively coerce ``value`` into canonical, hashable form.

    Rejects anything whose serialization is ambiguous or platform-dependent:
    NaN/Infinity, non-string mapping keys, sets (unordered), and arbitrary
    objects. Failing loudly here is the point - a silent coercion would break
    determinism in a way that is very hard to trace back later.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalError(f"non-finite float at {path}")
        rounded = round(value, FLOAT_PRECISION)
        # Collapse -0.0 and integral floats so 1.0 and 1 hash alike.
        if rounded == int(rounded):
            return int(rounded)
        return rounded
    if isinstance(value, str):
        # NFC normalization keeps visually identical strings from minting two
        # different IDs depending on where the bytes came from.
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key in value:
            if not isinstance(key, str):
                raise CanonicalError(f"non-string mapping key at {path}: {key!r}")
            out[unicodedata.normalize("NFC", key)] = _canonicalize(
                value[key], path=f"{path}.{key}"
            )
        return out
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v, path=f"{path}[{i}]") for i, v in enumerate(value)]
    raise CanonicalError(f"unhashable type {type(value).__name__} at {path}")


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text for ``value``.

    Sorted keys, no insignificant whitespace, and real UTF-8 rather than
    ASCII escape sequences, so exported strings stay readable in a diff.
    """
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON encoded as UTF-8 - the exact preimage that gets hashed."""
    return canonical_json(value).encode("utf-8")


def content_digest(value: Any) -> str:
    """Stable 32-char hex digest of any canonicalizable value."""
    return hashlib.blake2b(canonical_bytes(value), digest_size=_DIGEST_BYTES).hexdigest()


def mint_id(prefix: str, payload: Any) -> str:
    """Mint a content-addressed identifier such as ``art_9f2c...``.

    ``payload`` must contain exactly the fields that define the thing's
    identity - no more (or unrelated changes churn the ID) and no less (or
    distinct things collide).
    """
    if not re.fullmatch(r"[a-z]{3,4}", prefix):
        raise CanonicalError(f"invalid id prefix {prefix!r}")
    return f"{prefix}_{content_digest(payload)}"


def is_id(value: object, prefix: str | None = None) -> bool:
    """True if ``value`` looks like an Aether ID (optionally of ``prefix``)."""
    if not isinstance(value, str) or not _ID_RE.match(value):
        return False
    return prefix is None or value.startswith(f"{prefix}_")


def file_digests(path: str, *, chunk_size: int = 1 << 20) -> dict[str, Any]:
    """Hash a file on disk once, returning sha256, md5, and size.

    Both digests come out of a single pass; firmware images are large enough
    that a second read is worth avoiding.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "size": size}


def bytes_digests(data: bytes) -> dict[str, Any]:
    """In-memory equivalent of :func:`file_digests`."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
    }
