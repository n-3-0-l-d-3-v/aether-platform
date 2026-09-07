"""Parse QEMU user-mode execution logs into executed addresses.

QEMU's logging format is not a stable interface, so this handles the two shapes
that have been common across releases and picks whichever the log actually
contains:

``-d exec``
    ``Trace 0: 0x7f... [00000000/0000000000401136/00000033/ff000000]`` - one
    line per translated block entered, with the guest program counter as the
    second bracketed field.

``-d in_asm``
    ``IN: main`` followed by ``0x0000000000401136:  48 89 e5  mov %rsp,%rbp``
    - the disassembly of each block as it is translated.

Both are *block* granularity, not instruction granularity. A recorded address
means the block starting there was entered, which is what reachability needs
and all this claims.

Kept separate from the runner for the same reason the Ghidra importer is:
running QEMU needs QEMU, parsing its output needs nothing, and the parser is
where the bugs live.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

#: ``Trace 0: 0x<host> [<cs_base>/<guest_pc>/<flags>...]``
_EXEC_LINE = re.compile(
    r"^Trace\s+\d+:\s*0x[0-9a-fA-F]+\s*\[[^/\]]*/0*([0-9a-fA-F]+)/", re.MULTILINE
)

#: A disassembly line inside an ``IN:`` block.
_ASM_LINE = re.compile(r"^0x0*([0-9a-fA-F]+):\s", re.MULTILINE)

#: ``IN: symbol_name`` block headers, used to detect the in_asm format.
_IN_BLOCK = re.compile(r"^IN:\s*(\S*)\s*$", re.MULTILINE)

#: Refuse to hold more than this many distinct addresses from one trace. A
#: long-running target produces millions; reachability needs the set, not the
#: sequence, and a bounded set is enough to answer "was this reached".
MAX_DISTINCT_ADDRESSES = 200_000


@dataclass(frozen=True)
class TraceEvent:
    """One executed address and how often it was entered."""

    addr: int
    hit_count: int


@dataclass
class Trace:
    """The result of parsing one QEMU log."""

    events: list[TraceEvent]
    #: Which log format was recognised: "exec", "in_asm", or "none".
    format: str = "none"
    truncated: bool = False
    warnings: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.warnings is None:
            self.warnings = []

    @property
    def addresses(self) -> set[int]:
        return {event.addr for event in self.events}


def parse_trace(text: str, *, max_addresses: int = MAX_DISTINCT_ADDRESSES) -> Trace:
    """Parse a QEMU log, preferring block-entry records over disassembly.

    ``-d exec`` is preferred when both are present: it records every block
    *entry*, whereas ``in_asm`` records each block once when it is translated,
    so exec counts are real execution counts and in_asm counts are not.
    """
    if not text:
        return Trace(events=[], format="none", warnings=["the trace log was empty"])

    counts: Counter[int] = Counter()
    fmt = "none"
    warnings: list[str] = []

    exec_hits = _EXEC_LINE.findall(text)
    if exec_hits:
        fmt = "exec"
        for raw in exec_hits:
            counts[int(raw, 16)] += 1
    elif _IN_BLOCK.search(text):
        fmt = "in_asm"
        for raw in _ASM_LINE.findall(text):
            counts[int(raw, 16)] += 1
        warnings.append(
            "log is -d in_asm, which records each block once when translated; "
            "hit counts are translation counts, not execution counts"
        )
    else:
        return Trace(
            events=[],
            format="none",
            warnings=[
                "no QEMU trace records were recognised in the log; expected "
                "'-d exec' or '-d in_asm' output"
            ],
        )

    truncated = len(counts) > max_addresses
    if truncated:
        warnings.append(
            f"trace held {len(counts)} distinct addresses; kept the "
            f"{max_addresses} most frequently entered"
        )

    kept = counts.most_common(max_addresses) if truncated else counts.items()
    events = sorted(
        (TraceEvent(addr=addr, hit_count=count) for addr, count in kept),
        key=lambda event: event.addr,
    )
    return Trace(events=events, format=fmt, truncated=truncated, warnings=warnings)


def parse_trace_file(path: str, **kwargs: object) -> Trace:
    """Parse a QEMU log from disk."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_trace(handle.read(), **kwargs)  # type: ignore[arg-type]


def infer_load_base(
    addresses: set[int], function_starts: set[int], *, minimum_hits: int = 3
) -> int | None:
    """Guess the offset QEMU loaded a position-independent binary at.

    A PIE binary's static addresses do not match its runtime ones, so a trace
    would map onto nothing. This looks for the single delta that lines the most
    trace addresses up with known function entry points, and returns it only if
    the alignment is convincing.

    Returns ``None`` rather than guessing when the evidence is thin - an
    unaligned trace should produce no reachability claims, not wrong ones.
    """
    if not addresses or not function_starts:
        return None

    deltas: Counter[int] = Counter()
    for addr in list(addresses)[:2000]:
        for start in function_starts:
            delta = addr - start
            if delta >= 0:
                deltas[delta] += 1

    if not deltas:
        return None
    base, hits = deltas.most_common(1)[0]
    if hits < minimum_hits:
        return None
    # A zero delta means the binary was loaded where it was linked, which is
    # the normal non-PIE case and needs no adjustment.
    return base


__all__ = [
    "MAX_DISTINCT_ADDRESSES",
    "Trace",
    "TraceEvent",
    "infer_load_base",
    "parse_trace",
    "parse_trace_file",
]
