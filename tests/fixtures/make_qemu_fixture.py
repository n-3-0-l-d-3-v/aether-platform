"""Generate the recorded QEMU traces used by the reachability tests.

QEMU user-mode is not installed on every machine and cannot emulate a hand-built
ELF that was never meant to execute, so the runner cannot be exercised here. The
*importer* can, and that is where the address arithmetic and the attribution
logic live.

Addresses come from the real ELF sample's symbol table, so the mapping from
trace addresses to functions is genuine. What is fabricated is only which
functions ran - the part QEMU alone could tell us.

Three logs are produced:

``firmware_agent.exec.log``
    ``-d exec`` format. main, handle_name, and run_diagnostics execute;
    weak_token does not, so tests can assert that an unreached function
    produces no claim.
``firmware_agent.in_asm.log``
    the same run in ``-d in_asm`` format, to prove both parsers work.
``firmware_agent.pie.log``
    the same run with every address shifted by a load base, as a
    position-independent binary would appear.

Usage:
    python tests/fixtures/make_qemu_fixture.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from aether.adapters.triage import formats  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLE = os.path.join(REPO_ROOT, "examples", "firmware_agent.elf")
OUT_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "qemu")

#: A plausible load base for a position-independent mapping.
PIE_BASE = 0x4000000000

#: Which functions ran, and how many blocks each entered. weak_token is absent
#: on purpose: an unreached function must produce no reachability claim.
EXECUTED = {
    "main": 6,
    "handle_name": 3,
    "run_diagnostics": 2,
}


def _exec_line(index: int, guest_pc: int) -> str:
    return (
        f"Trace {index}: 0x7f4e2c0{index:04x} "
        f"[00000000/{guest_pc:016x}/00000033/ff000000]"
    )


def build_exec(entries: list[tuple[str, int]], base: int = 0) -> str:
    lines = []
    index = 0
    for name, addr in entries:
        for _ in range(EXECUTED[name]):
            lines.append(_exec_line(index, addr + base))
            index += 1
    return "\n".join(lines) + "\n"


def build_in_asm(entries: list[tuple[str, int]], base: int = 0) -> str:
    lines = []
    for name, addr in entries:
        lines.append("----------------")
        lines.append(f"IN: {name}")
        for offset in range(0, 3 * 4, 4):
            lines.append(
                f"0x{addr + base + offset:016x}:  48 89 e5              "
                f"mov    %rsp,%rbp"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    if not os.path.isfile(SAMPLE):
        print(f"missing {SAMPLE}; run examples/src/build_elf_sample.py first")
        return 1

    identification = formats.identify_file(SAMPLE)
    exports = {entry["name"]: int(entry["addr"]) for entry in identification.exports}
    missing = sorted(set(EXECUTED) - set(exports))
    if missing:
        print(f"sample does not export {missing}; regenerate it")
        return 1

    entries = sorted(
        ((name, exports[name]) for name in EXECUTED), key=lambda pair: pair[1]
    )
    os.makedirs(OUT_DIR, exist_ok=True)

    written = {
        "firmware_agent.exec.log": build_exec(entries),
        "firmware_agent.in_asm.log": build_in_asm(entries),
        "firmware_agent.pie.log": build_exec(entries, base=PIE_BASE),
    }
    for name, body in written.items():
        path = os.path.join(OUT_DIR, name)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)
        print(f"wrote {path} ({len(body.splitlines())} lines)")

    print(f"executed: {', '.join(f'{n}@0x{a:x}' for n, a in entries)}")
    print(f"not executed: weak_token@0x{exports.get('weak_token', 0):x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
