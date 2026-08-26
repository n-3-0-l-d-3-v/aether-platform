"""Generate the ELF evaluation sample.

Aether's evaluation harness needs a binary whose ground truth is known exactly:
every string, every import, every mitigation flag. Compiling one is not an
option here - the host toolchain emits PE - and shipping a scavenged ELF would
mean shipping guesses about its contents.

So this builds a small, structurally valid ELF64 by hand. It is not meant to
execute; it is meant to be *read* correctly by anything that parses ELF, which
is exactly what the triage adapter and Ghidra both do. Every value it writes is
mirrored in eval/suites/elf_sample.json as expected truth.

Usage:
    python examples/src/build_elf_sample.py examples/firmware_agent.elf
"""

from __future__ import annotations

import struct
import sys

ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_DYN = 3
EM_X86_64 = 0x3E

PT_LOAD = 1
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

STB_GLOBAL = 1
STT_FUNC = 2

#: Virtual base. Non-zero and unequal to the file offset on purpose, so that a
#: parser that confuses the two fails the evaluation instead of passing it.
VADDR_BASE = 0x400000

INTERP = b"/lib64/ld-linux-x86-64.so.2\x00"

#: Strings placed in .rodata. The evaluation suite asserts on these exactly.
RODATA_STRINGS: tuple[bytes, ...] = (
    b"AKIAIOSFODNN7EXAMPLE\x00",
    b"BusyBox v1.31.1 (2020-04-12 15:00:00 UTC) multi-call binary\x00",
    b"OpenSSL 1.0.2u  20 Dec 2019\x00",
    b"Dropbear v2019.78\x00",
    b"mysql://svcuser:hunter2@10.4.0.9:3306/telemetry\x00",
    b"-----BEGIN RSA PRIVATE KEY-----\x00",
    b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDb1example0key0material0here\x00",
    b"/etc/config/telemetry.conf\x00",
    b"firmware-agent starting up\x00",
    b"ping -c 1 %s\x00",
    b"Linux version 4.14.98 (buildbot@node7)\x00",
)

#: Undefined symbols: the dynamic linker resolves these, so they are imports.
IMPORTS: tuple[str, ...] = (
    "strcpy",
    "system",
    "printf",
    "rand",
    "srand",
    "memcpy",
    "__stack_chk_fail",
    "__printf_chk",
)

#: Defined symbols, at fabricated but internally consistent addresses.
EXPORTS: tuple[tuple[str, int], ...] = (
    ("main", 0x40),
    ("handle_name", 0x00),
    ("run_diagnostics", 0x18),
    ("weak_token", 0x30),
)


def _align(value: int, alignment: int = 16) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build() -> bytes:
    ehsize, phentsize, shentsize = 64, 56, 64
    phnum = 4
    phoff = ehsize

    cursor = _align(phoff + phnum * phentsize)

    interp_off = cursor
    cursor = _align(interp_off + len(INTERP))

    # A stand-in .text: `ret` padded out. Nothing disassembles this in anger;
    # it exists so the section table describes something real.
    text = b"\xc3" + b"\x90" * 0x7F
    text_off = cursor
    cursor = _align(text_off + len(text))

    rodata = b"".join(RODATA_STRINGS)
    rodata_off = cursor
    cursor = _align(rodata_off + len(rodata))

    # .dynstr, then .dynsym referencing it by offset.
    dynstr = bytearray(b"\x00")
    string_offsets: dict[str, int] = {}
    for name in list(IMPORTS) + [name for name, _ in EXPORTS]:
        string_offsets[name] = len(dynstr)
        dynstr.extend(name.encode("ascii") + b"\x00")
    dynstr_off = cursor
    cursor = _align(dynstr_off + len(dynstr))

    text_section_index = 2
    dynsym = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))  # null entry
    for name in IMPORTS:
        dynsym.extend(
            struct.pack(
                "<IBBHQQ",
                string_offsets[name],
                (STB_GLOBAL << 4) | STT_FUNC,
                0,
                0,  # SHN_UNDEF: an import
                0,
                0,
            )
        )
    for name, offset in EXPORTS:
        dynsym.extend(
            struct.pack(
                "<IBBHQQ",
                string_offsets[name],
                (STB_GLOBAL << 4) | STT_FUNC,
                0,
                text_section_index,
                VADDR_BASE + text_off + offset,
                0x18,
            )
        )
    dynsym_off = cursor
    cursor = _align(dynsym_off + len(dynsym))

    section_names = ["", ".interp", ".text", ".rodata", ".dynstr", ".dynsym", ".shstrtab"]
    shstrtab = bytearray()
    name_offsets: dict[str, int] = {}
    for name in section_names:
        name_offsets[name] = len(shstrtab)
        shstrtab.extend(name.encode("ascii") + b"\x00")
    shstrtab_off = cursor
    cursor = _align(shstrtab_off + len(shstrtab))

    shoff = cursor
    shnum = len(section_names)
    total = shoff + shnum * shentsize

    def vaddr(offset: int) -> int:
        return VADDR_BASE + offset

    header = bytearray()
    header += b"\x7fELF"
    header += bytes([ELFCLASS64, ELFDATA2LSB, 1, 0, 0])
    header += b"\x00" * 7
    header += struct.pack("<HH", ET_DYN, EM_X86_64)
    header += struct.pack("<I", 1)  # e_version
    header += struct.pack("<QQQ", vaddr(text_off), phoff, shoff)
    header += struct.pack("<I", 0)  # e_flags
    header += struct.pack("<HHHHHH", ehsize, phentsize, phnum, shentsize, shnum, 6)
    assert len(header) == ehsize, len(header)

    program_headers = b"".join(
        [
            # Everything in one PT_LOAD; a fixture does not need realistic
            # segment splitting, only a mapping a parser can follow.
            struct.pack(
                "<IIQQQQQQ", PT_LOAD, PF_R | PF_X, 0, vaddr(0), vaddr(0), total, total, 0x1000
            ),
            struct.pack(
                "<IIQQQQQQ",
                PT_INTERP,
                PF_R,
                interp_off,
                vaddr(interp_off),
                vaddr(interp_off),
                len(INTERP),
                len(INTERP),
                1,
            ),
            # No PF_X on the stack segment: this is what NX looks like.
            struct.pack("<IIQQQQQQ", PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0, 0x10),
            struct.pack(
                "<IIQQQQQQ",
                PT_GNU_RELRO,
                PF_R,
                rodata_off,
                vaddr(rodata_off),
                vaddr(rodata_off),
                len(rodata),
                len(rodata),
                1,
            ),
        ]
    )

    def shdr(
        name: str,
        sh_type: int,
        flags: int,
        addr: int,
        offset: int,
        size: int,
        link: int = 0,
        info: int = 0,
        align: int = 1,
        entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name_offsets[name],
            sh_type,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            align,
            entsize,
        )

    section_headers = b"".join(
        [
            shdr("", 0, 0, 0, 0, 0),
            shdr(".interp", SHT_PROGBITS, SHF_ALLOC, vaddr(interp_off), interp_off, len(INTERP)),
            shdr(
                ".text",
                SHT_PROGBITS,
                SHF_ALLOC | SHF_EXECINSTR,
                vaddr(text_off),
                text_off,
                len(text),
                align=16,
            ),
            shdr(
                ".rodata",
                SHT_PROGBITS,
                SHF_ALLOC,
                vaddr(rodata_off),
                rodata_off,
                len(rodata),
                align=8,
            ),
            shdr(".dynstr", SHT_STRTAB, SHF_ALLOC, vaddr(dynstr_off), dynstr_off, len(dynstr)),
            shdr(
                ".dynsym",
                SHT_DYNSYM,
                SHF_ALLOC,
                vaddr(dynsym_off),
                dynsym_off,
                len(dynsym),
                link=4,
                info=1,
                align=8,
                entsize=24,
            ),
            shdr(".shstrtab", SHT_STRTAB, 0, 0, shstrtab_off, len(shstrtab)),
        ]
    )

    image = bytearray(b"\x00" * total)
    image[0:ehsize] = header
    image[phoff : phoff + len(program_headers)] = program_headers
    image[interp_off : interp_off + len(INTERP)] = INTERP
    image[text_off : text_off + len(text)] = text
    image[rodata_off : rodata_off + len(rodata)] = rodata
    image[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    image[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    image[shstrtab_off : shstrtab_off + len(shstrtab)] = shstrtab
    image[shoff : shoff + len(section_headers)] = section_headers
    return bytes(image)


def main(argv: list[str]) -> int:
    destination = argv[1] if len(argv) > 1 else "examples/firmware_agent.elf"
    payload = build()
    with open(destination, "wb") as handle:
        handle.write(payload)
    import hashlib

    print(f"wrote {destination} ({len(payload)} bytes)")
    print(f"sha256 {hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
