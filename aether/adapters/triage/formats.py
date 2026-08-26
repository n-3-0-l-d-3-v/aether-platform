"""Header-level file identification for ELF, PE, and container formats.

This is *triage*, not analysis: it reads structure that the file format defines
explicitly - magic bytes, header fields, section tables, symbol tables - and
never infers anything from instruction bytes. Recovering functions, call
graphs, and decompilation is Ghidra's job and stays Ghidra's job.

It earns its place for two reasons. Firmware inventory needs to know what each
carved file *is* before anything heavier is worth running, and exploit
mitigation flags (NX, PIE, RELRO, ASLR) live in headers, so reporting them
costs one pass over bytes already in memory.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO

#: How many bytes are enough to identify anything here.
SNIFF_SIZE = 4096

# ELF e_machine -> normalized architecture name.
_ELF_MACHINES: dict[int, str] = {
    0x02: "sparc",
    0x03: "x86",
    0x08: "mips",
    0x14: "ppc",
    0x15: "ppc64",
    0x16: "s390",
    0x28: "arm",
    0x2A: "superh",
    0x32: "ia64",
    0x3E: "x86_64",
    0x53: "avr",
    0xB7: "aarch64",
    0xF3: "riscv",
    0x102: "loongarch",
}

# PE IMAGE_FILE_HEADER.Machine -> normalized architecture name.
_PE_MACHINES: dict[int, str] = {
    0x014C: "x86",
    0x0166: "mips",
    0x01A2: "superh",
    0x01C0: "arm",
    0x01C4: "armv7",
    0x01F0: "ppc",
    0x0200: "ia64",
    0x5032: "riscv32",
    0x5064: "riscv64",
    0x8664: "x86_64",
    0xAA64: "aarch64",
}

_ELF_TYPES: dict[int, str] = {
    1: "relocatable",
    2: "executable",
    3: "shared object",
    4: "core dump",
}

PT_INTERP = 3
PT_GNU_EH_FRAME = 0x6474E550
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1

#: Container and payload signatures, matched at offset 0 for identification and
#: scanned for by the carver. ``(name, magic, format, description)``.
CONTAINER_SIGNATURES: tuple[tuple[str, bytes, str, str], ...] = (
    ("squashfs_le", b"hsqs", "filesystem", "SquashFS filesystem, little endian"),
    ("squashfs_be", b"sqsh", "filesystem", "SquashFS filesystem, big endian"),
    ("cramfs", b"\x45\x3d\xcd\x28", "filesystem", "CramFS filesystem"),
    ("jffs2_le", b"\x85\x19", "filesystem", "JFFS2 filesystem, little endian"),
    ("ubi", b"UBI#", "filesystem", "UBI erase counter header"),
    ("ubifs", b"\x31\x18\x10\x06", "filesystem", "UBIFS superblock"),
    ("romfs", b"-rom1fs-", "filesystem", "RomFS filesystem"),
    ("ext_sb", b"\x53\xef", "filesystem", "ext2/3/4 superblock magic"),
    ("cpio_newc", b"070701", "archive", "ASCII cpio archive (SVR4, no CRC)"),
    ("cpio_crc", b"070702", "archive", "ASCII cpio archive (SVR4, CRC)"),
    ("cpio_odc", b"070707", "archive", "ASCII cpio archive (portable)"),
    ("tar", b"ustar", "archive", "POSIX tar archive"),
    ("zip", b"PK\x03\x04", "archive", "ZIP archive"),
    ("ar", b"!<arch>", "archive", "Unix ar archive"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip archive"),
    ("rar", b"Rar!\x1a\x07", "archive", "RAR archive"),
    ("gzip", b"\x1f\x8b\x08", "compressed", "gzip compressed data"),
    ("bzip2", b"BZh", "compressed", "bzip2 compressed data"),
    ("xz", b"\xfd7zXZ\x00", "compressed", "XZ compressed data"),
    ("lzma_alone", b"\x5d\x00\x00", "compressed", "LZMA compressed data"),
    ("lz4", b"\x04\x22\x4d\x18", "compressed", "LZ4 compressed data"),
    ("zstd", b"\x28\xb5\x2f\xfd", "compressed", "Zstandard compressed data"),
    ("lzo", b"\x89LZO", "compressed", "LZO compressed data"),
    ("uimage", b"\x27\x05\x19\x56", "data", "U-Boot uImage header"),
    ("android_boot", b"ANDROID!", "data", "Android boot image"),
    ("dtb", b"\xd0\x0d\xfe\xed", "data", "Flattened device tree blob"),
    ("pem_cert", b"-----BEGIN CERTIFICATE", "certificate", "PEM certificate"),
    ("pem_key", b"-----BEGIN", "certificate", "PEM encoded key material"),
    ("elf", b"\x7fELF", "elf", "ELF binary"),
    ("macho32", b"\xfe\xed\xfa\xce", "macho", "Mach-O 32-bit binary"),
    ("macho64", b"\xfe\xed\xfa\xcf", "macho", "Mach-O 64-bit binary"),
    ("macho_fat", b"\xca\xfe\xba\xbe", "macho", "Mach-O universal binary"),
    ("sqlite", b"SQLite format 3\x00", "data", "SQLite database"),
    ("png", b"\x89PNG\r\n\x1a\n", "data", "PNG image"),
)


@dataclass
class Section:
    """One section or segment, as the file's own tables describe it."""

    name: str
    addr_start: int
    addr_end: int
    file_offset: int
    permissions: str
    initialized: bool = True

    def to_data(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "addr_start": self.addr_start,
            "addr_end": self.addr_end,
            "file_offset": self.file_offset,
            "permissions": self.permissions,
            "initialized": self.initialized,
        }


@dataclass
class Identification:
    """Everything triage could establish about a file from its headers."""

    format: str = "unknown"
    media_type: str = "unknown"
    arch: str | None = None
    bits: int | None = None
    endian: str | None = None
    signature: str | None = None
    sections: list[Section] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    exports: list[dict[str, Any]] = field(default_factory=list)
    symbols: list[dict[str, Any]] = field(default_factory=list)
    #: Mitigation features keyed by the ``binary_hardening`` predicate's enum.
    hardening: dict[str, bool] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def file_data(self, *, path: str, digests: dict[str, Any], source: str) -> dict[str, Any]:
        """Assemble the payload for a ``file`` artifact."""
        data: dict[str, Any] = {
            "path": path,
            "sha256": digests["sha256"],
            "md5": digests["md5"],
            "size": digests["size"],
            "format": self.format,
            "media_type": self.media_type,
            "source": source,
        }
        if self.arch:
            data["arch"] = self.arch
        if self.bits:
            data["bits"] = self.bits
        if self.endian:
            data["endian"] = self.endian
        return data


def identify_bytes(head: bytes, *, size: int | None = None) -> Identification:
    """Identify a file from its leading bytes."""
    ident = Identification()
    if not head:
        ident.media_type = "empty file"
        return ident

    if head.startswith(b"\x7fELF"):
        return _identify_elf(head, size=size)
    if head.startswith(b"MZ"):
        return _identify_pe(head, size=size)
    if head.startswith(b"#!"):
        interpreter = head.split(b"\n", 1)[0][2:].decode("utf-8", "replace").strip()
        ident.format = "script"
        ident.media_type = f"script for {interpreter}" if interpreter else "script"
        ident.signature = "shebang"
        return ident

    for name, magic, fmt, description in CONTAINER_SIGNATURES:
        offset = _signature_offset(name)
        if head[offset : offset + len(magic)] == magic:
            ident.format = fmt
            ident.media_type = description
            ident.signature = name
            return ident

    ident.format = "data"
    ident.media_type = "unrecognized data"
    return ident


def identify_file(path: str) -> Identification:
    """Identify a file on disk, reading only its head."""
    import os

    try:
        size = os.path.getsize(path)
    except OSError:
        size = None
    with open(path, "rb") as handle:
        head = handle.read(SNIFF_SIZE)
        ident = identify_bytes(head, size=size)
        # PE import parsing needs bytes beyond the sniff window.
        if ident.format == "pe":
            handle.seek(0)
            _enrich_pe(handle, ident)
        elif ident.format == "elf":
            handle.seek(0)
            _enrich_elf(handle, ident)
    return ident


def _signature_offset(name: str) -> int:
    """Byte offset a signature is expected at. ``ustar`` sits inside the header."""
    if name == "tar":
        return 257
    if name == "ext_sb":
        return 1080
    return 0


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------


def _identify_elf(head: bytes, *, size: int | None = None) -> Identification:
    ident = Identification(format="elf", signature="elf")
    if len(head) < 20:
        ident.warnings.append("ELF header truncated")
        return ident

    ei_class, ei_data = head[4], head[5]
    ident.bits = {1: 32, 2: 64}.get(ei_class)
    ident.endian = {1: "little", 2: "big"}.get(ei_data)
    if ident.bits is None or ident.endian is None:
        ident.warnings.append("ELF identifies an unknown class or byte order")
        return ident

    prefix = "<" if ident.endian == "little" else ">"
    e_type, e_machine = struct.unpack_from(f"{prefix}HH", head, 16)
    ident.arch = _ELF_MACHINES.get(e_machine, f"unknown(0x{e_machine:x})")
    kind = _ELF_TYPES.get(e_type, "object")
    ident.media_type = f"ELF {ident.bits}-bit {ident.endian}-endian {kind}, {ident.arch}"
    ident.hardening["pie"] = False  # refined by _enrich_elf once phdrs are read
    return ident


def _enrich_elf(handle: BinaryIO, ident: Identification) -> None:
    """Read ELF program headers, section headers, and the dynamic symbol table."""
    try:
        data = handle.read()
    except OSError as exc:  # pragma: no cover - unreadable mid-file
        ident.warnings.append(f"could not read ELF body: {exc}")
        return

    is64 = ident.bits == 64
    prefix = "<" if ident.endian == "little" else ">"
    try:
        if is64:
            e_phoff, e_shoff = struct.unpack_from(f"{prefix}QQ", data, 32)
            e_phentsize, e_phnum = struct.unpack_from(f"{prefix}HH", data, 54)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{prefix}HHH", data, 58)
        else:
            e_phoff, e_shoff = struct.unpack_from(f"{prefix}II", data, 28)
            e_phentsize, e_phnum = struct.unpack_from(f"{prefix}HH", data, 42)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{prefix}HHH", data, 46)
        e_type = struct.unpack_from(f"{prefix}H", data, 16)[0]
    except struct.error:
        ident.warnings.append("ELF header fields extend past end of file")
        return

    has_interp = False
    gnu_stack_exec: bool | None = None
    has_relro = False
    for index in range(min(e_phnum, 256)):
        offset = e_phoff + index * e_phentsize
        try:
            if is64:
                p_type, p_flags = struct.unpack_from(f"{prefix}II", data, offset)
            else:
                p_type = struct.unpack_from(f"{prefix}I", data, offset)[0]
                p_flags = struct.unpack_from(f"{prefix}I", data, offset + 24)[0]
        except struct.error:
            break
        if p_type == PT_INTERP:
            has_interp = True
        elif p_type == PT_GNU_STACK:
            gnu_stack_exec = bool(p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_relro = True

    # NX is the absence of an executable stack. A missing PT_GNU_STACK means
    # the toolchain said nothing, and the kernel default applies - reported as
    # absent, because "unstated" is not "enforced".
    ident.hardening["nx"] = gnu_stack_exec is False
    ident.hardening["relro"] = has_relro
    # ET_DYN alone does not mean PIE: shared libraries are ET_DYN too. Requiring
    # a PT_INTERP segment separates a position-independent executable from a
    # library that merely looks like one.
    ident.hardening["pie"] = e_type == 3 and has_interp

    sections = _elf_sections(data, prefix, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    ident.sections = sections
    section_names = {s.name for s in sections}
    _elf_dynamic_symbols(data, prefix, is64, sections, ident)
    ident.hardening["stack_canary"] = any(
        sym["name"] == "__stack_chk_fail" for sym in ident.imports + ident.symbols
    )
    ident.hardening["fortify_source"] = any(
        sym["name"].endswith("_chk") for sym in ident.imports
    )
    if ".text" not in section_names and sections:
        ident.warnings.append("ELF has section headers but no .text")


def _elf_sections(
    data: bytes,
    prefix: str,
    is64: bool,
    e_shoff: int,
    e_shentsize: int,
    e_shnum: int,
    e_shstrndx: int,
) -> list[Section]:
    sections: list[Section] = []
    if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
        return sections

    def read_shdr(index: int) -> tuple[int, int, int, int, int, int] | None:
        offset = e_shoff + index * e_shentsize
        try:
            if is64:
                name, sh_type, flags, addr, sh_off, sh_size = struct.unpack_from(
                    f"{prefix}IIQQQQ", data, offset
                )
            else:
                name, sh_type, flags, addr, sh_off, sh_size = struct.unpack_from(
                    f"{prefix}IIIIII", data, offset
                )
        except struct.error:
            return None
        return name, sh_type, flags, addr, sh_off, sh_size

    strtab = read_shdr(e_shstrndx)
    if strtab is None:
        return sections
    str_off, str_size = strtab[4], strtab[5]
    strings = data[str_off : str_off + str_size]

    for index in range(min(e_shnum, 512)):
        header = read_shdr(index)
        if header is None:
            break
        name_off, sh_type, flags, addr, sh_off, sh_size = header
        end = strings.find(b"\x00", name_off)
        name = strings[name_off : end if end >= 0 else None].decode("utf-8", "replace")
        if not name:
            continue
        permissions = "r"
        if flags & 0x1:
            permissions += "w"
        if flags & 0x4:
            permissions += "x"
        sections.append(
            Section(
                name=name,
                addr_start=addr,
                addr_end=addr + sh_size,
                file_offset=sh_off,
                permissions=permissions,
                initialized=sh_type != 8,  # SHT_NOBITS
            )
        )
    return sections


def _elf_dynamic_symbols(
    data: bytes, prefix: str, is64: bool, sections: list[Section], ident: Identification
) -> None:
    """Read .dynsym/.dynstr to recover imports and exports.

    Symbol tables are declarative file structure, the same class of data as a
    section header. Nothing here interprets code.
    """
    by_name = {s.name: s for s in sections}
    dynsym, dynstr = by_name.get(".dynsym"), by_name.get(".dynstr")
    if dynsym is None or dynstr is None:
        return

    strings = data[dynstr.file_offset : dynstr.file_offset + (dynstr.addr_end - dynstr.addr_start)]
    entry_size = 24 if is64 else 16
    table_size = dynsym.addr_end - dynsym.addr_start
    count = min(table_size // entry_size, 20000) if entry_size else 0

    for index in range(count):
        offset = dynsym.file_offset + index * entry_size
        try:
            if is64:
                st_name, st_info, _st_other, st_shndx, st_value, _size = struct.unpack_from(
                    f"{prefix}IBBHQQ", data, offset
                )
            else:
                st_name, st_value, _size, st_info, _st_other, st_shndx = struct.unpack_from(
                    f"{prefix}IIIBBH", data, offset
                )
        except struct.error:
            break
        if not st_name:
            continue
        end = strings.find(b"\x00", st_name)
        name = strings[st_name : end if end >= 0 else None].decode("utf-8", "replace")
        if not name:
            continue
        sym_type = st_info & 0xF
        kind = {1: "object", 2: "function"}.get(sym_type, "unknown")
        record = {"name": name, "addr": st_value, "symbol_type": kind}
        if st_shndx == 0:  # SHN_UNDEF: resolved by the dynamic linker
            ident.imports.append({"name": name, "addr": st_value or None})
        else:
            ident.exports.append({"name": name, "addr": st_value})
            ident.symbols.append(record)


# --------------------------------------------------------------------------
# PE
# --------------------------------------------------------------------------

_DLL_NX = 0x0100
_DLL_ASLR = 0x0040
_DLL_CFG = 0x4000
_DLL_NO_SEH = 0x0400


def _identify_pe(head: bytes, *, size: int | None = None) -> Identification:
    ident = Identification(format="pe", signature="pe")
    try:
        pe_offset = struct.unpack_from("<I", head, 0x3C)[0]
    except struct.error:
        ident.format = "data"
        ident.media_type = "DOS executable or truncated MZ header"
        return ident
    if pe_offset + 24 > len(head) or head[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        ident.format = "data"
        ident.media_type = "MZ file without a PE header (DOS executable?)"
        return ident

    machine, _num_sections = struct.unpack_from("<HH", head, pe_offset + 4)
    characteristics = struct.unpack_from("<H", head, pe_offset + 22)[0]
    magic = struct.unpack_from("<H", head, pe_offset + 24)[0]

    ident.arch = _PE_MACHINES.get(machine, f"unknown(0x{machine:x})")
    ident.bits = 64 if magic == 0x20B else 32
    ident.endian = "little"
    is_dll = bool(characteristics & 0x2000)
    ident.media_type = (
        f"PE32{'+' if ident.bits == 64 else ''} {'DLL' if is_dll else 'executable'}, "
        f"{ident.arch}"
    )

    dll_characteristics_offset = pe_offset + 24 + (70 if ident.bits == 64 else 70)
    try:
        dll_characteristics = struct.unpack_from("<H", head, dll_characteristics_offset)[0]
    except struct.error:
        return ident
    ident.hardening["nx"] = bool(dll_characteristics & _DLL_NX)
    ident.hardening["aslr"] = bool(dll_characteristics & _DLL_ASLR)
    ident.hardening["cfg"] = bool(dll_characteristics & _DLL_CFG)
    ident.hardening["safeseh"] = ident.bits == 32 and not (dll_characteristics & _DLL_NO_SEH)
    return ident


def _enrich_pe(handle: BinaryIO, ident: Identification) -> None:
    """Read the PE section table and import directory."""
    data = handle.read()
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
        image_base = (
            struct.unpack_from("<Q", data, pe_offset + 24 + 24)[0]
            if magic == 0x20B
            else struct.unpack_from("<I", data, pe_offset + 24 + 28)[0]
        )
    except struct.error:
        ident.warnings.append("PE optional header truncated")
        return

    section_table = pe_offset + 24 + opt_size
    sections: list[tuple[int, int, int, int]] = []  # (vaddr, vsize, raw_ptr, raw_size)
    for index in range(min(num_sections, 96)):
        offset = section_table + index * 40
        try:
            raw_name = data[offset : offset + 8].rstrip(b"\x00")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, offset + 8)
            characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        except struct.error:
            break
        name = raw_name.decode("utf-8", "replace") or f"sect{index}"
        permissions = ""
        if characteristics & 0x40000000:
            permissions += "r"
        if characteristics & 0x80000000:
            permissions += "w"
        if characteristics & 0x20000000:
            permissions += "x"
        ident.sections.append(
            Section(
                name=name,
                addr_start=image_base + vaddr,
                addr_end=image_base + vaddr + vsize,
                file_offset=raw_ptr,
                permissions=permissions or "r",
                initialized=raw_size > 0,
            )
        )
        sections.append((vaddr, vsize, raw_ptr, raw_size))

    _pe_imports(data, pe_offset, magic, sections, ident)


def _pe_imports(
    data: bytes,
    pe_offset: int,
    magic: int,
    sections: list[tuple[int, int, int, int]],
    ident: Identification,
) -> None:
    """Walk the import directory, recording symbol/library pairs."""

    def rva_to_offset(rva: int) -> int | None:
        for vaddr, vsize, raw_ptr, raw_size in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return raw_ptr + (rva - vaddr)
        return None

    directory_base = pe_offset + 24 + (112 if magic == 0x20B else 96)
    try:
        import_rva, _import_size = struct.unpack_from("<II", data, directory_base + 8)
    except struct.error:
        return
    if not import_rva:
        return
    descriptor_offset = rva_to_offset(import_rva)
    if descriptor_offset is None:
        ident.warnings.append("PE import directory RVA falls outside every section")
        return

    def read_string(rva: int) -> str:
        offset = rva_to_offset(rva)
        if offset is None or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset)
        return data[offset : end if end >= 0 else offset + 128].decode("utf-8", "replace")

    thunk_size = 8 if magic == 0x20B else 4
    ordinal_flag = 1 << 63 if magic == 0x20B else 1 << 31

    for index in range(256):
        offset = descriptor_offset + index * 20
        try:
            lookup_rva, _t, _f, name_rva, _first_thunk = struct.unpack_from(
                "<IIIII", data, offset
            )
        except struct.error:
            break
        if not name_rva and not lookup_rva:
            break
        library = read_string(name_rva)
        thunk_rva = lookup_rva or _first_thunk
        thunk_offset = rva_to_offset(thunk_rva) if thunk_rva else None
        if thunk_offset is None:
            continue
        for slot in range(4096):
            entry_offset = thunk_offset + slot * thunk_size
            try:
                entry = (
                    struct.unpack_from("<Q", data, entry_offset)[0]
                    if thunk_size == 8
                    else struct.unpack_from("<I", data, entry_offset)[0]
                )
            except struct.error:
                break
            if entry == 0:
                break
            if entry & ordinal_flag:
                ident.imports.append(
                    {"name": f"ordinal_{entry & 0xFFFF}", "library": library,
                     "ordinal": entry & 0xFFFF}
                )
            else:
                name = read_string((entry & 0x7FFFFFFF) + 2)
                if name:
                    ident.imports.append({"name": name, "library": library})
