"""Generate the firmware evaluation sample.

Builds a small image with the shape real router firmware tends to have: a
vendor header, padding, then a gzip-compressed cpio root filesystem holding a
couple of binaries and some configuration. That exercises every stage of the
unpack path at once - offset scanning past a header, stream decompression, and
archive parsing - which a bare .tar.gz would not.

Usage:
    python examples/src/build_firmware_sample.py examples/demo_firmware.bin
"""

from __future__ import annotations

import gzip
import os
import struct
import sys

#: Files placed in the image's root filesystem, alongside the two binaries.
CONFIG_FILES: dict[str, bytes] = {
    "etc/telemetry.conf": (
        b"# telemetry agent configuration\n"
        b"endpoint=https://updates.example-vendor.net/v2/report\n"
        b"api_key=ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n"
        b"database=postgresql://telemetry:s3cr3tp4ss@10.4.0.9:5432/metrics\n"
        b"retry_interval=300\n"
    ),
    "etc/dropbear/dropbear_rsa_host_key.pem": (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEA1exampleKeyMaterialThatIsNotRealAndNeverWasUsedFor\n"
        b"AnythingAtAllItExistsOnlyToGiveTheEvaluationSuiteSomethingToFind00\n"
        b"-----END RSA PRIVATE KEY-----\n"
    ),
    "etc/banner": (
        b"BusyBox v1.31.1 (2020-04-12 15:00:00 UTC) built-in shell (ash)\n"
        b"Vendor Router OS 3.2.1 - unauthorized access prohibited\n"
    ),
    "usr/share/version": b"firmware-version=3.2.1-build447\nkernel=Linux version 4.14.98\n",
}


def cpio_newc(members: list[tuple[str, bytes, int]]) -> bytes:
    """Serialize files into an ASCII cpio (newc) archive.

    Writing the format directly keeps the sample generator dependency-free and
    exercises the same parser the carver uses on real initramfs images.
    """
    out = bytearray()
    inode = 1

    def field(value: int) -> bytes:
        return b"%08X" % (value & 0xFFFFFFFF)

    for name, payload, mode in members:
        raw_name = name.encode("utf-8") + b"\x00"
        out += b"070701"
        out += field(inode)
        out += field(mode)
        out += field(0)  # uid
        out += field(0)  # gid
        out += field(1)  # nlink
        out += field(0)  # mtime: zero keeps the sample byte-reproducible
        out += field(len(payload))
        out += field(0) * 4  # devmajor, devminor, rdevmajor, rdevminor
        out += field(len(raw_name))
        out += field(0)  # check
        out += raw_name
        out += b"\x00" * (-len(out) % 4)
        out += payload
        out += b"\x00" * (-len(out) % 4)
        inode += 1

    trailer = b"TRAILER!!!\x00"
    # The newc header is exactly 110 bytes: a 6-byte magic followed by 13
    # eight-digit hex fields. The trailer differs only in its reserved name.
    out += b"070701"
    out += field(0)  # ino
    out += field(0)  # mode
    out += field(0)  # uid
    out += field(0)  # gid
    out += field(1)  # nlink
    out += field(0)  # mtime
    out += field(0)  # filesize
    out += field(0) * 4  # devmajor, devminor, rdevmajor, rdevminor
    out += field(len(trailer))  # namesize
    out += field(0)  # check
    out += trailer
    out += b"\x00" * (-len(out) % 4)
    return bytes(out)


def uimage_header(payload_size: int, name: bytes = b"Vendor Router OS 3.2.1") -> bytes:
    """A plausible U-Boot uImage header, so the scanner has a header to skip."""
    header = bytearray(64)
    struct.pack_into(">I", header, 0, 0x27051956)  # magic
    struct.pack_into(">I", header, 8, 0)  # timestamp
    struct.pack_into(">I", header, 12, payload_size)
    struct.pack_into(">I", header, 16, 0x80000000)  # load address
    struct.pack_into(">I", header, 20, 0x80000040)  # entry point
    header[28] = 5  # OS: Linux
    header[29] = 2  # arch
    header[30] = 3  # type: ramdisk
    header[31] = 1  # compression: gzip
    header[32 : 32 + len(name)] = name[:31]
    return bytes(header)


def build(elf_path: str, pe_path: str) -> bytes:
    members: list[tuple[str, bytes, int]] = []
    for name, payload in sorted(CONFIG_FILES.items()):
        members.append((name, payload, 0o100644))

    if os.path.exists(elf_path):
        with open(elf_path, "rb") as handle:
            members.append(("bin/firmware_agent", handle.read(), 0o100755))
    if os.path.exists(pe_path):
        with open(pe_path, "rb") as handle:
            members.append(("bin/diagnostics.exe", handle.read(), 0o100755))

    members.sort(key=lambda m: m[0])
    archive = cpio_newc(members)
    # mtime=0 so repeated builds produce identical bytes.
    compressed = gzip.compress(archive, compresslevel=9, mtime=0)
    return uimage_header(len(compressed)) + b"\xff" * 192 + compressed


def main(argv: list[str]) -> int:
    destination = argv[1] if len(argv) > 1 else "examples/demo_firmware.bin"
    root = os.path.dirname(destination) or "."
    payload = build(
        os.path.join(root, "firmware_agent.elf"),
        os.path.join(root, "vulnerable_demo.exe"),
    )
    with open(destination, "wb") as handle:
        handle.write(payload)
    import hashlib

    print(f"wrote {destination} ({len(payload)} bytes)")
    print(f"sha256 {hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
