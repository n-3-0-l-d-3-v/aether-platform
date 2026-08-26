"""Generate the recorded Ghidra export used by the importer tests.

Ghidra is a multi-gigabyte install with a JVM dependency, so CI and most
contributor machines will never run it. The importer still has to be tested,
and testing it against invented data would only prove the tests agree with
themselves.

This builds an export that is consistent with the *real* bytes of
examples/firmware_agent.elf: section addresses, symbol addresses, and string
addresses are all read out of the actual file. What is fabricated is only what
Ghidra alone could supply - recovered function bounds, cross references, and
decompiled bodies - and those are written in Ghidra's own shapes.

The point is that the importer, the address arithmetic, and the convergence
between triage and Ghidra are all exercised for real. Only the disassembler is
stood in for.

Usage:
    python tests/fixtures/make_ghidra_fixture.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from aether.adapters.triage import formats  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLE = os.path.join(REPO_ROOT, "examples", "firmware_agent.elf")
OUT_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "ghidra", "firmware_agent")

#: Ghidra places unresolved externals in a synthetic block. Address values here
#: only need to be internally consistent, which is also true in a real program.
EXTERNAL_BASE = 0x500000

#: Recovered function bodies. Entry points come from the ELF's own symbol
#: table; sizes are what a disassembler would have determined.
FUNCTION_SIZES = {
    "handle_name": 0x18,
    "run_diagnostics": 0x18,
    "weak_token": 0x10,
    "main": 0x28,
}

#: Calls a disassembler would have recovered, as (caller, callee) pairs.
CALL_EDGES = [
    ("handle_name", "strcpy"),
    ("handle_name", "__stack_chk_fail"),
    ("run_diagnostics", "system"),
    ("run_diagnostics", "__printf_chk"),
    ("weak_token", "srand"),
    ("weak_token", "rand"),
    ("main", "printf"),
    ("main", "handle_name"),
    ("main", "run_diagnostics"),
    ("main", "weak_token"),
]

DECOMPILED = {
    "handle_name": (
        "void handle_name(char *param_1)\n"
        "{\n"
        "  char acStack_48 [64];\n"
        "  long lStack_8;\n"
        "  \n"
        "  lStack_8 = *(long *)(in_FS_OFFSET + 0x28);\n"
        "  strcpy(acStack_48,param_1);\n"
        "  printf(\"hello %s\\n\",acStack_48);\n"
        "  if (lStack_8 != *(long *)(in_FS_OFFSET + 0x28)) {\n"
        "    __stack_chk_fail();\n"
        "  }\n"
        "  return;\n"
        "}\n"
    ),
    "run_diagnostics": (
        "void run_diagnostics(char *param_1)\n"
        "{\n"
        "  char acStack_118 [256];\n"
        "  \n"
        "  __printf_chk(acStack_118,\"ping -c 1 %s\",param_1);\n"
        "  system(acStack_118);\n"
        "  return;\n"
        "}\n"
    ),
}


def build() -> dict[str, list[dict[str, object]]]:
    ident = formats.identify_file(SAMPLE)
    with open(SAMPLE, "rb") as handle:
        raw = handle.read()

    sections = [
        {
            "name": section.name,
            "addr_start": section.addr_start,
            "addr_end": section.addr_end,
            "permissions": section.permissions,
            "initialized": section.initialized,
        }
        for section in ident.sections
        if section.addr_start
    ]

    exports = {entry["name"]: int(entry["addr"]) for entry in ident.exports}
    functions = []
    for name, size in sorted(FUNCTION_SIZES.items(), key=lambda kv: exports.get(kv[0], 0)):
        entry = exports.get(name)
        if entry is None:
            continue
        functions.append(
            {
                "name": name,
                "addr_start": entry,
                "addr_end": entry + size - 1,
                "size": size,
                "signature": f"undefined {name}(void)",
                "calling_convention": "__stdcall",
                "is_thunk": False,
                "is_external": False,
                "param_count": 1 if name in ("handle_name", "run_diagnostics") else 0,
            }
        )

    imports = []
    import_addresses: dict[str, int] = {}
    for index, entry in enumerate(sorted(ident.imports, key=lambda e: e["name"])):
        address = EXTERNAL_BASE + index * 8
        import_addresses[entry["name"]] = address
        imports.append({"name": entry["name"], "library": "libc.so.6", "addr": address})
        # Ghidra also emits a thunk in the program's own address space.
        functions.append(
            {
                "name": entry["name"],
                "addr_start": address,
                "addr_end": address + 7,
                "size": 8,
                "signature": f"undefined {entry['name']}()",
                "calling_convention": "__stdcall",
                "is_thunk": True,
                "is_external": True,
                "param_count": 0,
            }
        )

    # Strings: read the real .rodata bytes so every address is genuine.
    rodata = next((s for s in ident.sections if s.name == ".rodata"), None)
    strings: list[dict[str, object]] = []
    if rodata is not None:
        blob = raw[rodata.file_offset : rodata.file_offset + (rodata.addr_end - rodata.addr_start)]
        cursor = 0
        for chunk in blob.split(b"\x00"):
            if len(chunk) >= 4:
                strings.append(
                    {
                        "text": chunk.decode("utf-8", "replace"),
                        "encoding": "ascii",
                        "addr": rodata.addr_start + cursor,
                        "length": len(chunk),
                    }
                )
            cursor += len(chunk) + 1

    symbols = [
        {
            "name": name,
            "addr": address,
            "symbol_type": "function",
            "namespace": "global",
            "is_primary": True,
        }
        for name, address in sorted(exports.items(), key=lambda kv: kv[1])
    ]

    xrefs = []
    for caller, callee in CALL_EDGES:
        caller_entry = exports.get(caller)
        if caller_entry is None:
            continue
        target = exports.get(callee) or import_addresses.get(callee)
        if target is None:
            continue
        xrefs.append(
            {
                "from_addr": caller_entry + 4,
                "to_addr": target,
                "ref_type": "call",
                "from_function": caller,
                "to_function": callee,
            }
        )
    # A data reference from main into .rodata, the way a real export has.
    if strings:
        xrefs.append(
            {
                "from_addr": exports.get("main", 0) + 8,
                "to_addr": int(strings[0]["addr"]),
                "ref_type": "data",
                "from_function": "main",
                "to_function": "",
            }
        )

    decompilation = [
        {
            "function_addr": exports[name],
            "function_name": name,
            "code": code,
            "decompiler": "ghidra",
            "line_count": code.count("\n") + 1,
        }
        for name, code in sorted(DECOMPILED.items())
        if name in exports
    ]

    meta = {
        "format": "aether.ghidra.export/1",
        "program": "firmware_agent.elf",
        "executable_path": "/examples/firmware_agent.elf",
        "executable_format": "Executable and Linking Format (ELF)",
        "executable_sha256": hashlib.sha256(raw).hexdigest(),
        "executable_md5": hashlib.md5(raw).hexdigest(),
        "language_id": "x86:LE:64:default",
        "processor": "x86",
        "address_size": 64,
        "endian": "little",
        "compiler_spec": "gcc",
        "image_base": 0x400000,
        "ghidra_version": "11.1.2",
        "counts": {},
        "decompiled": len(decompilation),
    }

    return {
        "meta": meta,
        "sections": sections,
        "functions": functions,
        "strings": strings,
        "symbols": symbols,
        "imports": imports,
        "exports": [{"name": n, "addr": a} for n, a in sorted(exports.items(), key=lambda kv: kv[1])],
        "xrefs": xrefs,
        "decompilation": decompilation,
    }


def main() -> int:
    if not os.path.isfile(SAMPLE):
        print(f"missing {SAMPLE}; run examples/src/build_elf_sample.py first")
        return 1
    export = build()
    os.makedirs(OUT_DIR, exist_ok=True)

    meta = export.pop("meta")
    counts = {}
    for stream, records in sorted(export.items()):
        path = os.path.join(OUT_DIR, f"{stream}.jsonl")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        counts[stream] = len(records)
    meta["counts"] = counts

    with open(os.path.join(OUT_DIR, "meta.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(meta, handle, sort_keys=True, indent=2)
        handle.write("\n")

    print(f"wrote fixture to {OUT_DIR}")
    for stream, count in sorted(counts.items()):
        print(f"  {stream}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
