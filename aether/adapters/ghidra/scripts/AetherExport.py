# Export a Ghidra program to Aether's deterministic JSONL interchange format.
#
# Runs inside Ghidra headless (analyzeHeadless -postScript AetherExport.py ...).
# That interpreter is Jython 2.7 in most installations and CPython 3 under
# PyGhidra, so this file stays inside the subset both accept: no f-strings, no
# type annotations, explicit .format() calls, and careful text handling.
#
# Everything is written sorted - by address, then by name - because Aether's
# export is meant to diff cleanly in Git, and a re-analysis that discovered
# nothing new should produce no diff at all.
#
# Arguments (all optional, positional):
#   [0] output directory                (default: program-name.aether next to cwd)
#   [1] max functions to decompile      (default: 40)
#   [2] comma-separated API names that make a function worth decompiling
#
# @category Aether
# @runtime Jython

from __future__ import print_function

import json
import os

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
except ImportError:  # pragma: no cover - only importable inside Ghidra
    DecompInterface = None
    ConsoleTaskMonitor = None

EXPORT_FORMAT = "aether.ghidra.export/1"
DEFAULT_DECOMPILE_LIMIT = 40
DECOMPILE_TIMEOUT_SECONDS = 60

# Reference types Aether models. Anything else collapses to "unknown" rather
# than inventing a category the schema does not have.
REF_TYPE_MAP = {
    "UNCONDITIONAL_CALL": "call",
    "CONDITIONAL_CALL": "call",
    "COMPUTED_CALL": "call",
    "CALL_TERMINATOR": "call",
    "COMPUTED_CALL_TERMINATOR": "call",
    "UNCONDITIONAL_JUMP": "jump",
    "CONDITIONAL_JUMP": "jump",
    "COMPUTED_JUMP": "jump",
    "JUMP_TERMINATOR": "jump",
    "READ": "read",
    "WRITE": "write",
    "READ_WRITE": "write",
    "DATA": "data",
    "PARAM": "data",
}


def _text(value):
    """Coerce any Java/Jython string-ish value to a clean unicode string."""
    if value is None:
        return ""
    try:
        text = unicode(value)  # noqa: F821 - Jython 2 only
    except NameError:
        text = str(value)
    out = []
    for ch in text:
        code = ord(ch)
        if code == 9 or code == 10 or (32 <= code < 127):
            out.append(ch)
        elif code > 127:
            out.append(ch)
        else:
            out.append(" ")
    return "".join(out)


def _addr(address):
    """Address as a plain integer, or None when Ghidra has no address."""
    if address is None:
        return None
    try:
        return int(address.getOffset())
    except Exception:
        return None


class Writer(object):
    """Collects records per stream and writes them sorted at the end."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.streams = {}

    def add(self, stream, record):
        self.streams.setdefault(stream, []).append(record)

    def flush(self, sort_keys_by_stream):
        if not os.path.isdir(self.out_dir):
            os.makedirs(self.out_dir)
        counts = {}
        for stream in sorted(self.streams.keys()):
            records = self.streams[stream]
            key = sort_keys_by_stream.get(stream)
            if key is not None:
                records.sort(key=key)
            path = os.path.join(self.out_dir, stream + ".jsonl")
            handle = open(path, "wb")
            try:
                for record in records:
                    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
                    if not isinstance(line, bytes):
                        line = line.encode("utf-8")
                    handle.write(line)
                    handle.write(b"\n")
            finally:
                handle.close()
            counts[stream] = len(records)
        return counts


def collect_memory_blocks(program, writer):
    for block in program.getMemory().getBlocks():
        permissions = ""
        if block.isRead():
            permissions += "r"
        if block.isWrite():
            permissions += "w"
        if block.isExecute():
            permissions += "x"
        writer.add(
            "sections",
            {
                "name": _text(block.getName()),
                "addr_start": _addr(block.getStart()),
                "addr_end": _addr(block.getEnd()),
                "permissions": permissions,
                "initialized": bool(block.isInitialized()),
            },
        )


def collect_functions(program, writer):
    """Record every function, keyed by entry point."""
    functions = []
    manager = program.getFunctionManager()
    iterator = manager.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        body = function.getBody()
        entry = _addr(function.getEntryPoint())
        if entry is None:
            continue
        record = {
            "name": _text(function.getName()),
            "addr_start": entry,
            "addr_end": _addr(body.getMaxAddress()),
            "size": int(body.getNumAddresses()),
            "signature": _text(function.getPrototypeString(False, False)),
            "calling_convention": _text(function.getCallingConventionName()),
            "is_thunk": bool(function.isThunk()),
            "is_external": bool(function.isExternal()),
            "param_count": int(function.getParameterCount()),
        }
        writer.add("functions", record)
        functions.append((function, record))
    return functions


def collect_strings(program, writer):
    listing = program.getListing()
    data_iterator = listing.getDefinedData(True)
    while data_iterator.hasNext():
        data = data_iterator.next()
        data_type = data.getDataType()
        type_name = _text(data_type.getName()).lower()
        if "string" not in type_name and "unicode" not in type_name:
            continue
        value = data.getValue()
        if value is None:
            continue
        text = _text(value)
        if not text:
            continue
        if "unicode" in type_name or "utf-16" in type_name:
            encoding = "utf16le"
        else:
            encoding = "ascii"
        writer.add(
            "strings",
            {
                "text": text,
                "encoding": encoding,
                "addr": _addr(data.getAddress()),
                "length": len(text),
            },
        )


def collect_symbols(program, writer):
    table = program.getSymbolTable()
    iterator = table.getAllSymbols(True)
    while iterator.hasNext():
        symbol = iterator.next()
        address = _addr(symbol.getAddress())
        if address is None:
            continue
        symbol_type = _text(symbol.getSymbolType()).lower()
        if "function" in symbol_type:
            kind = "function"
        elif "label" in symbol_type:
            kind = "label"
        else:
            kind = "unknown"
        record = {
            "name": _text(symbol.getName()),
            "addr": address,
            "symbol_type": kind,
            "namespace": _text(symbol.getParentNamespace().getName()),
            "is_primary": bool(symbol.isPrimary()),
        }
        writer.add("symbols", record)
        if symbol.isExternalEntryPoint():
            writer.add("exports", {"name": record["name"], "addr": address})

    external_iterator = table.getExternalSymbols()
    while external_iterator.hasNext():
        symbol = external_iterator.next()
        library = ""
        try:
            library = _text(symbol.getParentNamespace().getName())
        except Exception:
            library = ""
        writer.add(
            "imports",
            {
                "name": _text(symbol.getName()),
                "library": library,
                "addr": _addr(symbol.getAddress()),
            },
        )


def collect_xrefs(program, writer, limit=200000):
    """Record references, resolving both ends to their containing function."""
    manager = program.getReferenceManager()
    function_manager = program.getFunctionManager()
    count = 0
    iterator = manager.getReferenceSourceIterator(program.getMinAddress(), True)
    while iterator.hasNext() and count < limit:
        from_address = iterator.next()
        for reference in manager.getReferencesFrom(from_address):
            to_address = reference.getToAddress()
            source = _addr(from_address)
            target = _addr(to_address)
            if source is None or target is None:
                continue
            ref_type = REF_TYPE_MAP.get(_text(reference.getReferenceType()).upper(), "unknown")
            from_function = function_manager.getFunctionContaining(from_address)
            to_function = function_manager.getFunctionAt(to_address)
            writer.add(
                "xrefs",
                {
                    "from_addr": source,
                    "to_addr": target,
                    "ref_type": ref_type,
                    "from_function": _text(from_function.getName()) if from_function else "",
                    "to_function": _text(to_function.getName()) if to_function else "",
                },
            )
            count += 1
            if count >= limit:
                break


def rank_functions(functions, program, interesting_names):
    """Order functions by how much a reviewer is likely to want the source.

    Functions that reach a named risky API come first, then large functions.
    Ghidra decides nothing about risk here - the name list is supplied by
    Aether, so the policy stays on Aether's side of the bridge.
    """
    wanted = set()
    for name in interesting_names:
        cleaned = name.strip()
        if cleaned:
            wanted.add(cleaned.lower())

    ranked = []
    for function, record in functions:
        if record["is_external"] or record["is_thunk"]:
            continue
        score = 0
        try:
            for called in function.getCalledFunctions(None):
                if _text(called.getName()).lower().lstrip("_") in wanted:
                    score += 10
        except Exception:
            pass
        if record["name"].lower() in ("main", "entry", "_start", "wmain"):
            score += 5
        ranked.append((-score, -record["size"], record["addr_start"], function, record))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [(item[3], item[4]) for item in ranked]


def collect_decompilation(program, writer, functions, limit, interesting_names):
    if DecompInterface is None or limit <= 0:
        return 0
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()
    written = 0
    try:
        for function, record in rank_functions(functions, program, interesting_names):
            if written >= limit:
                break
            try:
                results = decompiler.decompileFunction(
                    function, DECOMPILE_TIMEOUT_SECONDS, monitor
                )
            except Exception:
                continue
            if results is None or not results.decompileCompleted():
                continue
            decompiled = results.getDecompiledFunction()
            if decompiled is None:
                continue
            code = _text(decompiled.getC())
            if not code:
                continue
            writer.add(
                "decompilation",
                {
                    "function_addr": record["addr_start"],
                    "function_name": record["name"],
                    "code": code,
                    "decompiler": "ghidra",
                    "line_count": code.count("\n") + 1,
                },
            )
            written += 1
    finally:
        decompiler.dispose()
    return written


def main():
    args = getScriptArgs()  # noqa: F821 - injected by Ghidra
    program = currentProgram  # noqa: F821 - injected by Ghidra

    out_dir = args[0] if len(args) > 0 else (program.getName() + ".aether")
    try:
        decompile_limit = int(args[1]) if len(args) > 1 else DEFAULT_DECOMPILE_LIMIT
    except ValueError:
        decompile_limit = DEFAULT_DECOMPILE_LIMIT
    interesting = args[2].split(",") if len(args) > 2 else []

    writer = Writer(out_dir)
    collect_memory_blocks(program, writer)
    functions = collect_functions(program, writer)
    collect_strings(program, writer)
    collect_symbols(program, writer)
    collect_xrefs(program, writer)
    decompiled = collect_decompilation(
        program, writer, functions, decompile_limit, interesting
    )

    sort_keys = {
        "sections": lambda r: (r.get("addr_start") or 0, r.get("name") or ""),
        "functions": lambda r: (r.get("addr_start") or 0, r.get("name") or ""),
        "strings": lambda r: (r.get("addr") or 0, r.get("text") or ""),
        "symbols": lambda r: (r.get("addr") or 0, r.get("name") or ""),
        "imports": lambda r: (r.get("name") or "", r.get("library") or ""),
        "exports": lambda r: (r.get("addr") or 0, r.get("name") or ""),
        "xrefs": lambda r: (
            r.get("from_addr") or 0,
            r.get("to_addr") or 0,
            r.get("ref_type") or "",
        ),
        "decompilation": lambda r: (r.get("function_addr") or 0,),
    }
    counts = writer.flush(sort_keys)

    language = program.getLanguage()
    meta = {
        "format": EXPORT_FORMAT,
        "program": _text(program.getName()),
        "executable_path": _text(program.getExecutablePath()),
        "executable_format": _text(program.getExecutableFormat()),
        "executable_sha256": _text(program.getExecutableSHA256()),
        "executable_md5": _text(program.getExecutableMD5()),
        "language_id": _text(language.getLanguageID()),
        "processor": _text(language.getProcessor()),
        "address_size": int(language.getLanguageDescription().getSize()),
        "endian": "big" if language.isBigEndian() else "little",
        "compiler_spec": _text(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": _addr(program.getImageBase()),
        "ghidra_version": _text(
            program.getMetadata().get("Created With Ghidra Version") or "unknown"
        ),
        "counts": counts,
        "decompiled": decompiled,
    }
    meta_path = os.path.join(out_dir, "meta.json")
    handle = open(meta_path, "wb")
    try:
        payload = json.dumps(meta, sort_keys=True, indent=2)
        if not isinstance(payload, bytes):
            payload = payload.encode("utf-8")
        handle.write(payload)
    finally:
        handle.close()

    print("[aether] exported to {0}".format(out_dir))
    for stream in sorted(counts.keys()):
        print("[aether]   {0}: {1}".format(stream, counts[stream]))


main()
