"""Light QEMU user-mode integration for basic reachability.

Answers one question: which recovered functions actually executed on a given
input. That turns "this binary imports system()" into "this binary imports
system() and run_diagnostics ran", which is the difference between attack
surface and observed behaviour.

Deliberately light, as Phase 1 specifies. No full-system emulation, no NVRAM
faking, no network stubbing - the things firmware rehosting frameworks exist
for. This runs a single user-mode binary under an emulator and records which
blocks were entered.

SAFETY, stated plainly and repeated in the CLI
----------------------------------------------
``qemu-user`` is an *emulator, not a sandbox*. It translates guest
instructions, but system calls are passed through to the host kernel. A binary
run this way can read your files, open network connections, and delete data,
exactly as a native process could. Firmware binaries are frequently hostile.

Because of that, execution never happens implicitly. ``aether analyze`` will
not invoke this adapter; a caller must pass ``allow_execution=True``, and the
CLI requires an explicit ``--allow-execution`` flag. Run untrusted targets in a
disposable virtual machine or container, never on a workstation you care about.

Recording and importing are split, as with Ghidra: a trace captured on an
isolated machine can be imported anywhere with ``aether import-trace``.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Any

from aether.adapters.base import Adapter, AdapterResult, Availability, run_process, which
from aether.adapters.qemu import trace as trace_parser
from aether.errors import AdapterError
from aether.evidence.models import EvidenceRef
from aether.project.store import Project
from aether.util import utc_now

#: Normalized architecture -> qemu-user binary name.
QEMU_BINARIES: dict[str, tuple[str, ...]] = {
    "x86_64": ("qemu-x86_64",),
    "x86": ("qemu-i386",),
    "arm": ("qemu-arm",),
    "aarch64": ("qemu-aarch64",),
    "mips": ("qemu-mips", "qemu-mipsel"),
    "ppc": ("qemu-ppc",),
    "ppc64": ("qemu-ppc64",),
    "riscv": ("qemu-riscv64",),
    "sparc": ("qemu-sparc",),
}

#: Default wall-clock ceiling for one traced run. Short on purpose: a
#: reachability probe is not a fuzzing campaign, and an emulated binary that
#: blocks on input would otherwise hang the command.
DEFAULT_TIMEOUT_SECONDS = 15

#: Cap on trace_hit artifacts written per run.
MAX_TRACE_ARTIFACTS = 5000


class QemuAdapter(Adapter):
    """Record which functions execute, under QEMU user-mode emulation."""

    name = "qemu"
    tool = "qemu-user"

    def __init__(self, arch: str | None = None, binary: str | None = None) -> None:
        self.arch = arch
        self._binary = binary or self._locate(arch)

    @staticmethod
    def _locate(arch: str | None) -> str | None:
        candidates: tuple[str, ...] = ()
        if arch and arch in QEMU_BINARIES:
            candidates = QEMU_BINARIES[arch]
        else:
            candidates = tuple(
                name for names in QEMU_BINARIES.values() for name in names
            )
        return which(*candidates)

    def probe(self) -> Availability:
        if not self._binary:
            wanted = (
                ", ".join(QEMU_BINARIES.get(self.arch, ()))
                if self.arch
                else "qemu-x86_64, qemu-arm, qemu-mips, ..."
            )
            return Availability(
                available=False,
                detail=f"no QEMU user-mode emulator found ({wanted})",
                remedy=(
                    "Install the qemu-user package - 'apt install qemu-user' on "
                    "Debian and Ubuntu, 'brew install qemu' on macOS. Traces "
                    "recorded elsewhere can be imported without it: "
                    "aether import-trace <log> --object <file>."
                ),
                cost=(
                    "No reachability evidence. Attack-surface answers report "
                    "which APIs are referenced but not which code actually ran."
                ),
            )
        result = run_process([self._binary, "-version"], timeout=30)
        version = "unknown"
        match = re.search(
            r"version\s+([0-9]+\.[0-9.]+)", (result.stdout or "") + (result.stderr or "")
        )
        if match:
            version = match.group(1)
        return Availability(available=True, version=version, detail=self._binary)

    # -- recording --------------------------------------------------------

    def analyze(
        self,
        project: Project,
        target: str,
        *,
        object_id: str | None = None,
        argv: list[str] | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        allow_execution: bool = False,
        load_base: int | None = None,
        keep_log: bool = False,
    ) -> AdapterResult:
        """Run ``target`` under QEMU and import the resulting trace.

        ``allow_execution`` is not a formality. This executes the target, and
        qemu-user does not contain what it executes.
        """
        if not allow_execution:
            raise AdapterError(
                "refusing to execute the target. Tracing runs the binary, and "
                "qemu-user is an emulator rather than a sandbox: its system "
                "calls reach the host kernel. Pass allow_execution=True (or "
                "--allow-execution) once you are running in a disposable "
                "environment."
            )
        availability = self.require()
        if not os.path.isfile(target):
            raise AdapterError(f"not a file: {target}")

        log_dir = os.path.join(project.work_dir, "qemu")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(
            log_dir, f"{os.path.basename(target)}-{utc_now().replace(':', '')}.log"
        )

        command = [
            self._binary,
            "-d",
            "exec,nochain",
            "-D",
            log_path,
            os.path.abspath(target),
            *(argv or []),
        ]
        # Run from a scratch directory so anything the target writes relative
        # to its working directory lands somewhere disposable.
        with tempfile.TemporaryDirectory(prefix="aether-qemu-") as scratch:
            result = run_process(command, timeout=timeout, cwd=scratch)

        warnings: list[str] = []
        if result.returncode != 0:
            warnings.append(
                f"the traced process exited {result.returncode}; a partial trace "
                "is still usable, and a non-zero exit is normal for a binary run "
                "without its expected environment"
            )
        if not os.path.isfile(log_path):
            raise AdapterError(
                f"QEMU produced no trace log at {log_path}. Its logging flags "
                "vary by build; try '-d in_asm' manually to confirm the build "
                "supports tracing."
            )

        parsed = trace_parser.parse_trace_file(log_path)
        outcome = self._import(
            project,
            parsed,
            target=target,
            object_id=object_id,
            tool_version=availability.version,
            load_base=load_base,
            run_label=" ".join(argv or []) or "(no arguments)",
            extra_warnings=warnings,
        )
        if not keep_log:
            try:
                os.remove(log_path)
            except OSError:
                pass
        return outcome

    # -- importing ---------------------------------------------------------

    def import_trace(
        self,
        project: Project,
        log_path: str,
        *,
        object_id: str | None = None,
        target: str | None = None,
        load_base: int | None = None,
        run_label: str = "",
    ) -> AdapterResult:
        """Import a QEMU log recorded elsewhere - on an isolated machine, say."""
        if not os.path.isfile(log_path):
            raise AdapterError(f"no such trace log: {log_path}")
        parsed = trace_parser.parse_trace_file(log_path)
        return self._import(
            project,
            parsed,
            target=target,
            object_id=object_id,
            tool_version="imported",
            load_base=load_base,
            run_label=run_label or os.path.basename(log_path),
            extra_warnings=[],
        )

    def _import(
        self,
        project: Project,
        parsed: trace_parser.Trace,
        *,
        target: str | None,
        object_id: str | None,
        tool_version: str,
        load_base: int | None,
        run_label: str,
        extra_warnings: list[str],
    ) -> AdapterResult:
        from aether.adapters.triage import TriageAdapter

        warnings = list(extra_warnings) + list(parsed.warnings)

        with project.run(
            tool=self.tool,
            tool_version=tool_version,
            adapter=self.name,
            params={"run_label": run_label, "trace_format": parsed.format},
            input_digest="",
        ) as rc:
            if object_id is None:
                if target is None:
                    raise AdapterError(
                        "a trace must be attached to something: pass --object "
                        "for a file already in the project, or --target for the "
                        "binary that was traced"
                    )
                artifact, _ident, _details = TriageAdapter().triage_into(
                    rc, project, target, source="ingest", emit_strings=False
                )
                object_id = artifact.artifact_id

            functions = _function_ranges(project, object_id)
            if not functions:
                warnings.append(
                    "no function artifacts exist for this object, so addresses "
                    "cannot be attributed. Run Ghidra over it first; the trace "
                    "is recorded but yields no reachability claims."
                )

            addresses = parsed.addresses
            base = load_base
            if base is None and functions and addresses:
                base = trace_parser.infer_load_base(
                    addresses, {start for start, _end, _name in functions}
                )
                if base:
                    warnings.append(
                        f"inferred a load base of 0x{base:x}; the target looks "
                        "position-independent, so trace addresses were adjusted "
                        "to match its static layout"
                    )

            counts = _attribute(parsed, functions, base or 0)
            written = 0
            for (start, name), (hits, sample_addr) in sorted(counts.items()):
                if written >= MAX_TRACE_ARTIFACTS:
                    break
                hit_artifact = rc.artifact(
                    "trace_hit",
                    {
                        "addr": sample_addr,
                        "tool": self.tool,
                        "hit_count": hits,
                        "function_name": name,
                        "run_label": run_label,
                    },
                    object_id=object_id,
                )
                written += 1

                function_artifact = _find_function_artifact(project, object_id, start, name)
                if function_artifact is None:
                    continue
                rc.add_claim(
                    "function_reached",
                    {
                        "name": name,
                        "addr": start,
                        "observed_by": "qemu_user",
                        "hit_count": hits,
                    },
                    [
                        EvidenceRef(function_artifact.artifact_id, "locus"),
                        EvidenceRef(hit_artifact.artifact_id, "support"),
                    ],
                    subject_id=object_id,
                    # Execution was observed; the uncertainty is only in whether
                    # the address mapping is right, which the load-base
                    # inference makes explicit.
                    confidence=0.95 if load_base is not None or base in (0, None) else 0.85,
                    producer="aether-qemu",
                    method=f"qemu-{parsed.format}",
                )

            if addresses and not counts and functions:
                warnings.append(
                    f"none of the {len(addresses)} traced addresses fell inside a "
                    "known function. If the target is position-independent, pass "
                    "--load-base with the address it was loaded at."
                )

            result = AdapterResult(
                adapter=self.name,
                run_id=rc.run.run_id,
                artifacts=rc.artifacts_written,
                artifacts_new=rc.artifacts_new,
                claims=rc.claims_written,
                claims_new=rc.claims_new,
                objects=[object_id],
                warnings=warnings,
                details={
                    "trace_format": parsed.format,
                    "distinct_addresses": len(addresses),
                    "functions_reached": len(counts),
                    "functions_known": len(functions),
                    "load_base": base or 0,
                    "run_label": run_label,
                },
            )
        return result


def _function_ranges(project: Project, object_id: str) -> list[tuple[int, int, str]]:
    """Sorted (start, end, name) for every function artifact on this object."""
    ranges: list[tuple[int, int, str]] = []
    for artifact in project.find_artifacts(
        kind="function", object_id=object_id, limit=5000
    ):
        start = artifact.data.get("addr_start")
        if not isinstance(start, int):
            continue
        end = artifact.data.get("addr_end")
        size = artifact.data.get("size")
        if not isinstance(end, int):
            end = start + (size if isinstance(size, int) else 1)
        ranges.append((start, max(end, start + 1), str(artifact.data.get("name") or "")))
    ranges.sort()
    return ranges


def _attribute(
    parsed: trace_parser.Trace,
    functions: list[tuple[int, int, str]],
    base: int,
) -> dict[tuple[int, str], tuple[int, int]]:
    """Map trace events onto functions: (start, name) -> (hits, sample addr)."""
    counts: dict[tuple[int, str], tuple[int, int]] = {}
    for event in parsed.events:
        static = event.addr - base
        for start, end, name in functions:
            if start <= static < end:
                hits, sample = counts.get((start, name), (0, static))
                counts[(start, name)] = (hits + event.hit_count, min(sample, static))
                break
    return counts


def _find_function_artifact(
    project: Project, object_id: str, start: int, name: str
) -> Any:
    for artifact in project.find_artifacts(
        kind="function", object_id=object_id, addr=start, limit=20
    ):
        if artifact.data.get("addr_start") == start and artifact.data.get("name") == name:
            return artifact
    return None


def probe() -> Availability:
    return QemuAdapter().probe()


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "QEMU_BINARIES",
    "QemuAdapter",
    "probe",
    "trace",
]
