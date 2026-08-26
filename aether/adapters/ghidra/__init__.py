"""Ghidra headless adapter: locate the install, run it, import what it exports.

Aether does not disassemble, decompile, or recover control flow. Ghidra does
all of that, and this module's entire job is to hand it a file and turn its
answers into evidence. If a future release of Ghidra gets better at any of
those things, Aether inherits the improvement without a line changing here.

The adapter is usable in three ways, in decreasing order of environmental
requirements:

``analyze``
    Run Ghidra headless, then import. Needs a Ghidra install and a JVM.
``import_directory``
    Import an export produced elsewhere - a colleague's machine, a build
    server, a container. Needs nothing.
``importer.import_export``
    Import an already-parsed export. Needs nothing, and is what the tests use.
"""

from __future__ import annotations

import os
import re
import shutil
from typing import Any

from aether.adapters.base import Adapter, AdapterResult, Availability, run_process, which
from aether.adapters.ghidra import importer
from aether.adapters.triage import TriageAdapter
from aether.adapters.triage.detectors import RISKY_APIS
from aether.errors import AdapterError, AdapterUnavailable
from aether.project.store import Project
from aether.util import utc_now

#: Environment variables checked, in order, when locating an install.
GHIDRA_ENV_VARS = ("AETHER_GHIDRA_HOME", "GHIDRA_INSTALL_DIR", "GHIDRA_HOME")

#: Default ceiling on decompiled functions per binary. Decompilation is by far
#: the slowest part of a headless run, and the graph rarely needs all of it.
DEFAULT_DECOMPILE_LIMIT = 40

_SCRIPT_NAME = "AetherExport.py"

#: Name of the throwaway Ghidra project created per run; it is deleted after.
GHIDRA_PROJECT_NAME = "aether"

#: Ceiling on Ghidra's auto-analysis for a single file.
ANALYSIS_TIMEOUT_SECONDS = 1200


def scripts_dir() -> str:
    """Directory holding the Ghidra-side export script."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")


def find_headless() -> str | None:
    """Locate ``analyzeHeadless``, checking env vars, PATH, then usual places."""
    executable = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"

    for variable in GHIDRA_ENV_VARS:
        root = os.environ.get(variable)
        if not root:
            continue
        for candidate in (
            os.path.join(root, "support", executable),
            os.path.join(root, executable),
        ):
            if os.path.isfile(candidate):
                return candidate

    found = which(executable, "analyzeHeadless")
    if found:
        return found

    for base in _candidate_roots():
        candidate = os.path.join(base, "support", executable)
        if os.path.isfile(candidate):
            return candidate
    return None


def _candidate_roots() -> list[str]:
    """Conventional install locations, newest-looking first."""
    roots: list[str] = []
    home = os.path.expanduser("~")
    parents = [
        home,
        os.path.join(home, "tools"),
        "/opt",
        "/usr/share",
        "/usr/local/share",
        "C:\\",
        "C:\\tools",
        "C:\\Program Files",
    ]
    for parent in parents:
        try:
            entries = os.listdir(parent)
        except OSError:
            continue
        for entry in sorted(entries, reverse=True):
            if entry.lower().startswith("ghidra"):
                roots.append(os.path.join(parent, entry))
    return roots


class GhidraAdapter(Adapter):
    """Bridge to Ghidra's headless analyzer."""

    name = "ghidra"
    tool = "ghidra"

    def __init__(self, headless: str | None = None) -> None:
        self._headless = headless or find_headless()

    def probe(self) -> Availability:
        if not self._headless:
            return Availability(
                available=False,
                detail="analyzeHeadless was not found",
                remedy=(
                    "Install Ghidra (https://ghidra-sre.org) and set "
                    "GHIDRA_INSTALL_DIR to its directory, or put support/"
                    "analyzeHeadless on PATH. Ghidra needs a JDK 21+ on PATH too. "
                    "Exports produced elsewhere can be imported without any of "
                    "this: aether import-ghidra <dir> --object <file>."
                ),
            )
        if not _java_available():
            return Availability(
                available=False,
                version=_ghidra_version(self._headless),
                detail=f"found {self._headless} but no Java runtime on PATH",
                remedy=(
                    "Install a JDK 21 or newer and ensure 'java' is on PATH, or "
                    "set JAVA_HOME. Ghidra headless cannot start without it."
                ),
            )
        return Availability(
            available=True,
            version=_ghidra_version(self._headless),
            detail=self._headless,
        )

    # -- running ----------------------------------------------------------

    def analyze(
        self,
        project: Project,
        target: str,
        *,
        logical_path: str | None = None,
        decompile_limit: int = DEFAULT_DECOMPILE_LIMIT,
        timeout: int = 1800,
        keep_export: bool = False,
        extra_args: list[str] | None = None,
    ) -> AdapterResult:
        """Run Ghidra headless over ``target`` and import the result."""
        availability = self.require()
        if not os.path.isfile(target):
            raise AdapterError(f"not a file: {target}")

        triage = TriageAdapter()
        export_dir = os.path.join(
            project.work_dir, "ghidra", f"{os.path.basename(target)}-{_stamp()}"
        )
        ghidra_project_dir = os.path.join(project.work_dir, "ghidra", "projects")
        os.makedirs(export_dir, exist_ok=True)
        os.makedirs(ghidra_project_dir, exist_ok=True)

        argv = self._build_argv(
            target, export_dir, ghidra_project_dir, decompile_limit, extra_args or []
        )
        result = run_process(argv, timeout=timeout)
        log_tail = ((result.stdout or "") + (result.stderr or ""))[-4000:]

        if not os.path.isfile(os.path.join(export_dir, "meta.json")):
            raise AdapterError(
                "Ghidra headless finished without producing an export "
                f"(exit {result.returncode}). Last output:\n{log_tail[-1500:]}"
            )

        export = importer.read_export(export_dir)
        try:
            outcome = self._import(
                project,
                export,
                target,
                logical_path=logical_path,
                triage=triage,
                tool_version=availability.version,
                params={"decompile_limit": decompile_limit},
            )
        finally:
            if not keep_export:
                shutil.rmtree(export_dir, ignore_errors=True)

        if result.returncode != 0:
            outcome.warnings.append(
                f"analyzeHeadless exited {result.returncode}; the export was still "
                "usable, but analysis may be incomplete"
            )
        return outcome

    def _build_argv(
        self,
        target: str,
        export_dir: str,
        ghidra_project_dir: str,
        decompile_limit: int,
        extra_args: list[str],
    ) -> list[str]:
        assert self._headless is not None
        # The risky-API list is passed *into* Ghidra so the export script can
        # rank which functions are worth the decompiler's time. The policy
        # stays here; Ghidra just applies it.
        interesting = ",".join(sorted(RISKY_APIS))

        argv = [
            self._headless,
            ghidra_project_dir,
            GHIDRA_PROJECT_NAME,
            "-import",
            os.path.abspath(target),
            "-scriptPath",
            scripts_dir(),
            "-postScript",
            _SCRIPT_NAME,
            os.path.abspath(export_dir),
            str(decompile_limit),
            interesting,
            "-deleteProject",
        ]

        # Callers can skip auto-analysis entirely (fast, but the export will
        # have no recovered functions). Otherwise cap how long Ghidra may spend
        # on one file, so a pathological binary cannot hang a batch.
        if "-noanalysis" in extra_args:
            argv.append("-noanalysis")
        else:
            argv.extend(["-analysisTimeoutPerFile", str(ANALYSIS_TIMEOUT_SECONDS)])

        argv.extend(arg for arg in extra_args if arg != "-noanalysis")
        return argv

    # -- importing --------------------------------------------------------

    def import_directory(
        self,
        project: Project,
        export_dir: str,
        *,
        target: str | None = None,
        object_id: str | None = None,
        logical_path: str | None = None,
    ) -> AdapterResult:
        """Import an export produced by a Ghidra run somewhere else.

        Needs either ``target`` (the original file, which gets ingested) or
        ``object_id`` (a file artifact already in the project). Without one of
        those there is nothing to attach the evidence to, and an unattached
        function artifact is not evidence of anything.
        """
        export = importer.read_export(export_dir)
        return self._import(
            project,
            export,
            target,
            object_id=object_id,
            logical_path=logical_path,
            triage=TriageAdapter(),
            tool_version=str(export["meta"].get("ghidra_version") or "unknown"),
            params={"export_dir": os.path.basename(export_dir)},
        )

    def _import(
        self,
        project: Project,
        export: dict[str, Any],
        target: str | None,
        *,
        triage: TriageAdapter,
        tool_version: str,
        params: dict[str, Any],
        object_id: str | None = None,
        logical_path: str | None = None,
    ) -> AdapterResult:
        meta = export.get("meta", {})
        warnings: list[str] = []

        with project.run(
            tool=self.tool,
            tool_version=tool_version,
            adapter=self.name,
            params=params,
            input_digest=str(meta.get("executable_sha256") or ""),
        ) as rc:
            if object_id is None:
                if target is None:
                    resolved = _resolve_by_digest(project, meta)
                    if resolved is None:
                        raise AdapterError(
                            "cannot attach this export to anything: pass --object "
                            "with a file already in the project, or --target with "
                            "the original binary"
                        )
                    object_id = resolved
                else:
                    artifact, _ident, _details = triage.triage_into(
                        rc,
                        project,
                        target,
                        logical_path=logical_path,
                        source="ingest",
                        # Ghidra's own string table is better located than a raw
                        # scan; letting triage also scan would add lower-quality
                        # duplicates of the same literals.
                        emit_strings=False,
                    )
                    object_id = artifact.artifact_id

            counts = importer.import_export(rc, project, export, object_id)

            recorded_digest = str(meta.get("executable_sha256") or "").lower()
            subject = project.get_artifact(object_id)
            if subject and recorded_digest:
                actual = str(subject.data.get("sha256") or "").lower()
                if actual and recorded_digest and actual != recorded_digest:
                    warnings.append(
                        "the export's recorded SHA-256 does not match the file it "
                        "was attached to; the evidence may describe a different "
                        "binary"
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
                details={**importer.summarize(export), "imported": counts},
            )
        return result


def _resolve_by_digest(project: Project, meta: dict[str, Any]) -> str | None:
    """Find an already-ingested file matching the export's recorded digest."""
    digest = str(meta.get("executable_sha256") or "").lower()
    if not digest:
        return None
    for artifact in project.objects():
        if str(artifact.data.get("sha256") or "").lower() == digest:
            return artifact.artifact_id
    return None


def _java_available() -> bool:
    if which("java", "java.exe"):
        return True
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        binary = "java.exe" if os.name == "nt" else "java"
        return os.path.isfile(os.path.join(java_home, "bin", binary))
    return False


def _ghidra_version(headless_path: str) -> str:
    """Read the version out of the install's application properties."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(headless_path)))
    properties = os.path.join(root, "Ghidra", "application.properties")
    try:
        with open(properties, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = re.match(r"\s*application\.version\s*=\s*(\S+)", line)
                if match:
                    return match.group(1)
    except OSError:
        pass
    return "unknown"


def _stamp() -> str:
    return utc_now().replace(":", "").replace("-", "").replace(".", "")[:15]


def probe() -> Availability:
    return GhidraAdapter().probe()


__all__ = [
    "AdapterUnavailable",
    "GhidraAdapter",
    "find_headless",
    "importer",
    "probe",
    "scripts_dir",
]
