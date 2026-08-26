"""Firmware unpacking adapter.

Prefers binwalk when it is installed, because binwalk knows about squashfs,
jffs2, ubifs, and a hundred vendor formats that Aether has no business
reimplementing. Falls back to :mod:`aether.adapters.binwalk.carver` otherwise,
which handles the standard-library-decodable subset and *reports* what it could
only locate.

Either way the output is the same shape: ``file`` artifacts for what came out,
``signature_hit`` artifacts for where they were found, and
``firmware_contains_file`` claims tying the two together. A consumer of the
evidence graph cannot tell which engine ran except by reading provenance -
which is the point.
"""

from __future__ import annotations

import os
import re
import shutil
from typing import Any

from aether.adapters.base import Adapter, AdapterResult, Availability, run_process, which
from aether.adapters.binwalk import carver
from aether.adapters.triage import TriageAdapter
from aether.adapters.triage.formats import identify_file
from aether.errors import AdapterError
from aether.evidence.models import EvidenceRef
from aether.project.store import Project
from aether.util import logical_path as normalize_path
from aether.version import AETHER_VERSION

#: How deep to follow containers inside containers.
DEFAULT_MAX_DEPTH = 3

_BINWALK_ROW = re.compile(r"^\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(\S.*)$")

#: Formats that hold other files rather than being the thing of interest.
_CONTAINER_FORMATS = frozenset({"archive", "compressed", "filesystem"})

#: Formats worth another unpacking pass. "data" is included because vendor
#: headers and padding routinely hide a real container behind an offset.
_RECURSE_FORMATS = _CONTAINER_FORMATS | {"data"}

#: Single-stream wrappers: unpacking one yields a blob, not a directory tree.
_TRANSPARENT_CONTAINERS = frozenset({"gzip", "bzip2", "xz"})


class BinwalkAdapter(Adapter):
    """Unpack a firmware image and inventory what it contains."""

    name = "binwalk"
    tool = "binwalk"

    def __init__(self, *, prefer_binwalk: bool = True) -> None:
        self.prefer_binwalk = prefer_binwalk
        self._binary = which("binwalk", "binwalk.exe")

    def probe(self) -> Availability:
        if not self._binary:
            return Availability(
                available=False,
                detail="binwalk was not found on PATH",
                remedy=(
                    "Install it with 'pip install binwalk' or from "
                    "https://github.com/ReFirmLabs/binwalk. Without it Aether falls "
                    "back to its built-in carver, which handles gzip/bzip2/xz/zip/"
                    "tar/cpio and identifies (but cannot unpack) squashfs, jffs2, "
                    "and ubifs."
                ),
            )
        result = run_process([self._binary, "--help"], timeout=60)
        version = "unknown"
        match = re.search(r"[Bb]inwalk\s+v?([0-9]+\.[0-9.]+)", result.stdout + result.stderr)
        if match:
            version = match.group(1)
        return Availability(available=True, version=version, detail=self._binary)

    @property
    def engine(self) -> str:
        """Which extraction engine this instance will actually use."""
        return "binwalk" if (self.prefer_binwalk and self._binary) else "aether-carver"

    def analyze(
        self,
        project: Project,
        image_path: str,
        *,
        logical_path: str | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        string_limit: int = 500,
        timeout: int = 900,
        keep_extracted: bool = False,
    ) -> AdapterResult:
        """Ingest a firmware image, unpack it, and triage everything inside."""
        if not os.path.isfile(image_path):
            raise AdapterError(f"not a file: {image_path}")

        engine = self.engine
        triage = TriageAdapter()
        warnings: list[str] = []
        inventory: list[dict[str, Any]] = []

        with project.run(
            tool=engine,
            tool_version=self.probe().version if engine == "binwalk" else AETHER_VERSION,
            adapter=self.name,
            params={"engine": engine, "max_depth": max_depth, "string_limit": string_limit},
            input_digest=os.path.basename(image_path),
        ) as rc:
            image_artifact, _ident, _details = triage.triage_into(
                rc,
                project,
                image_path,
                logical_path=logical_path or os.path.basename(image_path),
                source="ingest",
                string_limit=string_limit,
            )

            work_root = os.path.join(project.work_dir, f"extract-{rc.run.run_id}")
            os.makedirs(work_root, exist_ok=True)
            try:
                queue: list[tuple[str, str, str, int]] = [
                    (image_path, "", image_artifact.artifact_id, 0)
                ]
                seen_paths: set[str] = set()

                while queue:
                    current, prefix, parent_id, depth = queue.pop(0)
                    if depth > max_depth:
                        continue
                    stage = os.path.join(work_root, f"d{depth}-{len(seen_paths)}")
                    os.makedirs(stage, exist_ok=True)

                    hits, entries, notes = self._unpack(current, stage, engine, timeout)
                    warnings.extend(notes)

                    hit_by_offset: dict[int, str] = {}
                    for hit in hits:
                        hit_artifact = rc.artifact(
                            "signature_hit", hit.to_data(), object_id=parent_id
                        )
                        hit_by_offset[hit.offset] = hit_artifact.artifact_id

                    for entry in entries:
                        member_path = normalize_path(
                            posix_join(prefix, entry.path) if prefix else entry.path
                        )
                        if member_path in seen_paths:
                            continue
                        seen_paths.add(member_path)

                        child_ident = identify_file(entry.disk_path)
                        # A container that we are about to unpack would report
                        # its members' strings a second time, under its own
                        # name. Attribute findings to the file they belong to,
                        # not to the archive that happened to hold it.
                        is_container = child_ident.format in _CONTAINER_FORMATS
                        child, child_ident, _child_details = triage.triage_into(
                            rc,
                            project,
                            entry.disk_path,
                            logical_path=member_path,
                            source="extract",
                            parent_id=parent_id,
                            string_limit=string_limit,
                            emit_strings=not is_container,
                        )

                        evidence = [EvidenceRef(child.artifact_id, "locus")]
                        context_id = hit_by_offset.get(entry.source_offset)
                        if context_id:
                            evidence.append(EvidenceRef(context_id, "context"))
                        rc.add_claim(
                            "firmware_contains_file",
                            {"path": member_path, "format": child_ident.format},
                            evidence,
                            subject_id=parent_id,
                            # Extraction is mechanical: the bytes were produced by
                            # a decoder, not inferred. What stays uncertain is the
                            # original path when a container did not record one.
                            confidence=0.97,
                            producer=engine,
                            method=f"extract:{entry.via}",
                        )
                        inventory.append(
                            {
                                "path": member_path,
                                "format": child_ident.format,
                                "arch": child_ident.arch,
                                "size": entry.size,
                                "artifact_id": child.artifact_id,
                            }
                        )

                        if depth < max_depth and child_ident.format in _RECURSE_FORMATS:
                            # A gzip/xz/bzip2 stream is a wrapper, not a
                            # directory. Its contents belong at the enclosing
                            # path, so that a real file lands on "bin/busybox"
                            # rather than "0001a000.gunzipped/bin/busybox".
                            child_prefix = (
                                prefix if entry.via in _TRANSPARENT_CONTAINERS else member_path
                            )
                            queue.append(
                                (entry.disk_path, child_prefix, child.artifact_id, depth + 1)
                            )
            finally:
                if not keep_extracted:
                    shutil.rmtree(work_root, ignore_errors=True)

            result = AdapterResult(
                adapter=self.name,
                run_id=rc.run.run_id,
                artifacts=rc.artifacts_written,
                artifacts_new=rc.artifacts_new,
                claims=rc.claims_written,
                claims_new=rc.claims_new,
                objects=[image_artifact.artifact_id],
                warnings=warnings,
                details={
                    "engine": engine,
                    "image": image_artifact.data.get("path"),
                    "extracted": len(inventory),
                    "inventory": inventory[:200],
                },
            )
        return result

    # -- extraction engines ----------------------------------------------

    def _unpack(
        self, path: str, out_dir: str, engine: str, timeout: int
    ) -> tuple[list[carver.SignatureHit], list[carver.ExtractedEntry], list[str]]:
        if engine == "binwalk":
            return self._unpack_with_binwalk(path, out_dir, timeout)
        return self._unpack_with_carver(path, out_dir)

    def _unpack_with_carver(
        self, path: str, out_dir: str
    ) -> tuple[list[carver.SignatureHit], list[carver.ExtractedEntry], list[str]]:
        with open(path, "rb") as handle:
            data = handle.read(carver.MAX_EXTRACTED_BYTES)
        hits = carver.scan(data)
        entries, notes = carver.extract(data, hits, out_dir)
        return hits, entries, notes

    def _unpack_with_binwalk(
        self, path: str, out_dir: str, timeout: int
    ) -> tuple[list[carver.SignatureHit], list[carver.ExtractedEntry], list[str]]:
        """Shell out to binwalk and adopt whatever it produced.

        binwalk's own extraction layout varies by version, so rather than
        predicting it, this walks the output directory and takes what is there.
        """
        assert self._binary is not None
        notes: list[str] = []
        argv = [self._binary, "--extract", "--quiet", "--directory", out_dir, path]
        result = run_process(argv, timeout=timeout, cwd=out_dir)
        if result.returncode != 0 and "directory" in (result.stderr or "").lower():
            argv = [self._binary, "-e", "-q", path]
            result = run_process(argv, timeout=timeout, cwd=out_dir)
        if result.returncode != 0:
            notes.append(
                f"binwalk exited {result.returncode}: "
                f"{(result.stderr or result.stdout or '').strip()[:300]}"
            )

        hits: list[carver.SignatureHit] = []
        for line in (result.stdout or "").splitlines():
            match = _BINWALK_ROW.match(line)
            if not match or line.lstrip().startswith("DECIMAL"):
                continue
            offset = int(match.group(1))
            description = match.group(3).strip()
            hits.append(
                carver.SignatureHit(
                    signature=_signature_name(description),
                    offset=offset,
                    format="data",
                    description=description,
                )
            )

        entries: list[carver.ExtractedEntry] = []
        for directory, _dirnames, filenames in os.walk(out_dir):
            for filename in sorted(filenames):
                disk_path = os.path.join(directory, filename)
                try:
                    size = os.path.getsize(disk_path)
                except OSError:
                    continue
                relative = os.path.relpath(disk_path, out_dir)
                entries.append(
                    carver.ExtractedEntry(
                        path=relative.replace(os.sep, "/"),
                        disk_path=disk_path,
                        size=size,
                        source_offset=hits[0].offset if hits else 0,
                        via="binwalk",
                    )
                )
        return hits, entries, notes


def posix_join(prefix: str, member: str) -> str:
    prefix = prefix.rstrip("/")
    member = member.lstrip("/")
    return f"{prefix}/{member}" if prefix else member


def _signature_name(description: str) -> str:
    """Reduce a binwalk description to a short, stable signature slug."""
    token = re.split(r"[ ,]", description.strip().lower(), maxsplit=1)[0]
    return re.sub(r"[^a-z0-9_]+", "_", token) or "unknown"


def probe() -> Availability:
    return BinwalkAdapter().probe()


__all__ = ["BinwalkAdapter", "carver", "probe"]
