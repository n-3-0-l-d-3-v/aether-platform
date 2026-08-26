"""File ingestion: content-addressed blob storage and ``file`` artifacts.

Ingested bytes are copied into the project's blob store, sharded by digest.
A project is then self-contained: a firmware image can be deleted from the
user's Downloads folder and every carved file it produced is still analysable,
still hashed, still addressable by the same artifact ids.

Shared by every adapter that brings a new file into the graph - the top-level
ingest path and the firmware extractor alike - so that "a file entered the
project" means exactly one thing.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

from aether.adapters.triage import formats
from aether.canonical import file_digests
from aether.errors import IngestError
from aether.evidence.models import Artifact, EvidenceRef
from aether.project.store import Project, RunContext
from aether.util import logical_path as normalize_path


def blob_path(project: Project, sha256: str) -> str:
    """Where a blob with this digest lives inside the project."""
    return os.path.join(project.blobs_dir, sha256[:2], sha256)


def store_blob(project: Project, source_path: str, sha256: str) -> str:
    """Copy a file into the blob store; a no-op when it is already there."""
    destination = blob_path(project, sha256)
    if os.path.exists(destination):
        return destination
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    temporary = destination + ".partial"
    shutil.copyfile(source_path, temporary)
    os.replace(temporary, destination)
    return destination


def resolve_bytes(project: Project, artifact: Artifact) -> str:
    """Filesystem path holding a file artifact's bytes."""
    sha256 = artifact.data.get("sha256")
    if not sha256:
        raise IngestError(f"artifact {artifact.artifact_id} has no digest")
    path = blob_path(project, str(sha256))
    if not os.path.exists(path):
        raise IngestError(
            f"blob for {artifact.data.get('path')} is missing from the project store "
            f"(expected {path})"
        )
    return path


def ingest_file(
    rc: RunContext,
    project: Project,
    source_path: str,
    *,
    logical_path: str | None = None,
    source: str = "ingest",
    parent_id: str | None = None,
    identification: formats.Identification | None = None,
    emit_format_claim: bool = True,
    producer: str = "aether-triage",
) -> tuple[Artifact, formats.Identification]:
    """Bring one file into the project as a ``file`` artifact.

    Returns the artifact and the identification, so callers can go on to
    record sections, symbols, and strings without re-reading headers.
    """
    if not os.path.isfile(source_path):
        raise IngestError(f"not a file: {source_path}")

    digests = file_digests(source_path)
    ident = identification or formats.identify_file(source_path)
    path = normalize_path(logical_path or os.path.basename(source_path))

    store_blob(project, source_path, digests["sha256"])
    artifact = rc.artifact(
        "file",
        ident.file_data(path=path, digests=digests, source=source),
        parent_id=parent_id,
    )

    if emit_format_claim:
        statement: dict[str, Any] = {"format": ident.format}
        if ident.arch:
            statement["arch"] = ident.arch
        if ident.bits:
            statement["bits"] = ident.bits
        if ident.endian:
            statement["endian"] = ident.endian
        # Header identification is definitional, not inferential: the magic
        # bytes either say ELF or they do not. Anything short of a clean parse
        # already downgraded `format` to "data", so the confidence sits on the
        # parse succeeding rather than on a judgment call.
        confidence = 0.99 if ident.format not in ("unknown", "data") else 0.7
        rc.add_claim(
            "file_format_identified",
            statement,
            [EvidenceRef(artifact.artifact_id, "locus")],
            subject_id=artifact.artifact_id,
            confidence=confidence,
            producer=producer,
            method="header-magic",
        )

    return artifact, ident
