"""Deterministic, Git-friendly export of a project's evidence graph.

The export is split into two trees, and the split is the whole design:

``graph/``
    Artifacts, claims, and claim links. Content-addressed, sorted by id, and
    free of timestamps, host paths, and run ids. Re-analysing the same bytes
    with the same engine versions produces byte-identical files here, so
    ``git diff`` shows exactly what the new analysis *discovered* - not that it
    ran again.

``ledger/``
    Runs, attestations, and observations. Inherently time-varying, because
    provenance is a record of events. This tree grows; that is correct.

Committing ``graph/`` and reviewing its diff is the intended workflow. A
reviewer sees three new claims, not three thousand changed timestamps.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterable, Iterator

from aether.canonical import canonical_json, content_digest
from aether.project.store import Project
from aether.util import utc_now
from aether.version import AETHER_VERSION, EXPORT_FORMAT_VERSION

#: Files that make up the deterministic half of an export.
GRAPH_STREAMS = ("artifacts", "claims", "claim_links")

#: Files that make up the provenance ledger.
LEDGER_STREAMS = ("runs", "attestations", "observations")


def export_project(
    project: Project,
    out_dir: str,
    *,
    stable_only: bool = False,
    include_annotations: bool = True,
) -> dict[str, Any]:
    """Write the project to ``out_dir`` and return the manifest.

    ``stable_only`` writes just ``graph/``, for the case where the export is
    being committed and provenance would only add churn.
    """
    os.makedirs(out_dir, exist_ok=True)
    graph_dir = os.path.join(out_dir, "graph")
    os.makedirs(graph_dir, exist_ok=True)

    written: dict[str, dict[str, Any]] = {}
    for stream in GRAPH_STREAMS:
        path = os.path.join(graph_dir, f"{stream}.jsonl")
        written[f"graph/{stream}.jsonl"] = _write_jsonl(path, _iter_stream(project, stream))

    if not stable_only:
        ledger_dir = os.path.join(out_dir, "ledger")
        os.makedirs(ledger_dir, exist_ok=True)
        for stream in LEDGER_STREAMS:
            path = os.path.join(ledger_dir, f"{stream}.jsonl")
            written[f"ledger/{stream}.jsonl"] = _write_jsonl(
                path, _iter_stream(project, stream)
            )
        if include_annotations:
            path = os.path.join(out_dir, "annotations.jsonl")
            written["annotations.jsonl"] = _write_jsonl(
                path, _iter_stream(project, "annotations")
            )

    info = project.info()
    project_record = {
        "format": f"aether.project.export/{EXPORT_FORMAT_VERSION}",
        "project_id": info["project_id"],
        "name": info["name"],
        "created_at": info["created_at"],
        "schema_version": info["schema_version"],
        "aether_version": AETHER_VERSION,
    }
    with open(os.path.join(out_dir, "project.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(project_record, fh, sort_keys=True, indent=2)
        fh.write("\n")

    manifest = {
        "format": f"aether.export.manifest/{EXPORT_FORMAT_VERSION}",
        "project_id": info["project_id"],
        "aether_version": AETHER_VERSION,
        "stable_only": stable_only,
        "files": {
            name: {"records": data["records"], "digest": data["digest"]}
            for name, data in sorted(written.items())
        },
        # Digest over the deterministic tree only. Two analyses that found the
        # same things share this value even though their ledgers differ.
        "graph_digest": content_digest(
            {
                name: written[name]["digest"]
                for name in sorted(written)
                if name.startswith("graph/")
            }
        ),
        "exported_at": utc_now(),
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, sort_keys=True, indent=2)
        fh.write("\n")
    return manifest


def _write_jsonl(path: str, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Write canonical JSON lines and return a digest over the content."""
    lines: list[str] = [canonical_json(record) for record in records]
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for line in lines:
            handle.write(line)
            handle.write("\n")
    return {"records": len(lines), "digest": content_digest(lines)}


def _iter_stream(project: Project, stream: str) -> Iterator[dict[str, Any]]:
    """Yield one stream's records in a stable order.

    Ordering is by content-addressed id throughout. Insertion order would make
    the export depend on which adapter happened to run first, which is exactly
    the kind of incidental churn the format exists to avoid.
    """
    conn = project._conn  # noqa: SLF001 - the export is part of the project layer

    if stream == "artifacts":
        for row in conn.execute(
            "SELECT artifact_id, kind, object_id, parent_id, data FROM artifacts "
            "ORDER BY artifact_id"
        ):
            record: dict[str, Any] = {
                "id": row["artifact_id"],
                "kind": row["kind"],
                "data": json.loads(row["data"]),
            }
            if row["object_id"]:
                record["object_id"] = row["object_id"]
            if row["parent_id"]:
                record["parent_id"] = row["parent_id"]
            yield record

    elif stream == "claims":
        for row in conn.execute(
            "SELECT claim_id, predicate, schema_id, subject_id, statement, status "
            "FROM claims ORDER BY claim_id"
        ):
            evidence = [
                {"role": e["role"], "artifact_id": e["artifact_id"]}
                for e in conn.execute(
                    "SELECT role, artifact_id FROM claim_evidence WHERE claim_id = ? "
                    "ORDER BY role, artifact_id",
                    (row["claim_id"],),
                )
            ]
            record = {
                "id": row["claim_id"],
                "schema": row["schema_id"],
                "predicate": row["predicate"],
                "statement": json.loads(row["statement"]),
                "evidence": evidence,
                "status": row["status"],
            }
            if row["subject_id"]:
                record["subject_id"] = row["subject_id"]
            yield record

    elif stream == "claim_links":
        for row in conn.execute(
            "SELECT src_claim_id, dst_claim_id, relation FROM claim_links "
            "ORDER BY src_claim_id, dst_claim_id, relation"
        ):
            yield {
                "src": row["src_claim_id"],
                "dst": row["dst_claim_id"],
                "relation": row["relation"],
            }

    elif stream == "runs":
        for row in conn.execute("SELECT * FROM runs ORDER BY started_at, run_id"):
            yield {
                "id": row["run_id"],
                "tool": row["tool"],
                "tool_version": row["tool_version"],
                "adapter": row["adapter"],
                "params": json.loads(row["params"]),
                "input_digest": row["input_digest"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "status": row["status"],
                "exit_code": row["exit_code"],
                "aether_version": row["aether_version"],
                "notes": row["notes"],
            }

    elif stream == "attestations":
        for row in conn.execute(
            "SELECT * FROM attestations ORDER BY claim_id, attestation_id"
        ):
            yield {
                "id": row["attestation_id"],
                "claim_id": row["claim_id"],
                "producer_kind": row["producer_kind"],
                "producer": row["producer"],
                "run_id": row["run_id"],
                "confidence": row["confidence"],
                "created_at": row["created_at"],
                "method": row["method"],
            }

    elif stream == "observations":
        for row in conn.execute(
            "SELECT artifact_id, run_id, observed_at FROM artifact_observations "
            "ORDER BY artifact_id, run_id"
        ):
            yield {
                "artifact_id": row["artifact_id"],
                "run_id": row["run_id"],
                "observed_at": row["observed_at"],
            }

    elif stream == "annotations":
        for row in conn.execute("SELECT * FROM annotations ORDER BY annotation_id"):
            yield {
                "id": row["annotation_id"],
                "target_kind": row["target_kind"],
                "target_id": row["target_id"],
                "author": row["author"],
                "body": row["body"],
                "created_at": row["created_at"],
            }

    else:  # pragma: no cover - guarded by the caller
        raise ValueError(f"unknown export stream {stream!r}")


def graph_digest(out_dir: str) -> str | None:
    """Read back the graph digest from an export directory's manifest."""
    path = os.path.join(out_dir, "manifest.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle).get("graph_digest")


__all__ = ["GRAPH_STREAMS", "LEDGER_STREAMS", "export_project", "graph_digest"]
