"""General evidence-graph diff.

The last of Phase 2's four asks, and the cheapest one to make honest: because
artifact and claim ids are content-addressed (ADR 0002), diffing two graphs is
a set difference over ids, not a structural comparison. An artifact present in
both snapshots with the same id is, by construction, the same artifact - its
identity fields have not changed, because if they had it would be a different
id. What differs between two analyses of the same or related targets is
exactly the set of ids each one produced.

This is therefore a much simpler tool than "diff two directory trees": there is
no need to match records by heuristics, because the id already encodes
identity. The complexity that remains is presentation - grouping by kind and
predicate so a human sees "3 new secrets, 1 removed function" rather than a
bare list of hashes.

A snapshot can come from a live project or from an exported ``graph/``
directory, so a diff can compare two open projects, two commits of an
exported graph, or one of each.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from yugen.errors import YugenError
from yugen.project.store import Project


class DiffError(YugenError):
    """A snapshot could not be loaded, or a diff request was malformed."""

    exit_code = 10


@dataclass(frozen=True)
class GraphSnapshot:
    """The comparable content of one project or export: ids to summaries."""

    label: str
    #: artifact id -> {"kind": str, "name": str | None}
    artifacts: dict[str, dict[str, Any]]
    #: claim id -> {"predicate": str, "statement": dict, "subject_path": str | None}
    claims: dict[str, dict[str, Any]]

    def to_record(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "artifact_count": len(self.artifacts),
            "claim_count": len(self.claims),
        }


@dataclass
class GraphDiff:
    """Result of comparing two snapshots."""

    baseline: str
    target: str
    added_artifacts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    removed_artifacts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    added_claims: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    removed_claims: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def identical(self) -> bool:
        return not any(
            (
                self.added_artifacts,
                self.removed_artifacts,
                self.added_claims,
                self.removed_claims,
            )
        )

    def to_record(self) -> dict[str, Any]:
        def counts(grouped: dict[str, list[Any]]) -> dict[str, int]:
            return {key: len(value) for key, value in sorted(grouped.items())}

        return {
            "baseline": self.baseline,
            "target": self.target,
            "identical": self.identical,
            "summary": {
                "artifacts_added": sum(len(v) for v in self.added_artifacts.values()),
                "artifacts_removed": sum(len(v) for v in self.removed_artifacts.values()),
                "claims_added": sum(len(v) for v in self.added_claims.values()),
                "claims_removed": sum(len(v) for v in self.removed_claims.values()),
            },
            "added_artifacts_by_kind": counts(self.added_artifacts),
            "removed_artifacts_by_kind": counts(self.removed_artifacts),
            "added_claims_by_predicate": counts(self.added_claims),
            "removed_claims_by_predicate": counts(self.removed_claims),
            "added_artifacts": self.added_artifacts,
            "removed_artifacts": self.removed_artifacts,
            "added_claims": self.added_claims,
            "removed_claims": self.removed_claims,
        }


def snapshot_from_project(project: Project, *, label: str | None = None) -> GraphSnapshot:
    """Read the comparable content directly out of a live project's database."""
    conn = project._conn  # noqa: SLF001 - diffing is part of the project layer

    artifacts: dict[str, dict[str, Any]] = {}
    for row in conn.execute("SELECT artifact_id, kind, name FROM artifacts"):
        artifacts[row["artifact_id"]] = {"kind": row["kind"], "name": row["name"]}

    claims: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT claim_id, predicate, subject_id, statement FROM claims"
    ):
        subject_path = None
        if row["subject_id"]:
            subject = project.get_artifact(row["subject_id"])
            if subject is not None:
                subject_path = subject.data.get("path") or subject.name
        claims[row["claim_id"]] = {
            "predicate": row["predicate"],
            "statement": json.loads(row["statement"]),
            "subject_path": subject_path,
        }

    return GraphSnapshot(
        label=label or project.info().get("name") or project.root,
        artifacts=artifacts,
        claims=claims,
    )


def snapshot_from_export(export_dir: str, *, label: str | None = None) -> GraphSnapshot:
    """Read the comparable content out of an exported ``graph/`` directory."""
    graph_dir = os.path.join(export_dir, "graph")
    artifacts_path = os.path.join(graph_dir, "artifacts.jsonl")
    claims_path = os.path.join(graph_dir, "claims.jsonl")
    if not os.path.isfile(artifacts_path) or not os.path.isfile(claims_path):
        raise DiffError(
            f"{export_dir} does not look like a Yugen export (expected "
            "graph/artifacts.jsonl and graph/claims.jsonl). Run 'yugen export' "
            "first, or point at a project directory instead of an export."
        )

    artifacts: dict[str, dict[str, Any]] = {}
    with open(artifacts_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            data = record.get("data", {})
            name = (
                data.get("name")
                or data.get("path")
                or data.get("function_name")
                or data.get("text")
                or data.get("label")
            )
            artifacts[record["id"]] = {"kind": record["kind"], "name": name}

    subject_paths: dict[str, str | None] = {
        artifact_id: info["name"] for artifact_id, info in artifacts.items()
    }

    claims: dict[str, dict[str, Any]] = {}
    with open(claims_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            subject_id = record.get("subject_id")
            claims[record["id"]] = {
                "predicate": record["predicate"],
                "statement": record["statement"],
                "subject_path": subject_paths.get(subject_id) if subject_id else None,
            }

    return GraphSnapshot(
        label=label or os.path.basename(os.path.normpath(export_dir)),
        artifacts=artifacts,
        claims=claims,
    )


def diff_snapshots(baseline: GraphSnapshot, target: GraphSnapshot) -> GraphDiff:
    """Compare two snapshots by id. The core operation: two set differences."""
    added_artifact_ids = set(target.artifacts) - set(baseline.artifacts)
    removed_artifact_ids = set(baseline.artifacts) - set(target.artifacts)
    added_claim_ids = set(target.claims) - set(baseline.claims)
    removed_claim_ids = set(baseline.claims) - set(target.claims)

    diff = GraphDiff(baseline=baseline.label, target=target.label)

    for artifact_id in added_artifact_ids:
        info = target.artifacts[artifact_id]
        diff.added_artifacts.setdefault(info["kind"], []).append(
            {"id": artifact_id, "name": info["name"]}
        )
    for artifact_id in removed_artifact_ids:
        info = baseline.artifacts[artifact_id]
        diff.removed_artifacts.setdefault(info["kind"], []).append(
            {"id": artifact_id, "name": info["name"]}
        )
    for claim_id in added_claim_ids:
        info = target.claims[claim_id]
        diff.added_claims.setdefault(info["predicate"], []).append(
            {"id": claim_id, "statement": info["statement"], "subject_path": info["subject_path"]}
        )
    for claim_id in removed_claim_ids:
        info = baseline.claims[claim_id]
        diff.removed_claims.setdefault(info["predicate"], []).append(
            {"id": claim_id, "statement": info["statement"], "subject_path": info["subject_path"]}
        )

    for grouped in (
        diff.added_artifacts,
        diff.removed_artifacts,
        diff.added_claims,
        diff.removed_claims,
    ):
        for key in grouped:
            grouped[key].sort(key=lambda row: row["id"])

    return diff


def load_snapshot(path: str, *, label: str | None = None) -> GraphSnapshot:
    """Load a snapshot from either a live project directory or an export.

    A project directory has ``yugen.db`` at its root; an export has
    ``graph/artifacts.jsonl``. Both are read-only operations - a diff never
    writes to either side.
    """
    if os.path.isfile(os.path.join(path, "yugen.db")):
        project = Project.open(path, read_only=True)
        try:
            return snapshot_from_project(project, label=label)
        finally:
            project.close()
    if os.path.isfile(os.path.join(path, "graph", "artifacts.jsonl")):
        return snapshot_from_export(path, label=label)
    raise DiffError(
        f"{path} is neither a Yugen project (no yugen.db) nor an export "
        "(no graph/artifacts.jsonl)"
    )


def diff_paths(baseline_path: str, target_path: str) -> GraphDiff:
    """Convenience: load two snapshots by path and diff them."""
    return diff_snapshots(load_snapshot(baseline_path), load_snapshot(target_path))


__all__ = [
    "DiffError",
    "GraphDiff",
    "GraphSnapshot",
    "diff_paths",
    "diff_snapshots",
    "load_snapshot",
    "snapshot_from_export",
    "snapshot_from_project",
]
