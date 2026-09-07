"""Version tracking: compare embedded components across two projects.

The other half of Phase 2's "version tracking, diffing" line. Deliberately
scoped to what is directly measurable: which components changed version
between two independently analysed images. It does not attempt to diff
control flow, decompiled bodies, or the full evidence graph - that is a much
larger problem, and nothing here claims to solve it.

A project is a self-contained SQLite database, so two projects being compared
cannot share artifact ids: even identical bytes analysed twice only converge
within one project (ADR 0002), and two different firmware builds certainly do
not. Comparison therefore has to match by *meaning* - component name - not by
id, which is a weaker join than the content-addressed one the rest of Ultron
relies on. That weakness is the reason this stays a reporting function rather
than something that writes claims into both projects: a report is a snapshot
that can be wrong without corrupting the evidence graph.

The exception is ``record_version_changes``, which writes a
``component_version_changed`` claim into the *newer* project only, backed by
evidence that already exists there. The "from" version is recorded as text,
because it is a fact about a different project's graph that this project has
no way to cite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ultron.evidence.models import EvidenceRef
from ultron.project.store import Project
from ultron.version import ULTRON_VERSION


@dataclass(frozen=True)
class ComponentChange:
    """One component whose version differs between two projects."""

    component: str
    from_version: str | None
    to_version: str | None
    #: "added" (new in the target), "removed" (gone from the target), or
    #: "changed" (present in both, at different versions).
    kind: str

    def to_record(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "kind": self.kind,
        }


def _component_versions(project: Project) -> dict[str, set[str]]:
    """component name -> the set of versions claimed for it in this project.

    A set, not a single value: a firmware image can legitimately embed two
    copies of a library (a statically linked one and a shared one) at
    different versions, and collapsing that to "the" version would be a false
    precision the evidence does not support.
    """
    versions: dict[str, set[str]] = {}
    for claim in project.find_claims(predicate="embeds_component", limit=5000):
        name = str(claim["statement"].get("component") or "")
        version = claim["statement"].get("version")
        if not name:
            continue
        versions.setdefault(name, set())
        if version:
            versions[name].add(str(version))
    return versions


def diff_components(baseline: Project, target: Project) -> list[ComponentChange]:
    """Compare embedded components between two projects.

    ``target`` is conventionally the newer build, but nothing here assumes
    that beyond the field names in the result.
    """
    before = _component_versions(baseline)
    after = _component_versions(target)
    changes: list[ComponentChange] = []

    for name in sorted(set(before) | set(after)):
        old_versions = before.get(name, set())
        new_versions = after.get(name, set())
        if name not in before:
            changes.append(
                ComponentChange(name, None, _one(new_versions), "added")
            )
        elif name not in after:
            changes.append(
                ComponentChange(name, _one(old_versions), None, "removed")
            )
        elif old_versions != new_versions and (old_versions or new_versions):
            changes.append(
                ComponentChange(name, _one(old_versions), _one(new_versions), "changed")
            )
    return changes


def _one(versions: set[str]) -> str | None:
    """Render a version set for display: the single value, or a joined list."""
    if not versions:
        return None
    if len(versions) == 1:
        return next(iter(versions))
    return ", ".join(sorted(versions))


def record_version_changes(
    target: Project, changes: list[ComponentChange], *, baseline_label: str = "baseline"
) -> dict[str, Any]:
    """Write ``component_version_changed`` claims into the target project.

    Only ``changed`` entries are written - ``added``/``removed`` are not a
    version change and have no natural evidence locus in a project where the
    component is, respectively, new or absent. Evidence is whatever
    ``embeds_component`` claim in the target project asserted the new version;
    a component with no such claim (a version disappeared entirely) is skipped
    with a warning rather than guessed at.
    """
    changed = [c for c in changes if c.kind == "changed"]
    warnings: list[str] = []
    written = 0

    with target.run(
        tool="ultron-cartography",
        tool_version=ULTRON_VERSION,
        adapter="cartography-diff",
        params={"baseline_label": baseline_label},
    ) as rc:
        for change in changed:
            source_claims = [
                c
                for c in target.find_claims(predicate="embeds_component", limit=200)
                if str(c["statement"].get("component")) == change.component
            ]
            if not source_claims:
                warnings.append(
                    f"{change.component}: no embeds_component claim in the target "
                    "project to attach evidence to; change recorded in the report "
                    "only"
                )
                continue
            evidence = [
                EvidenceRef(ref["artifact_id"], "locus")
                for claim in source_claims
                for ref in claim["evidence"]
            ]
            if not evidence:
                continue
            rc.add_claim(
                "component_version_changed",
                {
                    "component": change.component,
                    "from_version": change.from_version or "unknown",
                    "to_version": change.to_version or "unknown",
                },
                evidence[:1],
                subject_id=source_claims[0].get("subject_id"),
                # A name match across independently analysed projects, one
                # level removed from a direct reading of this project's own
                # evidence - hence below what embeds_component itself scores.
                confidence=0.75,
                producer="ultron-cartography",
                method=f"diff-against:{baseline_label}",
            )
            written += 1

        result = {
            "run_id": rc.run.run_id,
            "changes_considered": len(changed),
            "claims_written": written,
            "warnings": warnings,
        }
    return result


__all__ = [
    "ComponentChange",
    "diff_components",
    "record_version_changes",
]
