"""Campaign/fleet correlation: grouping several firmware images by lineage.

The last of the four Phase 2 items ADR 0008 named. Scoped the same way the
rest of cartography is: two mechanical, checkable signals rather than an
attempt at "these belong to the same product line" in any sense broader than
what the evidence graph actually shows.

**Exact file reuse.** Two projects that both contain a file with the same
SHA-256 digest share a literal, byte-identical binary - a bootloader, a
statically linked busybox, a shared library. That is about as strong a
mechanical correlation signal as exists between two otherwise-independent
analyses, because it requires no interpretation at all: the hash either
matches or it does not.

**Shared component fingerprints.** Two projects whose embedded-component
version banners overlap on several components (not just one - a single shared
library version is common by coincidence at firmware scale) suggest a common
build lineage even without a shared file.

Projects are grouped into campaigns by these edges using union-find: if A
correlates with B and B correlates with C, all three land in one campaign,
whether or not A and C correlate directly. Nothing here attempts fuzzy vendor
or product-name matching, version-range reasoning, or anything not directly
observable in two projects' own evidence graphs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aether.project.store import Project


@dataclass(frozen=True)
class CorrelationEdge:
    """One reason two projects were judged to be in the same campaign."""

    left: str
    right: str
    kind: str  # "shared_file" or "shared_components"
    detail: str

    def to_record(self) -> dict[str, Any]:
        return {"left": self.left, "right": self.right, "kind": self.kind, "detail": self.detail}


@dataclass
class CampaignReport:
    """The result of correlating a set of projects."""

    campaigns: list[list[str]] = field(default_factory=list)
    edges: list[CorrelationEdge] = field(default_factory=list)
    singletons: list[str] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "campaigns": self.campaigns,
            "edges": [e.to_record() for e in self.edges],
            "singletons": self.singletons,
        }


class _UnionFind:
    """Minimal union-find for grouping labels into connected components."""

    def __init__(self, labels: list[str]) -> None:
        self._parent = {label: label for label in labels}

    def find(self, label: str) -> str:
        while self._parent[label] != label:
            self._parent[label] = self._parent[self._parent[label]]
            label = self._parent[label]
        return label

    def union(self, a: str, b: str) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a

    def groups(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for label in self._parent:
            grouped.setdefault(self.find(label), []).append(label)
        return grouped


def _file_digests(project: Project) -> dict[str, str]:
    """sha256 -> logical path, for every file artifact in the project."""
    digests: dict[str, str] = {}
    for artifact in project.find_artifacts(kind="file", limit=5000):
        sha256 = artifact.data.get("sha256")
        path = artifact.data.get("path") or artifact.name
        if isinstance(sha256, str) and sha256 and path:
            digests[sha256] = str(path)
    return digests


def _component_fingerprint(project: Project) -> set[tuple[str, str]]:
    """(component, version) pairs with a version, for every embeds_component claim."""
    fingerprint: set[tuple[str, str]] = set()
    for claim in project.find_claims(predicate="embeds_component", limit=5000):
        component = claim["statement"].get("component")
        version = claim["statement"].get("version")
        if component and version:
            fingerprint.add((str(component), str(version)))
    return fingerprint


def correlate_projects(
    projects: dict[str, Project], *, min_shared_components: int = 2
) -> CampaignReport:
    """Group projects into campaigns by shared files or component fingerprints.

    ``projects`` maps a display label (typically the project's path) to an
    open :class:`Project`. Read-only: nothing is written to any project, for
    the same reason version diffing stays a report by default - a campaign
    spans several independent databases, and there is no single graph a
    "this project belongs to campaign X" claim could honestly live in without
    citing artifacts that exist in a different project's database.
    """
    labels = list(projects)
    digests = {label: _file_digests(projects[label]) for label in labels}
    fingerprints = {label: _component_fingerprint(projects[label]) for label in labels}

    edges: list[CorrelationEdge] = []
    finder = _UnionFind(labels)

    for i, left in enumerate(labels):
        for right in labels[i + 1 :]:
            shared_files = set(digests[left]) & set(digests[right])
            if shared_files:
                sample = sorted(shared_files)[0]
                edges.append(
                    CorrelationEdge(
                        left,
                        right,
                        "shared_file",
                        f"{len(shared_files)} identical file(s), e.g. "
                        f"{digests[left][sample]} ({sample[:12]}...)",
                    )
                )
                finder.union(left, right)
                continue  # a file match is conclusive; no need to also check components

            shared_components = fingerprints[left] & fingerprints[right]
            if len(shared_components) >= min_shared_components:
                sample = ", ".join(
                    f"{c}@{v}" for c, v in sorted(shared_components)[:3]
                )
                edges.append(
                    CorrelationEdge(
                        left,
                        right,
                        "shared_components",
                        f"{len(shared_components)} shared component version(s): {sample}",
                    )
                )
                finder.union(left, right)

    groups = finder.groups()
    campaigns = [sorted(members) for members in groups.values() if len(members) > 1]
    singletons = sorted(
        members[0] for members in groups.values() if len(members) == 1
    )
    campaigns.sort(key=lambda members: (-len(members), members[0]))

    return CampaignReport(campaigns=campaigns, edges=edges, singletons=singletons)


__all__ = ["CampaignReport", "CorrelationEdge", "correlate_projects"]
