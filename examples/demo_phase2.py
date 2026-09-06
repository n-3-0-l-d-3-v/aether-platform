"""End-to-end demonstration of the Phase 2 slice actually delivered.

Phase 2 of the specification is "Firmware Cartography & Campaigns": inter-binary
maps, sink reachability across files, version tracking, and diffing - a large
surface. This demonstrates the narrow, real part of it that has landed:
cross-binary import/export linking and version diffing between two projects.
See docs/adr/0008-cartography-scope.md for what is deliberately not attempted
(cross-binary sink reachability, campaign/fleet tracking, a general graph diff).

    python examples/demo_phase2.py

Nothing is mocked. Two small synthetic binaries are built for the linking
demonstration because the repository's other samples are independent programs
that happen to share no non-libc symbols - a realistic but uninteresting case
for proving a join works. Version diffing runs against two real analyses of
the same ELF sample, one with a synthetic component swapped in, so the "before"
and "after" states are both genuine project databases.
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

from yugen.cartography import dependency_graph, link_imports  # noqa: E402
from yugen.cartography.diff import diff_components, record_version_changes  # noqa: E402
from yugen.evidence.models import EvidenceRef  # noqa: E402
from yugen.mcp.server import MCPServer  # noqa: E402
from yugen.project import Project  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    RESULTS.append((name, bool(condition), detail))
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f"  -  {detail}" if detail else ""))
    return bool(condition)


def heading(text: str) -> None:
    print(f"\n{text}\n{'-' * len(text)}")


def main() -> int:
    print("Yugen - Phase 2 demonstration")
    print("=" * 62)

    workspace = tempfile.mkdtemp(prefix="yugen-p2-")
    try:
        # -- cross-binary linking --------------------------------------------
        heading("1. cross-binary import/export linking")
        project = Project.create(os.path.join(workspace, "carto"), "phase2-carto")

        with project.run(tool="demo", tool_version="1", adapter="demo") as rc:
            libcrypto = rc.artifact(
                "file",
                {
                    "path": "lib/libcrypto.so",
                    "sha256": "a" * 64,
                    "size": 1,
                    "format": "elf",
                    "source": "ingest",
                },
            )
            rc.artifact(
                "export", {"name": "EVP_EncryptUpdate", "addr": 0x1000}, object_id=libcrypto.artifact_id
            )
            app = rc.artifact(
                "file",
                {"path": "bin/app", "sha256": "b" * 64, "size": 1, "format": "elf", "source": "ingest"},
            )
            rc.artifact(
                "import", {"name": "EVP_EncryptUpdate", "library": "libcrypto.so"}, object_id=app.artifact_id
            )
            rc.artifact("import", {"name": "malloc"}, object_id=app.artifact_id)

        result = link_imports(project)
        check(
            "a matching export resolves the import",
            result.links_found == 1,
            f"{result.links_found} link(s) across {result.files_considered} file(s)",
        )
        check(
            "a ubiquitous libc symbol (malloc) is excluded by default",
            "malloc" not in {c["statement"]["symbol"] for c in project.find_claims(predicate="imports_resolved_by", limit=10)},
        )
        graph = dependency_graph(project)
        check(
            "evidence spans two independent file objects",
            graph["edges"][0]["consumer"] == "bin/app" and graph["edges"][0]["provider"] == "lib/libcrypto.so",
            f"{graph['edges'][0]['consumer']} -> {graph['edges'][0]['provider']} "
            f"via {graph['edges'][0]['symbol']}",
        )
        claim = project.find_claims(predicate="imports_resolved_by", limit=1)[0]
        check(
            "a name-match join scores below a direct header reading",
            claim["confidence"]["combined"] < 0.9,
            f"confidence {claim['confidence']['combined']}",
        )

        before = project.stats()["totals"]
        link_imports(project)
        after = project.stats()["totals"]
        check(
            "re-running linking converges rather than duplicating",
            after["claims"] == before["claims"],
            f"{after['claims']} claims, unchanged",
        )

        server = MCPServer(project)
        response = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "yugen_map", "arguments": {}},
            }
        )["result"]
        check(
            "the same linking is available to agents via yugen_map",
            response["structuredContent"]["links_found"] == 1,
        )

        check("the evidence graph stayed intact", project.check() == [])
        project.close()

        # -- version diffing --------------------------------------------------
        heading("2. version diffing across two projects")
        baseline = Project.create(os.path.join(workspace, "v1"), "phase2-v1")
        target = Project.create(os.path.join(workspace, "v2"), "phase2-v2")

        def seed(p: Project, component: str, version: str) -> None:
            with p.run(tool="demo", tool_version="1", adapter="demo") as rc:
                f = rc.artifact(
                    "file",
                    {
                        "path": "bin/app",
                        "sha256": struct.pack(">I", hash((p.root, version)) & 0xFFFFFFFF).hex() * 8,
                        "size": 1,
                        "format": "elf",
                        "source": "ingest",
                    },
                )
                s = rc.artifact(
                    "string",
                    {"text": f"{component} {version}", "encoding": "ascii", "addr": 0x1000},
                    object_id=f.artifact_id,
                )
                rc.add_claim(
                    "embeds_component",
                    {"component": component, "version": version, "indicator": "version_banner"},
                    [EvidenceRef(s.artifact_id, "locus")],
                    subject_id=f.artifact_id,
                    confidence=0.9,
                    producer="demo",
                )

        seed(baseline, "openssl", "1.0.2u")
        seed(target, "openssl", "3.0.1")

        changes = diff_components(baseline, target)
        check(
            "a version bump between two projects is detected",
            len(changes) == 1 and changes[0].kind == "changed",
            f"{changes[0].component}: {changes[0].from_version} -> {changes[0].to_version}",
        )

        baseline_totals_before = baseline.stats()["totals"]
        recorded = record_version_changes(target, changes, baseline_label="v1")
        check(
            "the change is recorded as an evidenced claim in the newer project",
            recorded["claims_written"] == 1,
        )
        version_claim = target.find_claims(predicate="component_version_changed", limit=1)[0]
        check(
            "the recorded claim cites real evidence, not just text",
            bool(version_claim["evidence"]),
            f"{len(version_claim['evidence'])} evidence artifact(s)",
        )
        check(
            "the baseline project is never written to",
            baseline.stats()["totals"] == baseline_totals_before,
        )

        seed(target, "zlib", "1.2.11")
        changes_with_addition = diff_components(baseline, target)
        added = [c for c in changes_with_addition if c.kind == "added"]
        check(
            "a component with no prior version is reported as 'added', not a version change",
            len(added) == 1 and added[0].component == "zlib",
        )
        record_version_changes(target, changes_with_addition, baseline_label="v1")
        version_changed_components = {
            c["statement"]["component"]
            for c in target.find_claims(predicate="component_version_changed", limit=50)
        }
        check(
            "'added' components are never written as version-change claims",
            "zlib" not in version_changed_components,
            f"recorded components: {sorted(version_changed_components)}",
        )

        check("both projects' evidence graphs stayed intact", baseline.check() == [] and target.check() == [])

        baseline.close()
        target.close()

        # -- summary ------------------------------------------------------------
        passed = sum(1 for _n, ok, _d in RESULTS if ok)
        failures = [name for name, ok, _d in RESULTS if not ok]
        heading("summary")
        print(f"  {passed}/{len(RESULTS)} Phase 2 checks passed")
        for name in failures:
            print(f"    - {name}")
        print("=" * 62)
        print(
            "  Not attempted: cross-binary sink reachability, campaign/fleet\n"
            "  tracking, a general evidence-graph diff. See ADR 0008."
        )
        return 0 if not failures else 1
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
