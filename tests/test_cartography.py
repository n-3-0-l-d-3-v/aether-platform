"""Cartography: cross-binary linking and version diffing.

This is a deliberately narrow slice of Phase 2. It proves two mechanical
claims - "this import is satisfied by that export" and "this component's
version changed between two projects" - and is explicit that neither is proof
of a live runtime dependency or a security-relevant change.
"""

from __future__ import annotations

import pytest

from ultron.cartography import dependency_graph, link_imports
from ultron.cartography.diff import diff_components, record_version_changes
from ultron.evidence.models import EvidenceRef
from ultron.project import Project

FILE_A = {"path": "bin/app", "sha256": "a" * 64, "size": 1, "format": "elf", "source": "ingest"}
FILE_B = {"path": "lib/libcrypto.so", "sha256": "b" * 64, "size": 1, "format": "elf", "source": "ingest"}


def _seed_cross_binary(project: Project) -> None:
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        provider = rc.artifact("file", FILE_B)
        rc.artifact("export", {"name": "EVP_EncryptUpdate", "addr": 0x1000}, object_id=provider.artifact_id)

        consumer = rc.artifact("file", FILE_A)
        rc.artifact("import", {"name": "EVP_EncryptUpdate", "library": "libcrypto.so"}, object_id=consumer.artifact_id)
        rc.artifact("import", {"name": "malloc"}, object_id=consumer.artifact_id)


# -- linking ------------------------------------------------------------


def test_a_matching_export_resolves_the_import(project):
    _seed_cross_binary(project)
    result = link_imports(project)
    assert result.links_found == 1
    assert result.files_considered == 2

    claims = project.find_claims(predicate="imports_resolved_by", limit=10)
    assert len(claims) == 1
    assert claims[0]["statement"]["symbol"] == "EVP_EncryptUpdate"
    assert claims[0]["statement"]["provider_path"] == "lib/libcrypto.so"
    assert project.check() == []


def test_evidence_spans_both_files(project):
    """The point of cartography: evidence legitimately crosses file objects."""
    _seed_cross_binary(project)
    link_imports(project)
    claim = project.find_claims(predicate="imports_resolved_by", limit=1)[0]
    kinds_by_role = {ref["role"]: project.get_artifact(ref["artifact_id"]).kind for ref in claim["evidence"]}
    assert kinds_by_role == {"locus": "import", "support": "export"}


def test_ubiquitous_symbols_are_ignored_by_default(project):
    _seed_cross_binary(project)
    result = link_imports(project)
    symbols = {c["statement"]["symbol"] for c in project.find_claims(predicate="imports_resolved_by", limit=10)}
    assert "malloc" not in symbols
    assert result.links_found == 1


def test_ubiquitous_symbols_can_be_included(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        libc = rc.artifact("file", {**FILE_B, "path": "lib/libc.so"})
        rc.artifact("export", {"name": "malloc", "addr": 0x2000}, object_id=libc.artifact_id)
        app = rc.artifact("file", FILE_A)
        rc.artifact("import", {"name": "malloc"}, object_id=app.artifact_id)

    result = link_imports(project, ignore_ubiquitous=False)
    assert result.links_found == 1


def test_no_self_links(project):
    """A file's own export must never satisfy its own import."""
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_A)
        rc.artifact("export", {"name": "helper", "addr": 0x1000}, object_id=obj.artifact_id)
        rc.artifact("import", {"name": "helper"}, object_id=obj.artifact_id)
    result = link_imports(project)
    assert result.links_found == 0


def test_an_import_with_no_provider_is_silently_unresolved(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", FILE_A)
        rc.artifact("import", {"name": "totally_unresolved_symbol"}, object_id=obj.artifact_id)
    result = link_imports(project)
    assert result.links_found == 0
    assert result.claims_written == 0


def test_ambiguous_providers_are_all_recorded_at_reduced_confidence(project):
    """Two exporters of the same symbol: record both, do not guess."""
    _seed_cross_binary(project)
    with project.run(tool="t2", tool_version="1", adapter="test") as rc:
        alt = rc.artifact("file", {**FILE_B, "path": "lib/alt_crypto.so", "sha256": "c" * 64})
        rc.artifact("export", {"name": "EVP_EncryptUpdate", "addr": 0x3000}, object_id=alt.artifact_id)

    result = link_imports(project)
    claims = project.find_claims(predicate="imports_resolved_by", limit=10)
    assert result.links_found == 2
    providers = {c["statement"]["provider_path"] for c in claims}
    assert providers == {"lib/libcrypto.so", "lib/alt_crypto.so"}
    assert all(c["confidence"]["combined"] < 0.6 for c in claims), "ambiguity must lower confidence"


def test_confidence_is_below_a_direct_header_reading(project):
    """A name-match join is weaker evidence than reading one file's own structure."""
    _seed_cross_binary(project)
    link_imports(project)
    claim = project.find_claims(predicate="imports_resolved_by", limit=1)[0]
    assert claim["confidence"]["combined"] < 0.9


def test_no_evidence_warns_instead_of_silently_finding_nothing(project):
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        rc.artifact("file", FILE_A)
    result = link_imports(project)
    assert any("no export or symbol" in w for w in result.warnings)


def test_dependency_graph_reads_back_the_claims(project):
    _seed_cross_binary(project)
    link_imports(project)
    graph = dependency_graph(project)
    assert set(graph["nodes"]) == {"bin/app", "lib/libcrypto.so"}
    assert graph["edges"][0]["symbol"] == "EVP_EncryptUpdate"


def test_re_running_link_imports_converges(project):
    _seed_cross_binary(project)
    link_imports(project)
    before = project.stats()["totals"]
    link_imports(project)
    after = project.stats()["totals"]
    assert after["claims"] == before["claims"]


def test_cli_map_reports_links(tmp_path, capsys):
    from ultron.cli import main

    root = str(tmp_path / "proj")
    main(["init", root])
    capsys.readouterr()
    project = Project.open(root)
    _seed_cross_binary(project)
    project.close()

    assert main(["-P", root, "map"]) == 0
    output = capsys.readouterr().out
    assert "1 link(s) found" in output
    assert "EVP_EncryptUpdate" in output


# -- version diffing ------------------------------------------------------


def _seed_component(project: Project, component: str, version: str) -> None:
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        obj = rc.artifact("file", {**FILE_A, "sha256": "d" * 64})
        text = rc.artifact(
            "string", {"text": f"{component} {version}", "encoding": "ascii", "addr": 0x1000}, object_id=obj.artifact_id
        )
        rc.add_claim(
            "embeds_component",
            {"component": component, "version": version, "indicator": "version_banner"},
            [EvidenceRef(text.artifact_id, "locus")],
            subject_id=obj.artifact_id,
            confidence=0.9,
            producer="t",
        )


def test_a_version_bump_is_detected(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "3.0.1")

    changes = diff_components(baseline, target)
    assert len(changes) == 1
    assert changes[0].kind == "changed"
    assert changes[0].from_version == "1.0.2u"
    assert changes[0].to_version == "3.0.1"
    baseline.close()
    target.close()


def test_an_unchanged_component_produces_no_diff(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "1.0.2u")
    assert diff_components(baseline, target) == []
    baseline.close()
    target.close()


def test_a_new_component_is_reported_as_added_not_changed(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "1.0.2u")
    _seed_component(target, "zlib", "1.2.11")

    changes = diff_components(baseline, target)
    assert len(changes) == 1
    assert changes[0].kind == "added"
    assert changes[0].component == "zlib"
    assert changes[0].from_version is None
    baseline.close()
    target.close()


def test_a_removed_component_is_reported(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "dropbear", "2019.78")
    _seed_component(target, "openssl", "1.0.2u")  # unrelated, so baseline's component vanished

    changes = diff_components(baseline, target)
    kinds = {c.component: c.kind for c in changes}
    assert kinds["dropbear"] == "removed"
    assert kinds["openssl"] == "added"
    baseline.close()
    target.close()


def test_record_version_changes_writes_evidenced_claims(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "3.0.1")

    changes = diff_components(baseline, target)
    result = record_version_changes(target, changes, baseline_label="a")
    assert result["claims_written"] == 1

    claim = target.find_claims(predicate="component_version_changed", limit=1)[0]
    assert claim["statement"] == {
        "component": "openssl",
        "from_version": "1.0.2u",
        "to_version": "3.0.1",
    }
    assert claim["evidence"]
    assert target.check() == []
    baseline.close()
    target.close()


def test_record_version_changes_never_writes_into_the_baseline(tmp_path):
    """The from-version is text; the baseline project is never touched."""
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "3.0.1")

    before = baseline.stats()["totals"]
    changes = diff_components(baseline, target)
    record_version_changes(target, changes, baseline_label="a")
    after = baseline.stats()["totals"]
    assert after == before
    baseline.close()
    target.close()


def test_added_components_are_not_recorded_as_version_changes(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "1.0.2u")
    _seed_component(target, "zlib", "1.2.11")

    changes = diff_components(baseline, target)
    result = record_version_changes(target, changes, baseline_label="a")
    assert result["claims_written"] == 0
    assert not target.find_claims(predicate="component_version_changed", limit=10)
    baseline.close()
    target.close()


def test_confidence_is_below_a_direct_component_reading(tmp_path):
    baseline = Project.create(str(tmp_path / "a"), "a")
    target = Project.create(str(tmp_path / "b"), "b")
    _seed_component(baseline, "openssl", "1.0.2u")
    _seed_component(target, "openssl", "3.0.1")
    changes = diff_components(baseline, target)
    record_version_changes(target, changes, baseline_label="a")
    claim = target.find_claims(predicate="component_version_changed", limit=1)[0]
    direct = target.find_claims(predicate="embeds_component", limit=1)[0]
    assert claim["confidence"]["combined"] < direct["confidence"]["combined"]
    baseline.close()
    target.close()


def test_cli_diff_versions_reports_changes(tmp_path, capsys):
    from ultron.cli import main

    main(["init", str(tmp_path / "a")])
    main(["init", str(tmp_path / "b")])
    capsys.readouterr()

    a = Project.open(str(tmp_path / "a"))
    _seed_component(a, "openssl", "1.0.2u")
    a.close()
    b = Project.open(str(tmp_path / "b"))
    _seed_component(b, "openssl", "3.0.1")
    b.close()

    assert main(["-P", str(tmp_path / "b"), "diff-versions", str(tmp_path / "a"), "--record"]) == 0
    output = capsys.readouterr().out
    assert "openssl" in output
    assert "1.0.2u" in output
    assert "3.0.1" in output
    assert "recorded 1 component_version_changed" in output


def test_cli_diff_versions_with_no_changes(tmp_path, capsys):
    from ultron.cli import main

    main(["init", str(tmp_path / "a")])
    main(["init", str(tmp_path / "b")])
    capsys.readouterr()

    for path in (tmp_path / "a", tmp_path / "b"):
        p = Project.open(str(path))
        _seed_component(p, "openssl", "1.0.2u")
        p.close()

    assert main(["-P", str(tmp_path / "b"), "diff-versions", str(tmp_path / "a")]) == 0
    assert "no component differences found" in capsys.readouterr().out
