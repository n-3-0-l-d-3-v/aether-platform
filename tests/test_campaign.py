"""Campaign/fleet correlation: grouping projects by shared evidence.

Two signals, both mechanical: an identical file (by SHA-256) is conclusive;
several shared component-version pairs is a weaker signal gated by a
threshold so a single common library is never mistaken for a lineage.
"""

from __future__ import annotations

from aether.cartography.campaign import correlate_projects
from aether.evidence.models import EvidenceRef
from aether.project import Project


def _file_only(project: Project, path: str, sha256: str) -> None:
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        rc.artifact("file", {"path": path, "sha256": sha256, "size": 1, "format": "elf", "source": "ingest"})


def _with_components(project: Project, sha256: str, pairs: list[tuple[str, str]]) -> None:
    with project.run(tool="t", tool_version="1", adapter="test") as rc:
        f = rc.artifact("file", {"path": "bin/app", "sha256": sha256, "size": 1, "format": "elf", "source": "ingest"})
        for index, (component, version) in enumerate(pairs):
            s = rc.artifact(
                "string",
                {"text": f"{component} {version}", "encoding": "ascii", "addr": 0x1000 + index * 0x10},
                object_id=f.artifact_id,
            )
            rc.add_claim(
                "embeds_component",
                {"component": component, "version": version, "indicator": "version_banner"},
                [EvidenceRef(s.artifact_id, "locus")],
                subject_id=f.artifact_id,
                confidence=0.9,
                producer="t",
            )


# -- shared files -------------------------------------------------------


def test_an_identical_file_correlates_two_projects(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _file_only(a, "bin/boot", "x" * 64)
    _file_only(b, "bin/boot", "x" * 64)

    report = correlate_projects({"a": a, "b": b})
    assert report.campaigns == [["a", "b"]]
    assert report.singletons == []
    assert report.edges[0].kind == "shared_file"
    a.close()
    b.close()


def test_unrelated_projects_are_singletons(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _file_only(a, "bin/boot", "x" * 64)
    _file_only(b, "bin/other", "y" * 64)

    report = correlate_projects({"a": a, "b": b})
    assert report.campaigns == []
    assert report.singletons == ["a", "b"]
    assert report.edges == []
    a.close()
    b.close()


def test_a_shared_file_at_different_paths_still_correlates(tmp_path):
    """The signal is the byte content, not where it happens to live."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _file_only(a, "usr/bin/bootloader", "x" * 64)
    _file_only(b, "firmware/boot.bin", "x" * 64)

    report = correlate_projects({"a": a, "b": b})
    assert report.campaigns == [["a", "b"]]
    a.close()
    b.close()


# -- shared component fingerprints ---------------------------------------


def test_one_shared_component_is_not_enough_by_default(tmp_path):
    """A single shared library is common by coincidence at firmware scale."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _with_components(a, "a" * 64, [("busybox", "1.31.1")])
    _with_components(b, "b" * 64, [("busybox", "1.31.1")])

    report = correlate_projects({"a": a, "b": b})
    assert report.campaigns == []
    assert set(report.singletons) == {"a", "b"}
    a.close()
    b.close()


def test_two_shared_components_correlate_at_the_default_threshold(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _with_components(a, "a" * 64, [("busybox", "1.31.1"), ("openssl", "1.0.2u")])
    _with_components(b, "b" * 64, [("busybox", "1.31.1"), ("openssl", "1.0.2u"), ("dropbear", "2019.78")])

    report = correlate_projects({"a": a, "b": b})
    assert report.campaigns == [["a", "b"]]
    assert report.edges[0].kind == "shared_components"
    a.close()
    b.close()


def test_the_threshold_is_configurable(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _with_components(a, "a" * 64, [("busybox", "1.31.1")])
    _with_components(b, "b" * 64, [("busybox", "1.31.1")])

    lenient = correlate_projects({"a": a, "b": b}, min_shared_components=1)
    strict = correlate_projects({"a": a, "b": b}, min_shared_components=2)
    assert lenient.campaigns == [["a", "b"]]
    assert strict.campaigns == []
    a.close()
    b.close()


def test_different_versions_of_the_same_component_do_not_correlate(tmp_path):
    """openssl 1.0.2u and openssl 3.0.1 are different fingerprints entirely."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _with_components(a, "a" * 64, [("busybox", "1.31.1"), ("openssl", "1.0.2u")])
    _with_components(b, "b" * 64, [("busybox", "1.31.1"), ("openssl", "3.0.1")])

    report = correlate_projects({"a": a, "b": b})
    assert report.campaigns == []
    a.close()
    b.close()


# -- transitive grouping and mixed signals -------------------------------


def test_transitive_correlation_groups_three_projects(tmp_path):
    """A correlates with B (file), B correlates with C (components): one campaign."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    c = Project.create(str(tmp_path / "c"), "c")
    _file_only(a, "bin/boot", "shared" + "0" * 58)
    _file_only(b, "bin/boot", "shared" + "0" * 58)
    with b.run(tool="t", tool_version="1", adapter="test") as rc:
        f = rc.artifact("file", {"path": "bin/app", "sha256": "b" * 64, "size": 1, "format": "elf", "source": "ingest"})
        for index, (comp, ver) in enumerate([("busybox", "1.31.1"), ("openssl", "1.0.2u")]):
            s = rc.artifact("string", {"text": f"{comp} {ver}", "encoding": "ascii", "addr": 0x2000 + index * 0x10}, object_id=f.artifact_id)
            rc.add_claim("embeds_component", {"component": comp, "version": ver, "indicator": "version_banner"},
                         [EvidenceRef(s.artifact_id, "locus")], subject_id=f.artifact_id, confidence=0.9, producer="t")
    _with_components(c, "c" * 64, [("busybox", "1.31.1"), ("openssl", "1.0.2u")])

    report = correlate_projects({"a": a, "b": b, "c": c})
    assert report.campaigns == [["a", "b", "c"]]
    kinds = {e.kind for e in report.edges}
    assert kinds == {"shared_file", "shared_components"}
    a.close()
    b.close()
    c.close()


def test_two_separate_campaigns_are_not_merged(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    c = Project.create(str(tmp_path / "c"), "c")
    d = Project.create(str(tmp_path / "d"), "d")
    _file_only(a, "bin/boot", "aa" * 32)
    _file_only(b, "bin/boot", "aa" * 32)
    _file_only(c, "bin/other", "cc" * 32)
    _file_only(d, "bin/other", "cc" * 32)

    report = correlate_projects({"a": a, "b": b, "c": c, "d": d})
    assert sorted(report.campaigns) == [["a", "b"], ["c", "d"]]
    a.close()
    b.close()
    c.close()
    d.close()


def test_campaigns_are_read_only(tmp_path):
    """Correlating several projects must never write into any of them."""
    a = Project.create(str(tmp_path / "a"), "a")
    b = Project.create(str(tmp_path / "b"), "b")
    _file_only(a, "bin/boot", "x" * 64)
    _file_only(b, "bin/boot", "x" * 64)

    before_a = a.stats()["totals"]
    before_b = b.stats()["totals"]
    correlate_projects({"a": a, "b": b})
    assert a.stats()["totals"] == before_a
    assert b.stats()["totals"] == before_b
    a.close()
    b.close()


def test_a_single_project_has_no_correlations(tmp_path):
    a = Project.create(str(tmp_path / "a"), "a")
    _file_only(a, "bin/boot", "x" * 64)
    report = correlate_projects({"a": a})
    assert report.campaigns == []
    assert report.singletons == ["a"]
    a.close()


# -- front ends -------------------------------------------------------------


def test_cli_campaign_reports_a_correlation(tmp_path, capsys):
    from aether.cli import main

    main(["init", str(tmp_path / "a")])
    main(["init", str(tmp_path / "b")])
    capsys.readouterr()

    a = Project.open(str(tmp_path / "a"))
    _file_only(a, "bin/boot", "x" * 64)
    a.close()
    b = Project.open(str(tmp_path / "b"))
    _file_only(b, "bin/boot", "x" * 64)
    b.close()

    assert main(["campaign", str(tmp_path / "a"), str(tmp_path / "b")]) == 0
    output = capsys.readouterr().out
    assert "campaign 1" in output
    assert "shared_file" in output


def test_cli_campaign_requires_at_least_two_projects(tmp_path, capsys):
    from aether.cli import main

    main(["init", str(tmp_path / "a")])
    capsys.readouterr()
    assert main(["campaign", str(tmp_path / "a")]) != 0
    assert "at least two" in capsys.readouterr().err


def _mcp_call(server, name: str, arguments=None):
    """Minimal tools/call helper, kept local rather than importing test_mcp."""
    response = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
    )
    return response["result"]


def test_mcp_campaign_correlates_against_another_project(project, tmp_path):
    from aether.mcp.server import MCPServer

    other_dir = str(tmp_path / "other")
    other = Project.create(other_dir, "other")
    _file_only(other, "bin/boot", "x" * 64)
    other.close()

    _file_only(project, "bin/boot", "x" * 64)

    server = MCPServer(project)
    result = _mcp_call(server, "aether_campaign", {"other_projects": [other_dir]})["structuredContent"]
    assert result["campaigns"]
    assert "this_project" in result["campaigns"][0]


def test_mcp_campaign_requires_other_projects(project):
    from aether.mcp.server import MCPServer

    server = MCPServer(project)
    result = _mcp_call(server, "aether_campaign", {"other_projects": []})
    assert result["isError"] is True
    assert "at least one other project" in result["content"][0]["text"]
