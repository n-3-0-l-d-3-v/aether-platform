"""Analysis adapters: triage, the firmware carver, and the Ghidra bridge."""

from __future__ import annotations

import os

import pytest

from aether.adapters.binwalk import BinwalkAdapter, carver
from aether.adapters.ghidra import GhidraAdapter, importer
from aether.adapters.triage import TriageAdapter, detectors, formats, strings
from aether.errors import AdapterError


# -- format identification --------------------------------------------------


def test_elf_header_is_read_correctly(elf_sample):
    ident = formats.identify_file(elf_sample)
    assert ident.format == "elf"
    assert (ident.arch, ident.bits, ident.endian) == ("x86_64", 64, "little")
    assert {s.name for s in ident.sections} >= {".text", ".rodata", ".dynsym"}


def test_elf_mitigations_come_from_segments_and_symbols(elf_sample):
    ident = formats.identify_file(elf_sample)
    assert ident.hardening["nx"] is True
    assert ident.hardening["relro"] is True
    assert ident.hardening["pie"] is True
    assert ident.hardening["stack_canary"] is True


def test_elf_dynamic_symbols_split_into_imports_and_exports(elf_sample):
    ident = formats.identify_file(elf_sample)
    assert {i["name"] for i in ident.imports} >= {"strcpy", "system", "rand"}
    assert {e["name"] for e in ident.exports} >= {"main", "handle_name"}


def test_pe_header_is_read_correctly(pe_sample):
    ident = formats.identify_file(pe_sample)
    assert ident.format == "pe"
    assert ident.arch == "x86_64"
    assert ident.hardening["nx"] is True
    assert any(i["name"] == "strcpy" for i in ident.imports)


def test_unknown_bytes_do_not_masquerade_as_executables():
    ident = formats.identify_bytes(b"\x00\x01\x02\x03" * 64)
    assert ident.format == "data"


def test_truncated_elf_is_reported_not_crashed():
    ident = formats.identify_bytes(b"\x7fELF\x02\x01")
    assert ident.format == "elf"
    assert ident.warnings


def test_mz_without_pe_header_is_not_called_a_pe():
    ident = formats.identify_bytes(b"MZ" + b"\x00" * 200)
    assert ident.format == "data"


def test_shebang_is_recognized_as_a_script():
    ident = formats.identify_bytes(b"#!/bin/sh\necho hi\n")
    assert ident.format == "script"


# -- strings ----------------------------------------------------------------


def test_ascii_and_utf16_strings_are_both_found():
    # The 0xff separator matters: a printable ASCII byte immediately before a
    # UTF-16 run would be absorbed into it, since "d\\x00w\\x00" is
    # indistinguishable from the start of a wide string. Every strings tool
    # behaves this way; the payload just avoids the ambiguity.
    payload = b"\x00\x01" + b"hello world" + b"\xff\xff" + "windows".encode("utf-16-le")
    found = list(strings.iter_strings(payload, min_length=6))
    texts = {s.text for s in found}
    assert "hello world" in texts
    assert "windows" in texts
    assert {s.encoding for s in found} == {"ascii", "utf16le"}


def test_short_runs_are_not_strings():
    assert not list(strings.iter_strings(b"\x00abc\x00", min_length=6))


def test_strings_come_back_in_offset_order():
    payload = b"first_string\x00" + b"\x00" * 8 + b"second_string\x00"
    offsets = [s.file_offset for s in strings.iter_strings(payload, min_length=6)]
    assert offsets == sorted(offsets)


# -- detectors --------------------------------------------------------------


@pytest.mark.parametrize(
    "text,kind",
    [
        ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
        ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDb1example0key", "ssh_authorized_key"),
        ("mysql://user:pass@10.0.0.1:3306/db", "connection_string"),
        ("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "api_token"),
    ],
)
def test_secret_rules_fire_on_their_shapes(text, kind):
    assert kind in {d.kind for d in detectors.scan_secrets(text)}


def test_secret_previews_are_redacted():
    detection = next(detectors.scan_secrets("AKIAIOSFODNN7EXAMPLE"))
    assert detection.matched.startswith("AKIA")
    assert "IOSFODNN7EXAMPLE" not in detection.matched


def test_ordinary_text_produces_no_secrets():
    assert not list(detectors.scan_secrets("the quick brown fox jumps over the lazy dog"))


def test_component_banners_yield_versions():
    detection = next(detectors.scan_components("BusyBox v1.31.1 (2020-04-12) multi-call"))
    assert detection.kind == "busybox"
    assert detection.extra["version"] == "1.31.1"


def test_risky_api_classification_handles_decorated_names():
    assert detectors.classify_symbol("strcpy")[0] == "memory_copy"
    assert detectors.classify_symbol("_strcpy")[0] == "memory_copy"
    assert detectors.classify_symbol("__isoc99_scanf")[0] == "memory_copy"
    assert detectors.classify_symbol("strcpy@GLIBC_2.2.5")[0] == "memory_copy"
    assert detectors.classify_symbol("perfectly_ordinary_function") is None


def test_printf_is_not_flagged():
    """A rule that fires on every binary buys nothing and costs precision."""
    assert detectors.classify_symbol("printf") is None


# -- triage adapter end to end ----------------------------------------------


def test_triage_writes_artifacts_claims_and_provenance(triaged_elf):
    project, object_id = triaged_elf
    stats = project.stats()
    assert stats["artifacts_by_kind"]["file"] == 1
    assert stats["artifacts_by_kind"]["section"] >= 5
    assert stats["artifacts_by_kind"]["string"] > 10
    assert stats["claims_by_predicate"]["contains_hardcoded_secret"] >= 3
    assert project.check() == []


def test_triage_gives_strings_virtual_addresses(triaged_elf):
    """Without this, triage and Ghidra could not converge on one artifact."""
    project, _object_id = triaged_elf
    rodata_strings = [
        a
        for a in project.find_artifacts(kind="string", limit=200)
        if a.data.get("section") == ".rodata"
    ]
    assert rodata_strings
    assert all("addr" in a.data for a in rodata_strings)


def test_every_secret_claim_points_at_a_string(triaged_elf):
    project, _object_id = triaged_elf
    for claim in project.find_claims(predicate="contains_hardcoded_secret", limit=50):
        kinds = {
            project.get_artifact(ref["artifact_id"]).kind for ref in claim["evidence"]
        }
        assert "string" in kinds


def test_secret_claims_never_carry_the_full_secret(triaged_elf):
    """The literal stays in the artifact; the claim carries a masked preview."""
    project, _object_id = triaged_elf
    for claim in project.find_claims(predicate="contains_hardcoded_secret", limit=50):
        preview = claim["statement"].get("redacted_preview", "")
        assert "AKIAIOSFODNN7EXAMPLE" not in preview
        assert "*" in preview or len(preview) <= 4


def test_re_analysis_converges_rather_than_duplicating(triaged_elf, elf_sample):
    project, _object_id = triaged_elf
    before = project.stats()["totals"]
    TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    after = project.stats()["totals"]
    assert after["artifacts"] == before["artifacts"]
    assert after["claims"] == before["claims"]
    assert after["runs"] == before["runs"] + 1


# -- carver -----------------------------------------------------------------


def test_scanner_finds_signatures_past_a_vendor_header(firmware_sample):
    with open(firmware_sample, "rb") as handle:
        data = handle.read()
    hits = {h.signature for h in carver.scan(data)}
    assert "uimage" in hits
    assert "gzip" in hits


def test_gzip_validation_rejects_coincidental_magic():
    noise = b"\x00" * 100 + b"\x1f\x8b\x08" + b"\x00" * 100
    assert not [h for h in carver.scan(noise) if h.signature == "gzip"]


def test_full_unpack_chain_recovers_the_filesystem(firmware_sample, tmp_path):
    with open(firmware_sample, "rb") as handle:
        data = handle.read()
    outer = tmp_path / "outer"
    outer.mkdir()
    entries, _notes = carver.extract(data, carver.scan(data), str(outer))
    assert len(entries) == 1

    with open(entries[0].disk_path, "rb") as handle:
        inner_bytes = handle.read()
    inner = tmp_path / "inner"
    inner.mkdir()
    members, _notes = carver.extract(
        inner_bytes, carver.scan(inner_bytes), str(inner)
    )
    paths = {m.path for m in members}
    assert {"bin/firmware_agent", "etc/telemetry.conf", "etc/banner"} <= paths


def test_archive_members_cannot_escape_the_extraction_root(tmp_path):
    """Zip-slip: firmware member names are attacker-controlled."""
    root = str(tmp_path / "root")
    os.makedirs(root)
    assert carver.safe_join(root, "../../etc/passwd") is None
    assert carver.safe_join(root, "/etc/passwd") is not None  # leading slash stripped
    assert carver.safe_join(root, "a/../../../b") is None
    assert carver.safe_join(root, "normal/path.bin") is not None


def test_extraction_budget_refuses_runaway_output():
    budget = carver.Budget(max_files=2, max_bytes=1024)
    assert budget.allow(10)
    assert budget.allow(10)
    assert not budget.allow(10)
    assert budget.refused == 1


def test_unpackable_formats_are_reported_not_silently_dropped():
    payload = b"\x00" * 64 + b"hsqs" + b"\x00" * 256
    hits = carver.scan(payload)
    _entries, notes = carver.extract(payload, hits, ".")
    assert any("squashfs" in note.lower() for note in notes)
    assert any("binwalk" in note for note in notes)


def test_firmware_adapter_inventories_extracted_files(project, firmware_sample):
    result = BinwalkAdapter().analyze(
        project, firmware_sample, logical_path="demo_firmware.bin"
    )
    paths = {item["path"] for item in result.details["inventory"]}
    assert "bin/firmware_agent" in paths
    assert "etc/telemetry.conf" in paths

    claims = project.find_claims(predicate="firmware_contains_file", limit=50)
    assert claims
    for claim in claims:
        kinds = {project.get_artifact(r["artifact_id"]).kind for r in claim["evidence"]}
        assert "file" in kinds
    assert project.check() == []


def test_findings_attach_to_the_member_not_the_container(project, firmware_sample):
    """A key in etc/telemetry.conf is a finding about that file, not the blob."""
    BinwalkAdapter().analyze(project, firmware_sample, logical_path="demo_firmware.bin")
    subjects = set()
    for claim in project.find_claims(predicate="contains_hardcoded_secret", limit=50):
        subject = project.get_artifact(claim["subject_id"])
        subjects.add(subject.data.get("path"))
    assert "etc/telemetry.conf" in subjects
    assert not any(str(p).endswith(".gunzipped") for p in subjects)


# -- Ghidra bridge ----------------------------------------------------------


def test_probe_explains_how_to_install_when_absent():
    availability = GhidraAdapter(headless=None).probe()
    if not availability.available:
        assert "GHIDRA_INSTALL_DIR" in availability.remedy
        assert "import-ghidra" in availability.remedy


def test_reading_a_non_export_directory_fails_clearly(tmp_path):
    with pytest.raises(AdapterError, match="meta.json"):
        importer.read_export(str(tmp_path))


def test_malformed_jsonl_names_the_line(tmp_path, ghidra_export_dir):
    import shutil

    broken = tmp_path / "broken"
    shutil.copytree(ghidra_export_dir, broken)
    (broken / "functions.jsonl").write_text('{"ok":1}\nnot json at all\n', encoding="utf-8")
    with pytest.raises(AdapterError, match="functions.jsonl:2"):
        importer.read_export(str(broken))


def test_import_writes_functions_xrefs_and_decompilation(project, ghidra_export_dir, elf_sample):
    result = GhidraAdapter().import_directory(
        project, ghidra_export_dir, target=elf_sample, logical_path="bin/firmware_agent"
    )
    kinds = project.stats()["artifacts_by_kind"]
    assert kinds["function"] > 0
    assert kinds["xref"] > 0
    assert kinds["decompilation"] > 0
    assert result.details["program"] == "firmware_agent.elf"
    assert project.check() == []


def test_auto_named_functions_become_artifacts_but_not_claims(project, elf_sample):
    export = {
        "meta": {"program": "x", "executable_sha256": ""},
        "functions": [
            {"name": "FUN_00401000", "addr_start": 0x401000, "is_thunk": False,
             "is_external": False},
            {"name": "parse_request", "addr_start": 0x401100, "is_thunk": False,
             "is_external": False},
        ],
    }
    from aether.adapters.triage import TriageAdapter

    triaged = TriageAdapter().analyze(project, elf_sample, logical_path="bin/t")
    with project.run(tool="ghidra", tool_version="test", adapter="ghidra") as rc:
        counts = importer.import_export(rc, project, export, triaged.objects[0])
    assert counts["functions"] == 2
    assert counts["function_claims"] == 1
    named = {c["statement"]["name"] for c in project.find_claims(predicate="defines_function")}
    assert named == {"parse_request"}


def test_ghidra_and_triage_converge_on_shared_artifacts(project, elf_sample, ghidra_export_dir):
    triaged = TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    strings_before = project.count_artifacts(kind="string")
    imports_before = project.count_artifacts(kind="import")

    GhidraAdapter().import_directory(
        project, ghidra_export_dir, object_id=triaged.objects[0]
    )

    assert project.count_artifacts(kind="string") == strings_before
    assert project.count_artifacts(kind="import") == imports_before
    corroborated = [
        c for c in project.find_claims(limit=500) if c["confidence"]["producers"] > 1
    ]
    assert corroborated, "no claim was attested by both engines"


def test_call_sites_refine_the_import_only_claim(project, elf_sample, ghidra_export_dir):
    triaged = TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    GhidraAdapter().import_directory(project, ghidra_export_dir, object_id=triaged.objects[0])

    refined = [
        c
        for c in project.find_claims(predicate="uses_risky_api", limit=50)
        if c["statement"].get("call_site_count")
    ]
    assert refined
    for claim in refined:
        links = project.claim_links(claim["id"])
        assert any(link["relation"] == "refines" for link in links["outgoing"])


def test_import_warns_when_the_export_describes_other_bytes(project, ghidra_export_dir, elf_sample):
    import json
    import shutil

    from aether.adapters.triage import TriageAdapter

    triaged = TriageAdapter().analyze(project, elf_sample, logical_path="bin/firmware_agent")
    mismatched = os.path.join(project.work_dir, "mismatch")
    shutil.copytree(ghidra_export_dir, mismatched)
    meta_path = os.path.join(mismatched, "meta.json")
    with open(meta_path, encoding="utf-8") as handle:
        meta = json.load(handle)
    meta["executable_sha256"] = "f" * 64
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle)

    result = GhidraAdapter().import_directory(
        project, mismatched, object_id=triaged.objects[0]
    )
    assert any("SHA-256" in warning for warning in result.warnings)


def test_export_script_is_shipped_with_the_package():
    from aether.adapters.ghidra import scripts_dir

    script = os.path.join(scripts_dir(), "AetherExport.py")
    assert os.path.isfile(script)
    with open(script, encoding="utf-8") as handle:
        source = handle.read()
    # It runs under Ghidra's Jython 2.7, so it must avoid Python-3-only syntax.
    assert "f\"" not in source and "f'" not in source
    assert "getScriptArgs" in source


def test_headless_invocation_is_well_formed(tmp_path):
    """The one part of the runner testable without a Ghidra install."""
    from aether.adapters.ghidra import ANALYSIS_TIMEOUT_SECONDS, GHIDRA_PROJECT_NAME

    adapter = GhidraAdapter(headless="/opt/ghidra/support/analyzeHeadless")
    argv = adapter._build_argv(
        str(tmp_path / "target.bin"), str(tmp_path / "out"), str(tmp_path / "gp"), 12, []
    )

    assert argv[0].endswith("analyzeHeadless")
    assert argv[2] == GHIDRA_PROJECT_NAME
    assert "-import" in argv and "-deleteProject" in argv

    # The script and its three positional arguments must stay adjacent and in
    # order, or Ghidra hands them to the wrong consumer.
    script_index = argv.index("-postScript")
    assert argv[script_index + 1] == "AetherExport.py"
    assert argv[script_index + 2].endswith("out")
    assert argv[script_index + 3] == "12"
    assert "strcpy" in argv[script_index + 4]

    assert argv[argv.index("-analysisTimeoutPerFile") + 1] == str(ANALYSIS_TIMEOUT_SECONDS)


def test_noanalysis_replaces_the_timeout_and_is_not_duplicated(tmp_path):
    adapter = GhidraAdapter(headless="/opt/ghidra/support/analyzeHeadless")
    argv = adapter._build_argv(
        str(tmp_path / "t.bin"), str(tmp_path / "o"), str(tmp_path / "g"), 5, ["-noanalysis"]
    )
    assert argv.count("-noanalysis") == 1
    assert "-analysisTimeoutPerFile" not in argv


def test_extra_args_are_appended(tmp_path):
    adapter = GhidraAdapter(headless="/opt/ghidra/support/analyzeHeadless")
    argv = adapter._build_argv(
        str(tmp_path / "t.bin"), str(tmp_path / "o"), str(tmp_path / "g"), 5, ["-processor", "ARM:LE:32:v8"]
    )
    assert argv[-2:] == ["-processor", "ARM:LE:32:v8"]


# -- suspicious string indicators (Phase 1) ---------------------------------


@pytest.mark.parametrize(
    "text,category",
    [
        ("https://updates.example-vendor.net/v2/report", "url"),
        ("tftp://192.168.1.1/firmware.bin", "url"),
        ("connect to 10.4.0.9 now", "ip_address"),
        ("/bin/sh -c %s", "shell_command"),
        ("/dev/mtdblock3", "device_path"),
        ("/proc/self/maps", "device_path"),
        ("busybox telnetd -l /bin/sh", "debug_interface"),
        ("SELECT name FROM users WHERE id=?", "sql_fragment"),
    ],
)
def test_suspicious_rules_fire_on_their_shapes(text, category):
    assert category in {d.kind for d in detectors.scan_suspicious(text)}


@pytest.mark.parametrize(
    "text",
    [
        "hello world this is an ordinary message",
        "BusyBox v1.31.1 (2020-04-12 15:00:00 UTC) multi-call binary",
        "ping -c 1 %s",
        "GCC: (GNU) 14.2.0",
    ],
)
def test_ordinary_strings_are_not_suspicious(text):
    """A version banner is not a dotted-quad address, and must not read as one."""
    assert not list(detectors.scan_suspicious(text))


def test_one_detection_per_category_per_string():
    """A config listing twenty endpoints is one observation, not twenty."""
    text = "a=https://one.example/x b=https://two.example/y c=https://three.example/z"
    urls = [d for d in detectors.scan_suspicious(text) if d.kind == "url"]
    assert len(urls) == 1


def test_suspicious_indicators_score_below_credential_rules():
    """Indicators must never outrank a rigid credential shape."""
    strongest_indicator = max(rule.confidence for rule in detectors.SUSPICIOUS_RULES)
    aws = next(r for r in detectors.SECRET_RULES if r.rule_id == "aws-access-key-id")
    assert strongest_indicator < aws.confidence


def test_suspicious_claims_cite_the_string_they_came_from(project, firmware_sample):
    BinwalkAdapter().analyze(project, firmware_sample, logical_path="demo_firmware.bin")
    claims = project.find_claims(predicate="suspicious_string", limit=50)
    assert claims
    for claim in claims:
        kinds = {project.get_artifact(r["artifact_id"]).kind for r in claim["evidence"]}
        assert kinds == {"string"}
    categories = {c["statement"]["category"] for c in claims}
    assert "url" in categories


def test_suspicious_claims_are_capped_per_category(project, tmp_path):
    """Volume control: a binary full of URLs is still one file worth reviewing."""
    from aether.adapters.triage import MAX_SUSPICIOUS_PER_CATEGORY, TriageAdapter

    blob = tmp_path / "many_urls.bin"
    body = b"\x00".join(
        f"https://host{index}.example.test/path".encode() for index in range(200)
    )
    blob.write_bytes(b"\x00" + body + b"\x00")

    TriageAdapter().analyze(project, str(blob), logical_path="many_urls.bin")
    urls = [
        c
        for c in project.find_claims(predicate="suspicious_string", limit=500)
        if c["statement"]["category"] == "url"
    ]
    assert 0 < len(urls) <= MAX_SUSPICIOUS_PER_CATEGORY
