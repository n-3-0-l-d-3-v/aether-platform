"""The narrow natural-language interface.

Two properties carry the weight here. Classification must decline what it does
not handle rather than guessing, and no answer may assert anything about a
binary without citing the claims it rests on.
"""

from __future__ import annotations

import json

import pytest

from aether.errors import EvidenceError
from aether.nl import ask, classify, describe_supported, score_all
from aether.nl.model import Answer, AnswerError, AnswerLine, Finding, validate_answer
from aether.nl.questions import MATCH_THRESHOLD, QUESTION_TYPES, normalize


@pytest.fixture()
def firmware_project(analysed_firmware):
    """The shared analysed firmware project.

    Every test here only asks questions, and asking never writes, so the
    expensive unpack is done once per session rather than once per test.
    """
    return analysed_firmware


# -- classification ---------------------------------------------------------


def test_every_question_type_matches_its_own_examples():
    """A type that cannot classify its own documented examples is mis-tuned."""
    for question_type in QUESTION_TYPES.values():
        for example in question_type.examples:
            matched, score = classify(example)
            assert matched is not None, f"{question_type.id} declined {example!r}"
            assert matched.id == question_type.id, (
                f"{example!r} classified as {matched.id}, expected {question_type.id}"
            )
            assert score >= MATCH_THRESHOLD


@pytest.mark.parametrize(
    "question,expected",
    [
        ("Are there any hardcoded secrets?", "hardcoded_secrets"),
        ("any passwords in this thing", "hardcoded_secrets"),
        ("does it contain an api key", "hardcoded_secrets"),
        ("what third-party libraries does it use?", "embedded_components"),
        ("give me an sbom", "embedded_components"),
        ("which openssl version is embedded", "embedded_components"),
        ("what is the attack surface", "attack_surface"),
        ("does it call any dangerous functions", "attack_surface"),
        ("any suspicious strings?", "suspicious_indicators"),
        ("what urls does it contain", "suspicious_indicators"),
        ("does it phone home", "suspicious_indicators"),
        ("is this binary hardened", "binary_hardening"),
        ("are NX and RELRO enabled", "binary_hardening"),
        ("what mitigations does it have", "binary_hardening"),
    ],
)
def test_realistic_phrasings_classify_correctly(question, expected):
    matched, _score = classify(question)
    assert matched is not None, f"declined: {question!r}"
    assert matched.id == expected


@pytest.mark.parametrize(
    "question",
    [
        "what is the weather today",
        "write me a poem about binaries",
        "monkey business",
        "a piece of cake",
        "how do I exploit this",
        "delete all the evidence",
        "",
    ],
)
def test_out_of_scope_questions_are_declined(question):
    """Declining is the correct answer, and it must be the actual answer."""
    matched, _score = classify(question)
    assert matched is None


def test_single_word_terms_match_whole_words_only():
    """Substring matching let "key" fire on "monkey" and "pie" on "piece"."""
    assert classify("monkey business")[0] is None
    assert classify("a piece of cake")[0] is None
    assert classify("what is the api key")[0] is not None


def test_normalization_collapses_punctuation_and_case():
    assert normalize("  Are There   SECRETS?? ") == " are there secrets "


def test_scores_are_ordered_and_deterministic():
    first = score_all("are there hardcoded secrets")
    second = score_all("are there hardcoded secrets")
    assert [(q.id, s) for q, s in first] == [(q.id, s) for q, s in second]
    assert first[0][1] >= first[-1][1]


def test_supported_set_is_narrow_by_design():
    """Phase 1 permits four to five question types. Guard the ceiling."""
    assert 4 <= len(QUESTION_TYPES) <= 5
    described = describe_supported()
    assert len(described) == len(QUESTION_TYPES)
    for entry in described:
        assert entry["title"] and entry["example"]


# -- the citation invariant -------------------------------------------------


def test_every_answer_line_cites_a_claim(firmware_project):
    """The headline invariant, across every supported question type."""
    for question_type in QUESTION_TYPES.values():
        answer = ask(firmware_project, question_type.examples[0])
        assert answer.understood
        cited = set(answer.claim_ids)
        for line in answer.lines:
            if line.is_caveat:
                assert not line.claim_ids
            else:
                assert line.claim_ids, f"{question_type.id}: uncited line {line.text!r}"
                assert set(line.claim_ids) <= cited


def test_validate_rejects_an_uncited_assertion():
    answer = Answer(
        question="q",
        question_type="hardcoded_secrets",
        understood=True,
        match_confidence=1.0,
        lines=[AnswerLine("This firmware is definitely backdoored.")],
    )
    with pytest.raises(AnswerError, match="must cite at least one claim"):
        validate_answer(answer)


def test_validate_rejects_a_caveat_that_cites_claims():
    answer = Answer(
        question="q",
        question_type="hardcoded_secrets",
        understood=True,
        match_confidence=1.0,
        lines=[AnswerLine("A limit of the analysis.", ("clm_x",), is_caveat=True)],
    )
    with pytest.raises(AnswerError, match="must not cite"):
        validate_answer(answer)


def test_validate_rejects_a_citation_that_is_not_in_the_findings():
    answer = Answer(
        question="q",
        question_type="hardcoded_secrets",
        understood=True,
        match_confidence=1.0,
        lines=[AnswerLine("Something.", ("clm_" + "0" * 32,))],
    )
    with pytest.raises(AnswerError, match="not among the answer's findings"):
        validate_answer(answer)


def test_a_valid_answer_passes_validation():
    finding = Finding(
        claim_id="clm_" + "a" * 32,
        predicate="contains_hardcoded_secret",
        statement={"secret_kind": "api_token"},
        confidence=0.9,
        producers=("aether-triage",),
        subject_path="etc/config",
    )
    answer = Answer(
        question="q",
        question_type="hardcoded_secrets",
        understood=True,
        match_confidence=1.0,
        lines=[
            AnswerLine("One token found.", (finding.claim_id,)),
            AnswerLine("Pattern matches only.", is_caveat=True),
        ],
        findings=[finding],
    )
    validate_answer(answer)


# -- answering --------------------------------------------------------------


def test_secrets_answer_names_files_and_locations(firmware_project):
    answer = ask(firmware_project, "are there any hardcoded secrets?")
    assert answer.question_type == "hardcoded_secrets"
    assert answer.findings
    rendered = answer.render()
    assert "etc/telemetry.conf" in rendered
    for finding in answer.findings:
        assert finding.evidence, "a secret claim must resolve to its string"
        assert finding.evidence[0]["kind"] == "string"


def test_answers_can_be_scoped_to_one_file(firmware_project):
    scoped = ask(
        firmware_project, "any hardcoded secrets?", object_reference="etc/telemetry.conf"
    )
    assert scoped.scope == "etc/telemetry.conf"
    assert scoped.findings
    assert {f.subject_path for f in scoped.findings} == {"etc/telemetry.conf"}

    unscoped = ask(firmware_project, "any hardcoded secrets?")
    assert len(unscoped.findings) > len(scoped.findings)


def test_unknown_scope_is_a_clean_error(firmware_project):
    with pytest.raises(EvidenceError, match="no file in this project"):
        ask(firmware_project, "any secrets?", object_reference="no/such/file")


def test_empty_question_is_refused(firmware_project):
    with pytest.raises(EvidenceError, match="empty"):
        ask(firmware_project, "   ")


def test_declined_answer_offers_the_supported_set(firmware_project):
    answer = ask(firmware_project, "what is the capital of France")
    assert answer.understood is False
    assert answer.question_type is None
    assert len(answer.supported) == len(QUESTION_TYPES)
    assert not answer.findings
    validate_answer(answer)


def test_a_question_with_no_matching_evidence_still_answers_honestly(project, elf_sample):
    """No findings must produce a caveat, not silence and not an invention."""
    from aether.adapters.triage import TriageAdapter

    TriageAdapter().analyze(project, elf_sample, logical_path="bin/agent")
    answer = ask(project, "what urls does it contain", object_reference="bin/agent")
    assert answer.understood
    assert all(line.is_caveat for line in answer.lines) or answer.findings
    validate_answer(answer)


def test_attack_surface_reports_absence_of_dynamic_evidence(firmware_project):
    """Without a trace, reachability is unproven - and must say so."""
    answer = ask(firmware_project, "what is the attack surface?")
    assert any("reachability is unproven" in c for c in answer.caveats)


def test_answer_record_round_trips_through_json(firmware_project):
    answer = ask(firmware_project, "any suspicious strings?")
    record = json.loads(json.dumps(answer.to_record()))
    assert record["question_type"] == "suspicious_indicators"
    assert record["claim_ids"]
    assert all("claim_ids" in line for line in record["lines"])


def test_findings_are_ordered_by_confidence(firmware_project):
    answer = ask(firmware_project, "are there hardcoded secrets?")
    confidences = [f.confidence for f in answer.findings]
    assert confidences == sorted(confidences, reverse=True)


# -- front ends -------------------------------------------------------------


def test_cli_ask_renders_citations(tmp_path, firmware_sample, capsys):
    from aether.cli import main

    root = str(tmp_path / "proj")
    main(["init", root])
    main(["-P", root, "analyze", firmware_sample])
    capsys.readouterr()

    assert main(["-P", root, "ask", "are", "there", "any", "secrets?"]) == 0
    output = capsys.readouterr().out
    assert "hardcoded_secrets" in output
    assert "clm_" in output


def test_cli_ask_declines_without_failing(tmp_path, firmware_sample, capsys):
    """Declining is a correct outcome; the exit code must not say otherwise."""
    from aether.cli import main

    root = str(tmp_path / "proj")
    main(["init", root])
    main(["-P", root, "analyze", firmware_sample])
    capsys.readouterr()

    assert main(["-P", root, "ask", "what", "is", "the", "weather"]) == 0
    output = capsys.readouterr().out
    assert "not guessed at" in output
    assert "This interface answers" in output


def test_cli_ask_lists_supported_questions(capsys):
    from aether.cli import main

    assert main(["ask", "--list"]) == 0
    output = capsys.readouterr().out
    for question_type in QUESTION_TYPES:
        assert question_type in output


def test_mcp_ask_returns_structured_citations(firmware_project):
    from aether.mcp.server import MCPServer

    server = MCPServer(firmware_project)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "aether_ask",
                "arguments": {"question": "what components are embedded?"},
            },
        }
    )["result"]

    payload = response["structuredContent"]
    assert payload["understood"] is True
    assert payload["question_type"] == "embedded_components"
    assert payload["claim_ids"]
    for line in payload["lines"]:
        assert line["claim_ids"] or line["is_caveat"]


def test_mcp_ask_declines_out_of_scope_questions(firmware_project):
    from aether.mcp.server import MCPServer

    server = MCPServer(firmware_project)
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "aether_ask",
                "arguments": {"question": "should I ship this product"},
            },
        }
    )["result"]

    payload = response["structuredContent"]
    assert payload["understood"] is False
    assert payload["supported"]
    assert not response.get("isError")
