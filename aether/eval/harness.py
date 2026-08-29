"""Evaluation harness: score claims against declared ground truth.

A suite names a target, the pipeline to run over it, and what should and should
not end up in the graph. Running it produces a scored report.

Two design choices worth stating, because they determine what the numbers mean:

*Recall is measurable; precision is not, quite.* A suite can enumerate what
must be found, so recall over those expectations is a real figure. It cannot
enumerate everything true about a binary, so an unexpected claim is not
automatically wrong. Precision is therefore reported against explicitly
*forbidden* patterns - things asserted to be absent - and everything else is
reported as unscored volume rather than folded into a flattering number.

*Evidence is checked, not just claims.* An expectation may require that a
matched claim cites evidence of a particular kind. A ``contains_hardcoded_secret``
claim that points at a file rather than at the string artifact is not the same
finding, even though the statement reads identically, and the harness fails it.
That check is what keeps the evidence graph honest as the rules evolve.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any

from aether.errors import AetherError
from aether.project.store import Project
from aether.util import utc_now


class EvalError(AetherError):
    """A suite is malformed or its target is missing."""

    exit_code = 8


@dataclass
class ExpectationResult:
    """Outcome for one declared expectation."""

    expectation_id: str
    predicate: str
    satisfied: bool
    required: bool
    detail: str = ""
    matched_claim_ids: list[str] = field(default_factory=list)
    best_confidence: float = 0.0

    def to_record(self) -> dict[str, Any]:
        return {
            "id": self.expectation_id,
            "predicate": self.predicate,
            "satisfied": self.satisfied,
            "required": self.required,
            "detail": self.detail,
            "matched_claim_ids": self.matched_claim_ids[:5],
            "best_confidence": self.best_confidence,
        }


@dataclass
class SuiteReport:
    """Scored outcome for one suite."""

    suite: str
    target: str
    passed: bool
    results: list[ExpectationResult] = field(default_factory=list)
    forbidden_hits: list[dict[str, Any]] = field(default_factory=list)
    totals: dict[str, Any] = field(default_factory=dict)
    pipeline: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "target": self.target,
            "passed": self.passed,
            "expectations": [r.to_record() for r in self.results],
            "forbidden_hits": self.forbidden_hits,
            "totals": self.totals,
            "pipeline": self.pipeline,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


@dataclass
class QuestionReport:
    """Scored outcome for a question-classification suite.

    Reported separately from claim suites because the failure modes differ.
    Classifying one supported question as another is a nuisance; classifying an
    *unsupported* question as supported is the one that produces a confident
    answer to a question nobody asked, so it is counted on its own and gates
    the suite by default.
    """

    suite: str
    passed: bool
    total: int = 0
    correct: int = 0
    false_accepts: list[dict[str, Any]] = field(default_factory=list)
    false_declines: list[dict[str, Any]] = field(default_factory=list)
    misclassified: list[dict[str, Any]] = field(default_factory=list)
    per_type: dict[str, dict[str, Any]] = field(default_factory=dict)
    totals: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "kind": "questions",
            "passed": self.passed,
            "totals": self.totals,
            "per_type": self.per_type,
            "false_accepts": self.false_accepts,
            "false_declines": self.false_declines,
            "misclassified": self.misclassified,
        }


def run_question_suite(suite: dict[str, Any]) -> QuestionReport:
    """Score intent classification against a labelled question corpus.

    No project is needed: this measures whether the interface understands the
    question, not whether the graph has anything to say about it. The latter is
    what the claim suites cover.
    """
    from aether.nl import classify

    cases = suite.get("cases") or []
    if not cases:
        raise EvalError(f"{suite.get('name')}: a question suite needs 'cases'")

    correct = 0
    false_accepts: list[dict[str, Any]] = []
    false_declines: list[dict[str, Any]] = []
    misclassified: list[dict[str, Any]] = []
    predicted_counts: dict[str, int] = {}
    expected_counts: dict[str, int] = {}
    hits: dict[str, int] = {}

    for case in cases:
        question = str(case.get("question", ""))
        expected = case.get("expect")
        matched, score = classify(question)
        predicted = matched.id if matched else None

        if expected:
            expected_counts[expected] = expected_counts.get(expected, 0) + 1
        if predicted:
            predicted_counts[predicted] = predicted_counts.get(predicted, 0) + 1

        if predicted == expected:
            correct += 1
            if expected:
                hits[expected] = hits.get(expected, 0) + 1
        elif expected is None:
            false_accepts.append(
                {
                    "question": question,
                    "classified_as": predicted,
                    "score": round(score, 3),
                }
            )
        elif predicted is None:
            false_declines.append(
                {"question": question, "expected": expected, "score": round(score, 3)}
            )
        else:
            misclassified.append(
                {"question": question, "expected": expected, "got": predicted}
            )

    per_type: dict[str, dict[str, Any]] = {}
    for name in sorted(set(expected_counts) | set(predicted_counts)):
        matched_count = hits.get(name, 0)
        predicted_total = predicted_counts.get(name, 0)
        expected_total = expected_counts.get(name, 0)
        per_type[name] = {
            "expected": expected_total,
            "predicted": predicted_total,
            "correct": matched_count,
            "precision": round(matched_count / predicted_total, 4)
            if predicted_total
            else 1.0,
            "recall": round(matched_count / expected_total, 4) if expected_total else 1.0,
        }

    total = len(cases)
    in_scope = sum(expected_counts.values())
    out_of_scope = total - in_scope
    macro_precision = (
        sum(v["precision"] for v in per_type.values()) / len(per_type) if per_type else 1.0
    )
    macro_recall = (
        sum(v["recall"] for v in per_type.values()) / len(per_type) if per_type else 1.0
    )

    totals = {
        "cases": total,
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "correct": correct,
        "accuracy": round(correct / total, 4) if total else 1.0,
        "macro_precision": round(macro_precision, 4),
        "macro_recall": round(macro_recall, 4),
        "false_accepts": len(false_accepts),
        "false_declines": len(false_declines),
        "misclassified": len(misclassified),
        "false_accept_rate": round(len(false_accepts) / out_of_scope, 4)
        if out_of_scope
        else 0.0,
    }

    thresholds = suite.get("thresholds") or {}
    passed = (
        totals["accuracy"] >= float(thresholds.get("min_accuracy", 0.9))
        and totals["macro_precision"] >= float(thresholds.get("min_macro_precision", 0.9))
        and len(false_accepts) <= int(thresholds.get("max_false_accepts", 0))
    )

    return QuestionReport(
        suite=str(suite.get("name", "questions")),
        passed=passed,
        total=total,
        correct=correct,
        false_accepts=false_accepts,
        false_declines=false_declines,
        misclassified=misclassified,
        per_type=per_type,
        totals=totals,
    )


def load_suite(path: str) -> dict[str, Any]:
    """Read and structurally validate a suite file."""
    if not os.path.isfile(path):
        raise EvalError(f"no such suite: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        try:
            suite = json.load(handle)
        except json.JSONDecodeError as exc:
            raise EvalError(f"{path} is not valid JSON: {exc}") from exc

    if suite.get("kind") == "questions":
        if not isinstance(suite.get("cases"), list) or not suite["cases"]:
            raise EvalError(f"{path}: a question suite needs a non-empty 'cases' list")
        return suite

    for key in ("name", "target", "expectations"):
        if key not in suite:
            raise EvalError(f"{path} is missing required key {key!r}")
    if not isinstance(suite["expectations"], list):
        raise EvalError(f"{path}: 'expectations' must be a list")
    return suite


def run_suite(
    suite: dict[str, Any],
    *,
    base_dir: str = ".",
    project_dir: str | None = None,
    keep_project: bool = False,
) -> SuiteReport:
    """Build a fresh project, run the suite's pipeline, and score the result."""
    started_at = utc_now()
    target_spec = suite["target"]
    target_path = os.path.join(base_dir, target_spec["path"])
    if not os.path.isfile(target_path):
        raise EvalError(
            f"suite target not found: {target_path}. "
            "Sample binaries are generated - see examples/src/."
        )

    if target_spec.get("sha256"):
        from aether.canonical import file_digests

        actual = file_digests(target_path)["sha256"]
        if actual != target_spec["sha256"]:
            raise EvalError(
                f"target digest mismatch for {target_spec['path']}:\n"
                f"  expected {target_spec['sha256']}\n"
                f"  actual   {actual}\n"
                "The ground truth was written against different bytes; "
                "regenerate the sample or update the suite."
            )

    workspace = project_dir or tempfile.mkdtemp(prefix="aether-eval-")
    try:
        project = Project.create(workspace, suite["name"], exist_ok=True)
        pipeline = _run_pipeline(project, suite, target_path, base_dir)
        report = _score(project, suite, pipeline)
        report.target = target_spec["path"]
        report.started_at = started_at
        report.finished_at = utc_now()
        project.close()
        return report
    finally:
        if not keep_project and project_dir is None:
            shutil.rmtree(workspace, ignore_errors=True)


def _run_pipeline(
    project: Project, suite: dict[str, Any], target_path: str, base_dir: str
) -> list[dict[str, Any]]:
    """Execute the suite's declared analysis steps in order."""
    from aether.adapters.binwalk import BinwalkAdapter
    from aether.adapters.ghidra import GhidraAdapter
    from aether.adapters.triage import TriageAdapter

    logical = suite["target"].get("logical_path")
    steps = suite.get("pipeline") or ["triage"]
    executed: list[dict[str, Any]] = []
    object_id: str | None = None

    for step in steps:
        name, _, argument = str(step).partition(":")
        try:
            if name == "triage":
                result = TriageAdapter().analyze(project, target_path, logical_path=logical)
                object_id = result.objects[0]
            elif name == "firmware":
                result = BinwalkAdapter().analyze(project, target_path, logical_path=logical)
                object_id = result.objects[0]
            elif name == "ghidra":
                result = GhidraAdapter().analyze(project, target_path, logical_path=logical)
                object_id = result.objects[0]
            elif name == "ghidra-export":
                # Import a recorded export. This is what lets a suite exercise
                # the Ghidra path on a machine with no Ghidra install, which is
                # most machines, including CI.
                export_dir = os.path.join(base_dir, argument)
                result = GhidraAdapter().import_directory(
                    project,
                    export_dir,
                    object_id=object_id,
                    target=None if object_id else target_path,
                    logical_path=logical,
                )
                object_id = result.objects[0]
            else:
                raise EvalError(f"unknown pipeline step {name!r}")
        except AetherError as exc:
            executed.append({"step": str(step), "ok": False, "error": str(exc)})
            continue
        executed.append(
            {
                "step": str(step),
                "ok": True,
                "artifacts": result.artifacts,
                "claims": result.claims,
                "warnings": result.warnings[:3],
            }
        )
    return executed


def _score(
    project: Project, suite: dict[str, Any], pipeline: list[dict[str, Any]]
) -> SuiteReport:
    results: list[ExpectationResult] = []
    matched_ids: set[str] = set()

    for raw in suite["expectations"]:
        result = _check_expectation(project, raw)
        results.append(result)
        matched_ids.update(result.matched_claim_ids)

    forbidden_hits: list[dict[str, Any]] = []
    for raw in suite.get("forbidden", []):
        claims = _find_matching(project, raw)
        for claim in claims:
            forbidden_hits.append(
                {
                    "id": raw.get("id", raw.get("predicate")),
                    "claim_id": claim["id"],
                    "predicate": claim["predicate"],
                    "statement": claim["statement"],
                    "confidence": claim["confidence"]["combined"],
                }
            )

    required = [r for r in results if r.required]
    satisfied_required = [r for r in required if r.satisfied]
    optional = [r for r in results if not r.required]

    stats = project.stats()
    total_claims = int(stats["totals"]["claims"])
    recall = len(satisfied_required) / len(required) if required else 1.0

    totals = {
        "expectations": len(results),
        "required": len(required),
        "required_satisfied": len(satisfied_required),
        "optional": len(optional),
        "optional_satisfied": sum(1 for r in optional if r.satisfied),
        "recall": round(recall, 4),
        "forbidden_patterns": len(suite.get("forbidden", [])),
        "forbidden_hits": len(forbidden_hits),
        "claims_in_project": total_claims,
        # Claims the suite never spoke to. Not errors - a suite cannot
        # enumerate everything true about a binary - but worth watching, since
        # a jump here usually means a rule got noisier.
        "unscored_claims": max(0, total_claims - len(matched_ids)),
        "artifacts_in_project": int(stats["totals"]["artifacts"]),
        "integrity_problems": len(project.check()),
    }

    passed = (
        len(satisfied_required) == len(required)
        and not forbidden_hits
        and totals["integrity_problems"] == 0
        and all(step.get("ok") for step in pipeline)
    )
    return SuiteReport(
        suite=suite["name"],
        target="",
        passed=passed,
        results=results,
        forbidden_hits=forbidden_hits,
        totals=totals,
        pipeline=pipeline,
    )


def _check_expectation(project: Project, raw: dict[str, Any]) -> ExpectationResult:
    expectation_id = str(raw.get("id") or raw.get("predicate") or "unnamed")
    predicate = str(raw.get("predicate") or "")
    required = bool(raw.get("required", True))

    claims = _find_matching(project, raw)
    if not claims:
        return ExpectationResult(
            expectation_id,
            predicate,
            satisfied=False,
            required=required,
            detail="no claim matched",
        )

    min_confidence = float(raw.get("min_confidence", 0.0))
    confident = [c for c in claims if c["confidence"]["combined"] >= min_confidence]
    if not confident:
        best = max(c["confidence"]["combined"] for c in claims)
        return ExpectationResult(
            expectation_id,
            predicate,
            satisfied=False,
            required=required,
            detail=f"matched, but best confidence {best} < required {min_confidence}",
            matched_claim_ids=[c["id"] for c in claims],
            best_confidence=best,
        )

    # An expectation may demand that the claim rests on the right *kind* of
    # evidence, not merely that a claim with the right words exists.
    wanted_kind = raw.get("evidence_kind")
    if wanted_kind:
        with_evidence = []
        for claim in confident:
            kinds = set()
            for ref in claim["evidence"]:
                artifact = project.get_artifact(ref["artifact_id"])
                if artifact:
                    kinds.add(artifact.kind)
            if wanted_kind in kinds:
                with_evidence.append(claim)
        if not with_evidence:
            return ExpectationResult(
                expectation_id,
                predicate,
                satisfied=False,
                required=required,
                detail=f"matched, but no claim cites evidence of kind {wanted_kind!r}",
                matched_claim_ids=[c["id"] for c in confident],
                best_confidence=max(c["confidence"]["combined"] for c in confident),
            )
        confident = with_evidence

    min_producers = int(raw.get("min_producers", 0))
    if min_producers:
        corroborated = [
            c for c in confident if c["confidence"]["producers"] >= min_producers
        ]
        if not corroborated:
            best = max(c["confidence"]["producers"] for c in confident)
            return ExpectationResult(
                expectation_id,
                predicate,
                satisfied=False,
                required=required,
                detail=f"matched, but only {best} producer(s) attested; "
                f"{min_producers} required",
                matched_claim_ids=[c["id"] for c in confident],
            )
        confident = corroborated

    return ExpectationResult(
        expectation_id,
        predicate,
        satisfied=True,
        required=required,
        detail="ok",
        matched_claim_ids=[c["id"] for c in confident],
        best_confidence=max(c["confidence"]["combined"] for c in confident),
    )


def _find_matching(project: Project, raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Find claims whose statement is a superset of the expectation's match."""
    predicate = raw.get("predicate")
    candidates = project.find_claims(predicate=predicate, limit=2000)

    match = raw.get("match") or {}
    subject_path = raw.get("subject_path")
    out: list[dict[str, Any]] = []
    for claim in candidates:
        statement = claim["statement"]
        if any(statement.get(key) != value for key, value in match.items()):
            continue
        if subject_path:
            subject = project.get_artifact(claim["subject_id"]) if claim["subject_id"] else None
            path = str(subject.data.get("path")) if subject else ""
            if not (path == subject_path or path.endswith("/" + subject_path)):
                continue
        out.append(claim)
    return out


def run_suites(
    paths: list[str], *, base_dir: str = "."
) -> tuple[list[Any], dict[str, Any]]:
    """Run several suites of either kind and summarize."""
    reports: list[Any] = []
    for path in paths:
        suite = load_suite(path)
        if suite.get("kind") == "questions":
            reports.append(run_question_suite(suite))
        else:
            reports.append(run_suite(suite, base_dir=base_dir))

    claim_reports = [r for r in reports if isinstance(r, SuiteReport)]
    question_reports = [r for r in reports if isinstance(r, QuestionReport)]

    summary: dict[str, Any] = {
        "suites": len(reports),
        "passed": sum(1 for r in reports if r.passed),
        "failed": sum(1 for r in reports if not r.passed),
        "required_total": sum(r.totals["required"] for r in claim_reports),
        "required_satisfied": sum(r.totals["required_satisfied"] for r in claim_reports),
        "forbidden_hits": sum(r.totals["forbidden_hits"] for r in claim_reports),
    }
    summary["recall"] = (
        round(summary["required_satisfied"] / summary["required_total"], 4)
        if summary["required_total"]
        else 1.0
    )
    if question_reports:
        cases = sum(r.totals["cases"] for r in question_reports)
        correct = sum(r.totals["correct"] for r in question_reports)
        summary["question_cases"] = cases
        summary["question_accuracy"] = round(correct / cases, 4) if cases else 1.0
        summary["question_false_accepts"] = sum(
            r.totals["false_accepts"] for r in question_reports
        )
        summary["question_macro_precision"] = round(
            sum(r.totals["macro_precision"] for r in question_reports)
            / len(question_reports),
            4,
        )
    return reports, summary


__all__ = [
    "EvalError",
    "ExpectationResult",
    "QuestionReport",
    "SuiteReport",
    "load_suite",
    "run_question_suite",
    "run_suite",
    "run_suites",
]
