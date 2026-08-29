"""Evaluation harness: score structured claims against declared ground truth."""

from aether.eval.harness import (
    EvalError,
    ExpectationResult,
    QuestionReport,
    SuiteReport,
    load_suite,
    run_question_suite,
    run_suite,
    run_suites,
)

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
