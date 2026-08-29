"""The supported question types, and how each is answered from the graph.

Five types, deliberately. The specification says "narrow NL interface (only
4-5 question types)", and the discipline is the point: a narrow interface whose
precision can be measured is worth more than a broad one whose failures are
invisible. A question outside this set is declined, with the set listed - never
guessed at.

Nothing here calls a language model. Intent matching is weighted term scoring
over a curated vocabulary, which means it is deterministic, runs offline, is
testable case by case, and can be scored for precision on a fixed corpus. When
the score does not clear the threshold the honest answer is "I do not handle
that", and that is what comes back.

Each type declares which claim predicates answer it, so the whole path from a
question to bytes is: question -> question type -> predicates -> claims ->
evidence artifacts -> addresses in a file.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from aether.nl.model import AnswerLine, Finding

#: Below this score a question is treated as unsupported. Tuned on the phrase
#: corpus in eval/suites/nl_questions.json: high enough that "what is the
#: weather" is declined, low enough that a terse "any secrets?" is not.
MATCH_THRESHOLD = 0.30


def _singular(token: str) -> str:
    """Crude English singularization, enough for a question vocabulary.

    Not a stemmer and not trying to be. It exists so the vocabulary can be
    written once in the singular instead of listing every plural by hand, which
    is the kind of list that silently rots.
    """
    if len(token) > 4 and token.endswith("ies"):
        return token[:-3] + "y"
    if len(token) > 4 and token.endswith(("ses", "xes", "zes", "ches", "shes")):
        return token[:-2]
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


@dataclass(frozen=True)
class Normalized:
    """A question prepared for matching, in both the forms matching needs."""

    text: str
    tokens: frozenset[str]

    def has_phrase(self, phrase: str) -> bool:
        return phrase in self.text

    def has_word(self, word: str) -> bool:
        return word in self.tokens


def _contains(normalized: "Normalized", phrase: str) -> bool:
    """Match one vocabulary entry against a prepared question.

    Single words are matched as whole tokens, in both their written and
    singularized form. Substring matching would let "key" fire on "monkey" and
    "pie" on "piece" - exactly the silent mis-classification a narrow interface
    exists to avoid. Multi-word phrases stay substring matches, so
    "third party librar" catches both "libraries" and "library".
    """
    stripped = phrase.strip()
    if " " in stripped:
        return normalized.has_phrase(stripped)
    return normalized.has_word(stripped) or normalized.has_word(_singular(stripped))


@dataclass(frozen=True)
class Vocabulary:
    """Weighted terms that indicate one question type.

    Anchors are phrases specific enough to decide the question on their own;
    terms are suggestive; weak terms only break ties. Negatives subtract, which
    is how "component" stops pulling a hardening question toward the SBOM one.
    """

    anchors: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    weak: tuple[str, ...] = ()
    negatives: tuple[str, ...] = ()

    def score(self, text: "str | Normalized") -> float:
        normalized = prepare(text) if isinstance(text, str) else text
        total = 0.0
        for phrase in self.anchors:
            if _contains(normalized, phrase):
                total += 1.0
        for phrase in self.terms:
            if _contains(normalized, phrase):
                total += 0.5
        for phrase in self.weak:
            if _contains(normalized, phrase):
                total += 0.2
        for phrase in self.negatives:
            if _contains(normalized, phrase):
                total -= 0.6
        return total


@dataclass(frozen=True)
class PlanContext:
    """What a summarizer may look at beyond its own findings."""

    project: Any
    object_id: str | None = None
    scope_label: str | None = None


Summarizer = Callable[[list[Finding], PlanContext], "tuple[list[AnswerLine], list[str]]"]


@dataclass(frozen=True)
class QuestionType:
    """One answerable question."""

    id: str
    title: str
    description: str
    examples: tuple[str, ...]
    predicates: tuple[str, ...]
    vocabulary: Vocabulary
    summarize: Summarizer
    #: Claims below this confidence are excluded from the answer entirely.
    min_confidence: float = 0.0

    def to_record(self) -> dict[str, str]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "example": self.examples[0] if self.examples else "",
        }


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or singular + "s")


def _by_file(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.subject_path or "(unattributed)"].append(finding)
    return dict(grouped)


def _ids(findings: Sequence[Finding]) -> tuple[str, ...]:
    return tuple(f.claim_id for f in findings)


def _corroborated(findings: Sequence[Finding]) -> list[Finding]:
    return [f for f in findings if len(f.producers) > 1]


def _scope_phrase(context: PlanContext) -> str:
    return f"in {context.scope_label}" if context.scope_label else "across the project"


# --------------------------------------------------------------------------
# Summarizers
# --------------------------------------------------------------------------


def _summarize_secrets(
    findings: list[Finding], context: PlanContext
) -> tuple[list[AnswerLine], list[str]]:
    if not findings:
        return (
            [
                AnswerLine(
                    "No credential-shaped literals were found "
                    f"{_scope_phrase(context)}.",
                    is_caveat=True,
                )
            ],
            ["Absence of a detection is not evidence of absence; only the "
             "registered rules were applied."],
        )

    lines: list[AnswerLine] = []
    kinds = Counter(f.statement.get("secret_kind", "unknown") for f in findings)
    summary = ", ".join(
        f"{count} {kind.replace('_', ' ')}" for kind, count in kinds.most_common()
    )
    lines.append(
        AnswerLine(
            f"{len(findings)} credential-shaped "
            f"{_plural(len(findings), 'literal')} {_scope_phrase(context)}: {summary}.",
            _ids(findings),
        )
    )

    for path, group in sorted(_by_file(findings).items()):
        detail = ", ".join(
            sorted({f.statement.get("secret_kind", "unknown").replace("_", " ") for f in group})
        )
        lines.append(
            AnswerLine(f"{path} carries {detail}.", _ids(group))
        )

    strongest = max(findings, key=lambda f: f.confidence)
    location = strongest.evidence[0] if strongest.evidence else {}
    if location:
        lines.append(
            AnswerLine(
                "Highest-confidence match is "
                f"{strongest.statement.get('secret_kind', 'unknown').replace('_', ' ')} "
                f"at {location.get('location', 'an unrecorded location')} in "
                f"{strongest.subject_path or 'the subject'}, confidence "
                f"{strongest.confidence:.2f}.",
                (strongest.claim_id,),
            )
        )

    caveats = [
        "These are pattern matches. A match is credential-shaped; whether it is "
        "a live credential requires a human to check.",
        "Claims carry a masked preview only. The full literal stays in the "
        "string artifact, reachable through the claim's evidence.",
    ]
    return lines, caveats


def _summarize_components(
    findings: list[Finding], context: PlanContext
) -> tuple[list[AnswerLine], list[str]]:
    if not findings:
        return (
            [
                AnswerLine(
                    "No third-party component banners were identified "
                    f"{_scope_phrase(context)}.",
                    is_caveat=True,
                )
            ],
            ["Only components with a recognised version banner are detected; "
             "statically linked code without one is invisible to this check."],
        )

    lines: list[AnswerLine] = []
    by_component: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        key = (
            str(finding.statement.get("component", "unknown")),
            str(finding.statement.get("version", "")),
        )
        by_component[key].append(finding)

    lines.append(
        AnswerLine(
            f"{len(by_component)} distinct component "
            f"{_plural(len(by_component), 'version')} identified "
            f"{_scope_phrase(context)}.",
            _ids(findings),
        )
    )
    for (component, version), group in sorted(by_component.items()):
        where = sorted({f.subject_path for f in group if f.subject_path})
        label = f"{component} {version}".strip()
        location = f" in {', '.join(where[:3])}" if where else ""
        if len(where) > 3:
            location += f" and {len(where) - 3} other file(s)"
        lines.append(AnswerLine(f"{label}{location}.", _ids(group)))

    caveats = [
        "Versions come from banner strings, which vendors patch without "
        "updating. Treat them as a starting point for CVE lookup, not proof.",
        "Aether does not consult any vulnerability database; no claim here "
        "says a component is vulnerable.",
    ]
    return lines, caveats


def _summarize_attack_surface(
    findings: list[Finding], context: PlanContext
) -> tuple[list[AnswerLine], list[str]]:
    risky = [f for f in findings if f.predicate == "uses_risky_api"]
    reached = [f for f in findings if f.predicate == "function_reached"]

    if not risky:
        return (
            [
                AnswerLine(
                    f"No risky API usage was recorded {_scope_phrase(context)}.",
                    is_caveat=True,
                )
            ],
            ["Only symbols in the curated risky-API table are considered."],
        )

    lines: list[AnswerLine] = []
    categories: dict[str, list[Finding]] = defaultdict(list)
    for finding in risky:
        categories[str(finding.statement.get("category", "unknown"))].append(finding)

    apis = sorted({str(f.statement.get("api")) for f in risky})
    lines.append(
        AnswerLine(
            f"{len(apis)} risky {_plural(len(apis), 'API')} referenced "
            f"{_scope_phrase(context)}, across "
            f"{len(categories)} {_plural(len(categories), 'category', 'categories')}.",
            _ids(risky),
        )
    )
    for category, group in sorted(categories.items()):
        names = sorted({str(f.statement.get("api")) for f in group})
        lines.append(
            AnswerLine(
                f"{category.replace('_', ' ')}: {', '.join(names)}.",
                _ids(group),
            )
        )

    with_sites = [f for f in risky if f.statement.get("call_site_count")]
    if with_sites:
        detail = ", ".join(
            f"{f.statement.get('api')} ({f.statement.get('call_site_count')} call "
            f"{_plural(int(f.statement.get('call_site_count') or 0), 'site')})"
            for f in sorted(with_sites, key=lambda f: str(f.statement.get("api")))
        )
        lines.append(
            AnswerLine(
                f"Call sites were resolved for {detail}.",
                _ids(with_sites),
            )
        )

    if reached:
        names = sorted({str(f.statement.get("name")) for f in reached})
        lines.append(
            AnswerLine(
                f"Observed executing under emulation: {', '.join(names)}.",
                _ids(reached),
            )
        )

    caveats = [
        "Referencing an API is not a vulnerability. This is attack surface, "
        "and every claim here says only that the symbol is present.",
        "Without resolved call sites, an import may be linked but never called.",
    ]
    if not reached:
        caveats.append(
            "No dynamic evidence is present; reachability is unproven either way."
        )
    return lines, caveats


def _summarize_suspicious(
    findings: list[Finding], context: PlanContext
) -> tuple[list[AnswerLine], list[str]]:
    if not findings:
        return (
            [
                AnswerLine(
                    "No suspicious string indicators were recorded "
                    f"{_scope_phrase(context)}.",
                    is_caveat=True,
                )
            ],
            ["Only the registered indicator categories are scanned."],
        )

    lines: list[AnswerLine] = []
    categories: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        categories[str(finding.statement.get("category", "unknown"))].append(finding)

    lines.append(
        AnswerLine(
            f"{len(findings)} string {_plural(len(findings), 'indicator')} "
            f"{_scope_phrase(context)} across "
            f"{len(categories)} {_plural(len(categories), 'category', 'categories')}.",
            _ids(findings),
        )
    )
    for category, group in sorted(categories.items()):
        previews = sorted({str(f.statement.get("preview", "")) for f in group if f.statement.get("preview")})
        shown = "; ".join(previews[:3])
        if len(previews) > 3:
            shown += f"; and {len(previews) - 3} more"
        lines.append(
            AnswerLine(f"{category.replace('_', ' ')}: {shown}", _ids(group))
        )

    caveats = [
        "Indicators, not findings. A URL or device path in a binary is "
        "ordinary; these are flagged so a reviewer can decide.",
        "Detections are capped per category per file, so counts are a floor "
        "rather than a total.",
    ]
    return lines, caveats


def _summarize_hardening(
    findings: list[Finding], context: PlanContext
) -> tuple[list[AnswerLine], list[str]]:
    if not findings:
        return (
            [
                AnswerLine(
                    "No exploit-mitigation flags were recorded "
                    f"{_scope_phrase(context)}.",
                    is_caveat=True,
                )
            ],
            ["Mitigation flags are read from executable headers; a file that "
             "is not an ELF or PE has none to read."],
        )

    lines: list[AnswerLine] = []
    for path, group in sorted(_by_file(findings).items()):
        present = sorted(
            str(f.statement.get("feature")) for f in group if f.statement.get("present")
        )
        absent = sorted(
            str(f.statement.get("feature"))
            for f in group
            if not f.statement.get("present")
        )
        parts = []
        if present:
            parts.append(f"enabled: {', '.join(present)}")
        if absent:
            parts.append(f"absent: {', '.join(absent)}")
        lines.append(AnswerLine(f"{path} - {'; '.join(parts)}.", _ids(group)))

    missing = [f for f in findings if not f.statement.get("present")]
    if missing:
        features = sorted({str(f.statement.get("feature")) for f in missing})
        lines.append(
            AnswerLine(
                f"Mitigations reported absent somewhere in scope: {', '.join(features)}.",
                _ids(missing),
            )
        )

    caveats = [
        "These flags describe what the toolchain requested. They are read from "
        "headers and segment tables, not verified at runtime.",
        "A missing PT_GNU_STACK is reported as NX absent, because unstated is "
        "not the same as enforced.",
    ]
    return lines, caveats


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

QUESTION_TYPES: dict[str, QuestionType] = {}


def _register(question: QuestionType) -> None:
    QUESTION_TYPES[question.id] = question


_register(
    QuestionType(
        id="hardcoded_secrets",
        title="Hardcoded secrets and credentials",
        description="Credential-shaped literals embedded in the analysed files.",
        examples=(
            "Are there any hardcoded secrets?",
            "Does this firmware contain credentials or API keys?",
            "any passwords or private keys in here?",
        ),
        predicates=("contains_hardcoded_secret",),
        vocabulary=Vocabulary(
            anchors=(
                "hardcoded secret",
                "hard coded secret",
                "hardcoded credential",
                "api key",
                "private key",
                "access key",
                "secrets",
            ),
            terms=(
                "secret",
                "credential",
                "password",
                "passwd",
                "token",
                "keys",
                "hardcoded",
                "embedded key",
            ),
            weak=("key", "auth", "login"),
            negatives=("public key infrastructure",),
        ),
        summarize=_summarize_secrets,
    )
)

_register(
    QuestionType(
        id="embedded_components",
        title="Embedded third-party components",
        description="Third-party libraries and their versions, from banner strings.",
        examples=(
            "What third-party components are in this image?",
            "Which libraries and versions does it embed?",
            "give me an SBOM",
        ),
        predicates=("embeds_component",),
        vocabulary=Vocabulary(
            anchors=(
                "third party component",
                "third-party component",
                "sbom",
                "bill of materials",
                "what libraries",
                "which libraries",
                "third party librar",
                "third party softwar",
                "open source component",
                "component",
            ),
            terms=(
                "components",
                "libraries",
                "library",
                "dependencies",
                "dependency",
                "versions",
                "busybox",
                "openssl",
                "what software",
            ),
            weak=("version", "built with", "inside"),
        ),
        summarize=_summarize_components,
    )
)

_register(
    QuestionType(
        id="attack_surface",
        title="Attack surface",
        description="Risky API usage, with call sites and any observed execution.",
        examples=(
            "What is the attack surface?",
            "Does it use any dangerous functions?",
            "where could this be attacked?",
        ),
        predicates=("uses_risky_api", "function_reached"),
        vocabulary=Vocabulary(
            anchors=(
                "attack surface",
                "dangerous function",
                "risky api",
                "risky function",
                "unsafe function",
                "memory corruption",
                "command injection",
            ),
            terms=(
                "attack",
                "attacked",
                "attacker",
                "risky",
                "dangerous",
                "unsafe",
                "exploitable",
                "buffer overflow",
                "strcpy",
                "system call",
                "exposure",
            ),
            weak=("risk", "vulnerable", "surface"),
        ),
        summarize=_summarize_attack_surface,
    )
)

_register(
    QuestionType(
        id="suspicious_indicators",
        title="Suspicious strings and behaviours",
        description="URLs, addresses, shell fragments, device paths, and encoded blobs.",
        examples=(
            "Any suspicious strings?",
            "What URLs or IP addresses does it contain?",
            "does it phone home anywhere?",
        ),
        predicates=("suspicious_string",),
        vocabulary=Vocabulary(
            anchors=(
                "suspicious string",
                "suspicious behaviour",
                "suspicious behavior",
                "phone home",
                "ip address",
                "hardcoded url",
                "what urls",
                "network indicator",
            ),
            terms=(
                "suspicious",
                "urls",
                "url",
                "endpoints",
                "domains",
                "addresses",
                "beacon",
                "shell command",
                "indicators",
            ),
            weak=("network", "http", "connect", "behaviour", "behavior"),
        ),
        summarize=_summarize_suspicious,
    )
)

_register(
    QuestionType(
        id="binary_hardening",
        title="Exploit mitigations",
        description="Which hardening features the binaries were built with.",
        examples=(
            "Is this binary hardened?",
            "Does it have NX, PIE, and RELRO?",
            "what mitigations are enabled?",
        ),
        predicates=("binary_hardening",),
        vocabulary=Vocabulary(
            anchors=(
                "exploit mitigation",
                "mitigations",
                "hardened",
                "hardening",
                "stack canary",
                "relro",
                "nx bit",
                "aslr",
                "pie",
            ),
            terms=(
                "protections",
                "compiled with",
                "nx",
                "canary",
                "fortify",
                "safeseh",
                "defenses",
                "defences",
            ),
            weak=("secure", "protection"),
        ),
        summarize=_summarize_hardening,
    )
)


_PUNCTUATION = re.compile(r"[^a-z0-9+/_.-]+")


def normalize(text: str) -> str:
    """Lowercase and collapse punctuation, keeping phrase matching workable."""
    lowered = text.lower().strip()
    collapsed = _PUNCTUATION.sub(" ", lowered)
    return f" {' '.join(collapsed.split())} "


def prepare(text: str) -> Normalized:
    """Normalize once, in both the forms matching needs."""
    normalized = normalize(text)
    words = set(normalized.split())
    return Normalized(
        text=normalized,
        tokens=frozenset(words | {_singular(word) for word in words}),
    )


def score_all(text: str) -> list[tuple[QuestionType, float]]:
    """Score every question type against ``text``, best first."""
    normalized = prepare(text)
    scored = [
        (question, question.vocabulary.score(normalized))
        for question in QUESTION_TYPES.values()
    ]
    scored.sort(key=lambda pair: (-pair[1], pair[0].id))
    return scored


def classify(text: str) -> tuple[QuestionType | None, float]:
    """Pick the best question type, or ``(None, score)`` if none clears the bar.

    Returning None is a feature. A narrow interface that declines is measurable;
    one that guesses produces confident answers to questions nobody asked.
    """
    scored = score_all(text)
    if not scored:
        return None, 0.0
    best, best_score = scored[0]
    if best_score < MATCH_THRESHOLD:
        return None, max(best_score, 0.0)
    return best, best_score


def describe_supported() -> list[dict[str, str]]:
    """The supported question set, for the decline path and for discovery."""
    return [question.to_record() for question in QUESTION_TYPES.values()]


__all__ = [
    "MATCH_THRESHOLD",
    "Normalized",
    "PlanContext",
    "QUESTION_TYPES",
    "QuestionType",
    "Vocabulary",
    "classify",
    "describe_supported",
    "normalize",
    "prepare",
    "score_all",
]
