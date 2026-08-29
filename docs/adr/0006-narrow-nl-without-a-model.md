# ADR 0006: The natural-language interface contains no language model

**Status:** accepted · **Date:** 2026-08-28

## Context

Phase 1 calls for a "narrow NL interface (only 4-5 question types: secrets,
component indicators, basic attack surface, suspicious strings/behaviors)" and
for "measured precision on the evaluation suite".

The obvious implementation is to hand the question and some graph context to a
language model and let it answer. That is what "natural language interface"
usually means in 2026.

## Decision

Five question types, classified by weighted term scoring over a curated
vocabulary. No model call, no network request. Answers are assembled from
templates over claim data the deterministic engines produced.

A question that does not clear the score threshold is **declined**, with the
supported set listed.

## Rationale

Three of the project's absolute principles make the obvious implementation the
wrong one here.

**"Never let an agent emit free-text security claims."** A model asked to
summarise findings will produce fluent prose whose relationship to the evidence
is unverifiable sentence by sentence. The structure that survives is the answer
model in `aether/nl/model.py`: every explanatory line carries the claim ids it
rests on, `validate_answer` rejects any line that cites none, and a test asserts
the property holds across every question type. That constraint is satisfiable by
templates. It is not satisfiable by generated prose without a verification step
that would be harder than the generation.

**"Local-first. No cloud analysis of user samples by default."** Sending
questions about a customer's firmware to a hosted model is exactly the disclosure
this forbids. A local model would satisfy the letter of it, at the cost of a
multi-gigabyte dependency in a project whose core has none.

**"Measured precision."** This is the decisive one. Deterministic classification
can be scored on a fixed corpus and will produce the same number tomorrow.
`eval/suites/nl_questions.json` holds seventy labelled cases, and the result is a
figure that means something: change the vocabulary, re-run, see the effect.
Scoring a model's classification is possible but the number moves under you when
the model is updated, and attributing a regression becomes archaeology.

## What this costs

Real things, worth naming.

- **Phrasings nobody anticipated are declined.** A model would handle "does this
  thing leak anything it shouldn't" gracefully; term scoring will not, unless
  "leak" is in the vocabulary. The mitigation is that declining is explicit and
  lists what *is* answerable, so the failure is visible and recoverable rather
  than a confident wrong answer.
- **The vocabulary needs maintenance**, and it is maintained by the same people
  who write the corpus that scores it. `eval/suites/nl_questions.json` says so
  in its own description: the numbers measure internal consistency, not
  performance against real users. Honest reporting of a limited measurement
  beats an impressive one that is not reproducible.
- **Answers are templated**, so they read like a report rather than a
  conversation. For this audience that is arguably a feature.

## What would change the decision

A model used strictly as a *classifier* - question in, one of five type labels
out, no prose - would preserve every invariant above, because the answer would
still be assembled from templates over claims. That is a contained change: the
only thing that would move is `classify()`. If real-world phrasings turn out to
defeat term scoring, that is the next thing to try, and the existing corpus
becomes the benchmark for whether it actually helps.

What would not be acceptable is a model generating the answer text. The citation
invariant is the thing that makes this layer trustworthy, and prose that cites
evidence it did not consult is precisely the failure mode Aether exists to
prevent.
