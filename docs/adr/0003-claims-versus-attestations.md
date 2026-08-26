# ADR 0003: Claims and attestations are separate records

**Status:** accepted · **Date:** 2026-08-26

## Context

The specification's claim object carries "provenance (tool + agent + timestamp)"
and "confidence" as fields. Implemented literally, the producer becomes part of
what a claim *is*.

That surfaces a problem the first time two engines agree. Header triage reads an
ELF's `.rodata` and finds an AWS key. Ghidra later reports the same literal at
the same address. If provenance is part of the claim, the graph now holds two
rows with identical statements and identical evidence, differing only in who
said it.

Two engines independently reaching the same conclusion is not noise. It is the
strongest signal an evidence-first system can produce, and the literal reading
discards it.

## Decision

Split the record.

**Claim** — predicate, subject, typed statement, evidence refs. No producer, no
timestamp. Content-addressed, so the same assertion is one claim regardless of
who makes it or when.

**Attestation** — claim id, producer, producer kind, run id, confidence,
timestamp, method. Many per claim.

Confidence is therefore never a property of a claim. It is derived by
`combine_confidence`:

- **Maximum within a producer.** One tool firing two rules is one opinion, not
  two. Without this, a detector with overlapping patterns would inflate its own
  confidence.
- **Noisy-OR across distinct producers.** Two independent 0.7s become 0.91.

## Honesty about the combiner

Independence across producers is an assumption, not a fact. Two adapters
wrapping the same underlying engine are not independent, and the combined figure
flatters them. `combine_confidence` therefore always returns `per_producer`
alongside the combined value, so a caller who knows the producers are correlated
can recompute. The docstring says so plainly rather than leaving it implicit.

## Consequences

- Corroboration is first-class. `aether query claims` shows a producer count,
  and evaluation suites can require `min_producers: 2`.
- Curation status (`proposed`/`accepted`/`rejected`) sits on the claim, because
  it is a project-level decision about the assertion, not about one attestation.
- An agent's opinion never overwrites a tool's. It is an additional attestation,
  marked `producer_kind: agent`, on a claim that stays `proposed` — which is
  also the shape the Phase 3 approval queue will need.
- Slightly more machinery: two tables, and the confidence a caller sees is
  computed rather than stored.

## Related

The same reasoning produced claim-to-claim relations. When Ghidra resolves call
sites for an API that triage could only see in the import table, the specific
claim is linked as `refines` the general one rather than replacing it. The
coarse claim still holds when disassembly fails, and a reviewer sees one lineage
instead of two unrelated findings.
