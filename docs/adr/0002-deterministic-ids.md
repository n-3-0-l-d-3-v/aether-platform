# ADR 0002: Content-addressed ids, and what is excluded from them

**Status:** accepted · **Date:** 2026-08-26

## Context

The specification calls for "deterministic export of project state (JSONL or
equivalent) that is Git-friendly". Git-friendly is a stronger requirement than
it sounds: it means re-running an analysis that discovered nothing new must
produce *no diff at all*. Otherwise every re-analysis buries real findings under
churn, and reviewers stop reading the diff — which is the whole benefit.

## Decision

Every record id is `blake2b(canonical_json(identity_payload), 16)` with a type
prefix. Two rules govern the payload:

1. It contains exactly the fields that define the thing's *meaning* — no more
   (or unrelated changes churn the id), no less (or distinct things collide).
2. It contains no wall-clock time, no absolute host path, and no run id.

Canonicalization rejects anything ambiguous rather than coercing it: NaN and
infinity, non-string mapping keys, sets, arbitrary objects. Floats round to six
decimals and integral floats collapse to integers, so `1.0` and `1` cannot mint
different ids. Strings are NFC-normalized, so text that arrived from two sources
in different Unicode forms converges.

## The export split

Determinism cannot cover provenance, because provenance *is* time-varying. So
the export has two trees:

- `graph/` — artifacts, claims, links. Deterministic and content-addressed.
  Two independent analyses of the same bytes produce byte-identical files.
- `ledger/` — runs, attestations, observations. Grows with every run.

Commit `graph/`. Its diff is the discovery.

This is why artifacts carry no run id in the export even though the database
records which runs observed them: that relationship lives in
`ledger/observations.jsonl`, where growth is expected.

## Identity groups

A single fixed identity per kind broke cross-engine convergence, which is the
main thing content addressing was meant to deliver. A string found by a header
parser has a file offset; the same string found by a disassembler has a virtual
address. Requiring all identity fields would mint two ids for one literal.

`identity_groups` gives a kind ordered fallbacks — the first group whose fields
are all present wins. For `string`: prefer `(text, encoding, addr)`, fall back
to `(text, encoding, file_offset)`. Triage was also taught to translate offsets
into virtual addresses using the section table it already parses, so it can
speak the address coordinate system when one exists.

The same mechanism settles imports. A header parser cannot see which library an
ELF import resolves to; a disassembler can. Import identity is therefore the
symbol name alone. The cost — a PE importing the same name from two DLLs
collapses onto one artifact — is real but rare, and surfaces as a recorded field
conflict. The alternative was worse and universal: two artifacts for every
import of every binary, and convergence between engines that never happens.

## Consequences

- Re-analysis is idempotent. Verified by a test that builds two projects from
  scratch and asserts identical graph digests.
- Enriching an artifact never changes its id, so annotations and claims pointing
  at it survive re-analysis.
- Changing a kind's identity fields is a breaking change requiring a migration.
  That is correct, and the schema documents identity explicitly to make the
  weight of such a change visible.
- Run ids carry a nonce, because a run is an event rather than a value. A
  timestamp alone was not sufficient: Windows resolves wall time to roughly
  15ms, and two runs collided during testing.
