# ADR 0008: Phase 2 lands as four narrow, real capabilities

**Status:** accepted · **Date:** 2026-08-28 (revised 2026-08-28 - see the
addendum: two items originally deferred here were completed the same day)

## Context

Phase 2 of the specification is "Firmware Cartography & Campaigns": inter-binary
maps, sink reachability across files, version tracking, and diffing. That is
four substantial features, several of which (full campaign tracking,
cross-binary sink reachability) are research-scale problems on their own.

The project's own discipline says: "prefer working, measurable increments over
incomplete ambitious features" and "when in doubt, ask before adding scope."

## Decision

Land two pieces, both fully real and fully tested, and say plainly what is not
attempted.

**Cross-binary import/export linking** (`yugen/cartography/link_imports`).
For every file in a project, resolve its imports against every other file's
exports by symbol name. This is the actual substance of "inter-binary maps" -
which binary's undefined symbol is satisfied by which other binary's
definition - expressed as a new claim predicate, `imports_resolved_by`, whose
evidence spans two file objects.

**Version diffing** (`yugen/cartography/diff`). Compare `embeds_component`
claims across two independently analysed projects, matched by component name,
and optionally record `component_version_changed` claims in the newer project.

## What is deliberately not attempted here

*(Updated - see the addendum below: two of these three were completed in a
follow-up change once the tools to build them honestly already existed.
Struck through, not deleted, so this ADR still records the reasoning at the
time the scoping decision was made.)*

- ~~**Cross-binary sink reachability.**~~ Completed. See the addendum.
- ~~**Full campaign / fleet tracking.**~~ Completed, narrowly. See the addendum.
- ~~**A general evidence-graph diff.**~~ Completed. See the addendum.

All four Phase 2 items named in the specification now have a landed, scoped
slice. None of the four is the full research-scale version of what "Firmware
Cartography & Campaigns" could mean - see each addendum entry for exactly
where the line was drawn.

## Why a name match is honestly weak evidence, and the model says so

`imports_resolved_by` is inference over two independent observations - an
import in one file's symbol table, an export in another's - not a direct
reading of either file's own structure. Two real binaries can share a symbol
name that resolves to different implementations (symbol versioning, `LD_
PRELOAD`, static linking a private copy of a common library name). The
predicate's own documentation says the claim proves name agreement, not a live
dependency, and its confidence is fixed below what a header parse or symbol
table read earns elsewhere in Yugen - lower still when more than one file
exports the same name, since guessing which the dynamic linker would actually
pick is not something a static join can do.

Common libc/CRT symbols (`malloc`, `memcpy`, `printf`, ...) are excluded from
linking by default. At firmware scale nearly every binary imports them from
the C library, and including them would produce a graph dense with edges that
say nothing about *this* firmware's structure - the same reasoning that keeps
`printf` out of the risky-API table (ADR-adjacent to Phase 0's detector
design).

## Why version diffing stays a report, with one narrow write

Two projects are two independent SQLite databases. Even identical bytes only
converge onto one artifact *within* a project (ADR 0002); two different
firmware builds certainly share no ids. Comparison therefore matches by
component name, which is a weaker join than content addressing.

`diff_components` is a pure function returning a report - nothing is written,
so a wrong join costs nothing but a wrong answer, not a corrupted graph.
`record_version_changes` writes into the *target* project only, and only for
`component` names present with a version in both projects (a `changed`
outcome). `added`/`removed` outcomes are not written as claims because there is
no natural evidence locus for them: a component absent from a project has
nothing in that project's graph to attach evidence to, and writing a claim
about the *baseline* project from within the target project would mean citing
artifact ids that do not exist there - the exact thing the evidence model
exists to prevent.

## Consequences

- `imports_resolved_by` and `component_version_changed` bring the claim
  predicate count to fourteen; both were reviewed for the same property every
  predicate must have: no field of type "prose."
- Cartography claims can be produced and re-run idempotently, like every other
  adapter - running `link_imports` twice converges rather than duplicating.

## Addendum: cross-binary sink reachability and a general graph diff

Two of the three items this ADR originally deferred were completed in a
follow-up change, once the tools to build them honestly already existed.

**Cross-binary sink reachability** (`yugen/cartography/reachability.py`)
chains three claims that were already independently true in the graph: a
function observed executing under QEMU (`function_reached`), a call from that
function into an import (a Ghidra `xref`), and that import resolved to another
file's export (`imports_resolved_by`). The result, `cross_binary_reachable`,
says a *specific, observed* code path reaches the boundary of another binary
at a named symbol - not that the other binary's own implementation was itself
seen running, which nothing here observes. Its confidence is the *minimum* of
the two chained claims' confidences, not their product: this is one reasoning
chain where each half is necessary, not two independent observations
corroborating the same fact, so noisy-OR (ADR 0003's combination rule for
independent producers) does not apply here.

**A general evidence-graph diff** (`yugen/export/diff.py`) turned out to be
nearly free given content-addressed ids (ADR 0002): comparing two graphs is a
set difference over ids, because an id present on both sides is, by
construction, the same artifact or claim. It compares a live project against
another live project, an export against another export, or a project against
its own export - the last of which is asserted to be identical in a test,
since anything else would mean the export was lossy.

**Campaign/fleet correlation** (`yugen/cartography/campaign.py`) groups
several *projects* - not artifacts within one project - into campaigns using
two mechanical signals: an identical file (matching SHA-256) is conclusive; a
threshold number of shared component-version pairs (default two, configurable)
is a weaker but still real signal, deliberately gated so that one common
library shared by coincidence at firmware scale is never mistaken for a
lineage. Projects are grouped by these edges with union-find, so correlation
is transitive: if A matches B and B matches C, all three land in one campaign
whether or not A and C correlate directly.

This stays a read-only reporting function across N independent project
databases, for the same reason version diffing does: there is no single graph
a "these projects are a campaign" claim could honestly live in without citing
artifacts from a database it is not part of. Real-world testing surfaced an
honest limitation worth stating rather than hiding: two genuinely unrelated
sample binaries in this repository's own test fixtures correlate via the
component-fingerprint signal, because both happen to embed the same
placeholder `busybox`/`openssl` version banners used across the evaluation
suite. The threshold reduces this kind of false positive; it does not
eliminate it, and nothing claims otherwise.

Nothing here attempts fuzzy vendor or product-name matching, semantic
versioning reasoning, or any correlation signal not directly observable in two
projects' own evidence graphs. A campaign concept that model those things -
should one prove necessary - would be a substantially larger effort building
on this mechanical foundation, not a refinement of it.
