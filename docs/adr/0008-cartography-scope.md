# ADR 0008: Phase 2 lands as two narrow, real capabilities

**Status:** accepted · **Date:** 2026-08-28

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

**Cross-binary import/export linking** (`aether/cartography/link_imports`).
For every file in a project, resolve its imports against every other file's
exports by symbol name. This is the actual substance of "inter-binary maps" -
which binary's undefined symbol is satisfied by which other binary's
definition - expressed as a new claim predicate, `imports_resolved_by`, whose
evidence spans two file objects.

**Version diffing** (`aether/cartography/diff`). Compare `embeds_component`
claims across two independently analysed projects, matched by component name,
and optionally record `component_version_changed` claims in the newer project.

## What is deliberately not attempted

- **Cross-binary sink reachability.** "Binary A's exposed network handler calls
  into binary B's `system()`" requires resolving the call graph *through* the
  link edges above, which needs either static interprocedural analysis Aether
  does not perform or a QEMU trace that spans process boundaries, which
  `qemu-user` cannot produce. The link edges from this change are the
  prerequisite; the traversal on top of them is not built.
- **Full campaign / fleet tracking** - correlating many firmware images as
  variants of one product line. That needs a notion of "these N images are the
  same campaign" that nothing in the evidence model currently expresses.
- **A general evidence-graph diff.** Comparing every artifact and claim between
  two projects, not just components, is a real feature and a larger one; this
  ADR scopes down to the one dimension (component versions) that is both
  measurable and immediately useful.

## Why a name match is honestly weak evidence, and the model says so

`imports_resolved_by` is inference over two independent observations - an
import in one file's symbol table, an export in another's - not a direct
reading of either file's own structure. Two real binaries can share a symbol
name that resolves to different implementations (symbol versioning, `LD_
PRELOAD`, static linking a private copy of a common library name). The
predicate's own documentation says the claim proves name agreement, not a live
dependency, and its confidence is fixed below what a header parse or symbol
table read earns elsewhere in Aether - lower still when more than one file
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
- The next real step toward "sink reachability across files" is traversing
  `imports_resolved_by` edges from a QEMU-observed `function_reached` claim in
  one binary into another's risky-API usage. That is a natural Phase 2
  follow-up, not attempted in this change.
