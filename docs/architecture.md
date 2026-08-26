# Aether architecture

This document describes what Phase 0 actually is, and — more usefully — why the
pieces are shaped the way they are. Individual decisions with real trade-offs
have their own records in [adr/](adr/).

## The one-sentence version

Deterministic engines produce artifacts; anything that wants to assert something
must attach itself to those artifacts through a validated schema; and the whole
thing serializes to something a human can diff.

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│  Interfaces                                                  │
│  aether CLI            aether mcp (stdio JSON-RPC)           │
│  Both are thin front ends over the same library. Neither     │
│  touches SQLite, and neither contains analysis logic.        │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Project store  (aether/project/store.py)                    │
│  The only sanctioned way in or out. Writes happen inside a   │
│  run() block, so provenance cannot be forgotten.             │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Evidence model  (aether/evidence/)                          │
│  Artifact kinds and claim predicates, with the identity and  │
│  evidence rules that make convergence and validation work.   │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Adapters  (aether/adapters/)                                │
│  triage (built in) · ghidra headless · binwalk               │
│  Translation only. No adapter invents analysis.              │
└──────────────────────────────────────────────────────────────┘
```

## The data model

### Artifact

A concrete, locatable piece of evidence. Twelve kinds in Phase 0: `file`,
`section`, `function`, `string`, `xref`, `symbol`, `import`, `export`,
`decompilation`, `byte_span`, `signature_hit`.

Each kind declares which of its fields constitute *identity*. The id is
`blake2b(kind, object_id, identity_fields)`, which produces two properties that
matter more than they first appear:

**Enrichment is free.** A function observed as `{name, addr_start}` and the same
function later observed as `{name, addr_start, size, signature, param_count}`
share an id. The second observation fills in blanks rather than creating a
second row.

**Engines converge.** Triage reads an ELF's `.rodata` and finds a string at file
offset `0x1c0`. Ghidra later reports the same string at virtual address
`0x4001c0`. Both must be one artifact, or the graph accumulates duplicates on
every re-analysis. Two mechanisms make that work:

1. Triage translates file offsets into virtual addresses using the section table
   it already parsed, so it can speak Ghidra's coordinate system.
2. `identity_groups` gives a kind ordered fallbacks for what counts as identity.
   For `string` it is `(text, encoding, addr)` and then
   `(text, encoding, file_offset)` — prefer the address when one is known.

The same mechanism resolves a subtler case: a header parser cannot see which
library an ELF import comes from, but a disassembler can. Import identity is
therefore the symbol name alone. The trade-off — a PE importing the same name
from two DLLs collapses onto one artifact — is documented at the schema and
surfaces as a field conflict rather than silent loss.

**Field conflicts.** When a later observation disagrees about a non-identity
field, the first value is kept and the disagreement is reported to the caller.
A second engine never silently rewrites what the first concluded.

### Claim

A structured assertion. Ten predicates in Phase 0, from
`file_format_identified` through `contains_hardcoded_secret` and
`uses_risky_api`.

A claim is `predicate + typed fields + evidence refs in named roles`. It carries
no producer and no timestamp, so its id is content-addressed. Roles are `locus`
(the thing the claim is about), `support`, `context`, and `counter`.

Each predicate declares evidence requirements — `contains_hardcoded_secret`
requires at least one `string`, `byte_span`, or `file` in the `locus` role — and
the store enforces them by reading the cited artifacts' kinds back out of the
database. A producer cannot vouch for evidence it never wrote.

There is no field of type "prose" on any predicate, and a test asserts there
never will be. If a producer wants to say something the model cannot represent,
the correct response is to add a predicate — a reviewed, versioned act.

### Attestation

One producer standing behind one claim at one moment, with a confidence.

This is the modelling decision worth reading twice, and it has its own record:
[0003](adr/0003-claims-versus-attestations.md). Briefly: folding the producer
into the claim id would mean two engines reaching the same conclusion produce
two near-identical rows, throwing away exactly the signal an evidence-first
system exists to capture. Keeping them separate means corroboration is
representable.

Confidence is therefore derived, never stored on a claim: maximum within a
producer (a tool firing two rules is one opinion), noisy-OR across distinct
producers (two 0.7s become 0.91). Independence across producers is an
assumption, so `per_producer` is always returned for a caller who knows better.

### Run

The unit of provenance. Every write happens inside `project.run()`, which opens
a run row, hands back a `RunContext`, and closes it — all in one SQLite
transaction. A crashed adapter leaves a `failed` run and no artifacts.

Run ids carry a nonce rather than being derived purely from inputs. Two
identical analyses are two runs, and both belong in the ledger; a timestamp
alone was not enough to keep them apart, because Windows resolves wall time to
roughly 15ms. Nothing is lost, since the deterministic export never contains a
run id.

## Where invariants are enforced

Defence in depth, because a single check is one refactor away from being
bypassed.

| Invariant | Python | SQLite |
|---|---|---|
| Claim has ≥1 evidence artifact | `Claim.create`, `RunContext.add_claim` | trigger `trg_claim_evidence_min` |
| Evidence artifact exists | store reads kinds back before insert | FK on `claim_evidence` |
| Evidence is the right kind | `check_evidence_requirements` | — |
| Cited artifact cannot vanish | — | `ON DELETE RESTRICT` |
| Statement has no undeclared fields | `_validate_fields` | — |
| Every artifact has provenance | writes only inside a run | `integrity_problems()` |
| Confidence within [0,1] | `Attestation.create` | `CHECK` constraint |

`aether check` runs the at-rest checks. An empty result is the invariant
holding; anything else means a bug, a hand-edited database, or a partial
import.

## Adapters

An adapter runs an engine, translates the result, and writes it through a
`RunContext`. It holds no analysis logic.

Every adapter answers `probe()`, returning availability, a version, and — when
unavailable — a *remedy*: what to install, and what the gap costs. A user should
learn that Ghidra is missing before waiting on it, not after.

### triage (built in)

Header-level identification for ELF and PE: format, architecture, word size,
byte order, sections, symbol tables, and mitigation flags. Plus string
extraction and mechanical detectors.

This reads structure the file format defines explicitly. It never infers
anything from instruction bytes; recovering functions and control flow is
Ghidra's job and stays Ghidra's job. It earns its place because firmware
inventory needs to know what each carved file *is* before anything heavier is
worth running, and because mitigation flags live in headers.

The detectors — secret patterns, a curated risky-API table, component version
banners — are deterministic producers, not agents. Each maps an observable
pattern to one specific structured claim, and confidence is calibrated to the
*rule*: a rigid shape like an AWS key id scores 0.95, a loose keyword match
scores 0.45 and is expected to need corroboration. `printf` is deliberately not
in the risky-API table; a rule that fires on every binary costs precision and
buys nothing.

### ghidra

Two halves, split deliberately:

- **Runner** — locates `analyzeHeadless` via `GHIDRA_INSTALL_DIR`, PATH, or
  conventional install directories; invokes it with `AetherExport.py`.
- **Importer** — reads the export into the graph.

Running needs a JVM, a multi-gigabyte install, and minutes of wall time.
Importing needs none of those. The split means the translation layer — where the
bugs actually live — is unit-testable against recorded exports on any machine,
and an export can be handed between machines without handing over the whole
environment.

`AetherExport.py` runs inside Ghidra's interpreter, which is Jython 2.7 in most
installations and CPython 3 under PyGhidra, so it stays in the subset both
accept. It writes sorted JSONL. The risky-API list is passed *into* Ghidra so
the script can rank which functions are worth the decompiler's time — the policy
stays on Aether's side of the bridge.

Ghidra's `uses_risky_api` claims carry call sites resolved from xrefs, and are
linked as `refines` to the coarser import-only claim triage produced. Both stay:
the coarse one holds even when disassembly fails.

### binwalk

Prefers binwalk when installed, because binwalk knows about squashfs, jffs2,
ubifs, and a hundred vendor formats Aether has no business reimplementing.

Falls back to a built-in carver otherwise. The fallback is scoped to what the
standard library can already decode — gzip, bzip2, xz, zip, tar — plus cpio,
which is trivial to parse and ubiquitous in initramfs images. Everything else is
*located and reported*, never silently skipped: the run tells you a squashfs
image is at offset `0x4000` and that installing binwalk would unlock it.
Rationale in [0005](adr/0005-carver-fallback.md).

Two behaviours worth noting, both learned from output quality:

- A stream wrapper (gzip/bzip2/xz) yields a blob, not a directory. Its contents
  are attributed to the enclosing path, so a real file lands on
  `bin/busybox` rather than `0001a000.gunzipped/bin/busybox`.
- A container about to be unpacked is not string-scanned, so its members'
  secrets are attributed to the files they belong to rather than reported twice.

Archive members are attacker-controlled, so extraction paths go through
`safe_join` (zip-slip) and a byte/file budget.

## Export format

Two trees:

```
project.json              metadata
manifest.json             per-file digests and a graph digest
graph/
  artifacts.jsonl         content-addressed, sorted by id
  claims.jsonl
  claim_links.jsonl
ledger/
  runs.jsonl              provenance: inherently time-varying
  attestations.jsonl
  observations.jsonl
annotations.jsonl         free text, kept apart from findings
```

`graph/` is deterministic: canonical JSON, sorted keys, sorted lines, no
timestamps or run ids. Two independent analyses of the same bytes produce
byte-identical files, verified by a test that builds two projects from scratch
and compares digests. Commit it, and `git diff` shows three new claims rather
than three thousand changed timestamps.

`ledger/` grows. Provenance is a record of events; that is correct.

## MCP

A dependency-free stdio JSON-RPC server. Rationale in
[0004](adr/0004-mcp-without-sdk.md): the protocol surface Aether needs is small
and stable, and making the MCP server the one component that drags in an async
framework would undercut the local-first, zero-dependency property the rest of
the system has.

Transport (`server.py`) is isolated from tools (`tools.py`). `handle_message` is
a pure function of request to response, which makes the protocol testable
without spawning a subprocess, and swapping in the official SDK later would
touch framing and nothing else.

Two properties are treated as load-bearing in the tool design:

**Everything is addressable.** Every response carries ids, so an agent can
always go deeper — claim to evidence, evidence to containing object, object to
the rest of the image — without guessing or re-querying by name.

**Writing is possible but constrained.** An agent that cannot record what it
concluded is not much use. `aether_submit_claim` goes through exactly the same
validation an adapter does, and agent claims land as `proposed`, attributed to
the agent. Responses are size-bounded: an agent asking for "all strings" in a
firmware image gets a useful page and a total count, not a context window full
of noise.

## Evaluation

A suite names a target, a pipeline, and what must and must not appear.

The `ghidra-export:` pipeline step imports a recorded export, which is what lets
a suite exercise the disassembler-fed path on a machine with no Ghidra install —
most machines, including CI.

Expectations can require a confidence floor, a minimum number of independent
producers, and the *kind* of evidence the matched claim must cite. That last
check is what keeps the evidence graph honest as rules evolve: a claim with the
right words pointing at the wrong artifact is not the same finding.

What the numbers mean: recall is measurable because a suite can enumerate what
must be found. Precision is scored only against explicitly forbidden patterns,
because no suite can enumerate everything true about a binary. Everything else
is reported as `unscored_claims` — not an error, but worth watching, since a
jump there usually means a rule got noisier.

The harness has negative controls in the test suite: a suite demanding something
absent must fail, a forbidden pattern that fires must fail, and an expectation
demanding the wrong evidence kind must fail. A harness that cannot fail proves
nothing.

## Deliberate non-goals in Phase 0

Per the build specification: no natural-language interface, no multi-agent
orchestration, no firmware cartography, no dynamic analysis, no GUI, no cloud.
No new disassembler or decompiler, ever.

The evidence model exists to be proven before anything is built on top of it.
Phase 1 begins only once that gate is demonstrably passed —
`python examples/demo_phase0.py` is what "demonstrably" means here.
