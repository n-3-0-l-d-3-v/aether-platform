# Yugen architecture

This document describes what Yugen actually is through Phase 2, and — more
usefully — why the pieces are shaped the way they are. Individual decisions with real trade-offs
have their own records in [adr/](adr/).

## The one-sentence version

Deterministic engines produce artifacts; anything that wants to assert something
must attach itself to those artifacts through a validated schema; and the whole
thing serializes to something a human can diff.

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│  Interfaces                                                  │
│  yugen CLI            yugen mcp (stdio JSON-RPC)           │
│  Both are thin front ends over the same library. Neither     │
│  touches SQLite, and neither contains analysis logic.        │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Question interface  (yugen/nl/)                Phase 1     │
│  Five question types, classified deterministically. Answers  │
│  are templates over claims; every line cites claim ids.      │
│  Reads the graph. Never writes to it.                        │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Project store  (yugen/project/store.py)                    │
│  The only sanctioned way in or out. Writes happen inside a   │
│  run() block, so provenance cannot be forgotten.             │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Evidence model  (yugen/evidence/)                          │
│  Artifact kinds and claim predicates, with the identity and  │
│  evidence rules that make convergence and validation work.   │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  Adapters  (yugen/adapters/)                                │
│  triage (built in) · ghidra headless · binwalk               │
│  qemu user-mode (Phase 1, opt-in)                            │
│  Translation only. No adapter invents analysis.              │
└──────────────────────────────────────────────────────────────┘
```

## The data model

### Artifact

A concrete, locatable piece of evidence. Twelve kinds: `file`, `section`,
`function`, `string`, `xref`, `symbol`, `import`, `export`, `decompilation`,
`byte_span`, `signature_hit`, and `trace_hit` (Phase 1, a runtime observation).

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

A structured assertion. Fourteen predicates, from `file_format_identified`
through `contains_hardcoded_secret` and `uses_risky_api`, plus Phase 1's
`suspicious_string` and `function_reached`, plus Phase 2's
`imports_resolved_by` and `component_version_changed`.

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

`yugen check` runs the at-rest checks. An empty result is the invariant
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
  conventional install directories; invokes it with `YugenExport.py`.
- **Importer** — reads the export into the graph.

Running needs a JVM, a multi-gigabyte install, and minutes of wall time.
Importing needs none of those. The split means the translation layer — where the
bugs actually live — is unit-testable against recorded exports on any machine,
and an export can be handed between machines without handing over the whole
environment.

`YugenExport.py` runs inside Ghidra's interpreter, which is Jython 2.7 in most
installations and CPython 3 under PyGhidra, so it stays in the subset both
accept. It writes sorted JSONL. The risky-API list is passed *into* Ghidra so
the script can rank which functions are worth the decompiler's time — the policy
stays on Yugen's side of the bridge.

Ghidra's `uses_risky_api` claims carry call sites resolved from xrefs, and are
linked as `refines` to the coarser import-only claim triage produced. Both stay:
the coarse one holds even when disassembly fails.

### binwalk

Prefers binwalk when installed, because binwalk knows about squashfs, jffs2,
ubifs, and a hundred vendor formats Yugen has no business reimplementing.

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

### qemu (Phase 1)

Answers one question: which recovered functions actually executed. That is the
difference between "this binary imports `system()`" and "and `run_diagnostics`
ran", and it is the only thing this adapter claims.

Split into recording and importing, for the same reason the Ghidra bridge is:
running QEMU needs QEMU, and parsing its output needs nothing. The parser
handles both `-d exec` and `-d in_asm`, preferring the former because `in_asm`
records each block once *when translated*, so its counts are translation counts
rather than execution counts - and it says so in a warning rather than
presenting them as the same thing.

A position-independent binary is loaded somewhere other than where it was
linked, so its trace addresses match no known function. `infer_load_base` looks
for the single offset that aligns the most trace addresses with function entry
points, and returns nothing when the alignment is unconvincing. An unaligned
trace therefore produces no reachability claims rather than wrong ones.

Execution never happens implicitly. `qemu-user` is an emulator, not a sandbox -
its system calls reach the host kernel - so `yugen analyze` will not invoke it
and the CLI requires `--allow-execution`. See
[ADR 0007](adr/0007-emulation-is-opt-in.md).

## The question interface (Phase 1)

Five question types: hardcoded secrets, embedded components, attack surface,
suspicious indicators, and exploit mitigations. Each declares the claim
predicates that answer it, so the path from a question to bytes is explicit:

```
question -> question type -> predicates -> claims -> evidence artifacts
                                                  -> addresses in a file
```

**No language model is involved**, and the reasons are in
[ADR 0006](adr/0006-narrow-nl-without-a-model.md). The short version: the
citation invariant is satisfiable by templates and not by generated prose,
local-first forbids a hosted model, and deterministic classification is what
makes precision reproducible.

### The citation invariant

The specification permits free text in exactly one place - "explanations that
reference Claim IDs" - and `yugen/nl/model.py` makes that the only
representable shape. An `Answer` is a list of `AnswerLine`, and every line
either cites at least one claim id or is explicitly marked as a caveat.
`validate_answer` runs on every answer before it leaves the package, and a test
asserts the property holds across all five question types against real
projects.

A sentence asserting something about a binary without naming its evidence is
not constructible here. That is the difference between intending not to emit
unevidenced prose and being unable to.

### Classification, and declining

Intent matching is weighted term scoring over a curated vocabulary. Single words
match whole tokens, with light singularization so the vocabulary can be written
once in the singular; multi-word phrases match as substrings. Below the
threshold, the question is **declined** and the supported set is returned.

Declining is a feature, not a gap. A narrow interface that declines is
measurable; one that guesses produces confident answers to questions nobody
asked. `eval/suites/nl_questions.json` scores exactly that: seventy labelled
cases, twenty of them out of scope, with false accepts counted separately and
gating the suite at zero.

The corpus documents its own limitation. Vocabulary and cases share an author,
so the numbers measure internal consistency rather than performance against
phrasings nobody anticipated.

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
[0004](adr/0004-mcp-without-sdk.md): the protocol surface Yugen needs is small
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
concluded is not much use. `yugen_submit_claim` goes through exactly the same
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

## Cartography (Phase 2)

Phase 2 of the specification - "Firmware Cartography & Campaigns" - names four
things: inter-binary maps, sink reachability across files, version tracking,
and diffing. `yugen/cartography/` and `yugen/export/diff.py` land a narrow,
real slice of each; [ADR 0008](adr/0008-cartography-scope.md) is the scoping
decision, revised twice the same day as three of the four items moved from
"deferred" to "done."

**Cross-binary linking** (`link_imports`) resolves each file's imports against
every other file's exports in the same project, by symbol name. That is the
mechanical substance of an inter-binary map: which binary's undefined symbol is
satisfied by which other binary's definition. It is a join over two
independent symbol tables, not a direct reading of either file's own
structure, so the resulting `imports_resolved_by` claims score below what a
header parse earns elsewhere in Yugen - lower still when more than one file
exports the same name, in which case every candidate is recorded rather than
one being guessed. Common libc/CRT symbols are excluded by default: at
firmware scale nearly every binary imports them, and including them would
produce a graph dense with edges that say nothing about this firmware's
particular structure.

**Version diffing** (`yugen/cartography/diff.py`) compares `embeds_component`
claims between two independently analysed projects, matched by component name
since two different builds share no artifact ids - even identical bytes only
converge *within* one project (ADR 0002). It stays a pure reporting function by
default, so a wrong join costs a wrong answer rather than a corrupted graph;
`record_version_changes` optionally writes a `component_version_changed` claim
into the newer project only, backed by evidence that already exists there.

**Cross-binary sink reachability** (`yugen/cartography/reachability.py`)
chains three claims that already independently exist rather than observing
anything new: a function seen executing under QEMU (`function_reached`), a
call from it into an import (a Ghidra `xref`), and that import resolved to
another file's export (`imports_resolved_by`). The result,
`cross_binary_reachable`, is scoped precisely: it says a *specific, observed*
code path reaches the boundary of another binary at a named symbol, not that
the other binary's own implementation was itself seen running. Its confidence
is the *minimum* of the two chained claims, not their product - deliberately
not the noisy-OR combination ADR 0003 uses for independent corroboration,
because this is one reasoning chain where each half is necessary, not two
observations of the same fact.

**A general evidence-graph diff** (`yugen/export/diff.py`) turned out to be
nearly free given content-addressed ids (ADR 0002): comparing two graphs is a
set difference over ids, because an id present on both sides is, by
construction, the same artifact or claim. It compares a live project against
another, an export against another export, or a project against its own
export - the last of which is asserted identical in a test.

**Campaign/fleet correlation** (`yugen/cartography/campaign.py`) is the one
item that groups *projects*, not artifacts within one project. Two signals: an
identical file (matching SHA-256) is conclusive; a threshold number of shared
component-version pairs is a weaker but real signal, gated so one common
library shared by coincidence is never mistaken for a lineage. Grouping is
transitive via union-find. Testing this against the repository's own fixtures
surfaced an honest limitation worth stating rather than hiding: two unrelated
sample binaries correlate via the component-fingerprint signal because both
embed the same placeholder version banners used across the evaluation suite.
The threshold reduces this false-positive mode; it does not eliminate it.

Not attempted: fuzzy vendor/product-name matching, semantic version-range
reasoning, or any correlation signal beyond what two projects' own evidence
graphs directly show.

## The approval workflow (Phase 3, partial)

`yugen/review/` is the deterministic half of Phase 3's "Richer Agents &
Expansion." The evidence model already carried what it needed - a claim's
`status` field, and the fact that an MCP-submitted claim already lands as
`proposed` with `producer_kind="agent"` (Phase 0). What was missing was a
queue and a recorded human decision.

`pending()` lists proposed claims with an agent attestation; `approve()` /
`reject()` promote or reject one and leave an annotation recording who decided
and why. The property that matters is what is *not* built: there is no
approve or reject MCP tool, and per [ADR 0009](adr/0009-approval-is-cli-only.md)
there never will be. `yugen_review_queue` lets an agent see whether its own
proposal is still pending; only a human running `yugen review approve` at a
terminal can close the loop. A test enumerates the MCP tool registry and
asserts no tool name contains "approve" or "reject," so an agent cannot mark
its own homework even if a future change tried to add that convenience.

## Deliberate non-goals

Phase 0 shipped with no natural-language interface, no dynamic analysis, no
multi-agent orchestration, no cartography, no GUI, and no cloud. Phase 1 lifted
the first two, narrowly; Phase 2 lifted cartography, narrowly, across all four
of its named items; Phase 3 lifted the approval-workflow half of "richer
agents," narrowly, deliberately excluding agents from the write side of it.

**The first specialist agent (Phase 3, first slice).** `yugen/agents/` adds
one narrowly-scoped agent: a secrets/indicators triage agent that sends
already-extracted string evidence to a locally-running LLM (Ollama, via
`yugen/agents/backend.py`) and proposes `contains_hardcoded_secret` /
`suspicious_string` claims for patterns the deterministic rules in
`yugen/adapters/triage/detectors.py` would plausibly miss. No new predicate,
no new artifact kind, and no new MCP tool. Its backend is local-only by hard
requirement rather than a default, and every claim it proposes lands
`status="proposed"` through the same review gate ADR 0009 built - `yugen
agent secrets` never accepts anything itself. See
[ADR 0010](adr/0010-specialist-agents-are-local-and-cli-only.md).

This is one agent, not "full specialist agents" in the general sense the
original specification language meant - a component-identification agent, a
hardening-review agent, exposing this capability over MCP, and so on all
remain unbuilt, deliberately.

Still explicitly not started, and not silently assumed:

- **Broader natural language.** Five question types is the specification's
  number, and a test pins the ceiling. Loosening it trades away the property
  ADR 0006 built the interface around - that a narrow, deterministic set is
  measurable, where a broader one would not be. The question vocabulary also
  treats diffing as out of scope on purpose, so "diff this against the
  previous version" is declined rather than answered as an SBOM request.
- **A new disassembler or decompiler.** Never.

`python examples/demo_phase0.py`, `python examples/demo_phase1.py`, and
`python examples/demo_phase2.py` remain the gate demonstrations for their
phases.
