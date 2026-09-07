# Ultron

[![CI](https://github.com/n-3-0-l-d-3-v/aether-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/n-3-0-l-d-3-v/aether-platform/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-green)](LICENSE)
[![Runtime dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)](pyproject.toml)

**Evidence-first binary and firmware analysis.**

Ultron sits on top of mature engines — Ghidra headless, binwalk — and
contributes the thing they do not: a project model where **every finding is a
structured claim linked to the exact artifacts that support it**.

Free-text security claims are not merely discouraged here. They are
*unrepresentable*. A claim is a registered predicate with typed fields, and it
cannot be stored without artifact ids of the kinds that predicate demands. An
agent that tries to write "this looks exploitable" gets a schema error naming
the offending field.

Ultron builds no disassembler and no decompiler, and it never will. That work is
already done well; the gap is everything around it.

*Formerly named Aether, then Yugen. Yugen (幽玄) is a Japanese aesthetic term*
*for a truth perceived through subtle suggestion rather than full disclosure —*
*the same principle behind evidence-only, never-over-assert claims, and the*
*name this project carried while it was developed standalone. It is now*
*renamed Ultron on joining a personal multi-agent developer ecosystem, where*
*each specialist tool takes an agent name; here it is the reverse-engineering*
*and security specialist. The rename is cosmetic — every invariant below,*
*the evidence-graph discipline, the claim schema, and the zero-dependency*
*core, carries over unchanged. See*
*[ADR 0011](docs/adr/0011-rename-to-ultron-ecosystem-agent.md) for the full*
*reasoning.*

---

## Status: Phase 0 released, Phase 1 and 2 landed, Phase 3 partial

All 25 gate checks pass, 368 tests pass.

```bash
python examples/demo_phase0.py
```

```
  [PASS] ELF identified with architecture and word size
  [PASS] functions, xrefs, and decompilation imported
  [PASS] Ghidra converged onto existing artifacts instead of duplicating
  [PASS] nested container chain unpacked (uImage -> gzip -> cpio)
  [PASS] findings attributed to the member file, not the container blob
  [PASS] claim resolves to a string artifact at a concrete location
  [PASS] free-text claim from an agent is refused
  [PASS] two independent analyses produce byte-identical graphs
  [PASS] suite 'elf_sample' passes  -  recall 1.00, 0 false positive(s)
  ...
  25/25 gate checks passed
```

Phase 0 is released as
[v0.1.0-phase0](https://github.com/n-3-0-l-d-3-v/aether-platform/releases/tag/v0.1.0-phase0).

**Phase 1 has landed**: a narrow natural-language interface and light
emulation-based reachability.

```bash
$ ultron ask "are there any hardcoded secrets?"
[hardcoded_secrets] 11 claim(s) cited

11 credential-shaped literals across the project: 3 private key,
3 connection string, 2 aws access key, 1 api token, 1 ssh authorized key.
  [clm_0217e368bbeb, clm_f2f751393fbc, clm_1284ca2d2406, +8 more]
etc/telemetry.conf carries api token, connection string, password.
  [clm_1284ca2d2406, clm_0853d39c8248, clm_16dc579a703b]
  caveat: These are pattern matches. A match is credential-shaped; whether it
          is a live credential requires a human to check.
```

Five question types, matched deterministically with **no language model
involved** and no network request. Anything outside the set is declined with the
supported list, never guessed at. Every explanatory line cites the claim ids it
rests on, enforced by `validate_answer` rather than merely intended
([ADR 0006](docs/adr/0006-narrow-nl-without-a-model.md)).

Measured on a seventy-case labelled corpus: **accuracy 1.00, macro precision
1.00, zero false accepts**. The corpus states its own limitation - vocabulary
and cases share an author, so this measures internal consistency rather than
performance against phrasings nobody anticipated.

All 22 Phase 1 checks pass, covering both deliverables end to end:

```bash
python examples/demo_phase1.py
```

```
  [PASS] question set is narrow, as specified (4-5 types)
  [PASS] every explanatory line cites the claims it rests on
  [PASS] an unsupported question is declined, not guessed at
  [PASS] execution is refused unless explicitly allowed
  [PASS] a function that never ran produces no reachability claim
  [PASS] the attack-surface answer now reports observed execution
  [PASS] question classification suite passes
  ...
  22/22 Phase 1 checks passed
```

**Phase 2 has landed**, as four narrow, real capabilities rather than the full
"cartography and campaigns" surface at once:

```bash
$ ultron map
[cartography] run run_b05687d13748b3bad67b684d986c0f8e
  8 file(s) considered, 1 link(s) found

consumer   symbol             provider           conf
---------  -----------------  -----------------  ----
bin/app    EVP_EncryptUpdate  lib/libcrypto.so   0.6

$ ultron diff-versions ../previous-build --record
kind     component  from      to
-------  ---------  --------  ------
changed  openssl    1.0.2u    3.0.1

recorded 1 component_version_changed claim(s)
```

Cross-binary import/export linking resolves which file's undefined symbol is
satisfied by which other file's exported one, by name - a name match, not proof
of a live dependency, and the resulting claims say so at reduced confidence.
Version diffing compares embedded components across two independently analysed
projects and can record what changed, evidenced in the newer project.

```bash
$ ultron reach
[cartography] run run_d61b9bbf020e8572570e084d717f686d
  3 observed function(s) considered, 2 cross-binary sink(s) reached

observed in            function          reaches symbol  conf
----------------------  ----------------  --------------  ----
bin/firmware_agent      handle_name       strcpy          0.90
bin/firmware_agent      run_diagnostics   system          0.95

$ ultron diff-graph ./baseline ./current
comparing baseline -> current
  artifacts: +12 -0   claims: +8 -0
```

Cross-binary sink reachability chains three claims that already independently
exist - a function observed executing (QEMU), a call site into an import
(Ghidra), and that import resolved to another file's export (`ultron map`) -
into a claim that a *specific, observed* code path reaches the boundary of
another binary at a named symbol. Its confidence is the minimum, not the
product, of the two chained claims: this is one reasoning chain, not two
independent observations corroborating each other.

The general evidence-graph diff turned out to be nearly free given
content-addressed ids (ADR 0002): comparing two graphs is a set difference over
ids, so `ultron diff-graph` compares any two projects, two exports, or a
project against its own export.

`examples/demo_phase2.py` covers the first two capabilities end to end (14/14
checks); reachability and the graph diff are exercised by their own dedicated
suites, `tests/test_reachability.py` and `tests/test_graph_diff.py`:

```bash
python examples/demo_phase2.py
```

```
  [PASS] a matching export resolves the import
  [PASS] a ubiquitous libc symbol (malloc) is excluded by default
  [PASS] a name-match join scores below a direct header reading
  [PASS] re-running linking converges rather than duplicating
  [PASS] the same linking is available to agents via ultron_map
  [PASS] a version bump between two projects is detected
  [PASS] the recorded claim cites real evidence, not just text
  [PASS] the baseline project is never written to
  [PASS] 'added' components are never written as version-change claims
  ...
  14/14 Phase 2 checks passed
```

**Campaign/fleet correlation** groups several project directories - not
artifacts within one project - by shared evidence: an identical file (same
SHA-256) is conclusive; several shared component-version pairs is a weaker
signal, gated by a threshold so one common library is never mistaken for a
lineage.

```bash
$ ultron campaign ./firmware-v1 ./firmware-v2 ./unrelated-device
campaign 1: ./firmware-v1, ./firmware-v2
    ./firmware-v1 <-> ./firmware-v2  (shared_file: 1 identical file(s), e.g. bin/bootloader (f4e90c13...))

no correlation found for: ./unrelated-device
```

All four items the specification names under "Firmware Cartography &
Campaigns" now have a landed, scoped slice - see
[ADR 0008](docs/adr/0008-cartography-scope.md) for exactly where each line was
drawn, including an honest limitation the component-fingerprint signal
surfaced against this repository's own test fixtures.

**Phase 3, partially**: the approval-workflow half of "Richer Agents &
Expansion" is deterministic, local, and fits the existing evidence model
exactly - a claim's `status` field and the fact that an agent-submitted claim
already lands as `proposed`. That part is built:

```bash
$ ultron review list
id                predicate        conf  producers   subject  statement
----------------  ---------------  ----  ----------  -------  ------------------------
clm_6baf38592005  contains_string  0.50  agent:demo  bin/app  {"text": "sketchy string"}

$ ultron review approve clm_6baf38592005 --reviewer neil --note "reviewed, looks fine"
clm_6baf38592005... -> accepted by neil
```

`ultron_review_queue` lets an agent see the queue over MCP, but **there is no
approve or reject MCP tool, and there never will be** - a test enumerates the
tool registry and asserts no tool name contains "approve" or "reject". An
agent can see whether its own proposal is still pending; it cannot close the
loop itself. See [ADR 0009](docs/adr/0009-approval-is-cli-only.md).

**The first specialist agent has landed**, narrowly: `ultron agent secrets`
sends string evidence already in a project to a locally-running LLM (Ollama)
and proposes `contains_hardcoded_secret` / `suspicious_string` claims for
patterns the deterministic rules would plausibly miss. Its backend is
local-only by hard requirement, not a default - no cloud vendor is ever
called - and, like every other agent submission, its output lands as
`proposed` and needs a human running `ultron review approve` to go further.
There is no MCP tool for it, on purpose, for now. See
[ADR 0010](docs/adr/0010-specialist-agents-are-local-and-cli-only.md).

```bash
$ ultron agent secrets --model llama3.2 --max-claims 5
[agent secrets] proposed 1 claim(s)
  considered 42   skipped: existing 6, low-confidence 3, malformed 0
  these are 'proposed', not 'accepted' - review them with 'ultron review list' and 'ultron review approve'
```

This is one agent, not "full specialist agents" in the general sense the
specification meant - other specialist agents, and exposing this one over
MCP, remain future, separate decisions.

**Broader Accessible Mode** is the one Phase 3 item still not attempted,
deliberately: it means loosening the deliberately narrow, measured question
set from Phase 1 (ADR 0006), whose whole point was that narrow is what makes
precision reproducible. That is a choice for the project's owner to make
explicitly, not a default to assume.

## What works today

| Capability | State |
|---|---|
| Project model, SQLite persistence, migrations | working |
| Evidence graph: 12 artifact kinds, 14 claim predicates | working |
| Content-addressed ids with cross-engine convergence | working, tested |
| Provenance ledger; every write inside a transactional run | working |
| ELF/PE triage: headers, sections, symbol tables, mitigations | working |
| String extraction (ASCII + UTF-16LE) with section/address mapping | working |
| Rule-based detectors: secrets, components, risky APIs | working |
| Firmware unpacking: uImage → gzip → cpio, plus zip/tar/bzip2/xz | working |
| Ghidra export **import**: functions, xrefs, decompilation, symbols | working, tested against a recorded export |
| Ghidra headless **runner** | written, **not yet run against a real Ghidra install** |
| binwalk subprocess path | written, **not yet run against a real binwalk install** |
| Deterministic Git-friendly export | working, tested |
| MCP stdio server, 21 tools | working, tested |
| CLI: init/analyze/query/export/check/doctor/mcp/eval | working |
| Evaluation harness with ground-truth suites | working, recall 1.00 |
| **P1** narrow NL interface, 5 question types | working, tested |
| **P1** question-classification precision suite | working, 70 cases |
| **P1** QEMU trace parsing, load-base inference, attribution | working, tested against recorded traces |
| **P1** QEMU trace *recording* | written, **not yet run against a real QEMU install** |
| **P2** cross-binary import/export linking | working, tested |
| **P2** version diffing between two projects | working, tested |
| **P2** cross-binary sink reachability | working, tested |
| **P2** general evidence-graph diff | working, tested |
| **P2** campaign/fleet correlation across projects | working, tested |
| **P3** human approval workflow (CLI-only approve/reject) | working, tested |
| **P3** approve/reject as MCP tools | **never** - see ADR 0009 |
| **P3** secrets/indicators triage agent (local LLM, CLI-only) | working, tested - see ADR 0010 |
| **P3** other specialist agents / exposing this one over MCP | not started - future, separate decisions |
| **P3** broader Accessible Mode | not started - needs an explicit decision |

The two "not yet run" rows are stated plainly because they matter. The
translation layers on both sides are fully tested; what has not executed is the
subprocess invocation, because neither engine is installed on the machine Phase
0 was built on. See [Enabling the full engines](#enabling-the-full-engines).

## Quick start

Python 3.10+ and **no runtime dependencies**. Nothing to install:

```bash
git clone https://github.com/n-3-0-l-d-3-v/aether-platform.git
cd aether-platform
python examples/demo_phase0.py
```

Working with a project directly:

```bash
python cli/ultron.py init ./work
python cli/ultron.py -P ./work analyze examples/demo_firmware.bin
python cli/ultron.py -P ./work query objects
python cli/ultron.py -P ./work query claims --predicate contains_hardcoded_secret
python cli/ultron.py -P ./work query claim clm_1284ca2d2406
python cli/ultron.py -P ./work export ./work/export
```

Sample binaries are generated, not committed. `examples/demo_phase0.py` and the
test suite build them on demand; to build them by hand:

```bash
python examples/src/build_elf_sample.py examples/firmware_agent.elf
python examples/src/build_firmware_sample.py examples/demo_firmware.bin
```

Installing puts `ultron` on PATH:

```bash
pip install -e .
ultron doctor
```

## Running the tests

```bash
python -m pytest              # 368 tests
python -m pytest -q tests/test_evidence_model.py   # the invariants alone
```

The suite generates its own sample binaries on first run. PE-specific tests skip
cleanly on hosts that cannot produce a PE - note that a native `gcc` on Linux
compiles the sample into an ELF, so presence of a compiler is not enough and the
output is checked for an `MZ` header. Install a `mingw-w64` cross-compiler for
PE coverage on Linux.

CI runs the suite, the gate demonstration, an export-determinism check, and the
evaluation suites on Linux, Windows, and macOS across Python 3.10 and 3.12.

## What it looks like

```
$ ultron analyze demo_firmware.bin
[binwalk] run run_e65361591a1e...
  engine ultron-carver   extracted 7 file(s)
    bin/diagnostics.exe                    pe          132.4 KiB
    bin/firmware_agent                     elf         1.8 KiB
    etc/dropbear/dropbear_rsa_host_key.pem certificate 196 B
    etc/telemetry.conf                     data        219 B

$ ultron query claims --predicate contains_hardcoded_secret
id                predicate                  conf  prod  ev  subject             statement
----------------  -------------------------  ----  ----  --  -----------------  --------------------
clm_1284ca2d2406  contains_hardcoded_secret  0.95  1     1   etc/telemetry.conf  {"detector": "rul...
clm_0217e368bbeb  contains_hardcoded_secret  0.98  1     1   etc/dropbear/dro..  {"detector": "rul...

$ ultron query claim clm_1284ca2d2406
claim   clm_1284ca2d2406f45deb3f680afb7914f5
schema  ultron.claim.contains_hardcoded_secret/1
stated  {"detector": "rule:github-token", "redacted_preview": "ghp_****", "secret_kind": "api_token"}
conf    0.95 (max 0.95 across 1 producer(s))

evidence
role   kind    addr  artifact          name
-----  ------  ----  ----------------  ----------------------------------------
locus  string  0x56  art_6a75100355c5  api_key=ghp_A1b2C3d4E5f6G7h8I9j0K1l2...
```

Every finding walks back to bytes. That is the entire point.

## The model

Three record types carry everything.

**Artifact** — a concrete, locatable piece of evidence: a file, a function, a
string, an xref, a section, a decompiled body, a signature hit. Its id is a hash
of its *identity fields only*, so enriching an artifact never changes its id,
and two engines observing the same thing land on the same row.

**Claim** — a structured assertion: a registered predicate, typed fields, and
the artifacts backing it in named roles (`locus`, `support`, `context`,
`counter`). It carries no producer and no timestamp, so the same assertion from
two engines is *one* claim.

**Attestation** — one producer standing behind one claim at one moment, with a
confidence. Confidence is never a property of a claim; it is derived from the
attestations — maximum within a producer, noisy-OR across independent producers.
Two engines agreeing at 0.9 gives 0.99, not two near-duplicate findings.

That split is the central design decision:
[ADR 0003](docs/adr/0003-claims-versus-attestations.md).

### What is enforced, not merely encouraged

| Invariant | Where |
|---|---|
| No claim without evidence | `Claim.create`, the store, and a SQLite trigger that refuses to strand one |
| No free-text findings | Predicate schemas reject undeclared fields; a test asserts no predicate declares a prose field |
| Evidence must be the right *kind* | A `contains_hardcoded_secret` claim must cite a string, not a file |
| Provenance is never optional | Writes only happen inside a `project.run()` block |
| Agents cannot self-certify | MCP-submitted claims land as `proposed`, attributed to the agent |
| Partial analysis never lands | Each run is one transaction; a crashed engine leaves a `failed` run row and no artifacts |

Free text has exactly one home: annotations, in their own table and their own
export stream, where they can never be mistaken for findings.

## Enabling the full engines

Ultron runs without Ghidra or binwalk, at reduced depth, and says so. `ultron
doctor` reports every component - including the JDK on its own row, because
Ghidra headless fails on a missing or too-old runtime in a way that reads as a
Ghidra problem - along with what each gap costs and how to close it:

```bash
$ ultron doctor
ultron 0.1.0  (python 3.12.2, win32)

  ok       triage    0.1.0      built in; no external engine required
  MISSING  java      -          not found on PATH or under JAVA_HOME
           cost:     Ghidra headless cannot start at all.
           fix:      Install a JDK 21 or newer (for example Temurin, from
                     https://adoptium.net) and put 'java' on PATH, or set
                     JAVA_HOME.

  MISSING  ghidra    -          analyzeHeadless was not found
           cost:     No function recovery, cross references, or decompilation.
                     Header-level triage still runs.
           fix:      Install Ghidra (https://ghidra-sre.org) and set
                     GHIDRA_INSTALL_DIR to its directory, or put
                     support/analyzeHeadless on PATH. Or skip the local install
                     entirely: ultron import-ghidra <dir> --object <file>
                     ingests an export produced on any machine.

  MISSING  binwalk   -          binwalk was not found on PATH
           cost:     squashfs, jffs2, ubifs, and vendor formats are located but
                     not unpacked. gzip/bzip2/xz/zip/tar/cpio still work.
           fix:      Install it with 'pip install binwalk', or from
                     https://github.com/ReFirmLabs/binwalk. Full extraction
                     also wants sasquatch, jefferson, and ubi_reader.

1 of 4 components available.
Ultron still runs: header triage, firmware carving, the evidence graph,
the MCP server, and export all work without any external engine.
```

### Ghidra

Provides function recovery, cross references, decompilation, and precisely
located strings. Without it, header-level triage still runs.

1. Install [Ghidra](https://ghidra-sre.org) (11.x recommended).
2. Install a **JDK 21 or newer** and make sure `java` is on `PATH`, or set
   `JAVA_HOME`. Ghidra headless will not start without it.
3. Point Ultron at the install:

   ```bash
   export GHIDRA_INSTALL_DIR=/opt/ghidra_11.1.2_PUBLIC     # Linux/macOS
   setx GHIDRA_INSTALL_DIR "C:\ghidra_11.1.2_PUBLIC"       # Windows
   ```

   `ULTRON_GHIDRA_HOME` and `GHIDRA_HOME` are also honoured, and
   `support/analyzeHeadless` on `PATH` works too. Failing all of those, Ultron
   checks the conventional install directories.

4. Verify and run:

   ```bash
   ultron doctor
   ultron -P ./work analyze ./target.elf --engine ghidra
   ```

**You do not need Ghidra locally to use Ghidra results.** The bridge splits
running from importing, so an export produced on any machine can be ingested
anywhere:

```bash
# on the machine that has Ghidra
analyzeHeadless /tmp/proj ultron -import target.elf \
    -scriptPath ultron/adapters/ghidra/scripts \
    -postScript UltronExport.py /tmp/export 40 "" -deleteProject

# anywhere
ultron -P ./work import-ghidra /tmp/export --target ./target.elf
```

`UltronExport.py` runs inside Ghidra's own interpreter (Jython 2.7, or CPython
under PyGhidra) and stays in the subset both accept.

### binwalk

Provides squashfs, jffs2, ubifs, and vendor formats. Without it, the built-in
carver handles gzip, bzip2, xz, zip, tar, and cpio, and *reports* anything it
could only locate rather than silently skipping it.

```bash
pip install binwalk
# or: https://github.com/ReFirmLabs/binwalk
```

Full extraction also wants `sasquatch`, `jefferson`, and `ubi_reader`, which are
awkward on Windows — the reason the fallback carver exists
([ADR 0005](docs/adr/0005-carver-fallback.md)).

## Asking questions

A deliberately narrow interface: five question types, and anything else is
declined rather than answered badly.

```bash
ultron ask --list                              # what it answers
ultron ask "what third-party components are in this image?"
ultron ask "is this binary hardened?" --object bin/busybox
ultron ask "what is the attack surface?"
```

| Question type | Answers from |
|---|---|
| `hardcoded_secrets` | `contains_hardcoded_secret` |
| `embedded_components` | `embeds_component` |
| `attack_surface` | `uses_risky_api`, `function_reached` |
| `suspicious_indicators` | `suspicious_string` |
| `binary_hardening` | `binary_hardening` |

The same surface is available to agents as the `ultron_ask` MCP tool, returning
the identical structured record. Why no language model:
[ADR 0006](docs/adr/0006-narrow-nl-without-a-model.md).

## Reachability

Which recovered functions actually executed - what separates "this binary
imports `system()`" from "and `run_diagnostics` ran".

> **`qemu-user` is an emulator, not a sandbox.** Its system calls pass through
> to the host kernel, so a traced binary can do anything a native process could.
> Ultron never executes a target implicitly: `ultron analyze` will not do it,
> and `ultron trace` requires `--allow-execution`. Use a disposable VM or
> container. See [ADR 0007](docs/adr/0007-emulation-is-opt-in.md).

```bash
# on an isolated machine
qemu-arm -d exec,nochain -D trace.log ./target

# anywhere - executes nothing
ultron import-trace trace.log --object bin/target
```

Recording and importing are split exactly as they are for Ghidra. The parser
handles `-d exec` and `-d in_asm`, prefers the former because its counts are
real execution counts, and infers the load base of a position-independent
binary - declining to guess when the alignment is unconvincing, so an unaligned
trace produces no claims rather than wrong ones.

## MCP

The MCP server is the interface future agents work against, and it is a peer of
the CLI — both are thin front ends over one library.

```bash
ultron mcp              # stdio JSON-RPC
ultron mcp --read-only  # hide and refuse every write tool
```

Twenty-one tools: inventory, artifact and claim queries, string search,
decompilation retrieval, graph traversal, schema discovery, provenance,
`ultron_ask` for the question interface, plus `ultron_submit_claim` and
`ultron_annotate` for writes. Agent-submitted claims go through exactly the
validation an adapter does and land as `proposed`.

## Git-friendly export

`ultron export` writes two trees, and the split is the point:

- **`graph/`** — artifacts, claims, links. Content-addressed, sorted by id, no
  timestamps or run ids. Two independent analyses of the same bytes produce
  byte-identical files. Commit this; the diff shows what was *discovered*.
- **`ledger/`** — runs, attestations, observations. Provenance is a record of
  events, so it grows. That is correct.

## Evaluation

Ground truth lives in `eval/suites/*.json`:

```bash
$ ultron eval
[PASS] elf_sample       required 22/22   recall 1.00   false positives 0
[PASS] firmware_image   required 12/12   recall 1.00   false positives 0
```

An expectation can demand a confidence floor, a minimum number of independent
producers, and — importantly — that the matched claim cites evidence of a
specific *kind*. A `contains_hardcoded_secret` claim pointing at a file rather
than a string fails, even though the statement reads identically.

Recall is a real figure because a suite can enumerate what must be found.
Precision is scored only against explicitly forbidden patterns, since no suite
can enumerate everything true about a binary; unexpected claims are reported as
unscored volume rather than folded into a flattering number. The harness has
negative controls in the test suite — a harness that cannot fail proves nothing.

## Layout

```
ultron/
  canonical.py       deterministic serialization, hashing, id minting
  agents/            specialist agents: local-only LLM backend, secrets triage
  evidence/          artifact kinds, claim predicates, and their invariants
  project/           SQLite schema, migrations, and the only sanctioned store
  adapters/
    triage/          ELF/PE headers, strings, rule-based detectors
    ghidra/          headless runner, export script, importer
    binwalk/         firmware unpacking with a standard-library fallback
    qemu/            user-mode reachability tracing and trace parsing
  cartography/       cross-binary linking, reachability, diffing, campaigns
  export/            deterministic JSONL export, general graph diff
  mcp/               stdio MCP server and its tool surface
  nl/                the narrow question interface and its answer model
  review/            human approval workflow over agent-submitted claims
  eval/              evaluation harness
cli/                 entry point runnable without installing
docs/                architecture and decision records
eval/suites/         ground truth
examples/            sample generators and the gate demonstration
tests/               368 tests
```

## Documentation

- [Architecture](docs/architecture.md) — layers, data model, and why each
  piece is shaped the way it is
- [Decision records](docs/adr/) — the choices where a reasonable engineer would
  ask "why that way?":
  - [0001](docs/adr/0001-python-over-rust.md) Python for the core, zero runtime dependencies
  - [0002](docs/adr/0002-deterministic-ids.md) Content-addressed ids, and what is excluded from them
  - [0003](docs/adr/0003-claims-versus-attestations.md) Claims and attestations are separate records
  - [0004](docs/adr/0004-mcp-without-sdk.md) The MCP server speaks the protocol directly
  - [0005](docs/adr/0005-carver-fallback.md) A bounded extraction fallback when binwalk is absent
  - [0006](docs/adr/0006-narrow-nl-without-a-model.md) The NL interface contains no language model
  - [0007](docs/adr/0007-emulation-is-opt-in.md) Emulation never runs implicitly
  - [0008](docs/adr/0008-cartography-scope.md) Phase 2 lands as four narrow, real capabilities
  - [0009](docs/adr/0009-approval-is-cli-only.md) Approval and rejection are never exposed as MCP tools
  - [0010](docs/adr/0010-specialist-agents-are-local-and-cli-only.md) Specialist agents are local-only and CLI-only
  - [0011](docs/adr/0011-rename-to-ultron-ecosystem-agent.md) Rename to Ultron, joining a personal multi-agent ecosystem

## A note on the sample data

`examples/src/` generates binaries containing deliberately fake credentials —
AWS's own published example key (`AKIAIOSFODNN7EXAMPLE`), a synthetic
`ghp_A1b2C3d4...` token, PEM headers with no key material, and joke passwords.
None of it is real, and none of it is live. It exists so the evaluation suite
has a target whose ground truth is known exactly.

## Licence

Apache-2.0.
