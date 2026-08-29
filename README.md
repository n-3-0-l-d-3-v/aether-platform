# Aether

[![CI](https://github.com/n-3-0-l-d-3-v/aether-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/n-3-0-l-d-3-v/aether-platform/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-green)](LICENSE)
[![Runtime dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)](pyproject.toml)

**Evidence-first binary and firmware analysis.**

Aether sits on top of mature engines — Ghidra headless, binwalk — and
contributes the thing they do not: a project model where **every finding is a
structured claim linked to the exact artifacts that support it**.

Free-text security claims are not merely discouraged here. They are
*unrepresentable*. A claim is a registered predicate with typed fields, and it
cannot be stored without artifact ids of the kinds that predicate demands. An
agent that tries to write "this looks exploitable" gets a schema error naming
the offending field.

Aether builds no disassembler and no decompiler, and it never will. That work is
already done well; the gap is everything around it.

---

## Status: Phase 0 complete

All 25 gate checks pass, 266 tests pass.

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

Phases 1–3 (natural-language mode, multi-agent orchestration, firmware
cartography) are deliberately **not** started. The evidence model exists to be
proven before anything is built on top of it.

## What works today

| Capability | State |
|---|---|
| Project model, SQLite persistence, migrations | working |
| Evidence graph: 11 artifact kinds, 10 claim predicates | working |
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
| MCP stdio server, 15 tools | working, tested |
| CLI: init/analyze/query/export/check/doctor/mcp/eval | working |
| Evaluation harness with ground-truth suites | working, recall 1.00 |

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
python cli/aether.py init ./work
python cli/aether.py -P ./work analyze examples/demo_firmware.bin
python cli/aether.py -P ./work query objects
python cli/aether.py -P ./work query claims --predicate contains_hardcoded_secret
python cli/aether.py -P ./work query claim clm_1284ca2d2406
python cli/aether.py -P ./work export ./work/export
```

Sample binaries are generated, not committed. `examples/demo_phase0.py` and the
test suite build them on demand; to build them by hand:

```bash
python examples/src/build_elf_sample.py examples/firmware_agent.elf
python examples/src/build_firmware_sample.py examples/demo_firmware.bin
```

Installing puts `aether` on PATH:

```bash
pip install -e .
aether doctor
```

## Running the tests

```bash
python -m pytest              # 266 tests
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
$ aether analyze demo_firmware.bin
[binwalk] run run_e65361591a1e...
  engine aether-carver   extracted 7 file(s)
    bin/diagnostics.exe                    pe          132.4 KiB
    bin/firmware_agent                     elf         1.8 KiB
    etc/dropbear/dropbear_rsa_host_key.pem certificate 196 B
    etc/telemetry.conf                     data        219 B

$ aether query claims --predicate contains_hardcoded_secret
id                predicate                  conf  prod  ev  subject             statement
----------------  -------------------------  ----  ----  --  -----------------  --------------------
clm_1284ca2d2406  contains_hardcoded_secret  0.95  1     1   etc/telemetry.conf  {"detector": "rul...
clm_0217e368bbeb  contains_hardcoded_secret  0.98  1     1   etc/dropbear/dro..  {"detector": "rul...

$ aether query claim clm_1284ca2d2406
claim   clm_1284ca2d2406f45deb3f680afb7914f5
schema  aether.claim.contains_hardcoded_secret/1
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

Aether runs without Ghidra or binwalk, at reduced depth, and says so. `aether
doctor` reports every component - including the JDK on its own row, because
Ghidra headless fails on a missing or too-old runtime in a way that reads as a
Ghidra problem - along with what each gap costs and how to close it:

```bash
$ aether doctor
aether 0.1.0  (python 3.12.2, win32)

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
                     entirely: aether import-ghidra <dir> --object <file>
                     ingests an export produced on any machine.

  MISSING  binwalk   -          binwalk was not found on PATH
           cost:     squashfs, jffs2, ubifs, and vendor formats are located but
                     not unpacked. gzip/bzip2/xz/zip/tar/cpio still work.
           fix:      Install it with 'pip install binwalk', or from
                     https://github.com/ReFirmLabs/binwalk. Full extraction
                     also wants sasquatch, jefferson, and ubi_reader.

1 of 4 components available.
Aether still runs: header triage, firmware carving, the evidence graph,
the MCP server, and export all work without any external engine.
```

### Ghidra

Provides function recovery, cross references, decompilation, and precisely
located strings. Without it, header-level triage still runs.

1. Install [Ghidra](https://ghidra-sre.org) (11.x recommended).
2. Install a **JDK 21 or newer** and make sure `java` is on `PATH`, or set
   `JAVA_HOME`. Ghidra headless will not start without it.
3. Point Aether at the install:

   ```bash
   export GHIDRA_INSTALL_DIR=/opt/ghidra_11.1.2_PUBLIC     # Linux/macOS
   setx GHIDRA_INSTALL_DIR "C:\ghidra_11.1.2_PUBLIC"       # Windows
   ```

   `AETHER_GHIDRA_HOME` and `GHIDRA_HOME` are also honoured, and
   `support/analyzeHeadless` on `PATH` works too. Failing all of those, Aether
   checks the conventional install directories.

4. Verify and run:

   ```bash
   aether doctor
   aether -P ./work analyze ./target.elf --engine ghidra
   ```

**You do not need Ghidra locally to use Ghidra results.** The bridge splits
running from importing, so an export produced on any machine can be ingested
anywhere:

```bash
# on the machine that has Ghidra
analyzeHeadless /tmp/proj aether -import target.elf \
    -scriptPath aether/adapters/ghidra/scripts \
    -postScript AetherExport.py /tmp/export 40 "" -deleteProject

# anywhere
aether -P ./work import-ghidra /tmp/export --target ./target.elf
```

`AetherExport.py` runs inside Ghidra's own interpreter (Jython 2.7, or CPython
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

## MCP

The MCP server is the interface future agents work against, and it is a peer of
the CLI — both are thin front ends over one library.

```bash
aether mcp              # stdio JSON-RPC
aether mcp --read-only  # hide and refuse every write tool
```

Fifteen tools: inventory, artifact and claim queries, string search,
decompilation retrieval, graph traversal, schema discovery, provenance, plus
`aether_submit_claim` and `aether_annotate` for writes. Agent-submitted claims
go through exactly the validation an adapter does and land as `proposed`.

## Git-friendly export

`aether export` writes two trees, and the split is the point:

- **`graph/`** — artifacts, claims, links. Content-addressed, sorted by id, no
  timestamps or run ids. Two independent analyses of the same bytes produce
  byte-identical files. Commit this; the diff shows what was *discovered*.
- **`ledger/`** — runs, attestations, observations. Provenance is a record of
  events, so it grows. That is correct.

## Evaluation

Ground truth lives in `eval/suites/*.json`:

```bash
$ aether eval
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
aether/
  canonical.py       deterministic serialization, hashing, id minting
  evidence/          artifact kinds, claim predicates, and their invariants
  project/           SQLite schema, migrations, and the only sanctioned store
  adapters/
    triage/          ELF/PE headers, strings, rule-based detectors
    ghidra/          headless runner, export script, importer
    binwalk/         firmware unpacking with a standard-library fallback
  export/            deterministic JSONL export
  mcp/               stdio MCP server and its tool surface
  eval/              evaluation harness
cli/                 entry point runnable without installing
docs/                architecture and decision records
eval/suites/         ground truth
examples/            sample generators and the gate demonstration
tests/               266 tests
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

## A note on the sample data

`examples/src/` generates binaries containing deliberately fake credentials —
AWS's own published example key (`AKIAIOSFODNN7EXAMPLE`), a synthetic
`ghp_A1b2C3d4...` token, PEM headers with no key material, and joke passwords.
None of it is real, and none of it is live. It exists so the evaluation suite
has a target whose ground truth is known exactly.

## Licence

Apache-2.0.
