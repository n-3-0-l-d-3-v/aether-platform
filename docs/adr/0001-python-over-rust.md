# ADR 0001: Python for the core, not Rust

**Status:** accepted · **Date:** 2026-08-26

## Context

The build specification names Rust as preferred for the project, evidence, and
MCP layers, with Python acceptable "if it ships faster". Agent orchestration and
Accessible Mode are Python regardless, so a Rust core implies a language
boundary somewhere in Phase 1.

The target machine has Python 3.12 and no Rust toolchain installed.

## Decision

Python 3.10+ for the whole core, with **zero runtime dependencies**.

## Rationale

The decisive factor is not language preference but what Phase 0 is *for*. The
gate is about proving the evidence model — identity rules, convergence between
engines, validation that cannot be bypassed, deterministic export. Those are
design problems, and the cost of getting them wrong is a schema migration, not a
rewrite. Iterating on them in Python and porting a settled design later is
cheaper than settling them in Rust.

Three supporting reasons:

- Installing a Rust toolchain before writing a line is a real cost with no
  Phase 0 payoff.
- The agent layer is Python from Phase 1. A Rust core means an FFI or IPC
  boundary exactly where the most iteration will happen.
- Every heavy computation already lives in an external engine. Aether's core is
  SQLite queries, JSON, and hashing — none of which are where Rust would earn
  its keep.

The zero-dependency constraint is a deliberate addition, not an inheritance. It
keeps the CLI and MCP server runnable anywhere Python is, including inside
constrained analysis environments where installing packages is awkward or
disallowed. It cost one decision — hand-rolling the MCP transport, see
[0004](0004-mcp-without-sdk.md) — and bought a tool that runs from a bare
checkout.

## Consequences

- Performance on very large firmware images will eventually matter. The likely
  hot spots are already identified: signature scanning is one pass per signature
  and wants Aho-Corasick; string extraction is a byte loop.
- The store API is deliberately narrow, so a port would be bounded by
  `aether/project/store.py` and `aether/evidence/`.
- Type annotations are used throughout, which keeps a future port honest about
  what the current shapes actually are.

## Revisit when

Firmware images routinely exceed a gigabyte, or profiling shows the core rather
than the engines dominating wall time.
