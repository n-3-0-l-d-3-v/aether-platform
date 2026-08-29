# ADR 0007: Emulation never runs implicitly

**Status:** accepted · **Date:** 2026-08-28

## Context

Phase 1 asks for "light QEMU integration for basic reachability" - determining
which recovered functions actually execute, so that attack surface can be
separated from observed behaviour.

Reachability requires running the target. The targets are firmware binaries,
which are routinely hostile and are frequently the reason someone is using an
analysis tool in the first place.

## The thing that is easy to get wrong

`qemu-user` is an **emulator, not a sandbox**. It translates guest instructions
for a foreign architecture, but system calls are passed through to the host
kernel. A binary running under `qemu-arm` can open files, make network
connections, and delete data exactly as a native process could.

This is widely misunderstood, because "emulator" sounds like isolation and
because `qemu-system` - full-system emulation - genuinely does isolate. The
user-mode variant does not, and Aether uses the user-mode variant because
full-system rehosting is explicitly out of Phase 1 scope.

## Decision

Execution is never implicit.

- `aether analyze` does not invoke the QEMU adapter under any engine selection.
- `QemuAdapter.analyze` raises unless the caller passes `allow_execution=True`.
- The CLI requires `--allow-execution`, and the refusal explains *why* rather
  than naming the missing flag.
- Recording and importing are separate operations, so the normal path for
  untrusted firmware is to trace it on an isolated machine and import the log,
  which executes nothing.
- Traced processes get a short default timeout and a disposable working
  directory.

The refusal text names the actual risk:

> tracing runs the target binary, and qemu-user is an emulator rather than a
> sandbox - its system calls reach the host kernel

## Rationale

A tool that silently executes what it is pointed at, when its whole purpose is
analysing untrusted code, has a defect no amount of documentation fixes. The
friction of one flag is small; the failure it prevents is running malware on an
analyst's workstation because a convenience default did the obvious thing.

Separating record from import is what makes the safe path also the convenient
one. Someone with a disposable VM records there and imports here; nothing about
the evidence graph knows or cares which machine produced the log.

## What this does not do

It does not make emulation safe. A user who passes `--allow-execution` on their
workstation gets exactly what they asked for. The flag is informed consent, not
containment - and the documentation says that rather than implying the flag is a
safety feature.

Actual containment would mean a container or VM with no network and no shared
filesystem. That belongs to whoever operates the tool, and pretending otherwise
inside Aether would be worse than saying so plainly.

## Consequences

- Reachability requires a deliberate act, so it will be used less often than if
  it were automatic. That is the intended trade.
- The adapter's translation layer - parsing, load-base inference, attributing
  addresses to functions - is testable without QEMU and is where the tests
  concentrate, in the same split the Ghidra bridge uses.
- Nothing in CI executes a target binary.
