# ADR 0010: Specialist agents are local-only and CLI-only

**Status:** accepted · **Date:** 2026-09-06

## Context

Phase 3's "Richer Agents & Expansion" names two things: an approval workflow
(landed in ADR 0009 - `yugen/review/`) and "full specialist agents" -
autonomous, LLM-driven reasoning over evidence. The second was explicitly left
unbuilt, because it forces decisions the project's owner had not yet made:
which LLM to use, whether calls leave the machine, and how an agent's output
enters a graph whose whole design principle is that a claim is never free
text.

The first specialist agent picks the narrowest possible slice of that
scope: it supplements two predicates that already exist -
`contains_hardcoded_secret` and `suspicious_string` - with an LLM's judgment
over string evidence the deterministic triage adapter
(`yugen/adapters/triage/detectors.py`) already extracted. No new predicate, no
new artifact kind, no new evidence-schema field. The agent reads strings
already in the project and proposes claims in a shape the schema already
enforces.

## Decision

**The backend is pluggable, and the only real backend is local.**
`yugen/agents/backend.py` defines `LLMBackend` as a one-method protocol
(`complete(prompt) -> str`). `OllamaBackend` talks to a locally-running
[Ollama](https://ollama.com) server using nothing but `urllib` - no new
runtime dependency (ADR 0001) - and requires the caller to name a model they
have already pulled; there is no default model baked in. `FakeLLMBackend` is
a deterministic, no-network stand-in used only by tests and by anyone
experimenting with the agent's parsing logic directly through the Python API.

Local-only is a **hard requirement enforced by what exists**, not a default
that a future flag could quietly widen. There is no cloud backend in this
module, and adding one - accepting a vendor, a network dependency, and
sending user sample data off-machine - is explicitly out of scope for this
ADR. It would need its own decision, the same way emulation's real risk
(ADR 0007) got its own ADR rather than being folded into a "features" PR.
This directly satisfies Yugen's own "local-first, no cloud analysis of user
samples by default" principle instead of merely gesturing at it.

**No MCP tool.** `yugen agent secrets` (`yugen/cli.py`) is the only way to
run this agent. It is not reachable through `yugen.mcp.tools.TOOLS`, and
nothing in `yugen analyze` or any adapter invokes it implicitly.

**Output gets zero special trust.** Every claim `run_secrets_triage`
(`yugen/agents/secrets.py`) submits goes through `RunContext.add_claim` with
`producer_kind="agent"`, which means it lands with `status="proposed"` -
exactly like `yugen_submit_claim`'s output, exactly like the demo claim ADR
0009's tests build by hand. It enters `yugen review list` and leaves only
through `yugen review approve` or `yugen review reject`, run by a human.
Nothing about this agent's LLM backend, its confidence score, or its
producer name shortens that path.

## Rationale

**Why local-only is not a default.** A default can be overridden by a config
file, an environment variable, or a later contributor who adds "just one
more backend option" without reading this document. Making the cloud case
*absent* rather than *off* means the only way to send sample data to a cloud
API from this code is to write new code that does it - a deliberate,
reviewable act, not a flag flip.

**Why CLI-only, and why that reason differs from ADR 0009's.** ADR 0009 kept
approval off MCP because an agent-reachable approval tool would let an agent
mark its own homework - a structural safety property, permanent by
construction. That is not the concern here: nothing about a secrets-triage
agent creates a self-approval path, because its own output already lands as
`proposed` and needs the same human step everything else does. The actual
reason is narrower and temporary: this is a new, unproven capability, and
every previous phase in this project shipped its first slice narrow and
CLI/library-reachable before widening it - cartography's four capabilities in
ADR 0008, the approval queue itself exposing only a read-only MCP tool at
first. Exposing this over MCP later is a legitimate next step once the false
positive rate and prompt design have been exercised by real use; it is a
deliberate, separate decision, not a default this ADR forecloses on grounds
of safety.

**Why the schema was not touched.** Adding a predicate is "a reviewed,
versioned act," per `yugen/evidence/schemas.py`'s own docstring, not
something to bundle into a feature that is still finding its footing. Fitting
inside `contains_hardcoded_secret` and `suspicious_string` exactly - down to
validating the LLM's own `kind` output against the predicates' existing enums
before a claim is ever built - means this agent cannot express anything the
review queue does not already know how to show a human.

## What this does not solve

- **Prompt quality and false-positive rate are not addressed here.** The
  agent asks the model to skip cases a regex would already catch and to
  return strict JSON; how well any given local model follows that is a
  property of the model, not of this ADR. Nothing here claims the agent is
  accurate - only that its output, however accurate, is bounded the same way
  every other agent's output is.
- **No model management.** Pulling, updating, or choosing among locally
  installed Ollama models is left to the operator and to Ollama's own
  tooling.
- **No rate limiting or cost accounting for local inference.** `--max-claims`
  and `--batch-size` bound how much work one invocation does; they are not a
  policy layer.
- **A cloud backend, multi-turn agent conversations, tool-calling from the
  model, or any other specialist agent** (a component-identification agent,
  a hardening-review agent, and so on) are all future, separate decisions.

## Consequences

- `yugen/agents/backend.py` and `yugen/agents/secrets.py` add a new package
  with zero new runtime dependencies - `python -c "import yugen.cli,
  yugen.mcp.server, yugen.eval.harness"` still imports nothing but the
  standard library.
- A test enumerates the MCP tool registry and asserts nothing named `agent`
  appears in it, mirroring ADR 0009's durable guard against a safety boundary
  eroding as tools are added later.
- `OllamaBackend`'s tests mock `urllib.request.urlopen` at the network
  boundary rather than skipping when Ollama is absent, so they run in CI
  every time, the same way the QEMU adapter's translation layer is tested
  without QEMU (ADR 0007).
- The next specialist agent, whenever it is built, has this ADR's shape to
  either extend or explicitly deviate from - "local-only backend,
  CLI/library-only surface, proposed-only output" is now the default answer
  to give, not a fresh negotiation each time.
