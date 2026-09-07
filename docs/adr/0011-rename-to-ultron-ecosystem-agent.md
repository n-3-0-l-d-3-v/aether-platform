# ADR 0011: Rename to Ultron, joining a personal multi-agent ecosystem

**Status:** accepted · **Date:** 2026-09-07

## Context

This project shipped standalone as Aether, then Yugen, through Phases 0-3
(ADRs 0001-0010). It is now becoming one tool inside a personal multi-agent
developer ecosystem: a small set of specialist tools, each with its own name,
its own sensitivity tier, and a common contract (a manifest, a health check,
an MCP surface, a shared vault for durable notes) so a future orchestrator can
address them uniformly.

In that ecosystem every specialist is named after the capability it plays.
This one does binary and firmware reverse engineering and security triage -
the deterministic evidence graph, the Ghidra/binwalk backends, the narrow NL
interface, cross-binary reachability, and the local-only secrets agent. That
role is named **Ultron** in the ecosystem's naming scheme, hence the rename
covered by this ADR: package, CLI command, and all prose, everywhere except
ADRs 0001 through 0010, which are left untouched as the historical record of
decisions made under the old name.

## Decision

**This is a rename plus an additive contract, not a rewrite.** Every
invariant ADR 0001-0010 established is unchanged:

- the evidence graph (artifacts, claims, attestations) and its enforcement
  points (`ultron/evidence/schemas.py`, the SQLite triggers) are untouched in
  behavior;
- free-text claims remain structurally unrepresentable;
- the zero-runtime-dependency core (ADR 0001) is preserved - the rename adds
  no dependency;
- the hand-rolled MCP transport (ADR 0004) is kept as-is, renamed in place
  (see "What was considered and rejected" below);
- approval stays CLI-only (ADR 0009) and specialist agents stay local-only and
  CLI-only for LLM reasoning (ADR 0010) - this ADR does not expose `agent
  secrets` over MCP, only the existing five analysis tools that already had
  MCP equivalents before the rename.

**New, additive surface for ecosystem integration:**

- `agent.yaml` at the repo root - a static manifest (`name`, `role`,
  `default_sensitivity_tier`, `entrypoint`, `health_check_command`,
  `vault_write_path`, `sandboxed`) for a future orchestrator to discover this
  tool without parsing its source.
- `ultron --health` - a new, separate CLI subcommand returning a JSON status
  block (version, backend reachability, last-run timestamp, test-suite
  status). Kept distinct from the existing `ultron doctor`, which is
  human-facing prose with remedies; `--health` is a stable machine contract
  for a polling agent and does not carry doctor's wrapped, terminal-width-
  dependent text.
- `ultron/vault.py` and `ultron vault write` - writes RE findings as
  Markdown notes into `vault/Ultron/pending/`. A note only becomes committed
  knowledge once a human moves it to `vault/Ultron/approved/` (or sets
  `approved: true` in its frontmatter) - nothing in this tool auto-approves a
  vault note, mirroring the existing claim-review gate (ADR 0009) at the
  filesystem layer instead of the database layer.
- An explicit `private`-tier network guard (`ultron/network_policy.py`):
  the only outbound network call this project ever made was `OllamaBackend`
  talking to a caller-supplied host (ADR 0010), which already defaults to
  `localhost` but did not previously *refuse* a non-local host. It now does,
  unless a caller sets `ULTRON_ALLOW_REMOTE_AGENT_HOST=1` explicitly. Nothing
  else in the codebase performs network I/O - a test enumerates the standard
  library's own socket-opening entry points reachable from `ultron.cli`'s
  import graph and asserts none are called during `analyze`/`ask`/`map`/
  `reach`/`diff-versions`/`diff-graph`.

## What was considered and rejected

**Using the `mcp` PyPI package for the MCP server**, as the task naming this
rename suggested other ecosystem tools do. Rejected: ADR 0004 exists
specifically because pulling in an async framework and a web stack for a
protocol surface this small was judged not worth the dependency, and ADR 0001
makes zero runtime dependencies a load-bearing property advertised in the
README and checked in CI (`Verify the package really has no runtime
dependencies`). The existing hand-rolled transport already speaks the same
JSON-RPC-over-stdio protocol and already exposes `ultron_ask`, `ultron_map`,
`ultron_reach`, `ultron_diff_graph` (backing `diff-versions` and
`diff-graph`), and fifteen other tools as structured-data tool calls, not
reformatted prose - which is what the ecosystem contract actually asks for.
Renaming it in place satisfies the requirement without reopening ADR 0004. If
a future orchestrator specifically requires the reference `mcp` SDK's wire
compatibility quirks, that is a new decision with its own ADR, not a
side effect of a rename.

## Rationale

**Why leave ADRs 0001-0010 saying "Yugen."** They are dated records of
decisions made at a specific time, under a specific name, and rewriting them
to say "Ultron" would misrepresent when the renaming happened relative to the
decisions they document - the same reason a merged pull request's description
does not get edited after the fact. This ADR, and the README's lineage note,
carry the mapping forward for a reader who arrives via the new name.

**Why `--health` is not `doctor` renamed.** `doctor`'s output format (wrapped
paragraphs, indentation tuned to a terminal width) is a deliberate
human-readability decision documented in its own docstring. A polling health
agent wants a stable, flat JSON shape it can diff run over run; conflating the
two would mean every future wording tweak to `doctor`'s remedies is a
breaking change for the orchestrator. They share probe logic
(`ultron/adapters/*/probe()`) but are separate presentation layers over it,
the same split the codebase already uses between CLI rendering and JSON
(`_emit`).

**Why the vault gate is a second, independent gate rather than reusing
`ultron review`.** `ultron review` approves *claims* already inside a
project's SQLite graph - it has nothing to do with prose findings meant for a
cross-tool knowledge base outside any one project. Reusing its machinery would
mean giving free-text vault notes a path into the same tables the schema
system exists to keep claim-shaped, which is the one invariant this whole
project refuses to compromise. A separate `pending/` -> `approved/` filesystem
gate keeps the two review flows from ever touching the same enforcement code
that guarantees claims stay structured.

## Consequences

- The Python package, CLI command, and MCP tool names all changed from
  `yugen`/`yugen_*` to `ultron`/`ultron_*`. Any external script invoking the
  old command name needs updating; there is no compatibility shim, because a
  shim that silently accepts both names is exactly the kind of ambiguity this
  project's evidence model exists to refuse elsewhere.
- `docs/adr/0001` through `0010` still say "Yugen" throughout, by design; only
  this ADR and the README's lineage note describe the rename itself.
- `vault/Ultron/` is created under this repository's own working tree, not a
  shared location - a future ecosystem bootstrap step is expected to symlink
  or mount it at wherever the real shared vault lives. This tool does not
  assume or manage that shared location itself.
- `agent.yaml` and `--health` are read-only descriptions of this tool; neither
  one grants an orchestrator any capability this tool did not already expose
  through its CLI or MCP surface.
