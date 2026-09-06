# ADR 0009: Approval and rejection are never exposed as MCP tools

**Status:** accepted · **Date:** 2026-08-28

## Context

Phase 3 of the specification asks for "approval workflows" alongside "full
specialist agents." The evidence model already carries everything a workflow
needs: a claim's `status` field (`proposed` / `accepted` / `rejected` /
`superseded`), and the fact that an agent-submitted claim already lands as
`proposed`, attested with `producer_kind="agent"` (`aether_submit_claim`,
Phase 0). What was missing was a queue - a way to see what is waiting - and a
recorded act of a human deciding on it.

## Decision

`aether/review/` adds exactly that: `pending()` to list proposed claims (by
default, ones with at least one agent attestation), and `approve()` /
`reject()` to promote or reject one, each leaving an annotation recording who
decided and why.

The queue is exposed to MCP as `aether_review_queue` - read-only. **Approving
and rejecting are CLI-only** (`aether review approve/reject`) and are not, and
must never become, MCP tools.

## Rationale

An MCP tool is something an agent calls. If `aether_review_approve` existed
next to `aether_submit_claim`, an agent - or a chain of agents, or the same
agent invoked twice - could submit a claim and then approve it, and nothing in
the protocol would distinguish that from a human's decision. The claim would
read as reviewed and accepted while no human had looked at it. That is not an
edge case to guard against; it is the literal shape of "an agent marks its own
homework," which is the one thing "approval workflow" exists to prevent.

Restricting the write half to the CLI does not make it un-automatable by a
human who chooses to script it - a person can still write a script that calls
`aether review approve` in a loop. What it removes is the *protocol-level*
path by which an agent, acting inside its own MCP session, could grant itself
approval. The asymmetry is deliberate: agents propose over MCP, humans dispose
at a terminal.

## What this does not solve

This is a queue and an audit trail, not a policy engine. It does not:
- Require N-person review, or route claims to a specific reviewer.
- Rate-limit or throttle how many claims one agent can propose.
- Distinguish "this reviewer is authorized to approve claims of this kind"
  from any other string passed as `--reviewer`. The reviewer identity is
  exactly as trustworthy as whoever has shell access to run the CLI, which is
  the same trust boundary every other write in Aether already has.

A richer workflow - multi-stage approval, reviewer roles, notification when a
queue grows - is real additional scope, not implied by this change.

## Consequences

- `aether_submit_claim` and `aether_review_queue` together let an agent see
  the full lifecycle of its own proposals without ever being able to close
  the loop itself.
- A test enumerates the MCP tool registry and asserts no tool name contains
  "approve" or "reject" - a cheap, durable guard against this boundary eroding
  as tools are added later.
- The annotation body (`"accepted by alice: looks legit"`) is free text, and
  that is fine: it is commentary about a decision, not a claim about the
  binary, and annotations are exactly where Aether's evidence model already
  permits free text (they are never claims, and are exported in their own
  stream, distinct from `graph/claims.jsonl`).
