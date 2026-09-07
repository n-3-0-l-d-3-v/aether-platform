"""Specialist agents: LLM-assisted reasoning over evidence already in a project.

Everything in this package is additive and opt-in. An agent here never runs
implicitly - not from ``ultron analyze``, not from any adapter - and it never
writes a claim that skips human review: every claim an agent submits lands
with ``producer_kind="agent"`` and ``status="proposed"``, exactly like any
other agent-attested claim (see :mod:`ultron.review` and
`docs/adr/0009-approval-is-cli-only.md`). Nothing in this package is exposed
as an MCP tool; see `docs/adr/0010-specialist-agents-are-local-and-cli-only.md`.
"""

from __future__ import annotations

__all__: list[str] = []
