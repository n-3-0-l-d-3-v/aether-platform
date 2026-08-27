"""Common shape for analysis engine adapters.

An adapter is a thin bridge: it runs an external engine (or a small local
routine), converts what comes back into artifacts and claims, and writes them
through a :class:`~aether.project.store.RunContext`. Adapters hold no analysis
logic of their own beyond translation - the engines are the analysis.

Every adapter answers :meth:`Adapter.probe` so the CLI can tell a user *why*
something is unavailable before they wait on it, rather than after.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Sequence

from aether.errors import AdapterError


@dataclass(frozen=True)
class Availability:
    """Whether an engine can run here, and what to do if it cannot."""

    available: bool
    version: str = "unknown"
    detail: str = ""
    #: Actionable next step shown to the user when ``available`` is False.
    remedy: str = ""
    #: What analysis is lost while this engine is unavailable. Stated per
    #: engine rather than in one footnote, so a reader of a single MISSING line
    #: learns the consequence without having to assemble it themselves.
    cost: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "detail": self.detail,
            "remedy": self.remedy,
            "cost": self.cost,
        }


@dataclass
class AdapterResult:
    """What an adapter accomplished, for the CLI and for MCP responses."""

    adapter: str
    run_id: str
    artifacts: int = 0
    artifacts_new: int = 0
    claims: int = 0
    claims_new: int = 0
    objects: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "run_id": self.run_id,
            "artifacts": self.artifacts,
            "artifacts_new": self.artifacts_new,
            "claims": self.claims,
            "claims_new": self.claims_new,
            "objects": self.objects,
            "warnings": self.warnings,
            "details": self.details,
        }


class Adapter:
    """Base class. Subclasses implement :meth:`probe` and an ``analyze``."""

    #: Stable adapter identifier, recorded in provenance.
    name: str = "adapter"
    #: The engine being wrapped, recorded in provenance.
    tool: str = "unknown"

    def probe(self) -> Availability:  # pragma: no cover - overridden
        raise NotImplementedError

    def require(self) -> Availability:
        """Probe, raising :class:`AdapterError` when the engine is missing."""
        availability = self.probe()
        if not availability.available:
            message = f"{self.name}: {availability.detail}"
            if availability.remedy:
                message += f"\n  {availability.remedy}"
            from aether.errors import AdapterUnavailable

            raise AdapterUnavailable(message)
        return availability


def which(*candidates: str) -> str | None:
    """First executable among ``candidates`` that exists on PATH."""
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def run_process(
    argv: Sequence[str],
    *,
    timeout: int = 900,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an external engine, capturing output as text.

    ``check`` is deliberately not used: several engines exit non-zero while
    still producing usable output, and the adapter is better placed than this
    helper to decide what a given exit code means.
    """
    try:
        return subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
    except FileNotFoundError as exc:
        raise AdapterError(f"executable not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise AdapterError(
            f"{argv[0]} exceeded the {timeout}s timeout; "
            "raise it with --timeout if the target is genuinely large"
        ) from exc
