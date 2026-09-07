"""Structural enforcement of Ultron's ``private`` sensitivity tier.

Ultron is local-first and deterministic (ADR 0001); the only code path that
has ever made a network call is :class:`ultron.agents.backend.OllamaBackend`,
and only to a caller-named host (ADR 0010). This module gives that one path a
hard, checked boundary: a non-local host is refused unless a caller sets
``ULTRON_ALLOW_REMOTE_AGENT_HOST=1`` in the environment - an explicit,
reviewable override, not a silent default that could regress into a cloud
call.

Every other module in this package performs no network I/O at all: the core
analysis pipeline (triage, Ghidra import, binwalk, QEMU trace import,
cartography, the NL interface, MCP transport) reads and writes only the
local filesystem and the project's own SQLite database. There is nothing
else here for this module to guard.
"""

from __future__ import annotations

import os
import urllib.parse

#: Hostnames treated as "this machine" for the purposes of the private tier.
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

#: Set to exactly "1" to allow a non-local agent backend host. Anything else,
#: including unset, keeps the guard active.
OVERRIDE_ENV_VAR = "ULTRON_ALLOW_REMOTE_AGENT_HOST"


class RemoteHostRefused(RuntimeError):
    """Raised when a network call would leave localhost under the private tier."""


def is_local_host(url: str) -> bool:
    """Return whether ``url``'s hostname is one of the local addresses."""
    hostname = (urllib.parse.urlparse(url).hostname or "").lower()
    return hostname in _LOCAL_HOSTNAMES


def assert_local_host(url: str) -> None:
    """Raise :class:`RemoteHostRefused` unless ``url`` is local or overridden.

    Called once, at backend construction, rather than per-request: the
    decision is about *which host this process is configured to talk to*,
    not about any one call.
    """
    if os.environ.get(OVERRIDE_ENV_VAR) == "1":
        return
    if not is_local_host(url):
        raise RemoteHostRefused(
            f"refusing to configure a backend pointed at {url!r}: Ultron's "
            "default sensitivity tier is 'private' (see agent.yaml), which "
            "means no analysis data leaves this machine by default. Set "
            f"{OVERRIDE_ENV_VAR}=1 in the environment to explicitly override "
            "this for a non-local backend host."
        )


__all__ = ["OVERRIDE_ENV_VAR", "RemoteHostRefused", "assert_local_host", "is_local_host"]
