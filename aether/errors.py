"""Aether exception hierarchy.

Kept flat and explicit so the CLI and MCP layers can map failures onto stable
exit codes / JSON-RPC error codes without string matching.
"""


class AetherError(Exception):
    """Base class for every error Aether raises deliberately."""

    exit_code = 1


class ProjectError(AetherError):
    """Project could not be created, opened, or migrated."""

    exit_code = 2


class SchemaError(AetherError):
    """An artifact or claim failed structural validation.

    Raised before anything touches the database. The evidence graph must never
    contain a record that would not validate on the way back out.
    """

    exit_code = 3


class EvidenceError(AetherError):
    """An operation would have violated an evidence-graph invariant.

    The canonical case: a claim submitted with no supporting artifacts.
    """

    exit_code = 4


class AdapterError(AetherError):
    """An external analysis engine failed or is unavailable."""

    exit_code = 5


class AdapterUnavailable(AdapterError):
    """The external engine is not installed / not configured on this host."""

    exit_code = 6


class IngestError(AetherError):
    """A file could not be ingested."""

    exit_code = 7
