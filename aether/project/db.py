"""SQLite schema, connection setup, and migrations.

The schema encodes the evidence-graph invariants in the database itself where
SQLite allows it, rather than relying only on the Python layer. Two places
matter:

* ``claim_evidence`` has ``ON DELETE RESTRICT`` toward artifacts, so an
  artifact that a claim depends on cannot be deleted out from under it.
* ``trg_claim_evidence_min`` aborts any delete that would strand a surviving
  claim with zero evidence.

Together with the checks in :mod:`aether.project.store`, that makes "every
claim is backed by evidence" true at rest, not just at insert time.
"""

from __future__ import annotations

import sqlite3
from typing import Callable

from aether.errors import ProjectError
from aether.version import SCHEMA_VERSION

#: Filename of the project database inside the project directory.
DB_FILENAME = "aether.db"


_MIGRATION_1 = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE runs (
    run_id         TEXT PRIMARY KEY,
    tool           TEXT NOT NULL,
    tool_version   TEXT NOT NULL,
    adapter        TEXT NOT NULL,
    params         TEXT NOT NULL,
    input_digest   TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL,
    exit_code      INTEGER,
    aether_version TEXT NOT NULL DEFAULT '',
    notes          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_runs_adapter ON runs(adapter, started_at);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    object_id   TEXT REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
    parent_id   TEXT REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
    name        TEXT,
    addr_start  INTEGER,
    addr_end    INTEGER,
    data        TEXT NOT NULL
);
CREATE INDEX idx_artifacts_kind      ON artifacts(kind);
CREATE INDEX idx_artifacts_object    ON artifacts(object_id, kind);
CREATE INDEX idx_artifacts_parent    ON artifacts(parent_id);
CREATE INDEX idx_artifacts_name      ON artifacts(name);
CREATE INDEX idx_artifacts_addr      ON artifacts(object_id, addr_start);

-- Which run saw which artifact. An artifact observed by three runs has three
-- rows here and still exactly one row in `artifacts`.
CREATE TABLE artifact_observations (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    run_id      TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (artifact_id, run_id)
);
CREATE INDEX idx_observations_run ON artifact_observations(run_id);

CREATE TABLE claims (
    claim_id   TEXT PRIMARY KEY,
    predicate  TEXT NOT NULL,
    schema_id  TEXT NOT NULL,
    subject_id TEXT REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
    statement  TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'proposed'
);
CREATE INDEX idx_claims_predicate ON claims(predicate);
CREATE INDEX idx_claims_subject   ON claims(subject_id, predicate);
CREATE INDEX idx_claims_status    ON claims(status);

CREATE TABLE claim_evidence (
    claim_id    TEXT NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
    role        TEXT NOT NULL,
    PRIMARY KEY (claim_id, artifact_id, role)
);
CREATE INDEX idx_evidence_artifact ON claim_evidence(artifact_id);

CREATE TABLE attestations (
    attestation_id TEXT PRIMARY KEY,
    claim_id       TEXT NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
    producer_kind  TEXT NOT NULL,
    producer       TEXT NOT NULL,
    run_id         TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    confidence     REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at     TEXT NOT NULL,
    method         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_attestations_claim    ON attestations(claim_id);
CREATE INDEX idx_attestations_producer ON attestations(producer);

CREATE TABLE claim_links (
    src_claim_id TEXT NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
    dst_claim_id TEXT NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
    relation     TEXT NOT NULL,
    PRIMARY KEY (src_claim_id, dst_claim_id, relation),
    CHECK (src_claim_id <> dst_claim_id)
);
CREATE INDEX idx_links_dst ON claim_links(dst_claim_id, relation);

-- Free text is permitted here and nowhere else. An annotation is a human's
-- note about a record; it is never itself a security claim, and the export
-- keeps it in a separate stream so it can never be mistaken for one.
CREATE TABLE annotations (
    annotation_id TEXT PRIMARY KEY,
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('artifact','claim','project')),
    target_id     TEXT,
    author        TEXT NOT NULL,
    body          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_annotations_target ON annotations(target_kind, target_id);

-- Guard against a delete that would leave a claim standing with no evidence.
CREATE TRIGGER trg_claim_evidence_min
AFTER DELETE ON claim_evidence
BEGIN
    SELECT RAISE(ABORT, 'refusing to strand a claim without evidence')
    WHERE EXISTS (SELECT 1 FROM claims WHERE claim_id = OLD.claim_id)
      AND NOT EXISTS (SELECT 1 FROM claim_evidence WHERE claim_id = OLD.claim_id);
END;
"""


def _apply_script(script: str) -> Callable[[sqlite3.Connection], None]:
    """Wrap a DDL script as a self-contained, atomic migration step.

    ``executescript`` commits any open transaction before it runs, so a
    migration cannot inherit one from the caller. Each step therefore carries
    its own BEGIN/COMMIT and either lands whole or not at all.
    """

    def apply(conn: sqlite3.Connection) -> None:
        conn.executescript(f"BEGIN;\n{script}\nCOMMIT;")

    return apply


#: Ordered migrations. Index + 1 is the resulting schema version. Append only.
MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [
    _apply_script(_MIGRATION_1),
]


def connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    """Open a project database with Aether's standard pragmas."""
    if read_only:
        uri = f"file:{_uri_path(db_path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    else:
        conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        # WAL keeps a long-running MCP reader from blocking an analysis writer.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def _uri_path(path: str) -> str:
    """Turn a filesystem path into something sqlite's URI mode accepts."""
    normalized = path.replace("\\", "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized.replace("?", "%3f").replace("#", "%23")


def current_version(conn: sqlite3.Connection) -> int:
    """Schema version recorded in ``meta``; 0 for a fresh database."""
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
    except sqlite3.OperationalError:
        return 0
    return int(row["value"]) if row else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Bring the database up to :data:`aether.version.SCHEMA_VERSION`."""
    version = current_version(conn)
    if version > SCHEMA_VERSION:
        raise ProjectError(
            f"project was written by a newer Aether (schema v{version}); "
            f"this build understands v{SCHEMA_VERSION}"
        )
    if version == SCHEMA_VERSION:
        return version

    for index in range(version, SCHEMA_VERSION):
        MIGRATIONS[index](conn)
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(index + 1),),
        )
    return SCHEMA_VERSION


def integrity_problems(conn: sqlite3.Connection) -> list[dict[str, object]]:
    """Report evidence-graph violations that survived every other guard.

    Used by ``aether check``. An empty list is the invariant holding; anything
    here means a bug in the store, a hand-edited database, or a partial import.
    """
    problems: list[dict[str, object]] = []

    orphans = conn.execute(
        "SELECT claim_id FROM claims WHERE claim_id NOT IN "
        "(SELECT claim_id FROM claim_evidence)"
    ).fetchall()
    problems.extend(
        {"kind": "claim_without_evidence", "id": row["claim_id"]} for row in orphans
    )

    unattested = conn.execute(
        "SELECT claim_id FROM claims WHERE claim_id NOT IN "
        "(SELECT claim_id FROM attestations)"
    ).fetchall()
    problems.extend(
        {"kind": "claim_without_attestation", "id": row["claim_id"]}
        for row in unattested
    )

    dangling = conn.execute(
        "SELECT ce.claim_id, ce.artifact_id FROM claim_evidence ce "
        "LEFT JOIN artifacts a ON a.artifact_id = ce.artifact_id "
        "WHERE a.artifact_id IS NULL"
    ).fetchall()
    problems.extend(
        {
            "kind": "evidence_points_at_missing_artifact",
            "id": row["claim_id"],
            "artifact_id": row["artifact_id"],
        }
        for row in dangling
    )

    unobserved = conn.execute(
        "SELECT artifact_id FROM artifacts WHERE artifact_id NOT IN "
        "(SELECT artifact_id FROM artifact_observations)"
    ).fetchall()
    problems.extend(
        {"kind": "artifact_without_provenance", "id": row["artifact_id"]}
        for row in unobserved
    )

    for row in conn.execute("PRAGMA foreign_key_check").fetchall():
        problems.append({"kind": "foreign_key_violation", "id": str(tuple(row))})

    return problems
