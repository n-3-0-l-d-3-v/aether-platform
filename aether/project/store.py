"""The project store: the only sanctioned way in and out of the evidence graph.

Every adapter, CLI command, and MCP tool goes through this class. Nothing else
opens the database. That is what keeps the invariants in
:mod:`aether.evidence.schemas` from being one convenient shortcut away from
being bypassed.

Writes happen inside a :meth:`Project.run` block, which opens a run record,
gives the caller a :class:`RunContext`, and closes the run with a status. An
artifact or claim written outside a run is impossible by construction, so
provenance is never optional.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Mapping, Sequence

from aether.canonical import canonical_json, mint_id
from aether.errors import EvidenceError, ProjectError
from aether.evidence.models import (
    Artifact,
    Attestation,
    Claim,
    ClaimLink,
    EvidenceRef,
    Run,
    combine_confidence,
)
from aether.project import db
from aether.util import utc_now
from aether.version import AETHER_VERSION, SCHEMA_VERSION

#: Subdirectory inside a project that holds ingested/extracted file bytes.
BLOBS_DIRNAME = "blobs"
#: Subdirectory for adapter working output (Ghidra exports, binwalk logs).
WORK_DIRNAME = "work"


class RunContext:
    """Write handle scoped to a single adapter execution."""

    def __init__(self, project: "Project", run: Run) -> None:
        #: The project being written to. Adapters occasionally need to read
        #: existing state mid-run - to link a refined claim to the coarser one
        #: it supersedes, for instance - and going back through the store keeps
        #: that on the sanctioned path.
        self.project = project
        self._project = project
        self._conn = project._conn
        self.run = run
        self.artifacts_written = 0
        self.artifacts_new = 0
        self.claims_written = 0
        self.claims_new = 0
        self._field_conflicts: list[dict[str, Any]] = []

    # -- artifacts ------------------------------------------------------

    def add_artifact(self, artifact: Artifact) -> str:
        """Insert or converge an artifact, and record that this run saw it.

        Convergence rule: an artifact's identity fields fix its id, so a second
        observation of the same thing lands on the same row. Non-identity
        fields are *filled in* but never overwritten - first observation wins.
        A later engine that disagrees about, say, a function's end address does
        not silently rewrite history; the disagreement is reported back to the
        caller in :attr:`field_conflicts` instead.
        """
        row = self._conn.execute(
            "SELECT kind, data FROM artifacts WHERE artifact_id = ?",
            (artifact.artifact_id,),
        ).fetchone()

        if row is None:
            self._conn.execute(
                "INSERT INTO artifacts"
                "(artifact_id, kind, object_id, parent_id, name, addr_start, addr_end, data)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    artifact.artifact_id,
                    artifact.kind,
                    artifact.object_id,
                    artifact.parent_id,
                    artifact.name,
                    artifact.addr_start,
                    artifact.addr_end,
                    canonical_json(artifact.data),
                ),
            )
            self.artifacts_new += 1
        else:
            existing = json.loads(row["data"])
            merged = dict(existing)
            changed = False
            for key, value in artifact.data.items():
                if key not in merged:
                    merged[key] = value
                    changed = True
                elif merged[key] != value:
                    self._field_conflicts.append(
                        {
                            "artifact_id": artifact.artifact_id,
                            "field": key,
                            "kept": merged[key],
                            "rejected": value,
                        }
                    )
            if changed:
                probe = Artifact(
                    artifact_id=artifact.artifact_id,
                    kind=artifact.kind,
                    data=merged,
                    object_id=artifact.object_id,
                    parent_id=artifact.parent_id,
                )
                self._conn.execute(
                    "UPDATE artifacts SET data = ?, name = COALESCE(name, ?), "
                    "addr_end = COALESCE(addr_end, ?) WHERE artifact_id = ?",
                    (
                        canonical_json(merged),
                        probe.name,
                        probe.addr_end,
                        artifact.artifact_id,
                    ),
                )

        self._conn.execute(
            "INSERT OR IGNORE INTO artifact_observations(artifact_id, run_id, observed_at)"
            " VALUES (?, ?, ?)",
            (artifact.artifact_id, self.run.run_id, utc_now()),
        )
        self.artifacts_written += 1
        return artifact.artifact_id

    def artifact(
        self,
        kind: str,
        data: Mapping[str, Any],
        *,
        object_id: str | None = None,
        parent_id: str | None = None,
    ) -> Artifact:
        """Create, validate, and store an artifact in one step."""
        built = Artifact.create(kind, data, object_id=object_id, parent_id=parent_id)
        self.add_artifact(built)
        return built

    def add_artifacts(self, artifacts: Iterable[Artifact]) -> list[str]:
        return [self.add_artifact(a) for a in artifacts]

    @property
    def field_conflicts(self) -> list[dict[str, Any]]:
        """Non-identity fields where a later observation disagreed."""
        return list(self._field_conflicts)

    # -- claims ---------------------------------------------------------

    def add_claim(
        self,
        predicate: str,
        statement: Mapping[str, Any],
        evidence: Sequence[EvidenceRef],
        *,
        confidence: float,
        producer: str,
        producer_kind: str = "tool",
        subject_id: str | None = None,
        status: str = "proposed",
        method: str = "",
    ) -> Claim:
        """Assert a claim and attest to it as this run's producer.

        The evidence artifacts must already exist in the project: their kinds
        are read back from the database and checked against the predicate's
        requirements. A producer cannot vouch for evidence it never wrote.
        """
        if not evidence:
            raise EvidenceError(
                f"claim[{predicate}] was submitted with no evidence; "
                "claims without artifacts are not representable"
            )

        ids = sorted({ref.artifact_id for ref in evidence})
        placeholders = ",".join("?" * len(ids))
        rows = self._conn.execute(
            f"SELECT artifact_id, kind FROM artifacts WHERE artifact_id IN ({placeholders})",
            ids,
        ).fetchall()
        kinds = {row["artifact_id"]: row["kind"] for row in rows}
        missing = [i for i in ids if i not in kinds]
        if missing:
            raise EvidenceError(
                f"claim[{predicate}] cites artifact(s) not present in the project: "
                f"{missing}"
            )
        if subject_id is not None and subject_id not in kinds:
            subject_row = self._conn.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id = ?", (subject_id,)
            ).fetchone()
            if subject_row is None:
                raise EvidenceError(
                    f"claim[{predicate}] names a subject that is not in the project: "
                    f"{subject_id}"
                )

        claim = Claim.create(
            predicate,
            statement,
            evidence,
            subject_id=subject_id,
            status=status,
            evidence_kinds=kinds,
        )

        existed = self._conn.execute(
            "SELECT 1 FROM claims WHERE claim_id = ?", (claim.claim_id,)
        ).fetchone()
        if existed is None:
            self._conn.execute(
                "INSERT INTO claims"
                "(claim_id, predicate, schema_id, subject_id, statement, status)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    claim.claim_id,
                    claim.predicate,
                    claim.schema_id,
                    claim.subject_id,
                    canonical_json(claim.statement),
                    claim.status,
                ),
            )
            self.claims_new += 1
        for ref in claim.evidence:
            self._conn.execute(
                "INSERT OR IGNORE INTO claim_evidence(claim_id, artifact_id, role)"
                " VALUES (?, ?, ?)",
                (claim.claim_id, ref.artifact_id, ref.role),
            )

        attestation = Attestation.create(
            claim.claim_id,
            producer_kind=producer_kind,
            producer=producer,
            run_id=self.run.run_id,
            confidence=confidence,
            created_at=utc_now(),
            method=method,
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO attestations"
            "(attestation_id, claim_id, producer_kind, producer, run_id, confidence,"
            " created_at, method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attestation.attestation_id,
                attestation.claim_id,
                attestation.producer_kind,
                attestation.producer,
                attestation.run_id,
                attestation.confidence,
                attestation.created_at,
                attestation.method,
            ),
        )
        self.claims_written += 1
        return claim

    def link_claims(self, src: str, dst: str, relation: str) -> ClaimLink:
        """Record a typed relation between two claims."""
        link = ClaimLink(src_claim_id=src, dst_claim_id=dst, relation=relation)
        for claim_id in (src, dst):
            if not self._conn.execute(
                "SELECT 1 FROM claims WHERE claim_id = ?", (claim_id,)
            ).fetchone():
                raise EvidenceError(f"cannot link unknown claim {claim_id}")
        self._conn.execute(
            "INSERT OR IGNORE INTO claim_links(src_claim_id, dst_claim_id, relation)"
            " VALUES (?, ?, ?)",
            (src, dst, relation),
        )
        return link

    def annotate(
        self, target_kind: str, target_id: str | None, body: str, *, author: str = "user"
    ) -> str:
        """Attach a human note. The only place free text is allowed."""
        if target_kind not in ("artifact", "claim", "project"):
            raise ProjectError(f"cannot annotate target kind {target_kind!r}")
        annotation_id = mint_id(
            "ann",
            {"kind": target_kind, "target": target_id, "body": body, "author": author},
        )
        self._conn.execute(
            "INSERT OR REPLACE INTO annotations"
            "(annotation_id, target_kind, target_id, author, body, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (annotation_id, target_kind, target_id, author, body, utc_now()),
        )
        return annotation_id

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run.run_id,
            "adapter": self.run.adapter,
            "artifacts_written": self.artifacts_written,
            "artifacts_new": self.artifacts_new,
            "claims_written": self.claims_written,
            "claims_new": self.claims_new,
            "field_conflicts": len(self._field_conflicts),
        }


class Project:
    """An Aether project directory backed by SQLite."""

    def __init__(self, root: str, conn: sqlite3.Connection, read_only: bool = False):
        self.root = os.path.abspath(root)
        self._conn = conn
        self.read_only = read_only

    # -- lifecycle ------------------------------------------------------

    @staticmethod
    def create(root: str, name: str | None = None, *, exist_ok: bool = False) -> "Project":
        """Create a new project directory and database."""
        root = os.path.abspath(root)
        db_path = os.path.join(root, db.DB_FILENAME)
        if os.path.exists(db_path) and not exist_ok:
            raise ProjectError(
                f"a project already exists at {root}; pass --force to reuse it"
            )
        os.makedirs(root, exist_ok=True)
        os.makedirs(os.path.join(root, BLOBS_DIRNAME), exist_ok=True)
        os.makedirs(os.path.join(root, WORK_DIRNAME), exist_ok=True)

        conn = db.connect(db_path)
        db.migrate(conn)
        project = Project(root, conn)
        project_name = name or os.path.basename(root) or "aether-project"
        if db.current_version(conn) and not project.meta("project_id"):
            project._set_meta("project_id", mint_id("prj", {"name": project_name}))
            project._set_meta("project_name", project_name)
            project._set_meta("created_at", utc_now())
            project._set_meta("aether_version", AETHER_VERSION)
        return project

    @staticmethod
    def open(root: str, *, read_only: bool = False) -> "Project":
        """Open an existing project, migrating the schema if needed."""
        root = os.path.abspath(root)
        db_path = os.path.join(root, db.DB_FILENAME)
        if not os.path.exists(db_path):
            raise ProjectError(
                f"no Aether project at {root} (expected {db.DB_FILENAME}); "
                "run 'aether init' first"
            )
        conn = db.connect(db_path, read_only=read_only)
        if not read_only:
            db.migrate(conn)
        elif db.current_version(conn) != SCHEMA_VERSION:
            raise ProjectError(
                "project schema is out of date and the project was opened "
                "read-only; reopen for writing to migrate"
            )
        return Project(root, conn, read_only=read_only)

    @staticmethod
    def discover(start: str | None = None) -> str | None:
        """Walk upward from ``start`` looking for a project directory."""
        current = os.path.abspath(start or os.getcwd())
        while True:
            if os.path.exists(os.path.join(current, db.DB_FILENAME)):
                return current
            parent = os.path.dirname(current)
            if parent == current:
                return None
            current = parent

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Project":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- metadata -------------------------------------------------------

    def meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def info(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "project_id": self.meta("project_id"),
            "name": self.meta("project_name"),
            "created_at": self.meta("created_at"),
            "schema_version": db.current_version(self._conn),
            "aether_version": AETHER_VERSION,
        }

    @property
    def blobs_dir(self) -> str:
        return os.path.join(self.root, BLOBS_DIRNAME)

    @property
    def work_dir(self) -> str:
        return os.path.join(self.root, WORK_DIRNAME)

    # -- runs -----------------------------------------------------------

    @contextmanager
    def run(
        self,
        *,
        tool: str,
        tool_version: str,
        adapter: str,
        params: Mapping[str, Any] | None = None,
        input_digest: str = "",
        notes: str = "",
    ) -> Iterator[RunContext]:
        """Open a run, yield a write handle, and close the run atomically.

        The whole body executes inside one SQLite transaction. A crashed
        adapter leaves no half-imported artifacts, only a run row marked
        ``failed`` - which is itself useful provenance.
        """
        if self.read_only:
            raise ProjectError("project is open read-only; cannot start a run")

        started_at = utc_now()
        # A run is an *event*, not a content-addressed value: two identical
        # analyses are two runs, and both belong in the ledger. Deriving the id
        # from inputs plus a timestamp looked right until two runs landed in the
        # same clock tick - Windows resolves wall time to roughly 15ms - and
        # collided. The nonce makes the id unique by construction. Nothing is
        # lost: the deterministic graph export never contains a run id.
        run_id = mint_id(
            "run",
            {
                "tool": tool,
                "tool_version": tool_version,
                "adapter": adapter,
                "params": dict(params or {}),
                "input": input_digest,
                "started_at": started_at,
                "nonce": secrets.token_hex(8),
            },
        )
        run_record = Run(
            run_id=run_id,
            tool=tool,
            tool_version=tool_version,
            adapter=adapter,
            params=dict(params or {}),
            input_digest=input_digest,
            started_at=started_at,
            status="running",
            aether_version=AETHER_VERSION,
            notes=notes,
        )

        self._conn.execute("BEGIN")
        self._conn.execute(
            "INSERT INTO runs(run_id, tool, tool_version, adapter, params, input_digest,"
            " started_at, status, aether_version, notes)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                tool,
                tool_version,
                adapter,
                canonical_json(dict(params or {})),
                input_digest,
                started_at,
                "running",
                AETHER_VERSION,
                notes,
            ),
        )
        context = RunContext(self, run_record)
        try:
            yield context
        except BaseException:
            self._conn.execute("ROLLBACK")
            # Record the failure outside the rolled-back transaction so the
            # attempt is still visible in the ledger.
            self._conn.execute(
                "INSERT OR REPLACE INTO runs(run_id, tool, tool_version, adapter, params,"
                " input_digest, started_at, finished_at, status, aether_version, notes)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    tool,
                    tool_version,
                    adapter,
                    canonical_json(dict(params or {})),
                    input_digest,
                    started_at,
                    utc_now(),
                    "failed",
                    AETHER_VERSION,
                    notes,
                ),
            )
            raise
        else:
            self._conn.execute(
                "UPDATE runs SET finished_at = ?, status = ? WHERE run_id = ?",
                (utc_now(), "ok", run_id),
            )
            self._conn.execute("COMMIT")

    def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC, run_id LIMIT ?", (limit,)
        ).fetchall()
        return [
            {
                **dict(row),
                "params": json.loads(row["params"]),
            }
            for row in rows
        ]

    # -- artifact queries ------------------------------------------------

    def _artifact_from_row(self, row: sqlite3.Row) -> Artifact:
        return Artifact(
            artifact_id=row["artifact_id"],
            kind=row["kind"],
            data=json.loads(row["data"]),
            object_id=row["object_id"],
            parent_id=row["parent_id"],
        )

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        row = self._conn.execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if row is None and len(artifact_id) < 36:
            resolved = self.resolve_id(artifact_id)
            if resolved:
                row = self._conn.execute(
                    "SELECT * FROM artifacts WHERE artifact_id = ?", (resolved,)
                ).fetchone()
        return self._artifact_from_row(row) if row else None

    def find_artifacts(
        self,
        *,
        kind: str | None = None,
        object_id: str | None = None,
        parent_id: str | None = None,
        name_contains: str | None = None,
        addr: int | None = None,
        addr_min: int | None = None,
        addr_max: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Artifact]:
        """Query artifacts. All filters are ANDed; all are optional.

        ``addr`` matches an artifact whose range covers the address, which is
        how "what is at 0x401000?" gets answered without the caller knowing
        whether the answer is a function, a section, or a string.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if object_id:
            clauses.append("object_id = ?")
            params.append(object_id)
        if parent_id:
            clauses.append("parent_id = ?")
            params.append(parent_id)
        if name_contains:
            clauses.append("name LIKE ? ESCAPE '!'")
            params.append(f"%{_like_escape(name_contains)}%")
        if addr is not None:
            clauses.append(
                "(addr_start = ? OR (addr_start <= ? AND addr_end IS NOT NULL AND addr_end > ?))"
            )
            params.extend([addr, addr, addr])
        if addr_min is not None:
            clauses.append("addr_start >= ?")
            params.append(addr_min)
        if addr_max is not None:
            clauses.append("addr_start <= ?")
            params.append(addr_max)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM artifacts{where} "
            "ORDER BY kind, addr_start IS NULL, addr_start, name, artifact_id "
            "LIMIT ? OFFSET ?"
        )
        params.extend([_clamp_limit(limit), max(0, int(offset))])
        rows = self._conn.execute(sql, params).fetchall()
        return [self._artifact_from_row(row) for row in rows]

    def count_artifacts(self, *, kind: str | None = None, object_id: str | None = None) -> int:
        clauses, params = [], []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if object_id:
            clauses.append("object_id = ?")
            params.append(object_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        row = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM artifacts{where}", params
        ).fetchone()
        return int(row["n"])

    def objects(self) -> list[Artifact]:
        """Every file artifact in the project, images and extracted files alike."""
        rows = self._conn.execute(
            "SELECT * FROM artifacts WHERE kind = 'file' ORDER BY name, artifact_id"
        ).fetchall()
        return [self._artifact_from_row(row) for row in rows]

    def resolve_object(self, reference: str) -> Artifact | None:
        """Resolve a file artifact by id, exact path, or unique path suffix.

        Users type ``busybox``; the graph stores ``squashfs-root/bin/busybox``.
        Making the CLI and MCP tools meet them halfway costs one query.
        """
        direct = self.get_artifact(reference)
        if direct is not None and direct.kind == "file":
            return direct
        rows = self._conn.execute(
            "SELECT * FROM artifacts WHERE kind = 'file' AND (name = ? OR name LIKE ? ESCAPE '!')"
            " ORDER BY LENGTH(name), name LIMIT 2",
            (reference, f"%/{_like_escape(reference)}"),
        ).fetchall()
        if not rows:
            return None
        return self._artifact_from_row(rows[0])

    # -- claim queries ---------------------------------------------------

    def resolve_id(self, reference: str) -> str | None:
        """Resolve a full id or an unambiguous prefix, git-style.

        Ids are 36 characters, so anything that displays them in a table shows
        a prefix. Accepting that prefix back is the difference between the CLI
        being usable and being a copy-paste exercise. An ambiguous prefix is an
        error, never a silent pick.
        """
        reference = reference.strip()
        if not reference:
            return None
        table, column = (
            ("claims", "claim_id") if reference.startswith("clm_") else ("artifacts", "artifact_id")
        )
        exact = self._conn.execute(
            f"SELECT {column} AS id FROM {table} WHERE {column} = ?", (reference,)
        ).fetchone()
        if exact:
            return str(exact["id"])

        matches = self._conn.execute(
            f"SELECT {column} AS id FROM {table} WHERE {column} LIKE ? ESCAPE '!' LIMIT 5",
            (f"{_like_escape(reference)}%",),
        ).fetchall()
        if not matches:
            return None
        if len(matches) > 1:
            raise EvidenceError(
                f"{reference!r} is ambiguous; it matches "
                f"{[str(m['id']) for m in matches]}"
            )
        return str(matches[0]["id"])

    def get_claim(self, claim_id: str) -> dict[str, Any] | None:
        resolved = self.resolve_id(claim_id) if not claim_id.startswith("clm_") or len(
            claim_id
        ) < 36 else claim_id
        row = self._conn.execute(
            "SELECT * FROM claims WHERE claim_id = ?", (resolved or claim_id,)
        ).fetchone()
        return self._claim_from_row(row) if row else None

    def _claim_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        claim_id = row["claim_id"]
        evidence = [
            {"role": r["role"], "artifact_id": r["artifact_id"]}
            for r in self._conn.execute(
                "SELECT artifact_id, role FROM claim_evidence WHERE claim_id = ?"
                " ORDER BY role, artifact_id",
                (claim_id,),
            ).fetchall()
        ]
        attestations = [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM attestations WHERE claim_id = ? ORDER BY created_at, attestation_id",
                (claim_id,),
            ).fetchall()
        ]
        return {
            "id": claim_id,
            "predicate": row["predicate"],
            "schema": row["schema_id"],
            "subject_id": row["subject_id"],
            "statement": json.loads(row["statement"]),
            "status": row["status"],
            "evidence": evidence,
            "attestations": attestations,
            "confidence": combine_confidence(attestations),
        }

    def find_claims(
        self,
        *,
        predicate: str | None = None,
        subject_id: str | None = None,
        status: str | None = None,
        producer: str | None = None,
        artifact_id: str | None = None,
        min_confidence: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query claims, optionally filtered by the evidence they cite."""
        clauses: list[str] = []
        params: list[Any] = []
        joins = ""
        if predicate:
            clauses.append("c.predicate = ?")
            params.append(predicate)
        if subject_id:
            clauses.append("c.subject_id = ?")
            params.append(subject_id)
        if status:
            clauses.append("c.status = ?")
            params.append(status)
        if artifact_id:
            joins += " JOIN claim_evidence ce ON ce.claim_id = c.claim_id"
            clauses.append("ce.artifact_id = ?")
            params.append(artifact_id)
        if producer:
            joins += " JOIN attestations at ON at.claim_id = c.claim_id"
            clauses.append("at.producer = ?")
            params.append(producer)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT DISTINCT c.* FROM claims c{joins}{where} "
            "ORDER BY c.predicate, c.claim_id LIMIT ? OFFSET ?"
        )
        # Over-fetch when a confidence filter is active: it is applied after
        # aggregation, which SQL cannot do cheaply across attestations here.
        fetch_limit = _clamp_limit(limit) if min_confidence is None else _clamp_limit(limit) * 4
        params.extend([fetch_limit, max(0, int(offset))])
        rows = self._conn.execute(sql, params).fetchall()
        claims = [self._claim_from_row(row) for row in rows]
        if min_confidence is not None:
            claims = [
                c for c in claims if c["confidence"]["combined"] >= float(min_confidence)
            ]
        return claims[: _clamp_limit(limit)]

    def claim_links(self, claim_id: str) -> dict[str, list[dict[str, str]]]:
        outgoing = [
            {"relation": r["relation"], "claim_id": r["dst_claim_id"]}
            for r in self._conn.execute(
                "SELECT relation, dst_claim_id FROM claim_links WHERE src_claim_id = ?"
                " ORDER BY relation, dst_claim_id",
                (claim_id,),
            ).fetchall()
        ]
        incoming = [
            {"relation": r["relation"], "claim_id": r["src_claim_id"]}
            for r in self._conn.execute(
                "SELECT relation, src_claim_id FROM claim_links WHERE dst_claim_id = ?"
                " ORDER BY relation, src_claim_id",
                (claim_id,),
            ).fetchall()
        ]
        return {"outgoing": outgoing, "incoming": incoming}

    def contradictions(self, limit: int = 100) -> list[dict[str, Any]]:
        """Every pair of claims explicitly recorded as contradicting."""
        rows = self._conn.execute(
            "SELECT src_claim_id, dst_claim_id FROM claim_links WHERE relation = 'contradicts'"
            " ORDER BY src_claim_id, dst_claim_id LIMIT ?",
            (_clamp_limit(limit),),
        ).fetchall()
        return [
            {
                "left": self.get_claim(row["src_claim_id"]),
                "right": self.get_claim(row["dst_claim_id"]),
            }
            for row in rows
        ]

    def claims_for_artifact(self, artifact_id: str, limit: int = 100) -> list[dict[str, Any]]:
        return self.find_claims(artifact_id=artifact_id, limit=limit)

    def annotations(self, target_id: str | None = None) -> list[dict[str, Any]]:
        if target_id:
            rows = self._conn.execute(
                "SELECT * FROM annotations WHERE target_id = ? ORDER BY created_at",
                (target_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM annotations ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- graph -----------------------------------------------------------

    def neighbors(self, node_id: str, *, depth: int = 1, limit: int = 200) -> dict[str, Any]:
        """Walk the evidence graph outward from an artifact or a claim.

        Edges traversed: artifact containment (object/parent), claim-to-evidence
        in both directions, and claim-to-claim relations. One traversal serves
        "what do we know about this function?" and "what is this claim resting
        on?", which are the two questions agents ask most.
        """
        node_id = self.resolve_id(node_id) or node_id
        seen: set[str] = {node_id}
        frontier = [node_id]
        edges: list[dict[str, str]] = []
        nodes: dict[str, dict[str, Any]] = {}

        for _ in range(max(1, int(depth))):
            next_frontier: list[str] = []
            for current in frontier:
                for edge in self._edges_of(current):
                    edges.append(edge)
                    for endpoint in (edge["src"], edge["dst"]):
                        if endpoint not in seen and len(seen) < _clamp_limit(limit):
                            seen.add(endpoint)
                            next_frontier.append(endpoint)
            frontier = next_frontier
            if not frontier:
                break

        for identifier in sorted(seen):
            if identifier.startswith("art_"):
                artifact = self.get_artifact(identifier)
                if artifact:
                    nodes[identifier] = {
                        "type": "artifact",
                        "kind": artifact.kind,
                        "name": artifact.name,
                        "addr": artifact.addr_start,
                    }
            elif identifier.startswith("clm_"):
                claim = self.get_claim(identifier)
                if claim:
                    nodes[identifier] = {
                        "type": "claim",
                        "predicate": claim["predicate"],
                        "status": claim["status"],
                        "confidence": claim["confidence"]["combined"],
                    }

        unique_edges = {canonical_json(e): e for e in edges}
        return {
            "root": node_id,
            "nodes": nodes,
            "edges": [unique_edges[k] for k in sorted(unique_edges)],
        }

    def _edges_of(self, node_id: str) -> list[dict[str, str]]:
        edges: list[dict[str, str]] = []
        if node_id.startswith("art_"):
            row = self._conn.execute(
                "SELECT object_id, parent_id FROM artifacts WHERE artifact_id = ?",
                (node_id,),
            ).fetchone()
            if row:
                if row["object_id"]:
                    edges.append(
                        {"src": node_id, "dst": row["object_id"], "relation": "observed_in"}
                    )
                if row["parent_id"]:
                    edges.append(
                        {"src": node_id, "dst": row["parent_id"], "relation": "extracted_from"}
                    )
            for r in self._conn.execute(
                "SELECT claim_id, role FROM claim_evidence WHERE artifact_id = ? LIMIT 200",
                (node_id,),
            ).fetchall():
                edges.append(
                    {"src": r["claim_id"], "dst": node_id, "relation": f"evidence:{r['role']}"}
                )
            for r in self._conn.execute(
                "SELECT artifact_id FROM artifacts WHERE object_id = ? OR parent_id = ? LIMIT 200",
                (node_id, node_id),
            ).fetchall():
                edges.append(
                    {"src": r["artifact_id"], "dst": node_id, "relation": "observed_in"}
                )
        elif node_id.startswith("clm_"):
            for r in self._conn.execute(
                "SELECT artifact_id, role FROM claim_evidence WHERE claim_id = ?",
                (node_id,),
            ).fetchall():
                edges.append(
                    {"src": node_id, "dst": r["artifact_id"], "relation": f"evidence:{r['role']}"}
                )
            for r in self._conn.execute(
                "SELECT dst_claim_id, relation FROM claim_links WHERE src_claim_id = ?",
                (node_id,),
            ).fetchall():
                edges.append(
                    {"src": node_id, "dst": r["dst_claim_id"], "relation": r["relation"]}
                )
            for r in self._conn.execute(
                "SELECT src_claim_id, relation FROM claim_links WHERE dst_claim_id = ?",
                (node_id,),
            ).fetchall():
                edges.append(
                    {"src": r["src_claim_id"], "dst": node_id, "relation": r["relation"]}
                )
        return edges

    # -- reporting -------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        by_kind = {
            row["kind"]: row["n"]
            for row in self._conn.execute(
                "SELECT kind, COUNT(*) AS n FROM artifacts GROUP BY kind ORDER BY kind"
            ).fetchall()
        }
        by_predicate = {
            row["predicate"]: row["n"]
            for row in self._conn.execute(
                "SELECT predicate, COUNT(*) AS n FROM claims GROUP BY predicate"
                " ORDER BY predicate"
            ).fetchall()
        }
        by_status = {
            row["status"]: row["n"]
            for row in self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM claims GROUP BY status ORDER BY status"
            ).fetchall()
        }
        totals = self._conn.execute(
            "SELECT (SELECT COUNT(*) FROM artifacts) AS artifacts,"
            " (SELECT COUNT(*) FROM claims) AS claims,"
            " (SELECT COUNT(*) FROM attestations) AS attestations,"
            " (SELECT COUNT(*) FROM runs) AS runs,"
            " (SELECT COUNT(*) FROM claim_links WHERE relation='contradicts') AS contradictions,"
            " (SELECT COUNT(*) FROM annotations) AS annotations"
        ).fetchone()
        return {
            "project": self.info(),
            "totals": dict(totals),
            "artifacts_by_kind": by_kind,
            "claims_by_predicate": by_predicate,
            "claims_by_status": by_status,
        }

    def check(self) -> list[dict[str, Any]]:
        """Run the evidence-graph integrity checks."""
        return db.integrity_problems(self._conn)

    def set_claim_status(self, claim_id: str, status: str) -> None:
        """Promote or reject a claim. Curation, not assertion."""
        from aether.evidence.models import CLAIM_STATUSES

        if status not in CLAIM_STATUSES:
            raise EvidenceError(f"unknown claim status {status!r}")
        if not self._conn.execute(
            "SELECT 1 FROM claims WHERE claim_id = ?", (claim_id,)
        ).fetchone():
            raise EvidenceError(f"unknown claim {claim_id}")
        self._conn.execute(
            "UPDATE claims SET status = ? WHERE claim_id = ?", (status, claim_id)
        )


def _clamp_limit(limit: int, maximum: int = 5000) -> int:
    """Keep a caller - especially an agent - from asking for the whole graph."""
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return 100
    return max(1, min(value, maximum))


def _like_escape(value: str) -> str:
    """Escape LIKE wildcards so a user's underscore is a literal underscore."""
    return (
        value.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    )
