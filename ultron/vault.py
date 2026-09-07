"""Vault-write for RE findings, gated by explicit human review.

Ultron's own evidence graph (``ultron/evidence/``) already refuses free-text
findings inside a project's claim store. This module is a *different* kind of
output: prose notes meant for a shared, cross-tool knowledge base outside any
one project - the ecosystem "vault" a future orchestrator and other agents
read from. Because these notes are prose by nature, they cannot be schema-
checked the way a claim is; the safeguard here is procedural instead of
structural: a note is written to ``pending/`` first, and nothing in this
module - or anywhere else in Ultron - ever moves a note to ``approved/`` on
its own. Only an explicit call to :func:`approve_note` (wired to the CLI's
``ultron vault approve``, run by a human) does that.

This repository owns only a local ``vault/Ultron/`` folder. A future
ecosystem bootstrap step is expected to symlink or mount that path at
wherever the real shared vault lives; this module does not know or care
where that is.
"""

from __future__ import annotations

import datetime
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any

#: Default local vault path, matching agent.yaml's vault_write_path.
VAULT_ROOT_DEFAULT = "vault/Ultron"
PENDING_DIRNAME = "pending"
APPROVED_DIRNAME = "approved"

_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)


@dataclass(frozen=True)
class VaultNote:
    """One Markdown note, and where the review gate currently places it."""

    note_id: str
    path: str
    status: str  # "pending" | "approved"

    def to_record(self) -> dict[str, Any]:
        return {"note_id": self.note_id, "path": self.path, "status": self.status}


def _slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug or "note"


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _parse_frontmatter(text: str) -> dict[str, str]:
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}
    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def _set_frontmatter_field(text: str, key: str, value: str) -> str:
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return text
    lines = match.group(1).splitlines()
    for index, line in enumerate(lines):
        if line.startswith(f"{key}:"):
            lines[index] = f"{key}: {value}"
            break
    else:
        lines.append(f"{key}: {value}")
    new_block = "\n".join(lines)
    return text[: match.start(1)] + new_block + text[match.end(1):]


def write_finding(
    title: str,
    body: str,
    *,
    vault_root: str = VAULT_ROOT_DEFAULT,
    claim_ids: list[str] | None = None,
    tags: list[str] | None = None,
) -> VaultNote:
    """Write one finding as a *pending* Markdown note.

    Never writes into ``approved/``. ``claim_ids`` optionally cites the
    structured claims (from ``ultron query claim <id>``) this prose finding
    summarizes, so a reviewer can cross-check the note against real evidence
    even though the note itself is not a claim.
    """
    if not title.strip():
        raise ValueError("a vault finding needs a non-empty title")

    pending_dir = os.path.join(vault_root, PENDING_DIRNAME)
    os.makedirs(pending_dir, exist_ok=True)
    os.makedirs(os.path.join(vault_root, APPROVED_DIRNAME), exist_ok=True)

    timestamp = datetime.datetime.now(datetime.timezone.utc)
    note_id = f"note_{timestamp.strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"
    filename = f"{note_id}-{_slugify(title)}.md"
    path = os.path.join(pending_dir, filename)

    frontmatter = "\n".join(
        [
            "---",
            f"id: {note_id}",
            f"title: {title}",
            f"created_at: {timestamp.isoformat()}",
            "approved: false",
            f"claim_ids: [{', '.join(claim_ids or [])}]",
            f"tags: [{', '.join(tags or [])}]",
            "---",
            "",
        ]
    )
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(frontmatter)
        handle.write(body.rstrip("\n"))
        handle.write("\n")

    return VaultNote(note_id=note_id, path=path, status="pending")


def is_approved(path: str) -> bool:
    """A note counts as committed knowledge if it lives under ``approved/``,
    or its own frontmatter already says ``approved: true`` (a note approved
    in place before a sync step relocates it).
    """
    parts = os.path.normpath(path).split(os.sep)
    if APPROVED_DIRNAME in parts:
        return True
    try:
        text = _read(path)
    except OSError:
        return False
    return _parse_frontmatter(text).get("approved", "").lower() == "true"


def list_notes(vault_root: str = VAULT_ROOT_DEFAULT) -> list[VaultNote]:
    """List every note under both ``pending/`` and ``approved/``."""
    notes: list[VaultNote] = []
    for dirname in (PENDING_DIRNAME, APPROVED_DIRNAME):
        directory = os.path.join(vault_root, dirname)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".md"):
                continue
            path = os.path.join(directory, name)
            try:
                fields = _parse_frontmatter(_read(path))
            except OSError:
                fields = {}
            status = "approved" if is_approved(path) else "pending"
            notes.append(
                VaultNote(note_id=fields.get("id", name), path=path, status=status)
            )
    return notes


def approve_note(note_ref: str, *, vault_root: str = VAULT_ROOT_DEFAULT) -> VaultNote:
    """Move one pending note to ``approved/``, marking its frontmatter too.

    ``note_ref`` may be a full path or just the filename inside
    ``pending/``. This is the single function in Ultron that grants a vault
    note committed-knowledge status, and it only ever runs when something -
    the CLI's ``ultron vault approve``, run by a human - calls it explicitly.
    Nothing in the write path (:func:`write_finding`) or anywhere in the
    analysis pipeline calls this.
    """
    pending_dir = os.path.join(vault_root, PENDING_DIRNAME)
    approved_dir = os.path.join(vault_root, APPROVED_DIRNAME)
    os.makedirs(approved_dir, exist_ok=True)

    source = note_ref if os.path.isfile(note_ref) else os.path.join(pending_dir, os.path.basename(note_ref))
    if not os.path.isfile(source):
        raise FileNotFoundError(f"no pending vault note found for {note_ref!r}")

    text = _set_frontmatter_field(_read(source), "approved", "true")
    destination = os.path.join(approved_dir, os.path.basename(source))
    with open(destination, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    os.remove(source)

    fields = _parse_frontmatter(text)
    return VaultNote(
        note_id=fields.get("id", os.path.basename(destination)),
        path=destination,
        status="approved",
    )


__all__ = [
    "APPROVED_DIRNAME",
    "PENDING_DIRNAME",
    "VAULT_ROOT_DEFAULT",
    "VaultNote",
    "approve_note",
    "is_approved",
    "list_notes",
    "write_finding",
]
