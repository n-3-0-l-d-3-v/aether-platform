"""MCP tool surface over the evidence graph.

These tools are the contract future agents work against, so two properties are
treated as load-bearing:

*Everything is addressable.* Every response carries the ids of what it
describes, so an agent can always go one level deeper - claim to evidence,
evidence to containing object, object to the rest of the image - without
guessing or re-querying by name.

*Writing is possible but constrained.* ``submit_claim`` exists because an agent
that cannot record what it concluded is not much use. It goes through exactly
the same validation as an adapter: a registered predicate, typed fields, real
artifact ids, and the evidence kinds that predicate demands. An agent that
tries to assert prose gets a schema error, not a stored sentence. Agent claims
land as ``proposed`` and attributed to the agent, never as accepted fact.

Responses are size-bounded on purpose. An agent that asks for "all strings" in
a firmware image should get a useful page and a total count, not a context
window full of noise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from aether.errors import AetherError, EvidenceError
from aether.evidence.models import EvidenceRef
from aether.evidence.schemas import describe_registries
from aether.project.store import Project
from aether.util import hex_addr, human_size, sanitize_text

#: Hard ceiling on rows in any single response.
MAX_ROWS = 500
#: Characters of any single string value returned to a caller.
MAX_TEXT = 400


@dataclass(frozen=True)
class Tool:
    """One MCP tool: schema, description, and handler."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[Project, dict[str, Any]], dict[str, Any]]
    #: Write tools are refused when the server runs read-only.
    writes: bool = False


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


_LIMIT = {"type": "integer", "description": "Maximum rows to return.", "default": 50}
_OFFSET = {"type": "integer", "description": "Rows to skip, for paging.", "default": 0}


def _clamp(value: Any, default: int = 50) -> int:
    try:
        return max(1, min(int(value), MAX_ROWS))
    except (TypeError, ValueError):
        return default


def _artifact_row(project: Project, artifact: Any, *, verbose: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "artifact_id": artifact.artifact_id,
        "kind": artifact.kind,
        "name": sanitize_text(artifact.name or "", limit=MAX_TEXT) or None,
        "addr": hex_addr(artifact.addr_start) if artifact.addr_start is not None else None,
    }
    if artifact.object_id:
        row["object_id"] = artifact.object_id
    if verbose:
        data = dict(artifact.data)
        for key, value in list(data.items()):
            if isinstance(value, str):
                data[key] = sanitize_text(value, limit=MAX_TEXT)
        row["data"] = data
    return row


def _claim_row(claim: dict[str, Any], *, verbose: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "claim_id": claim["id"],
        "predicate": claim["predicate"],
        "statement": claim["statement"],
        "status": claim["status"],
        "confidence": claim["confidence"]["combined"],
        "producers": sorted(claim["confidence"]["per_producer"]),
        "evidence_count": len(claim["evidence"]),
    }
    if claim.get("subject_id"):
        row["subject_id"] = claim["subject_id"]
    if verbose:
        row["schema"] = claim["schema"]
        row["evidence"] = claim["evidence"]
        row["confidence_detail"] = claim["confidence"]
        row["attestations"] = [
            {
                "producer": a["producer"],
                "producer_kind": a["producer_kind"],
                "confidence": a["confidence"],
                "method": a["method"],
                "run_id": a["run_id"],
                "created_at": a["created_at"],
            }
            for a in claim["attestations"]
        ]
    return row


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


def _project_info(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    from aether.adapters.binwalk import BinwalkAdapter
    from aether.adapters.ghidra import GhidraAdapter
    from aether.adapters.triage import TriageAdapter

    stats = project.stats()
    engines = {}
    for adapter in (TriageAdapter(), GhidraAdapter(), BinwalkAdapter()):
        try:
            engines[adapter.name] = adapter.probe().to_record()
        except Exception as exc:  # noqa: BLE001 - probing must never break info
            engines[adapter.name] = {"available": False, "detail": str(exc)}
    return {
        "project": stats["project"],
        "totals": stats["totals"],
        "artifacts_by_kind": stats["artifacts_by_kind"],
        "claims_by_predicate": stats["claims_by_predicate"],
        "claims_by_status": stats["claims_by_status"],
        "engines": engines,
    }


def _list_objects(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    objects = project.objects()
    format_filter = args.get("format")
    if format_filter:
        objects = [o for o in objects if o.data.get("format") == format_filter]
    limit = _clamp(args.get("limit", 100), 100)
    rows = []
    for artifact in objects[: limit]:
        data = artifact.data
        rows.append(
            {
                "artifact_id": artifact.artifact_id,
                "path": data.get("path"),
                "format": data.get("format"),
                "arch": data.get("arch"),
                "bits": data.get("bits"),
                "size": data.get("size"),
                "size_human": human_size(int(data.get("size") or 0)),
                "sha256": data.get("sha256"),
                "source": data.get("source"),
                "parent_id": artifact.parent_id,
            }
        )
    return {"total": len(objects), "returned": len(rows), "objects": rows}


def _get_object(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    artifact = project.resolve_object(str(args["object"]))
    if artifact is None:
        raise EvidenceError(f"no file in this project matches {args['object']!r}")

    by_kind: dict[str, int] = {}
    for row in project._conn.execute(  # noqa: SLF001
        "SELECT kind, COUNT(*) AS n FROM artifacts WHERE object_id = ? GROUP BY kind",
        (artifact.artifact_id,),
    ):
        by_kind[row["kind"]] = row["n"]

    claims = project.find_claims(subject_id=artifact.artifact_id, limit=MAX_ROWS)
    by_predicate: dict[str, int] = {}
    for claim in claims:
        by_predicate[claim["predicate"]] = by_predicate.get(claim["predicate"], 0) + 1

    highlights = sorted(
        claims, key=lambda c: (-c["confidence"]["combined"], c["predicate"])
    )[: _clamp(args.get("highlight_limit", 15), 15)]

    return {
        "object": _artifact_row(project, artifact, verbose=True),
        "artifacts_by_kind": by_kind,
        "claims_by_predicate": by_predicate,
        "claim_count": len(claims),
        "highest_confidence_claims": [_claim_row(c) for c in highlights],
        "children": [
            {"artifact_id": c.artifact_id, "path": c.data.get("path")}
            for c in project.find_artifacts(kind="file", parent_id=artifact.artifact_id, limit=100)
        ],
    }


def _find_artifacts(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    object_id = None
    if args.get("object"):
        resolved = project.resolve_object(str(args["object"]))
        if resolved is None:
            raise EvidenceError(f"no file in this project matches {args['object']!r}")
        object_id = resolved.artifact_id

    addr = _parse_addr(args.get("addr"))
    limit = _clamp(args.get("limit", 50))
    results = project.find_artifacts(
        kind=args.get("kind"),
        object_id=object_id,
        name_contains=args.get("name_contains"),
        addr=addr,
        limit=limit,
        offset=int(args.get("offset") or 0),
    )
    total = project.count_artifacts(kind=args.get("kind"), object_id=object_id)
    return {
        "total_matching_kind_and_object": total,
        "returned": len(results),
        "artifacts": [
            _artifact_row(project, a, verbose=bool(args.get("verbose"))) for a in results
        ],
    }


def _get_artifact(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    artifact = project.get_artifact(str(args["artifact_id"]))
    if artifact is None:
        raise EvidenceError(f"unknown artifact {args['artifact_id']}")
    claims = project.claims_for_artifact(artifact.artifact_id, limit=_clamp(args.get("limit", 50)))
    container = project.get_artifact(artifact.object_id) if artifact.object_id else None
    return {
        "artifact": _artifact_row(project, artifact, verbose=True),
        "observed_in": (
            {"artifact_id": container.artifact_id, "path": container.data.get("path")}
            if container
            else None
        ),
        "cited_by_claims": [_claim_row(c) for c in claims],
    }


def _search_strings(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    object_id = None
    if args.get("object"):
        resolved = project.resolve_object(str(args["object"]))
        if resolved is None:
            raise EvidenceError(f"no file in this project matches {args['object']!r}")
        object_id = resolved.artifact_id
    limit = _clamp(args.get("limit", 50))
    results = project.find_artifacts(
        kind="string",
        object_id=object_id,
        name_contains=str(args["query"]),
        limit=limit,
        offset=int(args.get("offset") or 0),
    )
    rows = []
    for artifact in results:
        container = project.get_artifact(artifact.object_id) if artifact.object_id else None
        rows.append(
            {
                "artifact_id": artifact.artifact_id,
                "text": sanitize_text(str(artifact.data.get("text") or ""), limit=MAX_TEXT),
                "encoding": artifact.data.get("encoding"),
                "addr": hex_addr(artifact.data.get("addr")),
                "file_offset": artifact.data.get("file_offset"),
                "section": artifact.data.get("section"),
                "in_file": container.data.get("path") if container else None,
            }
        )
    return {"query": args["query"], "returned": len(rows), "matches": rows}


def _find_claims(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    subject_id = None
    if args.get("object"):
        resolved = project.resolve_object(str(args["object"]))
        if resolved is None:
            raise EvidenceError(f"no file in this project matches {args['object']!r}")
        subject_id = resolved.artifact_id

    claims = project.find_claims(
        predicate=args.get("predicate"),
        subject_id=subject_id,
        status=args.get("status"),
        producer=args.get("producer"),
        artifact_id=args.get("artifact_id"),
        min_confidence=args.get("min_confidence"),
        limit=_clamp(args.get("limit", 50)),
        offset=int(args.get("offset") or 0),
    )
    rows = []
    for claim in claims:
        row = _claim_row(claim, verbose=bool(args.get("verbose")))
        if claim.get("subject_id"):
            subject = project.get_artifact(claim["subject_id"])
            if subject:
                row["subject_path"] = subject.data.get("path") or subject.name
        rows.append(row)
    return {"returned": len(rows), "claims": rows}


def _get_claim(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    claim = project.get_claim(str(args["claim_id"]))
    if claim is None:
        raise EvidenceError(f"unknown claim {args['claim_id']}")

    evidence = []
    for ref in claim["evidence"]:
        artifact = project.get_artifact(ref["artifact_id"])
        if artifact is None:
            evidence.append({**ref, "missing": True})
            continue
        evidence.append({"role": ref["role"], **_artifact_row(project, artifact, verbose=True)})

    return {
        "claim": _claim_row(claim, verbose=True),
        "evidence": evidence,
        "links": project.claim_links(claim["id"]),
    }


def _neighbors(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    return project.neighbors(
        str(args["node_id"]),
        depth=int(args.get("depth") or 1),
        limit=_clamp(args.get("limit", 100), 100),
    )


def _contradictions(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    pairs = project.contradictions(limit=_clamp(args.get("limit", 25), 25))
    return {
        "count": len(pairs),
        "pairs": [
            {
                "left": _claim_row(pair["left"]) if pair["left"] else None,
                "right": _claim_row(pair["right"]) if pair["right"] else None,
            }
            for pair in pairs
        ],
    }


def _get_decompilation(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    object_id = None
    if args.get("object"):
        resolved = project.resolve_object(str(args["object"]))
        if resolved is None:
            raise EvidenceError(f"no file in this project matches {args['object']!r}")
        object_id = resolved.artifact_id

    results = project.find_artifacts(
        kind="decompilation",
        object_id=object_id,
        name_contains=args.get("function"),
        limit=_clamp(args.get("limit", 5), 5),
    )
    if not results:
        return {
            "returned": 0,
            "functions": [],
            "hint": (
                "No decompilation is stored for that query. Decompilation comes "
                "from a Ghidra run; check aether_project_info for whether the "
                "ghidra engine is available."
            ),
        }
    return {
        "returned": len(results),
        "functions": [
            {
                "artifact_id": a.artifact_id,
                "function_name": a.data.get("function_name"),
                "addr": hex_addr(a.data.get("function_addr")),
                "decompiler": a.data.get("decompiler"),
                "code": a.data.get("code"),
            }
            for a in results
        ],
    }


def _describe_schema(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    registries = describe_registries()
    if args.get("predicate"):
        name = str(args["predicate"])
        predicate = registries["claim_predicates"].get(name)
        if predicate is None:
            raise EvidenceError(
                f"unknown predicate {name!r}; known: "
                f"{sorted(registries['claim_predicates'])}"
            )
        return {"predicate": name, **predicate}
    if args.get("artifact_kind"):
        name = str(args["artifact_kind"])
        kind = registries["artifact_kinds"].get(name)
        if kind is None:
            raise EvidenceError(
                f"unknown artifact kind {name!r}; known: "
                f"{sorted(registries['artifact_kinds'])}"
            )
        return {"artifact_kind": name, **kind}
    return registries


def _runs(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    return {"runs": project.runs(limit=_clamp(args.get("limit", 25), 25))}


def _submit_claim(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    """Record an agent's structured conclusion, or explain why it is invalid."""
    predicate = str(args["predicate"])
    statement = args.get("statement") or {}
    evidence_args = args.get("evidence") or []
    if not evidence_args:
        raise EvidenceError(
            f"claim[{predicate}] needs evidence. Every claim must cite at least "
            "one artifact id; find them with aether_find_artifacts or "
            "aether_search_strings first."
        )

    refs = [
        EvidenceRef(str(item["artifact_id"]), str(item.get("role") or "locus"))
        for item in evidence_args
    ]
    producer = str(args.get("producer") or "agent:unnamed")
    confidence = float(args.get("confidence", 0.5))

    with project.run(
        tool="mcp",
        tool_version="1",
        adapter="mcp-agent",
        params={"producer": producer, "predicate": predicate},
        input_digest="",
    ) as rc:
        claim = rc.add_claim(
            predicate,
            statement,
            refs,
            confidence=confidence,
            producer=producer,
            # Agent output is never self-certifying. It enters as a proposal
            # attributed to the agent, for a human or a later gate to promote.
            producer_kind="agent",
            subject_id=args.get("subject_id"),
            status="proposed",
            method=str(args.get("method") or "agent-reasoning"),
        )
        run_id = rc.run.run_id

    stored = project.get_claim(claim.claim_id)
    return {
        "claim_id": claim.claim_id,
        "status": "proposed",
        "run_id": run_id,
        "claim": _claim_row(stored, verbose=True) if stored else None,
    }


def _annotate(project: Project, args: dict[str, Any]) -> dict[str, Any]:
    """Attach a free-text note. Notes are not claims and never become claims."""
    target_id = args.get("target_id")
    target_kind = str(args.get("target_kind") or "artifact")
    with project.run(
        tool="mcp", tool_version="1", adapter="mcp-agent", params={"kind": target_kind}
    ) as rc:
        annotation_id = rc.annotate(
            target_kind,
            str(target_id) if target_id else None,
            str(args["body"]),
            author=str(args.get("author") or "agent"),
        )
    return {"annotation_id": annotation_id, "target_id": target_id}


def _parse_addr(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError as exc:
        raise EvidenceError(f"could not parse address {value!r}") from exc


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

TOOLS: dict[str, Tool] = {}


def _register(tool: Tool) -> None:
    TOOLS[tool.name] = tool


_register(
    Tool(
        "aether_project_info",
        "Project overview: totals, artifact kinds, claim predicates, and which "
        "analysis engines are available on this machine. Call this first.",
        _schema({}),
        _project_info,
    )
)

_register(
    Tool(
        "aether_list_objects",
        "List every file in the project - top-level binaries and everything "
        "extracted from firmware images - with format, architecture, and size. "
        "This is the inventory.",
        _schema(
            {
                "format": {
                    "type": "string",
                    "description": "Filter by format, e.g. elf, pe, script, filesystem.",
                },
                "limit": _LIMIT,
            }
        ),
        _list_objects,
    )
)

_register(
    Tool(
        "aether_get_object",
        "Everything known about one file: identification, what was found inside "
        "it, and its highest-confidence claims. Accepts an artifact id, a full "
        "path, or a unique path suffix such as 'busybox'.",
        _schema(
            {
                "object": {
                    "type": "string",
                    "description": "Artifact id, path, or unique path suffix.",
                },
                "highlight_limit": {"type": "integer", "default": 15},
            },
            ["object"],
        ),
        _get_object,
    )
)

_register(
    Tool(
        "aether_find_artifacts",
        "Query concrete evidence: functions, strings, imports, sections, xrefs, "
        "symbols, decompilation, signature hits. Filter by kind, containing "
        "file, name substring, or address.",
        _schema(
            {
                "kind": {
                    "type": "string",
                    "description": "Artifact kind. Use aether_describe_schema to list them.",
                },
                "object": {"type": "string", "description": "Restrict to one file."},
                "name_contains": {"type": "string"},
                "addr": {
                    "type": "string",
                    "description": "Address, decimal or 0x-prefixed. Matches any "
                    "artifact whose range covers it.",
                },
                "verbose": {
                    "type": "boolean",
                    "description": "Include each artifact's full data payload.",
                    "default": False,
                },
                "limit": _LIMIT,
                "offset": _OFFSET,
            }
        ),
        _find_artifacts,
    )
)

_register(
    Tool(
        "aether_get_artifact",
        "One artifact in full, plus every claim that cites it as evidence.",
        _schema({"artifact_id": {"type": "string"}, "limit": _LIMIT}, ["artifact_id"]),
        _get_artifact,
    )
)

_register(
    Tool(
        "aether_search_strings",
        "Substring search across recovered string literals, with the address, "
        "section, and containing file for each hit.",
        _schema(
            {
                "query": {"type": "string"},
                "object": {"type": "string", "description": "Restrict to one file."},
                "limit": _LIMIT,
                "offset": _OFFSET,
            },
            ["query"],
        ),
        _search_strings,
    )
)

_register(
    Tool(
        "aether_find_claims",
        "Query structured claims. Every claim carries a predicate, typed "
        "fields, linked evidence, and a confidence derived from how many "
        "independent producers attested to it.",
        _schema(
            {
                "predicate": {
                    "type": "string",
                    "description": "e.g. contains_hardcoded_secret, uses_risky_api, "
                    "embeds_component, binary_hardening, firmware_contains_file.",
                },
                "object": {"type": "string", "description": "Claims about one file."},
                "artifact_id": {
                    "type": "string",
                    "description": "Claims citing this artifact as evidence.",
                },
                "status": {
                    "type": "string",
                    "enum": ["proposed", "accepted", "rejected", "superseded"],
                },
                "producer": {"type": "string"},
                "min_confidence": {"type": "number"},
                "verbose": {"type": "boolean", "default": False},
                "limit": _LIMIT,
                "offset": _OFFSET,
            }
        ),
        _find_claims,
    )
)

_register(
    Tool(
        "aether_get_claim",
        "One claim with its evidence artifacts fully resolved, its attestations, "
        "and its links to other claims. Use this to check what a finding "
        "actually rests on.",
        _schema({"claim_id": {"type": "string"}}, ["claim_id"]),
        _get_claim,
    )
)

_register(
    Tool(
        "aether_neighbors",
        "Walk the evidence graph outward from an artifact or claim: containment, "
        "evidence links, and claim-to-claim relations.",
        _schema(
            {
                "node_id": {"type": "string", "description": "An art_ or clm_ id."},
                "depth": {"type": "integer", "default": 1},
                "limit": {"type": "integer", "default": 100},
            },
            ["node_id"],
        ),
        _neighbors,
    )
)

_register(
    Tool(
        "aether_get_decompilation",
        "Decompiled source for one or more functions, as produced by Ghidra.",
        _schema(
            {
                "object": {"type": "string"},
                "function": {"type": "string", "description": "Function name substring."},
                "limit": {"type": "integer", "default": 3},
            }
        ),
        _get_decompilation,
    )
)

_register(
    Tool(
        "aether_contradictions",
        "Claim pairs explicitly recorded as contradicting each other.",
        _schema({"limit": {"type": "integer", "default": 25}}),
        _contradictions,
    )
)

_register(
    Tool(
        "aether_describe_schema",
        "The claim predicates you may assert and the artifact kinds that can "
        "back them, including which evidence each predicate requires. Read this "
        "before calling aether_submit_claim.",
        _schema(
            {
                "predicate": {"type": "string", "description": "Describe one predicate."},
                "artifact_kind": {"type": "string", "description": "Describe one kind."},
            }
        ),
        _describe_schema,
    )
)

_register(
    Tool(
        "aether_runs",
        "The provenance ledger: which engine ran when, with what parameters, "
        "and whether it succeeded.",
        _schema({"limit": {"type": "integer", "default": 25}}),
        _runs,
    )
)

_register(
    Tool(
        "aether_submit_claim",
        "Record a structured conclusion. The statement must match a registered "
        "predicate's fields exactly, and must cite artifact ids that already "
        "exist in the project - free-text findings are rejected. Submitted "
        "claims are stored as 'proposed' and attributed to you.",
        _schema(
            {
                "predicate": {"type": "string"},
                "statement": {
                    "type": "object",
                    "description": "Typed fields for the predicate. See "
                    "aether_describe_schema.",
                },
                "evidence": {
                    "type": "array",
                    "description": "Artifacts backing the claim.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "artifact_id": {"type": "string"},
                            "role": {
                                "type": "string",
                                "enum": ["locus", "support", "context", "counter"],
                                "default": "locus",
                            },
                        },
                        "required": ["artifact_id"],
                    },
                },
                "subject_id": {
                    "type": "string",
                    "description": "The file artifact the claim is about.",
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "producer": {
                    "type": "string",
                    "description": "Your identifier, e.g. agent:secrets-triage-v1.",
                },
                "method": {"type": "string"},
            },
            ["predicate", "statement", "evidence"],
        ),
        _submit_claim,
        writes=True,
    )
)

_register(
    Tool(
        "aether_annotate",
        "Attach a free-text note to an artifact, a claim, or the project. Notes "
        "are commentary and are stored separately from claims; they are never "
        "treated as findings.",
        _schema(
            {
                "body": {"type": "string"},
                "target_kind": {
                    "type": "string",
                    "enum": ["artifact", "claim", "project"],
                    "default": "artifact",
                },
                "target_id": {"type": "string"},
                "author": {"type": "string"},
            },
            ["body"],
        ),
        _annotate,
        writes=True,
    )
)


def list_tools(*, read_only: bool = False) -> list[dict[str, Any]]:
    """Tool descriptors for the MCP ``tools/list`` response."""
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
        }
        for tool in sorted(TOOLS.values(), key=lambda t: t.name)
        if not (read_only and tool.writes)
    ]


def call_tool(
    project: Project, name: str, arguments: dict[str, Any], *, read_only: bool = False
) -> dict[str, Any]:
    """Dispatch a tool call, translating Aether errors into useful messages."""
    tool = TOOLS.get(name)
    if tool is None:
        raise EvidenceError(
            f"unknown tool {name!r}; available: {sorted(TOOLS)}"
        )
    if tool.writes and read_only:
        raise AetherError(
            f"{name} modifies the project, but this server is running read-only"
        )
    return tool.handler(project, arguments or {})


__all__ = ["TOOLS", "Tool", "call_tool", "list_tools"]
