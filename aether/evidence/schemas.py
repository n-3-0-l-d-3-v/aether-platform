"""Declarative schemas for artifact kinds and claim predicates.

This module is the enforcement point for Aether's first absolute principle:
*no free-text security claims*. A claim is a ``predicate`` plus a fixed set of
typed fields declared here. There is deliberately no field of type "prose" on
any predicate - if a producer wants to say something Aether cannot represent,
the correct response is to add a predicate (a reviewed, versioned act), not to
smuggle a sentence into the graph.

Two registries live here:

``ARTIFACT_KINDS``
    What a piece of concrete evidence may look like, and - critically - which
    of its fields constitute its *identity*. Identity fields feed
    :func:`aether.canonical.mint_id`, so they decide when two observations are
    the same observation.

``CLAIM_PREDICATES``
    What may be asserted, with what fields, and what evidence must be attached
    for the assertion to be admissible at all. ``requires_evidence`` is not
    advisory: :mod:`aether.project.store` refuses the insert.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from aether.canonical import is_id
from aether.errors import SchemaError

# --------------------------------------------------------------------------
# Field specification
# --------------------------------------------------------------------------

#: Scalar types the validator understands. Deliberately small.
_SCALAR_TYPES: dict[str, tuple[type, ...]] = {
    "str": (str,),
    "int": (int,),
    "float": (float, int),
    "bool": (bool,),
}


@dataclass(frozen=True)
class Field:
    """One typed field on an artifact kind or claim predicate."""

    name: str
    type: str
    required: bool = False
    enum: tuple[str, ...] | None = None
    doc: str = ""
    #: Marks the field as part of the record's content-addressed identity.
    identity: bool = False
    #: For ``type="list"``: the element type.
    item_type: str = "str"
    #: Inclusive bounds for numeric fields.
    minimum: float | None = None
    maximum: float | None = None

    def validate(self, value: Any, where: str) -> Any:
        """Validate and normalize one value, or raise :class:`SchemaError`."""
        if value is None:
            if self.required:
                raise SchemaError(f"{where}.{self.name} is required")
            return None

        if self.type == "list":
            if not isinstance(value, (list, tuple)):
                raise SchemaError(f"{where}.{self.name} must be a list")
            item_types = _SCALAR_TYPES.get(self.item_type)
            if item_types is None:
                raise SchemaError(f"{where}.{self.name} has unknown item type")
            for index, item in enumerate(value):
                if not isinstance(item, item_types):
                    raise SchemaError(
                        f"{where}.{self.name}[{index}] must be {self.item_type}"
                    )
            return list(value)

        if self.type == "id":
            if not is_id(value):
                raise SchemaError(
                    f"{where}.{self.name} must be an Aether id, got {value!r}"
                )
            return value

        expected = _SCALAR_TYPES.get(self.type)
        if expected is None:
            raise SchemaError(f"unknown field type {self.type!r} on {self.name}")

        # bool is an int subclass; keep the two from silently substituting.
        if self.type != "bool" and isinstance(value, bool):
            raise SchemaError(f"{where}.{self.name} must be {self.type}, got bool")
        if not isinstance(value, expected):
            raise SchemaError(
                f"{where}.{self.name} must be {self.type}, got {type(value).__name__}"
            )

        if self.enum is not None and value not in self.enum:
            raise SchemaError(
                f"{where}.{self.name} must be one of {list(self.enum)}, got {value!r}"
            )
        if self.minimum is not None and value < self.minimum:
            raise SchemaError(f"{where}.{self.name} must be >= {self.minimum}")
        if self.maximum is not None and value > self.maximum:
            raise SchemaError(f"{where}.{self.name} must be <= {self.maximum}")
        return value


def _validate_fields(
    fields: Sequence[Field], data: Mapping[str, Any], where: str
) -> dict[str, Any]:
    """Validate ``data`` against ``fields``, rejecting undeclared keys.

    Rejecting unknown keys is what stops a producer from appending
    ``{"note": "looks exploitable"}`` to an otherwise-structured record.
    """
    if not isinstance(data, Mapping):
        raise SchemaError(f"{where} must be an object")

    declared = {f.name: f for f in fields}
    unknown = sorted(set(data) - set(declared))
    if unknown:
        raise SchemaError(
            f"{where} has undeclared field(s): {unknown}. "
            "Add them to the schema rather than passing free-form data."
        )

    out: dict[str, Any] = {}
    for name, spec in declared.items():
        value = spec.validate(data.get(name), where)
        if value is not None:
            out[name] = value
    return out


# --------------------------------------------------------------------------
# Artifact kinds
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactKind:
    """Schema for one class of concrete evidence."""

    name: str
    doc: str
    fields: tuple[Field, ...]
    #: True when the artifact stands alone (a file) rather than describing a
    #: location inside another object.
    standalone: bool = False
    #: Ordered fallbacks for what constitutes this kind's identity. The first
    #: group whose fields are *all* present is the one used.
    #:
    #: This is what lets two engines converge. Triage finds a string by file
    #: offset; Ghidra finds the same string by virtual address. If identity
    #: were simply "every identity field present", the two observations would
    #: mint different ids and the graph would carry the same literal twice.
    #: Preferring the address group when an address is known collapses them
    #: onto one artifact, so the second engine enriches rather than duplicates.
    #: Empty means "all identity fields, all required".
    identity_groups: tuple[tuple[str, ...], ...] = ()

    @property
    def identity_fields(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.identity)

    def identity_of(self, validated: Mapping[str, Any]) -> dict[str, Any]:
        """Extract the identity payload that will be hashed into the id."""
        groups = self.identity_groups or (self.identity_fields,)
        for group in groups:
            if all(validated.get(name) is not None for name in group):
                return {name: validated[name] for name in group}
        raise SchemaError(
            f"artifact[{self.name}] does not satisfy any identity group; "
            f"expected one of {[list(g) for g in groups]}"
        )

    def validate(self, data: Mapping[str, Any]) -> dict[str, Any]:
        validated = _validate_fields(self.fields, data, f"artifact[{self.name}]")
        self.identity_of(validated)  # raises when no group is satisfied
        return validated


def _kind(
    name: str,
    doc: str,
    *fields: Field,
    standalone: bool = False,
    identity_groups: tuple[tuple[str, ...], ...] = (),
) -> ArtifactKind:
    return ArtifactKind(
        name=name,
        doc=doc,
        fields=tuple(fields),
        standalone=standalone,
        identity_groups=identity_groups,
    )


#: Formats Aether normalizes to. Kept short on purpose: this is triage, not
#: a file-type database.
FORMATS: tuple[str, ...] = (
    "elf",
    "pe",
    "macho",
    "archive",
    "filesystem",
    "compressed",
    "script",
    "certificate",
    "data",
    "unknown",
)

ENCODINGS: tuple[str, ...] = ("ascii", "utf8", "utf16le", "utf16be", "unknown")

ARTIFACT_KINDS: dict[str, ArtifactKind] = {
    k.name: k
    for k in (
        _kind(
            "file",
            "A file on disk or carved out of a firmware image.",
            Field(
                "path",
                "str",
                required=True,
                identity=True,
                doc="Logical path: project-relative, or the path inside the image.",
            ),
            Field("sha256", "str", required=True, identity=True),
            Field("md5", "str"),
            Field("size", "int", required=True, minimum=0),
            Field("format", "str", required=True, enum=FORMATS),
            Field("arch", "str", doc="Normalized architecture, e.g. x86_64, arm, mips."),
            Field("bits", "int", minimum=8, maximum=128),
            Field("endian", "str", enum=("little", "big")),
            Field("media_type", "str", doc="Best-effort descriptive type string."),
            Field(
                "source",
                "str",
                required=True,
                enum=("ingest", "extract", "reference"),
                doc="How the file entered the project.",
            ),
            standalone=True,
        ),
        _kind(
            "section",
            "A named region of an object's address space.",
            Field("name", "str", required=True, identity=True),
            Field("addr_start", "int", required=True, identity=True, minimum=0),
            Field("addr_end", "int", minimum=0),
            Field("file_offset", "int", minimum=0),
            Field("permissions", "str", doc="Subset of r, w, x in that order."),
            Field("initialized", "bool"),
        ),
        _kind(
            "function",
            "A function recovered by a disassembler.",
            Field("name", "str", required=True, identity=True),
            Field("addr_start", "int", required=True, identity=True, minimum=0),
            Field("addr_end", "int", minimum=0),
            Field("size", "int", minimum=0),
            Field("signature", "str", doc="Prototype as rendered by the engine."),
            Field("calling_convention", "str"),
            Field("is_thunk", "bool"),
            Field("is_external", "bool"),
            Field("param_count", "int", minimum=0),
        ),
        _kind(
            "string",
            "A string literal observed in an object.",
            Field("text", "str", required=True, identity=True),
            Field("encoding", "str", required=True, identity=True, enum=ENCODINGS),
            Field("addr", "int", identity=True, minimum=0, doc="Virtual address when known."),
            Field(
                "file_offset",
                "int",
                identity=True,
                minimum=0,
                doc="File offset when no virtual address is available.",
            ),
            Field("length", "int", minimum=0),
            Field("section", "str"),
            identity_groups=(
                ("text", "encoding", "addr"),
                ("text", "encoding", "file_offset"),
            ),
        ),
        _kind(
            "xref",
            "A cross reference between two addresses.",
            Field("from_addr", "int", required=True, identity=True, minimum=0),
            Field("to_addr", "int", required=True, identity=True, minimum=0),
            Field(
                "ref_type",
                "str",
                required=True,
                identity=True,
                enum=("call", "jump", "read", "write", "data", "unknown"),
            ),
            Field("from_function", "str"),
            Field("to_function", "str"),
        ),
        _kind(
            "symbol",
            "A named symbol from a symbol table.",
            Field("name", "str", required=True, identity=True),
            Field("addr", "int", required=True, identity=True, minimum=0),
            Field(
                "symbol_type",
                "str",
                enum=("function", "object", "label", "external", "unknown"),
            ),
            Field("namespace", "str"),
            Field("is_primary", "bool"),
        ),
        _kind(
            "import",
            "An external symbol the object depends on.",
            Field("name", "str", required=True, identity=True),
            Field("library", "str", identity=True),
            Field("addr", "int", minimum=0),
            Field("ordinal", "int", minimum=0),
            # Identity is the symbol name alone, even though `library` is
            # marked as an identity field for documentation purposes.
            #
            # The tradeoff: a PE that imports the same name from two DLLs
            # collapses onto one artifact, and the losing library surfaces as a
            # field conflict rather than a second row. The alternative is worse
            # and far more common - a header parser that cannot see library
            # names and a disassembler that can would mint two artifacts for
            # every single import of every binary, and convergence between
            # engines would never happen at all.
            identity_groups=(("name",),),
        ),
        _kind(
            "export",
            "A symbol the object makes available to others.",
            Field("name", "str", required=True, identity=True),
            Field("addr", "int", identity=True, minimum=0),
            Field("ordinal", "int", minimum=0),
            identity_groups=(("name", "addr"), ("name",)),
        ),
        _kind(
            "decompilation",
            "Decompiled source text for one function.",
            Field("function_addr", "int", required=True, identity=True, minimum=0),
            Field("function_name", "str", required=True),
            Field("code", "str", required=True, identity=True),
            Field("decompiler", "str", required=True, identity=True),
            Field("line_count", "int", minimum=0),
        ),
        _kind(
            "byte_span",
            "A raw byte range, used as evidence for carving and patching.",
            Field("file_offset", "int", required=True, identity=True, minimum=0),
            Field("length", "int", required=True, identity=True, minimum=0),
            Field("sha256", "str"),
            Field("label", "str", identity=True),
            identity_groups=(
                ("file_offset", "length", "label"),
                ("file_offset", "length"),
            ),
        ),
        _kind(
            "signature_hit",
            "A magic-signature match inside a container or firmware image.",
            Field("signature", "str", required=True, identity=True),
            Field("file_offset", "int", required=True, identity=True, minimum=0),
            Field("description", "str"),
            Field(
                "extractor",
                "str",
                required=True,
                doc="Which tool reported the hit, e.g. binwalk or aether-carver.",
            ),
            Field("size", "int", minimum=0),
        ),
    )
}


def artifact_kind(name: str) -> ArtifactKind:
    """Look up an artifact kind, raising :class:`SchemaError` if unknown."""
    try:
        return ARTIFACT_KINDS[name]
    except KeyError:
        raise SchemaError(
            f"unknown artifact kind {name!r}; known kinds: {sorted(ARTIFACT_KINDS)}"
        ) from None


def validate_artifact_data(kind: str, data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an artifact payload against its kind."""
    return artifact_kind(kind).validate(data)


# --------------------------------------------------------------------------
# Claim predicates
# --------------------------------------------------------------------------

#: Roles an artifact can play on a claim.
EVIDENCE_ROLES: tuple[str, ...] = ("locus", "support", "context", "counter")


@dataclass(frozen=True)
class EvidenceRequirement:
    """A rule about what must be attached to a claim for it to be admissible."""

    role: str
    kinds: tuple[str, ...]
    minimum: int = 1
    doc: str = ""


@dataclass(frozen=True)
class ClaimPredicate:
    """Schema for one assertable statement."""

    name: str
    doc: str
    fields: tuple[Field, ...]
    requires_evidence: tuple[EvidenceRequirement, ...] = ()
    #: Bumped when the meaning of the predicate changes; part of the claim id.
    revision: int = 1

    @property
    def schema_id(self) -> str:
        return f"aether.claim.{self.name}/{self.revision}"

    def validate(self, statement: Mapping[str, Any]) -> dict[str, Any]:
        return _validate_fields(self.fields, statement, f"claim[{self.name}]")


def _pred(
    name: str,
    doc: str,
    *fields: Field,
    requires: Sequence[EvidenceRequirement] = (),
) -> ClaimPredicate:
    return ClaimPredicate(
        name=name, doc=doc, fields=tuple(fields), requires_evidence=tuple(requires)
    )


CLAIM_PREDICATES: dict[str, ClaimPredicate] = {
    p.name: p
    for p in (
        _pred(
            "file_format_identified",
            "The subject file was identified as a particular executable format.",
            Field("format", "str", required=True, enum=FORMATS),
            Field("arch", "str"),
            Field("bits", "int"),
            Field("endian", "str", enum=("little", "big")),
            requires=[
                EvidenceRequirement(
                    "locus", ("file",), 1, "The file whose format was identified."
                )
            ],
        ),
        _pred(
            "contains_string",
            "The subject object contains a specific string literal.",
            Field("text", "str", required=True),
            Field("encoding", "str", enum=ENCODINGS),
            requires=[
                EvidenceRequirement("locus", ("string",), 1, "The string artifact itself.")
            ],
        ),
        _pred(
            "defines_function",
            "The subject object defines a function at a given address.",
            Field("name", "str", required=True),
            Field("addr", "int", required=True, minimum=0),
            requires=[EvidenceRequirement("locus", ("function",), 1)],
        ),
        _pred(
            "imports_symbol",
            "The subject object imports an external symbol.",
            Field("symbol", "str", required=True),
            Field("library", "str"),
            requires=[EvidenceRequirement("locus", ("import", "symbol"), 1)],
        ),
        _pred(
            "exports_symbol",
            "The subject object exports a symbol.",
            Field("symbol", "str", required=True),
            requires=[EvidenceRequirement("locus", ("export", "symbol"), 1)],
        ),
        _pred(
            "uses_risky_api",
            "The subject object references an API with known misuse hazards. "
            "This is an attack-surface indicator, not a vulnerability finding.",
            Field("api", "str", required=True),
            Field(
                "category",
                "str",
                required=True,
                enum=(
                    "memory_copy",
                    "command_exec",
                    "format_string",
                    "weak_crypto",
                    "weak_random",
                    "unsafe_deserialization",
                    "privilege",
                    "network",
                ),
            ),
            Field("call_site_count", "int", minimum=0),
            requires=[
                EvidenceRequirement("locus", ("import", "symbol", "function"), 1),
                EvidenceRequirement(
                    "support",
                    ("xref", "decompilation", "string"),
                    0,
                    "Call sites, when the engine resolved them.",
                ),
            ],
        ),
        _pred(
            "contains_hardcoded_secret",
            "A credential-shaped literal is embedded in the subject object.",
            Field(
                "secret_kind",
                "str",
                required=True,
                enum=(
                    "private_key",
                    "certificate",
                    "aws_access_key",
                    "api_token",
                    "password",
                    "ssh_authorized_key",
                    "jwt",
                    "connection_string",
                    "unknown",
                ),
            ),
            Field(
                "detector",
                "str",
                required=True,
                doc="Identifier of the rule or model that flagged it.",
            ),
            Field(
                "redacted_preview",
                "str",
                doc="Truncated, masked excerpt. Never the full secret.",
            ),
            requires=[EvidenceRequirement("locus", ("string", "byte_span", "file"), 1)],
        ),
        _pred(
            "embeds_component",
            "A third-party component appears to be present in the subject.",
            Field("component", "str", required=True),
            Field("version", "str"),
            Field(
                "indicator",
                "str",
                required=True,
                enum=(
                    "version_banner",
                    "symbol_pattern",
                    "path_pattern",
                    "build_id",
                    "license_text",
                    "hash_match",
                ),
            ),
            requires=[
                EvidenceRequirement("locus", ("string", "symbol", "file", "import"), 1)
            ],
        ),
        _pred(
            "firmware_contains_file",
            "A firmware image contains an extracted file at a path.",
            Field("path", "str", required=True),
            Field("format", "str", enum=FORMATS),
            requires=[
                EvidenceRequirement("locus", ("file",), 1),
                EvidenceRequirement("context", ("signature_hit", "byte_span"), 0),
            ],
        ),
        _pred(
            "binary_hardening",
            "Presence or absence of an exploit-mitigation feature.",
            Field(
                "feature",
                "str",
                required=True,
                enum=(
                    "nx",
                    "pie",
                    "relro",
                    "stack_canary",
                    "fortify_source",
                    "aslr",
                    "cfg",
                    "safeseh",
                    "authenticode",
                ),
            ),
            Field("present", "bool", required=True),
            requires=[
                EvidenceRequirement("locus", ("file", "section", "symbol", "import"), 1)
            ],
        ),
    )
}


def claim_predicate(name: str) -> ClaimPredicate:
    """Look up a claim predicate, raising :class:`SchemaError` if unknown."""
    try:
        return CLAIM_PREDICATES[name]
    except KeyError:
        raise SchemaError(
            f"unknown claim predicate {name!r}; "
            f"known predicates: {sorted(CLAIM_PREDICATES)}"
        ) from None


def validate_claim_statement(
    predicate: str, statement: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate a claim statement body against its predicate."""
    return claim_predicate(predicate).validate(statement)


def check_evidence_requirements(
    predicate: str, roles: Mapping[str, Sequence[str]]
) -> None:
    """Verify attached evidence satisfies a predicate's requirements.

    ``roles`` maps an evidence role to the artifact *kinds* attached under it.
    Raises :class:`aether.errors.EvidenceError` when a requirement is unmet -
    this is the check that makes "claims must be backed by evidence" real.
    """
    from aether.errors import EvidenceError  # local import: avoids a cycle

    spec = claim_predicate(predicate)
    for role in roles:
        if role not in EVIDENCE_ROLES:
            raise EvidenceError(
                f"unknown evidence role {role!r}; expected one of {list(EVIDENCE_ROLES)}"
            )
    for requirement in spec.requires_evidence:
        attached = list(roles.get(requirement.role, ()))
        wrong = sorted({k for k in attached if k not in requirement.kinds})
        if wrong:
            raise EvidenceError(
                f"claim[{predicate}] role {requirement.role!r} accepts "
                f"{list(requirement.kinds)} but received {wrong}"
            )
        if len(attached) < requirement.minimum:
            raise EvidenceError(
                f"claim[{predicate}] requires at least {requirement.minimum} "
                f"artifact(s) of kind {list(requirement.kinds)} in role "
                f"{requirement.role!r}; got {len(attached)}"
            )


def describe_registries() -> dict[str, Any]:
    """Machine-readable dump of both registries, for MCP discovery tools."""

    def field_doc(f: Field) -> dict[str, Any]:
        return {
            "name": f.name,
            "type": f.type if f.type != "list" else f"list[{f.item_type}]",
            "required": f.required,
            "enum": list(f.enum) if f.enum else None,
            "identity": f.identity,
            "doc": f.doc,
        }

    return {
        "artifact_kinds": {
            name: {
                "doc": kind.doc,
                "standalone": kind.standalone,
                "identity_fields": list(kind.identity_fields),
                "identity_groups": [
                    list(g) for g in (kind.identity_groups or (kind.identity_fields,))
                ],
                "fields": [field_doc(f) for f in kind.fields],
            }
            for name, kind in sorted(ARTIFACT_KINDS.items())
        },
        "claim_predicates": {
            name: {
                "schema_id": pred.schema_id,
                "doc": pred.doc,
                "fields": [field_doc(f) for f in pred.fields],
                "requires_evidence": [
                    {
                        "role": r.role,
                        "kinds": list(r.kinds),
                        "minimum": r.minimum,
                        "doc": r.doc,
                    }
                    for r in pred.requires_evidence
                ],
            }
            for name, pred in sorted(CLAIM_PREDICATES.items())
        },
        "evidence_roles": list(EVIDENCE_ROLES),
    }
