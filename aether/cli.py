"""The ``aether`` command line.

Every command is a thin wrapper over the project store or an adapter; none of
them contain analysis logic, and none of them touch the database directly.
Anything the CLI can do, the MCP tools can do too - they are two front ends
over one library, which is the only way the two stay in agreement.

Human-readable output by default; ``--json`` everywhere for scripting.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable

from aether.errors import AetherError, ProjectError
from aether.project.store import Project
from aether.util import hex_addr, human_size, sanitize_text
from aether.version import AETHER_VERSION

#: Written to stderr so it never contaminates --json output on stdout.
def _warn(message: str) -> None:
    print(message, file=sys.stderr)


def _emit(payload: Any, as_json: bool, renderer: Callable[[Any], None]) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        renderer(payload)


def _open_project(args: argparse.Namespace, *, read_only: bool = False) -> Project:
    root = args.project or Project.discover()
    if not root:
        raise ProjectError(
            "no Aether project found here or in any parent directory. "
            "Run 'aether init' first, or pass --project <dir>."
        )
    return Project.open(root, read_only=read_only)


def _table(rows: list[list[str]], headers: list[str]) -> None:
    """Print a plain aligned table. No dependencies, no colour, no surprises."""
    if not rows:
        print("(none)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    root = os.path.abspath(args.path)
    project = Project.create(root, args.name, exist_ok=args.force)
    info = project.info()
    project.close()
    _emit(
        info,
        args.json,
        lambda p: print(
            f"initialized project '{p['name']}' at {p['root']}\n"
            f"  project id     {p['project_id']}\n"
            f"  schema version {p['schema_version']}"
        ),
    )
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Ingest and analyze a file, choosing engines automatically by default."""
    from aether.adapters.binwalk import BinwalkAdapter
    from aether.adapters.ghidra import GhidraAdapter
    from aether.adapters.triage import TriageAdapter
    from aether.adapters.triage.formats import identify_file

    project = _open_project(args)
    try:
        results = []
        engine = args.engine
        if engine == "auto":
            # Containers go to the firmware path; executables get triage, plus
            # Ghidra when it is actually installed.
            identification = identify_file(args.file)
            engine = (
                "firmware"
                if identification.format in ("archive", "compressed", "filesystem", "data")
                else "binary"
            )

        if engine == "firmware":
            results.append(
                BinwalkAdapter().analyze(
                    project,
                    args.file,
                    logical_path=args.path,
                    max_depth=args.max_depth,
                    string_limit=args.string_limit,
                )
            )
        else:
            if engine in ("binary", "triage"):
                results.append(
                    TriageAdapter().analyze(
                        project,
                        args.file,
                        logical_path=args.path,
                        string_limit=args.string_limit,
                    )
                )
            if engine in ("binary", "ghidra"):
                ghidra = GhidraAdapter()
                availability = ghidra.probe()
                if availability.available:
                    results.append(
                        ghidra.analyze(
                            project,
                            args.file,
                            logical_path=args.path,
                            decompile_limit=args.decompile_limit,
                        )
                    )
                elif engine == "ghidra":
                    raise AetherError(f"{availability.detail}\n  {availability.remedy}")
                else:
                    _warn(
                        f"note: skipping Ghidra - {availability.detail}. "
                        "Header-level triage still ran."
                    )

        payload = [r.to_record() for r in results]

        def render(records: list[dict[str, Any]]) -> None:
            for record in records:
                details = record["details"]
                print(f"[{record['adapter']}] run {record['run_id']}")
                print(
                    f"  artifacts {record['artifacts']} "
                    f"({record['artifacts_new']} new)   "
                    f"claims {record['claims']} ({record['claims_new']} new)"
                )
                if details.get("format"):
                    print(
                        f"  {details.get('path')}: {details.get('media_type')}"
                    )
                if details.get("extracted") is not None:
                    print(f"  engine {details.get('engine')}   extracted {details['extracted']} file(s)")
                    for item in details.get("inventory", [])[:20]:
                        print(
                            f"    {item['path'][:56]:58s}{item['format']:12s}"
                            f"{human_size(item['size'])}"
                        )
                for warning in record["warnings"][:5]:
                    print(f"  ! {warning}")
            stats = project.stats()
            print(
                f"\nproject now holds {stats['totals']['artifacts']} artifacts "
                f"and {stats['totals']['claims']} claims"
            )

        _emit(payload, args.json, render)
        return 0
    finally:
        project.close()


def cmd_import_ghidra(args: argparse.Namespace) -> int:
    from aether.adapters.ghidra import GhidraAdapter

    project = _open_project(args)
    try:
        result = GhidraAdapter().import_directory(
            project,
            args.export_dir,
            target=args.target,
            object_id=args.object,
            logical_path=args.path,
        )
        _emit(
            result.to_record(),
            args.json,
            lambda r: print(
                f"imported Ghidra export for {r['details'].get('program')}\n"
                f"  artifacts {r['artifacts']} ({r['artifacts_new']} new)   "
                f"claims {r['claims']} ({r['claims_new']} new)\n"
                f"  {json.dumps(r['details'].get('imported', {}), sort_keys=True)}"
            ),
        )
        for warning in result.warnings:
            _warn(f"! {warning}")
        return 0
    finally:
        project.close()


def cmd_query(args: argparse.Namespace) -> int:
    # The schema is a property of Aether, not of any project. Requiring one
    # would mean you could not ask what you are allowed to assert until after
    # you had something to assert it about.
    if args.what == "schema":
        return _query_schema(args)
    project = _open_project(args, read_only=False)
    try:
        return _dispatch_query(project, args)
    finally:
        project.close()


def _query_schema(args: argparse.Namespace) -> int:
    from aether.evidence.schemas import describe_registries

    registries = describe_registries()
    if args.name:
        for bucket in ("claim_predicates", "artifact_kinds"):
            if args.name in registries[bucket]:
                print(json.dumps(registries[bucket][args.name], indent=2, sort_keys=True))
                return 0
        raise AetherError(f"unknown predicate or artifact kind {args.name!r}")

    def render(r: dict[str, Any]) -> None:
        print("claim predicates")
        _table(
            [
                [
                    name,
                    ", ".join(
                        f"{f['name']}{'*' if f['required'] else ''}" for f in spec["fields"]
                    )[:56],
                    ", ".join(
                        f"{req['role']}:{'|'.join(req['kinds'])}"
                        for req in spec["requires_evidence"]
                        if req["minimum"]
                    )[:44],
                ]
                for name, spec in r["claim_predicates"].items()
            ],
            ["predicate", "fields (* = required)", "required evidence"],
        )
        print()
        print("artifact kinds")
        _table(
            [
                [name, ", ".join(spec["identity_fields"])[:44], spec["doc"][:56]]
                for name, spec in r["artifact_kinds"].items()
            ],
            ["kind", "identity fields", "description"],
        )

    _emit(registries, args.json, render)
    return 0


def _dispatch_query(project: Project, args: argparse.Namespace) -> int:
    what = args.what

    if what == "stats":
        stats = project.stats()

        def render(s: dict[str, Any]) -> None:
            print(f"project {s['project']['name']}  ({s['project']['root']})")
            for key, value in s["totals"].items():
                print(f"  {key:16s} {value}")
            print("\nartifacts by kind")
            _table(
                [[k, str(v)] for k, v in s["artifacts_by_kind"].items()],
                ["kind", "count"],
            )
            print("\nclaims by predicate")
            _table(
                [[k, str(v)] for k, v in s["claims_by_predicate"].items()],
                ["predicate", "count"],
            )

        _emit(stats, args.json, render)
        return 0

    if what == "objects":
        objects = project.objects()
        payload = [
            {
                "artifact_id": o.artifact_id,
                "path": o.data.get("path"),
                "format": o.data.get("format"),
                "arch": o.data.get("arch"),
                "size": o.data.get("size"),
                "sha256": o.data.get("sha256"),
            }
            for o in objects
        ]
        _emit(
            payload,
            args.json,
            lambda rows: _table(
                [
                    [
                        r["artifact_id"][:16],
                        str(r["path"])[:52],
                        str(r["format"]),
                        str(r["arch"] or "-"),
                        human_size(int(r["size"] or 0)),
                    ]
                    for r in rows
                ],
                ["id", "path", "format", "arch", "size"],
            ),
        )
        return 0

    if what == "artifacts":
        results = project.find_artifacts(
            kind=args.kind,
            object_id=_resolve_object_id(project, args.object),
            name_contains=args.name,
            addr=_parse_addr(args.addr),
            limit=args.limit,
        )
        payload = [
            {
                "artifact_id": a.artifact_id,
                "kind": a.kind,
                "name": sanitize_text(a.name or "", limit=70),
                "addr": hex_addr(a.addr_start),
                "data": a.data,
            }
            for a in results
        ]
        _emit(
            payload,
            args.json,
            lambda rows: _table(
                [
                    [r["artifact_id"][:16], r["kind"], r["addr"], str(r["name"])[:60]]
                    for r in rows
                ],
                ["id", "kind", "addr", "name"],
            ),
        )
        return 0

    if what == "strings":
        results = project.find_artifacts(
            kind="string",
            object_id=_resolve_object_id(project, args.object),
            name_contains=args.name,
            limit=args.limit,
        )
        payload = [
            {
                "artifact_id": a.artifact_id,
                "text": sanitize_text(str(a.data.get("text") or ""), limit=90),
                "addr": hex_addr(a.data.get("addr")),
                "section": a.data.get("section"),
                "encoding": a.data.get("encoding"),
            }
            for a in results
        ]
        _emit(
            payload,
            args.json,
            lambda rows: _table(
                [
                    [r["addr"], str(r["section"] or "-"), r["encoding"], r["text"]]
                    for r in rows
                ],
                ["addr", "section", "enc", "text"],
            ),
        )
        return 0

    if what == "claims":
        claims = project.find_claims(
            predicate=args.predicate,
            subject_id=_resolve_object_id(project, args.object),
            status=args.status,
            producer=args.producer,
            min_confidence=args.min_confidence,
            limit=args.limit,
        )
        payload = []
        for claim in claims:
            subject = (
                project.get_artifact(claim["subject_id"]) if claim["subject_id"] else None
            )
            payload.append(
                {
                    "claim_id": claim["id"],
                    "predicate": claim["predicate"],
                    "statement": claim["statement"],
                    "confidence": claim["confidence"]["combined"],
                    "producers": sorted(claim["confidence"]["per_producer"]),
                    "status": claim["status"],
                    "evidence_count": len(claim["evidence"]),
                    "subject": (subject.data.get("path") if subject else None),
                }
            )
        _emit(
            payload,
            args.json,
            lambda rows: _table(
                [
                    [
                        r["claim_id"][:16],
                        r["predicate"][:26],
                        f"{r['confidence']:.2f}",
                        str(len(r["producers"])),
                        str(r["evidence_count"]),
                        str(r["subject"] or "-")[:26],
                        json.dumps(r["statement"], sort_keys=True)[:70],
                    ]
                    for r in rows
                ],
                ["id", "predicate", "conf", "prod", "ev", "subject", "statement"],
            ),
        )
        return 0

    if what == "claim":
        claim = project.get_claim(args.id)
        if claim is None:
            raise AetherError(f"unknown claim {args.id}")
        evidence = []
        for ref in claim["evidence"]:
            artifact = project.get_artifact(ref["artifact_id"])
            evidence.append(
                {
                    "role": ref["role"],
                    "artifact_id": ref["artifact_id"],
                    "kind": artifact.kind if artifact else "MISSING",
                    "name": sanitize_text(artifact.name or "", limit=80) if artifact else "",
                    "addr": hex_addr(artifact.addr_start) if artifact else "-",
                }
            )
        payload = {
            "claim": claim,
            "evidence": evidence,
            "links": project.claim_links(claim["id"]),
        }

        def render(p: dict[str, Any]) -> None:
            c = p["claim"]
            print(f"claim   {c['id']}")
            print(f"schema  {c['schema']}")
            print(f"status  {c['status']}")
            print(f"stated  {json.dumps(c['statement'], sort_keys=True)}")
            conf = c["confidence"]
            print(
                f"conf    {conf['combined']} "
                f"(max {conf['max']} across {conf['producers']} producer(s))"
            )
            for producer, value in conf["per_producer"].items():
                print(f"          {producer:24s} {value}")
            print("\nevidence")
            _table(
                [
                    [e["role"], e["kind"], e["addr"], e["artifact_id"][:16], e["name"][:50]]
                    for e in p["evidence"]
                ],
                ["role", "kind", "addr", "artifact", "name"],
            )
            print("\nattestations")
            _table(
                [
                    [a["producer"], a["producer_kind"], f"{a['confidence']:.2f}", a["method"]]
                    for a in c["attestations"]
                ],
                ["producer", "kind", "conf", "method"],
            )
            links = p["links"]
            if links["outgoing"] or links["incoming"]:
                print("\nrelated claims")
                for link in links["outgoing"]:
                    print(f"  --{link['relation']}--> {link['claim_id']}")
                for link in links["incoming"]:
                    print(f"  <--{link['relation']}-- {link['claim_id']}")

        _emit(payload, args.json, render)
        return 0

    if what == "graph":
        payload = project.neighbors(args.id, depth=args.depth)

        def render(g: dict[str, Any]) -> None:
            print(f"graph around {g['root']}  ({len(g['nodes'])} nodes, {len(g['edges'])} edges)")
            _table(
                [
                    [
                        node_id[:16],
                        node["type"],
                        str(node.get("kind") or node.get("predicate") or ""),
                        sanitize_text(str(node.get("name") or ""), limit=48),
                    ]
                    for node_id, node in g["nodes"].items()
                ],
                ["id", "type", "kind", "name"],
            )
            print()
            _table(
                [[e["src"][:16], e["relation"], e["dst"][:16]] for e in g["edges"]],
                ["from", "relation", "to"],
            )

        _emit(payload, args.json, render)
        return 0

    if what == "runs":
        runs = project.runs(limit=args.limit)
        _emit(
            runs,
            args.json,
            lambda rows: _table(
                [
                    [
                        r["run_id"][:16],
                        r["adapter"],
                        f"{r['tool']} {r['tool_version']}",
                        r["status"],
                        r["started_at"][:19],
                    ]
                    for r in rows
                ],
                ["run", "adapter", "tool", "status", "started"],
            ),
        )
        return 0

    if what == "contradictions":
        pairs = project.contradictions(limit=args.limit)
        _emit(
            pairs,
            args.json,
            lambda rows: print(f"{len(rows)} contradicting claim pair(s)")
            if not rows
            else _table(
                [
                    [
                        p["left"]["id"][:16],
                        p["left"]["predicate"],
                        p["right"]["id"][:16],
                        p["right"]["predicate"],
                    ]
                    for p in rows
                ],
                ["left", "left predicate", "right", "right predicate"],
            ),
        )
        return 0

    raise AetherError(f"unknown query target {what!r}")


def cmd_export(args: argparse.Namespace) -> int:
    from aether.export import export_project

    project = _open_project(args, read_only=True)
    try:
        manifest = export_project(project, args.out, stable_only=args.stable)
        _emit(
            manifest,
            args.json,
            lambda m: (
                print(f"exported to {args.out}"),
                print(f"  graph digest {m['graph_digest']}"),
                _table(
                    [[name, str(f["records"]), f["digest"][:16]] for name, f in m["files"].items()],
                    ["file", "records", "digest"],
                ),
            )
            and None,
        )
        return 0
    finally:
        project.close()


def cmd_check(args: argparse.Namespace) -> int:
    project = _open_project(args, read_only=True)
    try:
        problems = project.check()
        _emit(
            problems,
            args.json,
            lambda rows: print("evidence graph is intact: no integrity problems")
            if not rows
            else _table(
                [[p["kind"], str(p.get("id", ""))[:40]] for p in rows], ["problem", "id"]
            ),
        )
        return 1 if problems else 0
    finally:
        project.close()


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report which engines are available, and what each gap costs.

    The JDK gets its own row rather than hiding behind Ghidra's. Ghidra headless
    fails on a missing or too-old runtime in a way that reads as a Ghidra
    problem, and reporting Java only once Ghidra is already installed withholds
    the information exactly when someone is still setting things up.
    """
    import textwrap

    from aether.adapters.binwalk import BinwalkAdapter
    from aether.adapters.ghidra import GhidraAdapter, probe_java
    from aether.adapters.triage import TriageAdapter

    components: dict[str, Any] = {"triage": TriageAdapter().probe().to_record()}
    components["java"] = probe_java().to_record()
    components["ghidra"] = GhidraAdapter().probe().to_record()
    components["binwalk"] = BinwalkAdapter().probe().to_record()

    def render(rows: dict[str, Any]) -> None:
        print(f"aether {AETHER_VERSION}  (python {sys.version.split()[0]}, {sys.platform})")
        print()
        for name, info in rows.items():
            mark = "ok     " if info["available"] else "MISSING"
            version = info["version"] if info["version"] != "unknown" else "-"
            header = f"  {mark}  {name:9s} {version:10s} "
            detail_lines = textwrap.wrap(info["detail"], width=80 - len(header)) or [""]
            print(header + detail_lines[0])
            for line in detail_lines[1:]:
                print(" " * len(header) + line)
            for label, text in (("cost", info.get("cost")), ("fix", info.get("remedy"))):
                if info["available"] or not text:
                    continue
                # 21 columns of indent already spent; keep the line under 80.
                wrapped = textwrap.wrap(text, width=58)
                print(f"           {label + ':':9s} {wrapped[0]}")
                for line in wrapped[1:]:
                    print(f"                     {line}")
            if not info["available"]:
                print()

        available = sum(1 for info in rows.values() if info["available"])
        print(f"{available} of {len(rows)} components available.")
        if available < len(rows):
            print(
                "Aether still runs: header triage, firmware carving, the evidence "
                "graph,\nthe MCP server, and export all work without any external "
                "engine."
            )

    _emit(components, args.json, render)
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    """Answer one of the supported questions from the evidence graph."""
    from aether.nl import ask, describe_supported

    if args.list:
        supported = describe_supported()
        _emit(
            supported,
            args.json,
            lambda rows: _table(
                [[r["id"], r["title"], r["example"]] for r in rows],
                ["id", "answers", "example"],
            ),
        )
        return 0

    if not args.question:
        raise AetherError(
            "ask what? Pass a question, or 'aether ask --list' to see what "
            "this interface answers."
        )

    project = _open_project(args)
    try:
        answer = ask(
            project, " ".join(args.question), object_reference=args.object
        )

        def render(record: dict[str, Any]) -> None:
            if record["scope"]:
                print(f"scope: {record['scope']}")
            if not record["understood"]:
                print(answer.render())
                print()
                print("This interface answers:")
                _table(
                    [[r["id"], r["title"], r["example"]] for r in record["supported"]],
                    ["id", "answers", "example"],
                )
                return
            print(
                f"[{record['question_type']}] "
                f"{len(record['claim_ids'])} claim(s) cited"
            )
            print()
            print(answer.render())

        _emit(answer.to_record(), args.json, render)
        # Declining is a correct outcome, not an error: exit 0 either way.
        return 0
    finally:
        project.close()


def cmd_mcp(args: argparse.Namespace) -> int:
    from aether.mcp.server import serve_project

    root = args.project or Project.discover()
    if not root:
        raise AetherError("no Aether project found; run 'aether init' first")
    return serve_project(root, read_only=args.read_only)


def cmd_eval(args: argparse.Namespace) -> int:
    from aether.eval import run_suites

    paths = args.suites or _default_suites()
    if not paths:
        raise AetherError("no suites given and none found under eval/suites/")
    reports, summary = run_suites(paths, base_dir=args.base_dir)

    payload = {"summary": summary, "reports": [r.to_record() for r in reports]}

    def render(p: dict[str, Any]) -> None:
        for report in p["reports"]:
            status = "PASS" if report["passed"] else "FAIL"
            totals = report["totals"]

            if report.get("kind") == "questions":
                print(f"[{status}] {report['suite']}  (question classification)")
                print(
                    f"       accuracy {totals['accuracy']:.2f}"
                    f"   macro precision {totals['macro_precision']:.2f}"
                    f"   macro recall {totals['macro_recall']:.2f}"
                    f"   over {totals['cases']} case(s)"
                )
                print(
                    f"       false accepts {totals['false_accepts']}"
                    f"   false declines {totals['false_declines']}"
                    f"   misclassified {totals['misclassified']}"
                )
                for hit in report["false_accepts"]:
                    print(
                        f"       FALSE ACCEPT  {hit['question'][:44]!r} -> "
                        f"{hit['classified_as']}"
                    )
                for miss in report["false_declines"]:
                    print(
                        f"       FALSE DECLINE {miss['question'][:44]!r} "
                        f"(expected {miss['expected']})"
                    )
                for wrong in report["misclassified"]:
                    print(
                        f"       WRONG TYPE    {wrong['question'][:44]!r} -> "
                        f"{wrong['got']}, expected {wrong['expected']}"
                    )
                print()
                continue

            print(f"[{status}] {report['suite']}  ({report['target']})")
            print(
                f"       required {totals['required_satisfied']}/{totals['required']}"
                f"   recall {totals['recall']:.2f}"
                f"   false positives {totals['forbidden_hits']}"
                f"   integrity problems {totals['integrity_problems']}"
            )
            for step in report["pipeline"]:
                if not step.get("ok"):
                    print(f"       ! pipeline step {step['step']} failed: {step.get('error')}")
            for expectation in report["expectations"]:
                if not expectation["satisfied"]:
                    flag = "MISS" if expectation["required"] else "miss"
                    print(
                        f"       {flag} {expectation['id']:36s} {expectation['detail']}"
                    )
            for hit in report["forbidden_hits"]:
                print(f"       FALSE POSITIVE {hit['id']}: {json.dumps(hit['statement'])}")
            print()

        s = p["summary"]
        print(
            f"{s['passed']}/{s['suites']} suites passed   "
            f"recall {s['recall']:.2f} over {s['required_total']} expectations   "
            f"{s['forbidden_hits']} false positive(s)"
        )
        if "question_cases" in s:
            print(
                f"question interface: accuracy {s['question_accuracy']:.2f}"
                f"   macro precision {s['question_macro_precision']:.2f}"
                f"   over {s['question_cases']} case(s)"
                f"   {s['question_false_accepts']} false accept(s)"
            )

    _emit(payload, args.json, render)
    return 0 if summary["failed"] == 0 else 1


def _default_suites() -> list[str]:
    directory = os.path.join(os.getcwd(), "eval", "suites")
    if not os.path.isdir(directory):
        return []
    return [
        os.path.join(directory, name)
        for name in sorted(os.listdir(directory))
        if name.endswith(".json")
    ]


def _resolve_object_id(project: Project, reference: str | None) -> str | None:
    if not reference:
        return None
    artifact = project.resolve_object(reference)
    if artifact is None:
        raise AetherError(f"no file in this project matches {reference!r}")
    return artifact.artifact_id


def _parse_addr(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError as exc:
        raise AetherError(f"could not parse address {value!r}") from exc


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aether",
        description=(
            "Evidence-first binary and firmware analysis. Every finding is a "
            "structured claim linked to the artifacts that support it."
        ),
    )
    parser.add_argument("--version", action="version", version=f"aether {AETHER_VERSION}")
    parser.add_argument(
        "--project",
        "-P",
        help="Project directory. Defaults to the nearest one at or above the cwd.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of tables.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init", help="Create a new project.")
    p_init.add_argument("path", nargs="?", default=".", help="Directory to create.")
    p_init.add_argument("--name", help="Project name (defaults to the directory name).")
    p_init.add_argument("--force", action="store_true", help="Reuse an existing project.")
    p_init.set_defaults(func=cmd_init)

    p_analyze = subparsers.add_parser(
        "analyze", help="Ingest and analyze a binary or firmware image."
    )
    p_analyze.add_argument("file")
    p_analyze.add_argument(
        "--engine",
        choices=["auto", "binary", "triage", "ghidra", "firmware"],
        default="auto",
        help="auto picks firmware unpacking for containers, triage+Ghidra otherwise.",
    )
    p_analyze.add_argument("--path", help="Logical path to record for this file.")
    p_analyze.add_argument("--string-limit", type=int, default=3000)
    p_analyze.add_argument("--decompile-limit", type=int, default=40)
    p_analyze.add_argument("--max-depth", type=int, default=3)
    p_analyze.set_defaults(func=cmd_analyze)

    p_import = subparsers.add_parser(
        "import-ghidra", help="Import a Ghidra export produced elsewhere."
    )
    p_import.add_argument("export_dir")
    p_import.add_argument("--object", help="Attach to a file already in the project.")
    p_import.add_argument("--target", help="Ingest this file and attach to it.")
    p_import.add_argument("--path", help="Logical path for a newly ingested target.")
    p_import.set_defaults(func=cmd_import_ghidra)

    p_query = subparsers.add_parser("query", help="Read the evidence graph.")
    query_subs = p_query.add_subparsers(dest="what", required=True)

    q_stats = query_subs.add_parser("stats", help="Counts by artifact kind and predicate.")
    q_objects = query_subs.add_parser("objects", help="Every file in the project.")

    q_artifacts = query_subs.add_parser("artifacts", help="Query artifacts.")
    q_artifacts.add_argument("--kind")
    q_artifacts.add_argument("--object")
    q_artifacts.add_argument("--name")
    q_artifacts.add_argument("--addr")
    q_artifacts.add_argument("--limit", type=int, default=50)

    q_strings = query_subs.add_parser("strings", help="Search recovered strings.")
    q_strings.add_argument("name", nargs="?", help="Substring to search for.")
    q_strings.add_argument("--object")
    q_strings.add_argument("--limit", type=int, default=50)

    q_claims = query_subs.add_parser("claims", help="Query structured claims.")
    q_claims.add_argument("--predicate")
    q_claims.add_argument("--object")
    q_claims.add_argument("--status")
    q_claims.add_argument("--producer")
    q_claims.add_argument("--min-confidence", type=float, dest="min_confidence")
    q_claims.add_argument("--limit", type=int, default=50)

    q_claim = query_subs.add_parser("claim", help="One claim, with its evidence.")
    q_claim.add_argument("id")

    q_graph = query_subs.add_parser("graph", help="Walk the graph around a node.")
    q_graph.add_argument("id")
    q_graph.add_argument("--depth", type=int, default=1)

    q_runs = query_subs.add_parser("runs", help="Provenance ledger.")
    q_runs.add_argument("--limit", type=int, default=25)

    q_contra = query_subs.add_parser("contradictions", help="Contradicting claim pairs.")
    q_contra.add_argument("--limit", type=int, default=25)

    q_schema = query_subs.add_parser(
        "schema", help="Claim predicates and artifact kinds you can use."
    )
    q_schema.add_argument("name", nargs="?", help="Describe one predicate or kind.")

    for sub in (
        q_stats,
        q_objects,
        q_artifacts,
        q_strings,
        q_claims,
        q_claim,
        q_graph,
        q_runs,
        q_contra,
        q_schema,
    ):
        sub.set_defaults(func=cmd_query)

    p_export = subparsers.add_parser("export", help="Write a Git-friendly export.")
    p_export.add_argument("out", help="Output directory.")
    p_export.add_argument(
        "--stable",
        action="store_true",
        help="Write only the deterministic graph/ tree, omitting the ledger.",
    )
    p_export.set_defaults(func=cmd_export)

    p_check = subparsers.add_parser("check", help="Verify evidence-graph integrity.")
    p_check.set_defaults(func=cmd_check)

    p_doctor = subparsers.add_parser("doctor", help="Report which engines are available.")
    p_doctor.set_defaults(func=cmd_doctor)

    p_ask = subparsers.add_parser(
        "ask",
        help="Ask one of the supported questions in plain language.",
        description=(
            "A deliberately narrow interface: five question types, matched "
            "deterministically with no language model involved. Anything "
            "outside the set is declined rather than guessed at. Every line of "
            "the answer cites the claim ids it rests on."
        ),
    )
    p_ask.add_argument("question", nargs="*", help="The question to answer.")
    p_ask.add_argument("--object", help="Restrict the answer to one file.")
    p_ask.add_argument(
        "--list", action="store_true", help="List the supported question types."
    )
    p_ask.set_defaults(func=cmd_ask)

    p_mcp = subparsers.add_parser("mcp", help="Serve the project over MCP on stdio.")
    p_mcp.add_argument(
        "--read-only", action="store_true", help="Refuse tools that write claims."
    )
    p_mcp.set_defaults(func=cmd_mcp)

    p_eval = subparsers.add_parser("eval", help="Score claims against ground truth.")
    p_eval.add_argument("suites", nargs="*", help="Suite files (default: eval/suites/*.json).")
    p_eval.add_argument("--base-dir", default=".", help="Root for paths inside suites.")
    p_eval.set_defaults(func=cmd_eval)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AetherError as exc:
        _warn(f"error: {exc}")
        return exc.exit_code
    except BrokenPipeError:  # pragma: no cover - piping into head
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        _warn("interrupted")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
