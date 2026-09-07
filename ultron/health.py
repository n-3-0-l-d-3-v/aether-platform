"""Machine-readable health status, for a future ecosystem health agent to poll.

Deliberately separate from ``ultron doctor``: doctor is human-facing prose
with wrapped remedy text tuned to a terminal width (see its docstring in
``ultron/cli.py``); a polling agent wants a small, stable JSON shape it can
diff run over run without doctor's wording changing underneath it. Both sit
over the same adapter ``probe()`` calls, they just render differently.

Health collection never runs the test suite itself - that would make
``ultron --health`` slow and, worse, recursive when a health agent's own
poll interval is short. It instead reports the most recent *cached* pytest
outcome, from pytest's own ``.pytest_cache``, and says ``"unknown"`` when
there is none - an honest gap rather than a guess.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any

from ultron.version import ULTRON_VERSION


def collect_health(project_root: str | None = None) -> dict[str, Any]:
    from ultron.adapters.binwalk import BinwalkAdapter
    from ultron.adapters.ghidra import GhidraAdapter
    from ultron.project.store import Project

    ghidra = GhidraAdapter().probe()
    binwalk = BinwalkAdapter().probe()

    last_run_at = _last_run_at(project_root)

    return {
        "name": "Ultron",
        "version": ULTRON_VERSION,
        "status": "ok",
        "backends": {
            "ghidra": {"available": ghidra.available, "detail": ghidra.detail},
            "binwalk": {"available": binwalk.available, "detail": binwalk.detail},
        },
        "last_run_at": last_run_at,
        "test_suite_status": _test_suite_status(),
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def _last_run_at(project_root: str | None) -> str | None:
    from ultron.project.store import Project

    root = project_root or Project.discover()
    if not root:
        return None
    try:
        project = Project.open(root, read_only=True)
    except Exception:
        return None
    try:
        runs = project.runs(limit=1)
        return runs[0]["started_at"] if runs else None
    except Exception:
        return None
    finally:
        project.close()


def _test_suite_status() -> str:
    path = os.path.join(".pytest_cache", "v", "cache", "lastfailed")
    if not os.path.isfile(path):
        return "unknown"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return "unknown"
    return "passing" if not data else "failing"


__all__ = ["collect_health"]
