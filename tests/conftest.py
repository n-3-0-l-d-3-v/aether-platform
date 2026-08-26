"""Shared fixtures.

Sample binaries are *generated*, not committed, so the tests build them on
demand. That keeps the repository free of opaque binary blobs and means the
ground truth in eval/suites is checkable against a generator anyone can read.
"""

from __future__ import annotations

import os
import runpy
import subprocess
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO_ROOT)

EXAMPLES = os.path.join(REPO_ROOT, "examples")
ELF_SAMPLE = os.path.join(EXAMPLES, "firmware_agent.elf")
PE_SAMPLE = os.path.join(EXAMPLES, "vulnerable_demo.exe")
FIRMWARE_SAMPLE = os.path.join(EXAMPLES, "demo_firmware.bin")
GHIDRA_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "ghidra", "firmware_agent")


def _run_generator(script: str, *args: str) -> None:
    argv = [os.path.join(EXAMPLES, "src", script), *args]
    saved = sys.argv
    sys.argv = argv
    try:
        runpy.run_path(argv[0], run_name="__main__")
    except SystemExit as exc:
        if exc.code not in (0, None):
            raise
    finally:
        sys.argv = saved


@pytest.fixture(scope="session")
def elf_sample() -> str:
    """A structurally valid ELF64 with known strings, imports, and flags."""
    if not os.path.isfile(ELF_SAMPLE):
        _run_generator("build_elf_sample.py", ELF_SAMPLE)
    return ELF_SAMPLE


@pytest.fixture(scope="session")
def pe_sample() -> str:
    """A real PE, compiled locally. Skipped where no compiler is available."""
    if not os.path.isfile(PE_SAMPLE):
        source = os.path.join(EXAMPLES, "src", "vulnerable_demo.c")
        compiler = None
        for candidate in ("gcc", "x86_64-w64-mingw32-gcc", "clang", "cc"):
            from shutil import which

            if which(candidate):
                compiler = candidate
                break
        if compiler is None:
            pytest.skip("no C compiler available to build the PE sample")
        subprocess.run(
            [compiler, "-O0", "-g0", "-o", PE_SAMPLE, source], check=True, timeout=180
        )
    return PE_SAMPLE


@pytest.fixture(scope="session")
def firmware_sample(elf_sample: str) -> str:
    """A uImage header, padding, and a gzipped cpio filesystem."""
    if not os.path.isfile(FIRMWARE_SAMPLE):
        _run_generator("build_firmware_sample.py", FIRMWARE_SAMPLE)
    return FIRMWARE_SAMPLE


@pytest.fixture(scope="session")
def ghidra_export_dir(elf_sample: str) -> str:
    """A recorded Ghidra export consistent with the ELF sample's real bytes."""
    if not os.path.isfile(os.path.join(GHIDRA_FIXTURE, "meta.json")):
        script = os.path.join(REPO_ROOT, "tests", "fixtures", "make_ghidra_fixture.py")
        saved = sys.argv
        sys.argv = [script]
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise
        finally:
            sys.argv = saved
    return GHIDRA_FIXTURE


@pytest.fixture()
def project(tmp_path):
    """An empty project in a temporary directory."""
    from aether.project import Project

    instance = Project.create(str(tmp_path / "proj"), "test")
    yield instance
    instance.close()


@pytest.fixture()
def triaged_elf(project, elf_sample):
    """A project with the ELF sample triaged, and its file artifact id."""
    from aether.adapters.triage import TriageAdapter

    result = TriageAdapter().analyze(
        project, elf_sample, logical_path="bin/firmware_agent"
    )
    return project, result.objects[0]
