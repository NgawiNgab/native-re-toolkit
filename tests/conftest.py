"""Test fixtures: compile sample C binaries with gcc (skipped if missing)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE_SRC = Path(__file__).parent / "fixtures" / "src"
FIXTURE_BUILD = Path(__file__).parent / "fixtures" / "build"

GCC = shutil.which("gcc")
STRIP = shutil.which("strip")

# name -> (source, extra flags)
_TARGETS = {
    "hello": ("hello.c", ["-O0", "-g0", "-fno-pie", "-no-pie", "-fstack-protector-strong"]),
    "hello_o2": ("hello.c", ["-O2", "-g0", "-fno-pie", "-no-pie", "-fstack-protector-strong"]),
    "hello_pie": ("hello.c", ["-O2", "-g0"]),
    "branchy_o0": ("branchy.c", ["-O0", "-g0", "-fno-pie", "-no-pie"]),
    "branchy_o2": ("branchy.c", ["-O2", "-g0", "-fno-pie", "-no-pie"]),
    "crypto": ("crypto_consts.c", ["-O0", "-g0", "-fno-pie", "-no-pie"]),
    "wide": ("wide_strings.c", ["-O0", "-g0", "-fno-pie", "-no-pie"]),
    "diff_v1": ("diff_v1.c", ["-O0", "-g0", "-fno-pie", "-no-pie"]),
    "diff_v2": ("diff_v2.c", ["-O0", "-g0", "-fno-pie", "-no-pie"]),
}

_STRIPPED = ["hello", "diff_v1", "diff_v2"]


def _build_all() -> dict[str, Path]:
    FIXTURE_BUILD.mkdir(parents=True, exist_ok=True)
    built: dict[str, Path] = {}
    for name, (src, flags) in _TARGETS.items():
        out = FIXTURE_BUILD / name
        subprocess.run(
            [GCC, *flags, "-o", str(out), str(FIXTURE_SRC / src)],
            check=True,
            capture_output=True,
        )
        built[name] = out
    for name in _STRIPPED:
        out = FIXTURE_BUILD / f"{name}_stripped"
        shutil.copy2(built[name], out)
        subprocess.run([STRIP, "-s", str(out)], check=True, capture_output=True)
        built[f"{name}_stripped"] = out
    return built


@pytest.fixture(scope="session")
def fixtures() -> dict[str, Path]:
    """Compiled sample binaries. Skips when gcc/strip are unavailable."""
    if GCC is None or STRIP is None:
        pytest.skip("gcc/strip not available")
    return _build_all()


@pytest.fixture(scope="session")
def hello(fixtures) -> Path:
    return fixtures["hello"]


@pytest.fixture(scope="session")
def hello_binary(hello):
    from native_re_toolkit import open_binary

    return open_binary(str(hello))
