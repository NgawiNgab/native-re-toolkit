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

# IBT variants reproduce the Ubuntu default toolchain layout
# (-fcf-protection=full + .plt.sec): notrack jump tables, endbr64 PLT
# stubs. They exercise the same code paths that broke CI on
# ubuntu-latest while the classic fixtures cover the Debian layout.
_IBT_FLAGS = ["-fcf-protection=full", "-Wl,-z,ibtplt"]
_IBT_TARGETS = {
    "hello_ibt": ("hello.c", ["-O0", "-g0", "-fno-pie", "-no-pie",
                              "-fstack-protector-strong", *_IBT_FLAGS]),
    "hello_o2_ibt": ("hello.c", ["-O2", "-g0", "-fno-pie", "-no-pie",
                                 "-fstack-protector-strong", *_IBT_FLAGS]),
    "branchy_o2_ibt": ("branchy.c", ["-O2", "-g0", "-fno-pie", "-no-pie",
                                     *_IBT_FLAGS]),
}


def _toolchain_supports_ibtplt() -> bool:
    """Probe: older binutils rejects `-z ibtplt`; skip IBT fixtures then."""
    probe_src = FIXTURE_SRC / "hello.c"
    probe_out = FIXTURE_BUILD / ".probe_ibt"
    try:
        FIXTURE_BUILD.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            [GCC, *_IBT_FLAGS, "-o", str(probe_out), str(probe_src)],
            capture_output=True,
        )
        return r.returncode == 0
    except Exception:
        return False
    finally:
        probe_out.unlink(missing_ok=True)


def _build_all() -> dict[str, Path]:
    FIXTURE_BUILD.mkdir(parents=True, exist_ok=True)
    built: dict[str, Path] = {}
    targets = dict(_TARGETS)
    if _toolchain_supports_ibtplt():
        targets.update(_IBT_TARGETS)
    for name, (src, flags) in targets.items():
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
