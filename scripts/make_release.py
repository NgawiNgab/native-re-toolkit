#!/usr/bin/env python3
"""Build release artifacts: sdist, wheel, and a self-contained nrt.pyz.

The .pyz bundles the runtime dependencies (capstone, pyelftools, pefile)
so it runs with just a Python interpreter. A NOTICE file with third-party
licenses is included in the archive.

Usage: python scripts/make_release.py
Outputs land in dist/.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

NOTICE = """\
native-re-toolkit bundles the following third-party packages:

* capstone  - BSD 3-Clause License - https://www.capstone-engine.org
              Copyright (c) 2013-, Nguyen Anh Quynh et al.
* pyelftools - public domain - https://github.com/eliben/pyelftools
* pefile    - MIT License - https://github.com/erocarrera/pefile
              Copyright (c) 2005-2024, Ero Carrera

See the respective project pages for full license texts.
"""

PYZ_MAIN = '''\
"""nrt.pyz launcher: unpack native libraries, then run the CLI."""

import hashlib
import os
import sys
import zipfile


def _ensure_native_libs():
    pyz = os.path.dirname(os.path.abspath(__file__))
    if not zipfile.is_zipfile(pyz):
        return
    with open(pyz, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()[:16]
    cache_root = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    dest = os.path.join(cache_root, "nrt", digest)
    marker = os.path.join(dest, ".ok")
    if not os.path.exists(marker):
        os.makedirs(dest, exist_ok=True)
        with zipfile.ZipFile(pyz) as zf:
            for name in zf.namelist():
                # native libraries shipped inside wheels
                if name.startswith("capstone/lib/") or name.endswith((".so", ".dll", ".dylib")):
                    zf.extract(name, dest)
        with open(marker, "w") as fh:
            fh.write("ok")
    os.environ.setdefault(
        "LIBCAPSTONE_PATH", os.path.join(dest, "capstone", "lib")
    )


_ensure_native_libs()

from native_re_toolkit.cli import main

sys.exit(main())
'''


def run(cmd: list[str], **kw) -> None:
    print("+", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, cwd=ROOT, check=True, **kw)


def main() -> int:
    DIST.mkdir(exist_ok=True)

    # 1. sdist + wheel of the library itself
    run([sys.executable, "-m", "pip", "install", "-q", "--upgrade", "build"])
    run([sys.executable, "-m", "build", "--outdir", str(DIST)])

    # 2. self-contained zipapp with runtime deps bundled
    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / "pyz"
        stage.mkdir()
        run([
            sys.executable, "-m", "pip", "install", "-q",
            "--target", str(stage),
            str(ROOT), "capstone>=5.0", "pyelftools>=0.29", "pefile>=2023.2.7",
        ])
        (stage / "NOTICE").write_text(NOTICE)
        # zipimport cannot dlopen a .so from inside the archive, so the
        # launcher extracts capstone's native lib to a cache dir and
        # points LIBCAPSTONE_PATH at it (capstone honors that env var
        # before its normal search).
        (stage / "__main__.py").write_text(PYZ_MAIN)
        # prune bytecode caches and test dirs to shrink the archive
        for junk in stage.rglob("__pycache__"):
            import shutil

            shutil.rmtree(junk, ignore_errors=True)
        out = DIST / "nrt.pyz"
        zipapp.create_archive(stage, target=out, interpreter="/usr/bin/env python3", compressed=True)
        out.chmod(0o755)
        print(f"built {out} ({out.stat().st_size / 1024:.0f} KiB)")

    print("\nartifacts in dist/:")
    for p in sorted(DIST.iterdir()):
        print(f"  {p.name}  {p.stat().st_size / 1024:.1f} KiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
