"""Entropy and packer-heuristic tests."""

import os

from native_re_toolkit import open_binary
from native_re_toolkit.analysis.entropy import analyze_entropy, shannon_entropy


def test_shannon_extremes():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    uniform = bytes(range(256)) * 4
    assert abs(shannon_entropy(uniform) - 8.0) < 1e-9


def test_random_is_high():
    rnd = os.urandom(4096)
    assert shannon_entropy(rnd) > 7.2


def test_fixture_entropy(hello):
    b = open_binary(str(hello))
    rep = analyze_entropy(b)
    assert not rep.packed_suspect
    assert rep.file_entropy < 7.0
    names = {s.name for s in rep.sections}
    assert ".text" in names
    text = next(s for s in rep.sections if s.name == ".text")
    assert text.verdict in ("normal", "high")


def test_packed_suspect(tmp_path):
    """A crafted ELF-like fixture: reuse hello but overwrite .text with random bytes."""
    import shutil

    b = open_binary  # noqa
    src = None
    # craft with the synthetic PE instead: overlay does not matter here.
    from tests.synth import build_min_pe

    data = bytearray(build_min_pe())
    # fill .text raw area (0x200..0x400) with random bytes
    data[0x200:0x400] = os.urandom(0x200)
    p = tmp_path / "packed.exe"
    p.write_bytes(bytes(data))
    binary = open_binary(str(p))
    rep = analyze_entropy(binary)
    text = next(s for s in rep.sections if s.name == ".text")
    assert text.entropy > 7.2
    assert rep.packed_suspect
