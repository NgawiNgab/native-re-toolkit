"""Mach-O loader tests on a synthetic minimal 64-bit binary."""

import pytest

from native_re_toolkit import open_binary
from tests.synth import build_min_macho


@pytest.fixture
def macho_path(tmp_path):
    p = tmp_path / "synth_macho"
    p.write_bytes(build_min_macho())
    return str(p)


def test_headers(macho_path):
    b = open_binary(macho_path)
    assert b.format == "macho"
    assert b.arch == "x86_64"
    assert b.bits == 64
    assert b.endian == "little"


def test_sections(macho_path):
    b = open_binary(macho_path)
    assert len(b.sections) == 1
    sec = b.sections[0]
    assert sec.name == "__text"
    assert sec.executable
    assert sec.data == b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3"
    assert b.section_at(sec.vaddr) is sec


def test_image_base(macho_path):
    b = open_binary(macho_path)
    assert b.image_base == 0x100000000
