"""PE loader tests on a synthetic minimal PE32+."""

import pytest

from native_re_toolkit import open_binary
from tests.synth import build_min_pe


@pytest.fixture
def pe_path(tmp_path):
    p = tmp_path / "synth.exe"
    p.write_bytes(build_min_pe())
    return str(p)


@pytest.fixture
def pe_overlay_path(tmp_path):
    p = tmp_path / "synth_overlay.exe"
    p.write_bytes(build_min_pe(with_overlay=True))
    return str(p)


def test_headers(pe_path):
    b = open_binary(pe_path)
    assert b.format == "pe"
    assert b.arch == "x86_64"
    assert b.bits == 64
    assert b.image_base == 0x140000000
    assert b.entry == 0x140001000
    assert b.subsystem == "console"
    assert b.pe_type == "exe"


def test_sections(pe_path):
    b = open_binary(pe_path)
    names = {s.name for s in b.sections}
    assert names == {".text", ".rdata"}
    text = next(s for s in b.sections if s.name == ".text")
    assert text.executable
    assert text.vaddr == 0x140001000
    # code bytes present
    assert text.data[:6] == b"\xb8\x2a\x00\x00\x00\xc3"


def test_security(pe_path):
    b = open_binary(pe_path)
    assert b.security["nx_compat"] is True
    assert b.security["dynamic_base"] is True
    assert b.security["high_entropy_va"] is True


def test_overlay(pe_path, pe_overlay_path):
    b = open_binary(pe_path)
    assert b.overlay_size == 0
    b2 = open_binary(pe_overlay_path)
    assert b2.overlay_size == 104
    assert b2.overlay_offset > 0
    assert b2.overlay_offset + b2.overlay_size == b2.file_size


def test_va_roundtrip(pe_path):
    b = open_binary(pe_path)
    off = b.va_to_offset(0x140001000)
    assert off == 0x200
    assert b.offset_to_va(0x200) == 0x140001000
    assert b.read_va(0x140001000, 6) == b"\xb8\x2a\x00\x00\x00\xc3"


def test_rdata_string(pe_path):
    b = open_binary(pe_path)
    assert b.read_c_string(0x140002000) == "Hello PE"


def test_disasm_integration(pe_path):
    from native_re_toolkit.disasm.engine import Disassembler

    b = open_binary(pe_path)
    dis = Disassembler.for_binary(b)
    text = next(s for s in b.sections if s.name == ".text")
    insns = dis.linear(text.data, text.vaddr, on_error="stop")
    first = insns[text.vaddr]
    assert first.mnemonic == "mov"
    assert "0x2a" in first.op_str
