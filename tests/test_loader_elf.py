"""ELF loader tests on gcc-compiled fixtures."""

import pytest

from native_re_toolkit import open_binary


def test_basic_header(hello):
    b = open_binary(str(hello))
    assert b.format == "elf"
    assert b.arch == "x86_64"
    assert b.bits == 64
    assert b.endian == "little"
    assert b.entry != 0
    assert b.image_base == 0x400000  # -no-pie build


def test_sections(hello):
    b = open_binary(str(hello))
    names = {s.name for s in b.sections}
    assert ".text" in names
    assert ".rodata" in names
    text = next(s for s in b.sections if s.name == ".text")
    assert text.executable
    assert text.data, "section data should be populated"
    assert b.section_at(text.vaddr) is text


def test_symbols(hello):
    b = open_binary(str(hello))
    names = {s.name for s in b.symbols}
    assert "main" in names
    assert "add" in names
    assert "mul" in names
    assert "vulnerable_copy" in names
    main = b.symbol_named("main")
    assert main is not None and main.is_function and main.value != 0
    funcs = b.function_symbols()
    assert any(f.name == "add" for f in funcs)


def test_imports_and_libraries(hello):
    b = open_binary(str(hello))
    assert "libc.so.6" in b.libraries
    names = b.imported_function_names()
    assert "printf" in names
    assert "snprintf" in names
    # version suffixes stripped
    assert not any("@" in n for n in names)


def test_plt_and_got_resolution(hello):
    b = open_binary(str(hello))
    assert "printf" in b.plt_imports.values()
    assert "printf" in b.got_imports.values()
    # every PLT stub name should resolve through name_for_address
    for va, name in b.plt_imports.items():
        assert b.name_for_address(va) == f"{name}@plt"


def test_security_features(hello):
    b = open_binary(str(hello))
    sec = b.security
    assert sec["nx"] is True
    assert sec["pie"] is False
    assert sec["canary"] is True       # -fstack-protector-all
    assert sec["stripped"] is False


def test_stripped_binary(fixtures):
    b = open_binary(str(fixtures["hello_stripped"]))
    assert b.security["stripped"] is True
    assert b.function_symbols() == []
    # dynsym survives stripping: imports still visible
    assert "printf" in b.imported_function_names()


def test_pie_binary(fixtures):
    b = open_binary(str(fixtures["hello_pie"]))
    assert b.security["pie"] is True
    assert b.elf_type == "ET_DYN"


def test_va_offset_roundtrip(hello):
    b = open_binary(str(hello))
    text = next(s for s in b.sections if s.name == ".text")
    va = text.vaddr + 4
    off = b.va_to_offset(va)
    assert off == text.offset + 4
    assert b.offset_to_va(off) == va
    assert b.va_to_offset(0x10) is None  # unmapped


def test_read_va_and_c_string(hello):
    b = open_binary(str(hello))
    # entry bytes must be readable
    assert len(b.read_va(b.entry, 16)) == 16
    # find "Hello" string address via section scan
    rodata = next(s for s in b.sections if s.name == ".rodata")
    idx = rodata.data.find(b"Hello,")
    assert idx >= 0
    va = rodata.vaddr + idx
    assert b.read_c_string(va) == "Hello, %d %d\n"


def test_sha256_stable(hello):
    b = open_binary(str(hello))
    assert len(b.sha256) == 64
    assert b.sha256 == b.sha256


def test_symbol_version_stripped(hello):
    b = open_binary(str(hello))
    for s in b.symbols:
        assert "@" not in s.name


def test_describe(hello):
    b = open_binary(str(hello))
    d = b.describe()
    assert d["format"] == "elf"
    assert d["sections"] == len(b.sections)
