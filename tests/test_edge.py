"""Edge cases, error paths, and PIE coverage."""

import json

import pytest

from native_re_toolkit import FormatError, open_binary
from native_re_toolkit.cli import main
from native_re_toolkit.disasm.engine import Disassembler
from native_re_toolkit.errors import UnsupportedArchError
from native_re_toolkit.util import hexdump, human_size


def test_open_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    with pytest.raises(FormatError):
        open_binary(str(p))


def test_open_text_file(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("hello world, not a binary\n")
    with pytest.raises(FormatError):
        open_binary(str(p))


def test_open_missing_file():
    with pytest.raises((FileNotFoundError, OSError)):
        open_binary("/nonexistent/path/to/binary")


def test_unsupported_arch():
    with pytest.raises(UnsupportedArchError):
        from native_re_toolkit.disasm.engine import Disassembler

        Disassembler("m68k", 32, "big")


def test_hexdump_format():
    out = hexdump(b"\x00\x01ABC" + b"\xff" * 11, base=0x1000)
    line = out.splitlines()[0]
    assert line.startswith("00001000")
    assert "|" in line
    assert "ABC" in line


def test_human_size():
    assert human_size(512) == "512 B"
    assert human_size(2048) == "2.0 KiB"
    assert human_size(5 * 1024 * 1024) == "5.0 MiB"


def test_pie_rip_relative_string_xrefs(fixtures):
    """PIE binaries use RIP-relative lea; string xrefs must resolve."""
    from native_re_toolkit.analysis.strings import extract_strings
    from native_re_toolkit.analysis.xrefs import build_xrefs
    from native_re_toolkit.disasm.discovery import discover_functions

    b = open_binary(str(fixtures["hello_pie"]))
    assert b.security["pie"] is True
    res = discover_functions(b)
    strings = extract_strings(b)
    db = build_xrefs(b, res.functions, strings)
    named = [x for x in db.xrefs if x.dst_name and "Hello" in str(x.dst_name)]
    assert named, "no RIP-relative string xref in PIE binary"


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_cli_sections_json(hello, capsys):
    rc = main(["sections", str(hello), "--json"])
    rows = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert any(r["name"] == ".text" for r in rows)


def test_cli_bad_symbol(hello, capsys):
    rc = main(["disasm", str(hello), "nonexistent_function_xyz"])
    assert rc == 1
    assert "cannot resolve" in capsys.readouterr().err


def test_binary_describe_keys(hello):
    b = open_binary(str(hello))
    d = b.describe()
    for key in ("path", "format", "arch", "bits", "endian", "entry",
                "image_base", "file_size", "sections", "symbols",
                "imports", "exports"):
        assert key in d


def test_entry_seed_in_stripped(fixtures):
    """Stripped binaries keep the entry point; discovery must use it."""
    from native_re_toolkit.disasm.discovery import discover_functions

    b = open_binary(str(fixtures["hello_stripped"]))
    res = discover_functions(b)
    assert b.entry in res.functions
