"""String extraction tests."""

from native_re_toolkit import open_binary
from native_re_toolkit.analysis.strings import (
    build_string_map,
    extract_strings,
    string_covering,
)


def test_ascii_strings(hello):
    b = open_binary(str(hello))
    strings = extract_strings(b)
    values = {s.value for s in strings}
    assert "Hello, %d %d\n" in values
    assert "n=%d" in values
    assert "/lib64/ld-linux-x86-64.so.2" in values


def test_min_len(hello):
    b = open_binary(str(hello))
    s4 = extract_strings(b, min_len=4)
    s8 = extract_strings(b, min_len=8)
    assert len(s8) <= len(s4)
    assert all(len(s.value) >= 8 for s in s8)


def test_utf16le(fixtures):
    b = open_binary(str(fixtures["wide"]))
    strings = extract_strings(b, min_len=4)
    hits = [s for s in strings if s.encoding == "utf16le" and "Hello Wide" in s.value]
    assert hits, f"utf16le string not found; got {[(s.encoding, s.value) for s in strings]}"


def test_utf16be(fixtures):
    b = open_binary(str(fixtures["wide"]))
    strings = extract_strings(b, min_len=4)
    hits = [s for s in strings if s.encoding == "utf16be" and "WideBE!" in s.value]
    assert hits


def test_encoding_filter(fixtures):
    b = open_binary(str(fixtures["wide"]))
    strings = extract_strings(b, encodings=("ascii",))
    assert all(s.encoding == "ascii" for s in strings)
    assert any("plain ascii marker" in s.value for s in strings)


def test_offsets_and_va(fixtures):
    b = open_binary(str(fixtures["wide"]))
    strings = extract_strings(b)
    for s in strings:
        # file offset must map back to the same VA
        assert b.offset_to_va(s.offset) == s.va
        # and the bytes at that offset start the string
        with open(b.path, "rb") as fh:
            fh.seek(s.offset)
            raw = fh.read(8)
        if s.encoding == "ascii":
            assert raw.startswith(s.value[:8].encode("ascii"))


def test_string_covering():
    from native_re_toolkit.analysis.strings import StringRef

    strs = [StringRef(va=0x1000, offset=0, value="Hello, %d %d\n", encoding="ascii", section=".rodata")]
    assert string_covering(strs, 0x1000) is strs[0]
    assert string_covering(strs, 0x1008) is strs[0]   # interior pointer
    assert string_covering(strs, 0x2000) is None


def test_executable_excluded(hello):
    b = open_binary(str(hello))
    strings = extract_strings(b)
    assert all(s.section != ".text" for s in strings)
    strings_inc = extract_strings(b, include_executable=True)
    assert len(strings_inc) >= len(strings)
