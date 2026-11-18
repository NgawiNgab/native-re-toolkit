"""Signature engine tests."""

import pytest

from native_re_toolkit import open_binary
from native_re_toolkit.analysis.signatures import (
    compile_pattern,
    find_all,
    load_signatures,
    parse_pattern,
    scan_binary,
    scan_bytes,
)
from native_re_toolkit.errors import AnalysisError


def test_parse_pattern():
    values, mask = parse_pattern("48 8d ?? 24 0f")
    assert values == bytes([0x48, 0x8D, 0x00, 0x24, 0x0F])
    assert mask == bytes([0xFF, 0xFF, 0x00, 0xFF, 0xFF])


def test_parse_nibble_wildcards():
    values, mask = parse_pattern("4? ?f 0a")
    assert values == bytes([0x40, 0x0F, 0x0A])
    assert mask == bytes([0xF0, 0x0F, 0xFF])


def test_parse_errors():
    with pytest.raises(AnalysisError):
        parse_pattern("zz")
    with pytest.raises(AnalysisError):
        parse_pattern("123")
    with pytest.raises(AnalysisError):
        parse_pattern("")


def test_find_all_basic():
    sig = compile_pattern("de ad ?? ef", name="t")
    data = b"\x00\xde\xad\xbe\xef\x00\xde\xad\xcc\xef\x00\x00"
    assert find_all(data, sig) == [1, 6]


def test_find_all_no_match():
    sig = compile_pattern("01 02 03 04", name="t")
    assert find_all(b"\xff" * 64, sig) == []


def test_find_all_fully_masked():
    sig = compile_pattern("?? ??", name="t")
    hits = find_all(b"\x01\x02\x03", sig)
    assert hits == [0, 1]


def test_scan_bytes_base_va():
    sig = compile_pattern("aa bb", name="t")
    m = scan_bytes(b"\x00\x00\xaa\xbb", [sig], base_va=0x4000)
    assert m[0].va == 0x4002 and m[0].offset == 2


def test_bundled_pack_loads():
    sigs = load_signatures()
    names = {s.name for s in sigs}
    assert "sha256_k_table" in names
    assert "aes_sbox" in names
    assert "base64_alphabet" in names
    assert all(s.length >= 8 for s in sigs)


def test_scan_crypto_fixture(fixtures):
    """Every bundled signature must match its ground-truth array."""
    b = open_binary(str(fixtures["crypto"]))
    sigs = load_signatures()
    matches = scan_binary(b, sigs)
    by_name = {}
    for m in matches:
        by_name.setdefault(m.name, []).append(m)

    # ground truth: symbol addresses of the embedded tables
    expected = {
        "sha256_k_table": "sha256_k",
        "aes_sbox": "aes_sbox",
        "md5_k_table": "md5_k",
        "crc32_ieee_table": "crc32_tab",
        "chacha20_sigma": "chacha_sigma",
        "base64_alphabet": "b64_alpha",
    }
    for sig_name, sym_name in expected.items():
        sym = b.symbol_named(sym_name)
        assert sym is not None, f"fixture symbol {sym_name} missing"
        hits = by_name.get(sig_name, [])
        assert any(m.va == sym.value for m in hits), (
            f"{sig_name} not found at {sym_name} ({hex(sym.value)}); "
            f"hits: {[hex(m.va) for m in hits]}"
        )


def test_no_false_positives_on_hello(hello):
    """The hello fixture must NOT match crypto signatures."""
    b = open_binary(str(hello))
    matches = scan_binary(b, load_signatures())
    assert matches == [], f"unexpected matches: {[(m.name, hex(m.va)) for m in matches]}"


def test_custom_pack(fixtures, tmp_path):
    pack = tmp_path / "pack.json"
    pack.write_text(
        '{"version": 1, "signatures": ['
        '{"name": "hello_str", "pattern": "48 65 6c 6c 6f", "tags": ["t"]}'
        "]}"
    )
    b = open_binary(str(fixtures["hello"]))
    sigs = load_signatures(str(pack))
    assert len(sigs) == 1
    matches = scan_binary(b, sigs)
    assert len(matches) == 1
    assert matches[0].name == "hello_str"
