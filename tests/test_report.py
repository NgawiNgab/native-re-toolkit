"""Report builder tests."""

import json

from native_re_toolkit import open_binary
from native_re_toolkit.report import build_report, report_html, report_json, report_text


def test_report_structure(hello):
    b = open_binary(str(hello))
    rep = build_report(b)
    for key in (
        "tool", "binary", "sha256", "security", "imports",
        "sections", "entropy", "functions", "strings", "xrefs",
        "signature_matches",
    ):
        assert key in rep, key
    assert rep["tool"]["name"] == "native-re-toolkit"
    assert rep["functions"]["total"] > 0
    assert rep["functions"]["from_symbols"] > 0
    assert rep["strings"]["total"] > 0
    assert rep["xrefs"]["calls"] > 0


def test_report_json_roundtrip(hello):
    b = open_binary(str(hello))
    text = report_json(build_report(b))
    doc = json.loads(text)
    assert doc["binary"]["arch"] == "x86_64"


def test_report_html(hello):
    b = open_binary(str(hello))
    page = report_html(build_report(b))
    assert "<html" in page
    assert "Functions" in page
    assert "Security features" in page
    # no unescaped braces from format() leftovers
    assert "{" + "body" + "}" not in page


def test_report_text(hello):
    b = open_binary(str(hello))
    txt = report_text(build_report(b))
    assert "format=elf" in txt
    assert "functions=" in txt


def test_report_full_disasm(hello):
    b = open_binary(str(hello))
    rep = build_report(b, with_disasm=True)
    with_code = [f for f in rep["functions"]["list"] if "disasm" in f]
    assert with_code
    first = with_code[0]["disasm"][0]
    assert {"addr", "bytes", "mnemonic", "op_str"} <= set(first)


def test_report_limits(hello):
    b = open_binary(str(hello))
    rep = build_report(b, max_strings=2)
    assert len(rep["strings"]["list"]) == 2
    assert rep["strings"]["truncated"] is True
