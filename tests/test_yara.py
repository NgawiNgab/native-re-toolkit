"""Optional YARA integration tests (skipped without yara-python)."""

import pytest

from native_re_toolkit.analysis.signatures import yara_scan
from native_re_toolkit.errors import AnalysisError

yara = pytest.importorskip("yara")


RULE = """
rule HelloString {
    strings:
        $s = "Hello, %d %d"
    condition:
        $s
}
rule Sha256K {
    strings:
        $k = { 98 2f 8a 42 91 44 37 71 }
    condition:
        $k
}
"""


def test_yara_scan_fixture(hello, tmp_path):
    rules = tmp_path / "rules.yar"
    rules.write_text(RULE)
    results = yara_scan(str(hello), RULE)
    by_rule = {r["rule"]: r for r in results}
    assert "HelloString" in by_rule
    assert by_rule["HelloString"]["matches"], "expected a match offset"
    assert "Sha256K" not in by_rule  # hello has no crypto constants


def test_yara_scan_crypto(fixtures):
    results = yara_scan(str(fixtures["crypto"]), RULE)
    by_rule = {r["rule"]: r for r in results}
    assert "Sha256K" in by_rule
    m = by_rule["Sha256K"]["matches"][0]
    assert m["offset"] > 0


def test_yara_bad_rule_raises():
    with pytest.raises(Exception):
        yara_scan("/bin/true", "rule broken { condition: }")
