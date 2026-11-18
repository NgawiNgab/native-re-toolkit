"""Binary diffing tests."""

from native_re_toolkit import open_binary
from native_re_toolkit.diff.bindiff import diff_binaries, diff_functions
from native_re_toolkit.disasm.discovery import discover_functions


def _funcs(path):
    b = open_binary(str(path))
    return discover_functions(b).functions


def test_self_diff_all_identical(fixtures):
    old = open_binary(str(fixtures["diff_v1"]))
    new = open_binary(str(fixtures["diff_v1"]))
    rep = diff_binaries(old, new)
    assert rep.added == []
    assert rep.removed == []
    assert rep.changed == []
    assert len(rep.identical) > 0


def test_version_diff(fixtures):
    old = open_binary(str(fixtures["diff_v1"]))
    new = open_binary(str(fixtures["diff_v2"]))
    rep = diff_binaries(old, new)
    s = rep.summary()

    changed_names = {p.old.name for p in rep.changed} | {p.new.name for p in rep.changed}
    added_names = {p.new.name for p in rep.added}
    removed_names = {p.old.name for p in rep.removed}

    assert "compute" in changed_names
    assert "new_feature" in added_names
    assert "legacy_func" in removed_names
    assert "helper" not in changed_names
    assert "helper" not in removed_names
    # main differs only in immediate operands -> mnemonic-identical
    assert "main" in {p.old.name for p in rep.identical}
    assert s["identical"] >= 1               # helper + libc stubs identical


def test_changed_similarity(fixtures):
    old = open_binary(str(fixtures["diff_v1"]))
    new = open_binary(str(fixtures["diff_v2"]))
    rep = diff_binaries(old, new)
    compute = next(p for p in rep.pairs if (p.old and p.old.name == "compute"))
    assert compute.status == "changed"
    assert 0.3 < compute.similarity < 0.999
    assert compute.match_method == "name"


def test_stripped_address_matching(fixtures):
    """Stripped twins have no symbols: address matching must kick in."""
    old = open_binary(str(fixtures["diff_v1_stripped"]))
    new = open_binary(str(fixtures["diff_v2_stripped"]))
    rep = diff_binaries(old, new)
    s = rep.summary()
    # both compiled with identical flags -> same layout, address match works
    assert s["matched"] > 0
    assert s["removed"] >= 1    # legacy_func gone
    assert s["added"] >= 1      # new_feature appeared
    methods = {p.match_method for p in rep.pairs if p.status != "added"}
    assert "address" in methods or "hash" in methods


def test_diff_report_serialization(fixtures):
    old = open_binary(str(fixtures["diff_v1"]))
    new = open_binary(str(fixtures["diff_v2"]))
    rep = diff_binaries(old, new)
    d = rep.to_dict()
    assert "summary" in d and "pairs" in d
    assert all("status" in p for p in d["pairs"])


def test_plt_stubs_excluded(fixtures):
    old = open_binary(str(fixtures["diff_v1"]))
    new = open_binary(str(fixtures["diff_v2"]))
    rep = diff_binaries(old, new)
    names = {
        (p.old or p.new).name
        for p in rep.pairs
        if (p.old or p.new) is not None
    }
    assert not any(n.endswith("@plt") for n in names)
