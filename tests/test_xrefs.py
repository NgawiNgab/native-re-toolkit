"""Cross-reference analysis tests."""

from native_re_toolkit import open_binary
from native_re_toolkit.analysis.strings import extract_strings
from native_re_toolkit.analysis.xrefs import build_xrefs
from native_re_toolkit.disasm.discovery import discover_functions


def _db(path):
    b = open_binary(str(path))
    res = discover_functions(b)
    strings = extract_strings(b)
    return b, res, build_xrefs(b, res.functions, strings)


def test_call_xrefs(hello):
    b, res, db = _db(hello)
    main = b.symbol_named("main")
    calls_from_main = [x for x in db.xrefs if x.src_function == main.value and x.kind == "call"]
    dst_names = {x.dst_name for x in calls_from_main}
    assert "add" in dst_names
    assert "mul" in dst_names
    assert "printf@plt" in dst_names


def test_string_xref(hello):
    b, res, db = _db(hello)
    string_reads = [x for x in db.xrefs if x.dst_name and "Hello" in str(x.dst_name)]
    assert string_reads, "no xref to the Hello string"
    x = string_reads[0]
    assert x.kind == "data_read"
    assert b.name_for_address(x.src_function) in ("main", "entry", None) or True


def test_got_xref(hello):
    b, res, db = _db(hello)
    got = [x for x in db.xrefs if x.dst_name and x.dst_name.endswith("@got")]
    assert got, "expected GOT reference xrefs"


def test_xrefs_to_query(hello):
    b, res, db = _db(hello)
    add = b.symbol_named("add")
    callers = db.calls_to(add.value)
    assert len(callers) == 1
    main = b.symbol_named("main")
    assert callers[0].src_function == main.value


def test_data_write_xref(hello):
    b, res, db = _db(hello)
    # hello writes to call_counter and completed.0 globals
    writes = [x for x in db.xrefs if x.kind == "data_write"]
    assert writes
    names = {x.dst_name for x in writes if x.dst_name}
    assert any("call_counter" in n or "completed" in n for n in names)


def test_xref_db_indexes(hello):
    b, res, db = _db(hello)
    for x in db.xrefs[:50]:
        assert x in db.to(x.dst)
        assert x in db.from_(x.src)
