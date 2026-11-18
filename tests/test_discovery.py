"""Function discovery tests: symbols, heuristics, stripped binaries."""

from native_re_toolkit import open_binary
from native_re_toolkit.disasm.discovery import discover_functions


def test_discovery_covers_symbols(hello):
    b = open_binary(str(hello))
    res = discover_functions(b)
    # every symtab function in .text must be recovered
    for sym in b.function_symbols():
        assert sym.value in res.functions, f"missing function {sym.name}"
        assert res.functions[sym.value].name == sym.name


def test_discovery_plt_stubs(hello):
    b = open_binary(str(hello))
    res = discover_functions(b)
    names = {f.name for f in res.functions.values()}
    assert "printf@plt" in names


def test_discovery_entry(hello):
    b = open_binary(str(hello))
    res = discover_functions(b)
    assert b.entry in res.functions
    # named after the CRT symbol when available, else the synthetic name
    assert res.functions[b.entry].name in ("_start", "entry")


def test_stripped_recovery(fixtures):
    plain = open_binary(str(fixtures["hello"]))
    stripped = open_binary(str(fixtures["hello_stripped"]))

    # ground truth: function start addresses from the unstripped twin
    truth = {s.value for s in plain.function_symbols()}
    res = discover_functions(stripped)
    found = set(res.functions)
    recovered = truth & found
    ratio = len(recovered) / len(truth)
    assert ratio >= 0.8, (
        f"stripped recovery too low: {ratio:.2f} "
        f"(missing: {sorted(hex(a) for a in truth - found)})"
    )
    # heuristic findings must be flagged
    assert any(f.discovered for f in res.functions.values())


def test_heuristic_flag_and_naming(fixtures):
    stripped = open_binary(str(fixtures["hello_stripped"]))
    res = discover_functions(stripped)
    discovered = [f for f in res.functions.values() if f.discovered]
    assert discovered
    for f in discovered:
        assert f.name.startswith("sub_")


def test_no_heuristics_mode(fixtures):
    b = open_binary(str(fixtures["hello"]))
    res = discover_functions(b, prologue_scan=False)
    assert res.from_heuristics == 0


def test_o2_build_discovery(fixtures):
    b = open_binary(str(fixtures["hello_o2"]))
    res = discover_functions(b)
    truth = {s.value for s in b.function_symbols()}
    assert truth <= set(res.functions)


def test_discovery_is_deterministic(hello):
    b = open_binary(str(hello))
    r1 = discover_functions(b)
    r2 = discover_functions(open_binary(str(hello)))
    assert set(r1.functions) == set(r2.functions)
