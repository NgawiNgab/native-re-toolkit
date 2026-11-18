"""Regression tests for IBT/CET binaries (-fcf-protection=full, .plt.sec).

Ubuntu's default toolchain produces these; they broke three tests in CI
(PR #1): PLT stubs moved to .plt.sec with an endbr64 entry point, and
switch dispatch became `notrack jmp [reg*8 + base]`. The insn-level
tests need no fixtures; the fixture tests skip when the local toolchain
cannot emit IBT PLTs (pre-2.31 binutils).
"""

import pytest

from native_re_toolkit import open_binary
from native_re_toolkit.disasm.discovery import discover_functions
from native_re_toolkit.disasm.engine import Disassembler


def _ibt(fixtures, name):
    path = fixtures.get(name)
    if path is None:
        pytest.skip("toolchain cannot build -fcf-protection/-z ibtplt fixtures")
    return path


# ---------------------------------------------------------------------------
# instruction level (toolchain independent)
# ---------------------------------------------------------------------------

def _fast(b: bytes, va: int = 0x4011FF):
    d = Disassembler("x86_64", 64, "little")
    return next(iter(d.disasm(b, va, count=1)))


def test_notrack_jmp_classified_as_jump():
    # notrack jmp qword ptr ds:[rdi*8 + 0x402008]  (IBT switch dispatch)
    ins = _fast(bytes.fromhex("3eff24fd08204000"))
    assert ins.mnemonic == "jmp"
    assert ins.is_jump and not ins.is_conditional
    assert ins.indirect
    assert ins.mem_ref == 0x402008  # jump table base recovered


def test_notrack_call_classified():
    ins = _fast(bytes.fromhex("3effd0"))  # notrack call rax
    assert ins.mnemonic == "call"
    assert ins.is_call and ins.indirect


def test_repz_ret_classified_as_ret():
    ins = _fast(bytes.fromhex("f3c3"))  # AMD-friendly rep ret
    assert ins.mnemonic == "ret"
    assert ins.is_ret and ins.terminates_block


def test_bnd_jmp_classified():
    ins = _fast(bytes.fromhex("f2ffe0"))  # bnd jmp rax
    assert ins.mnemonic == "jmp"
    assert ins.is_jump and ins.indirect


# ---------------------------------------------------------------------------
# fixture level (IBT toolchain layout)
# ---------------------------------------------------------------------------

def test_ibt_plt_stub_entries(fixtures):
    """plt_imports must key on the stub entry (endbr64), not the jmp."""
    b = open_binary(str(_ibt(fixtures, "hello_ibt")))
    assert b.plt_imports, "expected resolved PLT stubs"
    for stub, name in b.plt_imports.items():
        assert stub % 16 == 0, f"stub {name}@{stub:#x} not stub-aligned"
        assert b.read_va(stub, 4) == b"\xf3\x0f\x1e\xfa", (
            f"stub {name}@{stub:#x} does not start with endbr64"
        )


def test_ibt_call_xrefs(fixtures):
    """Calls through .plt.sec resolve to import names (CI failure 3)."""
    from native_re_toolkit.analysis.strings import extract_strings
    from native_re_toolkit.analysis.xrefs import build_xrefs

    b = open_binary(str(_ibt(fixtures, "hello_ibt")))
    res = discover_functions(b)
    db = build_xrefs(b, res.functions, extract_strings(b))
    main = b.symbol_named("main")
    calls = {
        x.dst_name
        for x in db.xrefs
        if x.src_function == main.value and x.kind == "call"
    }
    assert "printf@plt" in calls
    assert "add" in calls and "mul" in calls
    weird = [n for n in calls if n and "+0x" in str(n)]
    assert not weird, f"unresolved call names: {weird}"


def test_ibt_discovery_covers_symbols(fixtures):
    """__stack_chk_fail is noreturn: main must not swallow the next
    function (CI failure 2: _start missing)."""
    b = open_binary(str(_ibt(fixtures, "hello_o2_ibt")))
    res = discover_functions(b)
    truth = {s.value for s in b.function_symbols()}
    assert truth <= set(res.functions), (
        f"missing: {[hex(a) for a in truth - set(res.functions)]}"
    )


def test_ibt_switch_jump_table(fixtures):
    """`notrack jmp [reg*8 + base]` must yield jump-table edges
    (CI failure 1)."""
    b = open_binary(str(_ibt(fixtures, "branchy_o2_ibt")))
    res = discover_functions(b)
    fn = res.functions.get(b.symbol_named("dispatch").value)
    assert fn.jump_tables, "expected a jump table in the IBT -O2 switch"
    targets = next(iter(fn.jump_tables.values()))
    assert len(targets) >= 8
    assert "jump_table" in {k for _, _, k in fn.edges}


def test_plt_stub_purity(fixtures):
    """PLT stubs are `endbr64; jmp *GOT` (or `jmp *GOT; push; jmp`):
    the function must not absorb the resolver or neighbours, and the
    indirect jump through the GOT must not be read as a jump table."""
    for name in ("hello", "hello_ibt"):
        if name not in fixtures:
            continue
        b = open_binary(str(fixtures[name]))
        res = discover_functions(b)
        for stub, imp in b.plt_imports.items():
            fn = res.functions.get(stub)
            assert fn is not None, f"{name}: {imp}@plt not discovered"
            assert len(fn.insns) <= 4, (
                f"{name}: {imp}@plt has {len(fn.insns)} insns "
                "(swallowed the resolver?)"
            )
            assert not fn.jump_tables, (
                f"{name}: {imp}@plt GOT jump misread as jump table"
            )
