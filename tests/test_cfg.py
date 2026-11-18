"""CFG construction tests."""

from native_re_toolkit import open_binary
from native_re_toolkit.disasm.cfg import build_function
from native_re_toolkit.disasm.engine import Disassembler


def _fn(binary_path, name):
    b = open_binary(str(binary_path))
    dis = Disassembler.for_binary(b)

    def in_code(va):
        sec = b.section_at(va)
        return sec is not None and sec.executable

    sym = b.symbol_named(name)
    assert sym is not None, f"symbol {name} missing"
    return b, build_function(dis, b.read_va, in_code, sym.value, name)


def test_single_block_function(fixtures):
    _, fn = _fn(fixtures["hello"], "add")
    assert fn.num_blocks >= 1
    # add() has no branches at -O0 -> exactly one block, one exit
    assert fn.num_blocks == 1
    assert fn.edges == []
    last = fn.blocks[fn.start].insns[-1]
    assert last.is_ret


def test_ifelse_cfg(fixtures):
    _, fn = _fn(fixtures["branchy_o0"], "classify")
    assert fn.num_blocks >= 4  # entry, then/elif/else arms, return merge
    kinds = {k for _, _, k in fn.edges}
    assert "cond_true" in kinds
    assert "cond_false" in kinds


def test_loop_backedge(fixtures):
    _, fn = _fn(fixtures["branchy_o0"], "sum_to")
    # a loop must have at least one edge going backwards
    backedges = [(s, d) for s, d, _ in fn.edges if d <= s]
    assert backedges, "expected a loop back-edge"


def test_switch_jump_table(fixtures):
    _, fn = _fn(fixtures["branchy_o2"], "dispatch")
    assert fn.jump_tables, "expected a jump table in -O2 switch"
    targets = next(iter(fn.jump_tables.values()))
    assert len(targets) >= 8  # 8 cases
    kinds = {k for _, _, k in fn.edges}
    assert "jump_table" in kinds


def test_recursion_call(fixtures):
    b, fn = _fn(fixtures["branchy_o0"], "fib")
    # fib calls itself
    assert fn.start in fn.calls


def test_dot_output(fixtures):
    _, fn = _fn(fixtures["branchy_o0"], "classify")
    dot = fn.to_dot()
    assert dot.startswith("digraph")
    assert "->" in dot
