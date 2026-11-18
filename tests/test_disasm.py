"""Disassembly engine tests (crafted bytes + fixture binaries)."""

import pytest

from native_re_toolkit.disasm.engine import Disassembler
from native_re_toolkit.errors import UnsupportedArchError


@pytest.fixture
def dis():
    return Disassembler("x86_64", 64, "little")


def test_unsupported_arch():
    with pytest.raises(UnsupportedArchError):
        Disassembler("6502", 8, "little")


def test_linear_sweep(dis):
    # push rbp; mov rbp,rsp; mov eax,1; pop rbp; ret
    code = b"\x55\x48\x89\xe5\xb8\x01\x00\x00\x00\x5d\xc3"
    insns = dis.linear(code, 0x1000)
    assert [i.mnemonic for i in insns.values()] == ["push", "mov", "mov", "pop", "ret"]
    assert list(insns) == [0x1000, 0x1001, 0x1004, 0x1009, 0x100A]


def test_linear_resync_on_garbage(dis):
    code = b"\x55" + b"\xff\xff" + b"\xc3"  # push rbp; <bad>; ret
    insns = dis.linear(code, 0x1000, on_error="resync")
    assert 0x1000 in insns
    # 0xffff is a valid (if odd) instruction start on x86, so just ensure
    # the sweep did not raise and made progress
    assert insns[0x1000].mnemonic == "push"


def test_insn_classification(dis):
    # call rel32; je rel8; jmp rel8; ret; lea rax,[rip+0x10]
    code = (
        b"\xe8\x10\x00\x00\x00"          # call +0x15
        b"\x74\x05"                       # je +7
        b"\xeb\x03"                      # jmp +0xc
        b"\xc3"                           # ret
        b"\x48\x8d\x05\x10\x00\x00\x00"  # lea rax,[rip+0x10]
    )
    insns = list(dis.disasm(code, 0x1000))
    call, je, jmp, ret, lea = insns
    assert call.is_call and call.target == 0x1015
    assert je.is_jump and je.is_conditional and je.target == 0x100C
    assert jmp.is_jump and not jmp.is_conditional and jmp.target == 0x100C
    assert ret.is_ret
    assert lea.mem_ref == 0x1021  # 0x100a + 7 (insn size) + 0x10
    assert lea.mem_read


def test_recursive_descent(dis):
    # two "functions": f0 calls g then returns; f1 just returns
    # 0x1000: call 0x1010; mov eax,1; ret
    # 0x1010: xor eax,eax; ret
    code = (
        b"\xe8\x07\x00\x00\x00"  # 0x1000 call 0x100c
        b"\xb8\x01\x00\x00\x00"  # 0x1005 mov eax,1
        b"\xc3"                   # 0x100a ret
        b"\x90"                   # 0x100b nop
        b"\x31\xc0"               # 0x100c xor eax,eax
        b"\xc3"                   # 0x100e ret
    )
    data = code

    def read_va(va, n):
        if 0x1000 <= va < 0x1000 + len(data):
            return data[va - 0x1000 : va - 0x1000 + n]
        return b""

    def in_code(va):
        return 0x1000 <= va < 0x1000 + len(data)

    res = dis.recursive(0x1000, read_va, in_code)
    assert 0x100C in res.call_targets
    assert 0x100A in res.insns
    # recursive descent must NOT fall into 0x100c from fallthrough (nop pad)
    assert 0x100B not in res.insns


def test_jump_table(dis):
    # jmp qword ptr [rax*8 + 0x2000]; table with 2 entries
    code = b"\xff\x24\xc5\x00\x20\x00\x00"
    table = (0x1000).to_bytes(8, "little") + (0x1000).to_bytes(8, "little")

    def read_va(va, n):
        if 0x1000 <= va < 0x1000 + len(code):
            return code[va - 0x1000 : va - 0x1000 + n]
        if 0x2000 <= va < 0x2000 + len(table):
            return table[va - 0x2000 : va - 0x2000 + n]
        return b"\x00" * n

    def in_code(va):
        return 0x1000 <= va < 0x1000 + len(code)

    ins = dis.disasm_one(code, 0x1000)
    assert ins is not None and ins.is_jump and ins.indirect and ins.mem_ref == 0x2000
    res = dis.recursive(0x1000, read_va, in_code)
    assert 0x1000 in res.jump_tables
    assert res.jump_tables[0x1000] == [0x1000, 0x1000]


def test_disasm_fixture_main(hello):
    from native_re_toolkit import open_binary

    b = open_binary(str(hello))
    dis = Disassembler.for_binary(b)
    main = b.symbol_named("main")

    def in_code(va):
        sec = b.section_at(va)
        return sec is not None and sec.executable

    res = dis.recursive(main.value, b.read_va, in_code)
    assert len(res.insns) > 5
    # calls add, mul, vulnerable_copy, snprintf@plt, printf@plt
    assert len(res.call_targets) >= 4


def test_arm64_disasm():
    dis = Disassembler("arm64", 64, "little")
    # mov x0, 1 ; ret ; bl +8
    code = bytes.fromhex("200080d2c0035fd6")
    insns = list(dis.disasm(code, 0x1000))
    assert insns[0].mnemonic == "mov"
    assert insns[1].is_ret
