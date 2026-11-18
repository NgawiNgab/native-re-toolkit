"""Normalized, architecture-independent instruction model.

Two construction paths:

* :func:`from_capstone_fast` - used by default: mnemonic/op_str based
  classification that works with ``Cs.detail = False`` (roughly 8x
  faster decoding). x86/x86-64 get full branch-target and memory
  reference recovery via Intel-syntax parsing; other architectures get
  branch classification with target extraction.

* :func:`from_capstone` (detail path) - operand-based classification
  used when explicit detail decoding is requested.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Optional

import capstone

# capstone generic groups
_GRP_JUMP = capstone.CS_GRP_JUMP
_GRP_CALL = capstone.CS_GRP_CALL
_GRP_RET = capstone.CS_GRP_RET
_GRP_INT = capstone.CS_GRP_INT
_GRP_IRET = capstone.CS_GRP_IRET

_X86_COND_JUMPS = {
    "jo", "jno", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jz", "je", "jne",
    "jnz", "jbe", "jna", "ja", "jnbe", "js", "jns", "jp", "jpe", "jnp",
    "jpo", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle",
    "loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz",
}
_X86_UNCOND_JUMPS = {"jmp", "ljmp"}
_X86_CALLS = {"call", "lcall"}
_X86_RETS = {"ret", "retf", "retq", "iret", "iretq", "iretd"}
_X86_NOPS = {"nop", "nopl", "nopw", "fnop", "endbr32", "endbr64", "pause", "hint"}

_ARM64_UNCOND_JUMPS = {"b", "br"}
_ARM64_COND_PREFIX = ("b.",)
_ARM64_COND_JUMPS = {"cbz", "cbnz", "tbz", "tbnz"}
_ARM64_CALLS = {"bl", "blr"}
_ARM64_RETS = {"ret", "retaa", "retab", "eret"}

# generic branch tables for architectures where we only use mnemonics
_MIPS_JUMPS = {"j", "jr", "jal", "jalr", "b", "beq", "bne", "beqz", "bnez",
               "bgtz", "blez", "bltz", "bgez", "bal", "jic", "jialc"}
_MIPS_CALLS = {"jal", "jalr", "bal", "jialc"}
_MIPS_COND = {"beq", "bne", "beqz", "bnez", "bgtz", "blez", "bgez"}
_MIPS_RETS = {"jr"}  # refined by op_str == "$ra" check is skipped; approximated
_PPC_JUMPS = {"b", "ba", "bl", "bla", "bc", "bca", "bcl", "beq", "bne",
              "bgt", "blt", "bge", "ble", "blr", "bctr", "bcctr"}
_PPC_CALLS = {"bl", "bla", "bcl"}
_PPC_COND = {"bc", "bca", "beq", "bne", "bgt", "blt", "bge", "ble"}
_PPC_RETS = {"blr"}

_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_X86_RIP_MEM_RE = re.compile(r"\[\s*rip\s*(?:(\+|-)\s*(0x[0-9a-fA-F]+))?\s*\]")
_X86_ABS_MEM_RE = re.compile(r"\[\s*(0x[0-9a-fA-F]+)\s*\]")
_X86_ANY_MEM_RE = re.compile(r"\[([^\]]*)\]")

# mnemonics whose first-operand memory access is a read, not a write
_X86_MEM_READ_OPS = {"cmp", "test", "push"}


@dataclass(slots=True)
class Insn:
    """A single disassembled instruction with normalized semantics."""

    addr: int
    size: int
    mnemonic: str
    op_str: str
    data: bytes
    is_call: bool = False
    is_jump: bool = False
    is_conditional: bool = False
    is_ret: bool = False
    is_nop: bool = False
    is_privileged_or_trap: bool = False
    target: Optional[int] = None      # direct branch/call target
    mem_ref: Optional[int] = None     # absolute address referenced (RIP-relative etc.)
    mem_write: bool = False
    mem_read: bool = False
    indirect: bool = False            # indirect branch/call (register or memory)
    imms: tuple = ()                  # immediate operand values (non-branch insns)

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def is_branch(self) -> bool:
        return self.is_call or self.is_jump or self.is_ret

    @property
    def terminates_block(self) -> bool:
        """True when execution cannot fall through past this instruction."""
        return self.is_ret or (self.is_jump and not self.is_conditional) or self.is_privileged_or_trap

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.addr:#x}: {self.mnemonic} {self.op_str}".rstrip()


# ----------------------------------------------------------------------
# fast path (detail=False)
# ----------------------------------------------------------------------
def from_capstone_fast(ci: "capstone.CsInsn", arch: str) -> Insn:
    """Build an :class:`Insn` from a capstone instruction decoded with
    ``detail=False`` using mnemonic tables and op_str parsing."""
    mnemonic = sys.intern(ci.mnemonic.lower())
    op_str = ci.op_str
    ins = Insn(
        addr=ci.address,
        size=ci.size,
        mnemonic=mnemonic,
        op_str=op_str,
        data=bytes(ci.bytes),
    )
    if arch in ("x86", "x86_64"):
        _fast_x86(ins, mnemonic, op_str)
    elif arch == "arm64":
        _fast_arm64(ins, mnemonic, op_str)
    elif arch.startswith("mips"):
        _fast_generic(ins, mnemonic, op_str, _MIPS_JUMPS, _MIPS_CALLS, _MIPS_COND, _MIPS_RETS)
    elif arch.startswith("ppc"):
        _fast_generic(ins, mnemonic, op_str, _PPC_JUMPS, _PPC_CALLS, _PPC_COND, _PPC_RETS)
    else:
        _fast_generic(ins, mnemonic, op_str, set(), set(), set(), set())
    return ins


def _parse_branch_target(op_str: str) -> Optional[int]:
    """A plain hex operand means a direct branch target."""
    text = op_str.strip().lstrip("#")
    if _HEX_RE.fullmatch(text):
        return int(text, 16) & 0xFFFFFFFFFFFFFFFF
    return None


def _fast_x86(ins: Insn, mnemonic: str, op_str: str) -> None:
    ins.is_call = mnemonic in _X86_CALLS
    ins.is_jump = mnemonic in _X86_UNCOND_JUMPS or mnemonic in _X86_COND_JUMPS
    ins.is_conditional = mnemonic in _X86_COND_JUMPS
    ins.is_ret = mnemonic in _X86_RETS
    ins.is_nop = mnemonic in _X86_NOPS
    ins.is_privileged_or_trap = mnemonic in {"ud2", "int3", "hlt"} or mnemonic.startswith("int")

    if ins.is_call or ins.is_jump:
        tgt = _parse_branch_target(op_str)
        if tgt is not None:
            ins.target = tgt
            return
        ins.indirect = True
        # indirect through memory: [rip+x] thunk or jump table [r*N + disp]
        m = _X86_ANY_MEM_RE.search(op_str)
        if m:
            inner = m.group(1)
            rip_m = _X86_RIP_MEM_RE.search(op_str)
            if rip_m:
                disp = int(rip_m.group(2), 16) if rip_m.group(2) else 0
                if rip_m.group(1) == "-":
                    disp = -disp
                ins.mem_ref = (ins.addr + ins.size + disp) & 0xFFFFFFFFFFFFFFFF
            elif "*" in inner:
                hexes = _HEX_RE.findall(inner)
                if hexes:
                    ins.mem_ref = int(hexes[-1], 16)  # jump table base
            else:
                abs_m = _X86_ABS_MEM_RE.search(op_str)
                if abs_m:
                    ins.mem_ref = int(abs_m.group(1), 16)
        return

    # non-branch: memory references and immediates
    if "[" in op_str and "fs:" not in op_str and "gs:" not in op_str:
        rip_m = _X86_RIP_MEM_RE.search(op_str)
        abs_m = None if rip_m else _X86_ABS_MEM_RE.search(op_str)
        if rip_m:
            disp = int(rip_m.group(2), 16) if rip_m.group(2) else 0
            if rip_m.group(1) == "-":
                disp = -disp
            ins.mem_ref = (ins.addr + ins.size + disp) & 0xFFFFFFFFFFFFFFFF
        elif abs_m:
            ins.mem_ref = int(abs_m.group(1), 16)
        if ins.mem_ref is not None:
            head = op_str.split(",", 1)[0]
            if "[" in head and mnemonic not in _X86_MEM_READ_OPS:
                ins.mem_write = True
            else:
                ins.mem_read = True
    if ins.mem_ref is None:
        hexes = _HEX_RE.findall(op_str)
        if hexes:
            ins.imms = tuple(int(h, 16) for h in hexes)


def _fast_arm64(ins: Insn, mnemonic: str, op_str: str) -> None:
    ins.is_call = mnemonic in _ARM64_CALLS
    ins.is_ret = mnemonic in _ARM64_RETS
    ins.is_jump = (
        mnemonic in _ARM64_UNCOND_JUMPS
        or mnemonic in _ARM64_COND_JUMPS
        or mnemonic.startswith(_ARM64_COND_PREFIX)
    )
    ins.is_conditional = (
        mnemonic in _ARM64_COND_JUMPS or mnemonic.startswith(_ARM64_COND_PREFIX)
    )
    ins.is_nop = mnemonic in {"nop", "hint"}
    ins.indirect = mnemonic in {"br", "blr"}
    if (ins.is_call or ins.is_jump) and not ins.indirect:
        hexes = _HEX_RE.findall(op_str)
        if hexes:
            ins.target = int(hexes[-1], 16) & 0xFFFFFFFFFFFFFFFF


def _fast_generic(ins, mnemonic, op_str, jumps, calls, conds, rets) -> None:
    ins.is_call = mnemonic in calls
    ins.is_jump = mnemonic in jumps
    ins.is_conditional = mnemonic in conds
    ins.is_ret = mnemonic in rets
    ins.is_nop = mnemonic in {"nop"}
    if (ins.is_call or ins.is_jump) and not ins.is_conditional:
        hexes = _HEX_RE.findall(op_str)
        if hexes:
            ins.target = int(hexes[-1], 16)
        elif "[" in op_str or op_str.strip().startswith("$"):
            ins.indirect = True
    elif ins.is_conditional:
        hexes = _HEX_RE.findall(op_str)
        if hexes:
            ins.target = int(hexes[-1], 16)


# ----------------------------------------------------------------------
# detail path (Cs.detail = True)
# ----------------------------------------------------------------------
def from_capstone(ci: "capstone.CsInsn", arch: str) -> Insn:
    """Normalize a capstone instruction into :class:`Insn` (detail mode)."""
    mnemonic = sys.intern(ci.mnemonic.lower())
    ins = Insn(
        addr=ci.address,
        size=ci.size,
        mnemonic=mnemonic,
        op_str=ci.op_str,
        data=bytes(ci.bytes),
    )
    groups = set(ci.groups) if hasattr(ci, "groups") else set()

    if arch in ("x86", "x86_64"):
        _classify_x86(ci, ins, groups, mnemonic)
    elif arch == "arm64":
        _classify_arm64(ci, ins, groups, mnemonic)
    else:
        _classify_generic(ci, ins, groups, mnemonic)
    return ins


def _classify_x86(ci, ins: Insn, groups: set, mnemonic: str) -> None:
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

    ins.is_call = mnemonic in _X86_CALLS or _GRP_CALL in groups
    ins.is_jump = mnemonic in _X86_UNCOND_JUMPS or mnemonic in _X86_COND_JUMPS or _GRP_JUMP in groups
    ins.is_conditional = mnemonic in _X86_COND_JUMPS
    ins.is_ret = mnemonic in _X86_RETS or _GRP_RET in groups or _GRP_IRET in groups
    ins.is_nop = mnemonic in _X86_NOPS
    ins.is_privileged_or_trap = mnemonic in {"ud2", "int3", "hlt"} or _GRP_INT in groups

    ops = getattr(ci, "operands", [])
    if ins.is_call or ins.is_jump:
        if ops:
            op = ops[0]
            if op.type == X86_OP_IMM:
                ins.target = op.imm & 0xFFFFFFFFFFFFFFFF
            else:
                ins.indirect = True
    # memory operands: RIP-relative -> absolute reference
    for i, op in enumerate(ops):
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            ins.mem_ref = (ci.address + ci.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
            ins.mem_write = _x86_op_is_write(ci, i)
            ins.mem_read = not ins.mem_write
        elif op.type == X86_OP_MEM and op.mem.index and not op.mem.base and ins.is_jump:
            # jump table: jmp [index*scale + disp]
            ins.mem_ref = op.mem.disp & 0xFFFFFFFFFFFFFFFF
            ins.indirect = True
        elif op.type == X86_OP_MEM and not op.mem.base and not op.mem.index and op.mem.disp:
            # absolute memory reference [disp] (non-PIE addressing)
            ins.mem_ref = op.mem.disp & 0xFFFFFFFFFFFFFFFF
            ins.mem_write = _x86_op_is_write(ci, i)
            ins.mem_read = not ins.mem_write
    if not ins.is_branch:
        ins.imms = tuple(
            op.imm & 0xFFFFFFFFFFFFFFFF
            for op in ops
            if op.type == X86_OP_IMM
        )


def _x86_op_is_write(ci, idx: int) -> bool:
    op = ci.operands[idx]
    access = getattr(op, "access", 0)
    return bool(access & capstone.CS_AC_WRITE)


def _classify_arm64(ci, ins: Insn, groups: set, mnemonic: str) -> None:
    from capstone.arm64_const import ARM64_OP_IMM

    ins.is_call = mnemonic in _ARM64_CALLS or _GRP_CALL in groups
    ins.is_ret = mnemonic in _ARM64_RETS or _GRP_RET in groups
    ins.is_jump = (
        mnemonic in _ARM64_UNCOND_JUMPS
        or mnemonic in _ARM64_COND_JUMPS
        or mnemonic.startswith(_ARM64_COND_PREFIX)
        or _GRP_JUMP in groups
    )
    ins.is_conditional = (
        mnemonic in _ARM64_COND_JUMPS or mnemonic.startswith(_ARM64_COND_PREFIX)
    )
    ins.is_nop = mnemonic in {"nop", "hint"}
    ins.indirect = mnemonic in {"br", "blr"}
    ops = getattr(ci, "operands", [])
    if (ins.is_call or ins.is_jump) and ops:
        op = ops[0]
        if op.type == ARM64_OP_IMM:
            ins.target = op.imm & 0xFFFFFFFFFFFFFFFF


def _classify_generic(ci, ins: Insn, groups: set, mnemonic: str) -> None:
    ins.is_call = _GRP_CALL in groups
    ins.is_jump = _GRP_JUMP in groups
    ins.is_ret = _GRP_RET in groups
    ins.is_nop = mnemonic == "nop"
    ops = getattr(ci, "operands", [])
    if (ins.is_call or ins.is_jump) and ops:
        op = ops[0]
        if getattr(op, "type", 0) == 2:  # CS_OP_IMM for most archs
            ins.target = getattr(op, "imm", None)
        else:
            ins.indirect = True
