"""Normalized, architecture-independent instruction model."""

from __future__ import annotations

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


@dataclass
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


def from_capstone(ci: "capstone.CsInsn", arch: str) -> Insn:
    """Normalize a capstone instruction into :class:`Insn`."""
    mnemonic = ci.mnemonic.lower()
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
