"""Disassembly engines: linear sweep and recursive descent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from ..errors import UnsupportedArchError
from .archs import create_disassembler
from .insn import Insn, from_capstone


class Disassembler:
    """Wraps a Capstone instance for a specific binary."""

    def __init__(self, arch: str, bits: int, endian: str):
        self.arch = arch
        self.bits = bits
        self.endian = endian
        self.md, self.fixed_size = create_disassembler(arch, bits, endian)

    @classmethod
    def for_binary(cls, binary) -> "Disassembler":
        return cls(binary.arch, binary.bits, binary.endian)

    # ------------------------------------------------------------------
    def disasm(self, data: bytes, va: int) -> Iterator[Insn]:
        """Yield normalized instructions for a byte buffer."""
        for ci in self.md.disasm(data, va):
            yield from_capstone(ci, self.arch)

    def disasm_one(self, data: bytes, va: int) -> Optional[Insn]:
        for ins in self.disasm(data[:64], va):
            return ins
        return None

    # ------------------------------------------------------------------
    def linear(
        self,
        data: bytes,
        va: int,
        *,
        max_insns: int = 0,
        on_error: str = "resync",
    ) -> dict[int, Insn]:
        """Linear sweep over *data*; best-effort resync after bad bytes.

        ``on_error='resync'`` skips forward (1 byte for variable-length ISAs,
        one instruction for fixed-width) when decoding fails.
        ``on_error='stop'`` aborts at the first failure.
        """
        out: dict[int, Insn] = {}
        pos = 0
        n = len(data)
        step = self.fixed_size or 1
        count = 0
        while pos < n:
            if max_insns and count >= max_insns:
                break
            addr = va + pos
            ins = self.disasm_one(data[pos:], addr)
            if ins is None or ins.size == 0 or pos + ins.size > n:
                if on_error == "stop":
                    break
                pos += step
                continue
            out[addr] = ins
            count += 1
            pos += ins.size
        return out

    # ------------------------------------------------------------------
    def recursive(
        self,
        entry: int,
        read_va: Callable[[int, int], bytes],
        in_code: Callable[[int], bool],
        *,
        max_insns: int = 200_000,
        max_jump_table: int = 1024,
    ) -> "RecursiveResult":
        """Recursive-descent disassembly starting at *entry*.

        Follows direct jumps, both arms of conditional jumps and simple
        jump tables. Calls are recorded (their targets returned in
        ``call_targets``) but not entered.
        """
        insns: dict[int, Insn] = {}
        call_targets: set[int] = set()
        data_refs: list[Insn] = []
        jump_tables: dict[int, list[int]] = {}
        work = [entry]
        seen_starts: set[int] = set()
        ptr_size = 8 if self.bits == 64 else 4

        while work and len(insns) < max_insns:
            addr = work.pop()
            if addr in seen_starts:
                continue
            seen_starts.add(addr)
            cur = addr
            while len(insns) < max_insns:
                if cur in insns:
                    break  # merge with already decoded stream
                if not in_code(cur):
                    break
                raw = read_va(cur, 64)
                if len(raw) < 1:
                    break
                ins = self.disasm_one(raw, cur)
                if ins is None or ins.size == 0:
                    break
                insns[cur] = ins
                if ins.mem_ref is not None and not ins.is_jump:
                    data_refs.append(ins)
                if ins.is_call:
                    if ins.target is not None and in_code(ins.target):
                        call_targets.add(ins.target)
                    cur += ins.size
                    continue
                if ins.is_jump:
                    if ins.is_conditional:
                        if ins.target is not None and in_code(ins.target):
                            work.append(ins.target)
                        cur += ins.size
                        continue
                    # unconditional
                    if ins.target is not None and in_code(ins.target):
                        work.append(ins.target)
                    elif ins.indirect and ins.mem_ref is not None:
                        targets = self._read_jump_table(
                            ins.mem_ref, read_va, in_code, ptr_size, max_jump_table
                        )
                        if targets:
                            jump_tables[ins.addr] = targets
                            work.extend(targets)
                    break
                if ins.is_ret or ins.is_privileged_or_trap:
                    break
                cur += ins.size

        return RecursiveResult(
            entry=entry,
            insns=insns,
            call_targets=call_targets,
            data_refs=data_refs,
            jump_tables=jump_tables,
            truncated=len(insns) >= max_insns,
        )

    def _read_jump_table(
        self,
        table_va: int,
        read_va: Callable[[int, int], bytes],
        in_code: Callable[[int], bool],
        ptr_size: int,
        max_entries: int,
    ) -> list[int]:
        """Read an absolute-address jump table (non-PIC switch tables)."""
        targets: list[int] = []
        raw = read_va(table_va, ptr_size * max_entries)
        if len(raw) < ptr_size:
            return targets
        for i in range(0, len(raw) - ptr_size + 1, ptr_size):
            val = int.from_bytes(raw[i : i + ptr_size], "little" if self.endian == "little" else "big")
            if in_code(val):
                targets.append(val)
            else:
                break
        return targets


@dataclass
class RecursiveResult:
    entry: int
    insns: dict[int, Insn]
    call_targets: set[int] = field(default_factory=set)
    data_refs: list[Insn] = field(default_factory=list)
    jump_tables: dict[int, list[int]] = field(default_factory=dict)
    truncated: bool = False
