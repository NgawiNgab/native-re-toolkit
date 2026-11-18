"""Disassembly engines: linear sweep and recursive descent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from ..errors import UnsupportedArchError
from .archs import create_disassembler
from .insn import Insn, from_capstone, from_capstone_fast

# libc/CRT functions that never return; a call to one ends the block.
NORETURN_NAMES = frozenset({
    "exit", "_exit", "_Exit", "exit_group", "abort", "__stack_chk_fail",
    "__assert_fail", "panic", "err", "errx", "verr", "verrx",
    "ExitProcess", "pthread_exit", "__cxa_throw", "longjmp", "siglongjmp",
    "__longjmp", "_longjmp", "quick_exit", "_tcgetattr__noreturn",
})


class _StreamDecoder:
    """Decodes forward with one long-lived capstone generator.

    Creating a ``Cs.disasm`` generator per instruction is the dominant
    cost of recursive descent; streaming decodes whole chunks and only
    restarts the generator on seeks (branch targets) or chunk ends.
    """

    def __init__(self, dis: "Disassembler", read_va, chunk: int = 4096):
        self.dis = dis
        self.read_va = read_va
        self.chunk = chunk
        self._gen = None
        self._next_va: int = -1

    def at(self, va: int) -> Optional[Insn]:
        for _ in range(2):
            if self._gen is None or self._next_va != va:
                raw = self.read_va(va, self.chunk)
                if not raw:
                    self._gen = None
                    return None
                self._gen = self.dis.disasm(raw, va)
            try:
                ins = next(self._gen)
            except StopIteration:
                self._gen = None
                continue  # chunk end or bad byte: restart once at va
            self._next_va = ins.addr + ins.size
            return ins
        return None


class Disassembler:
    """Wraps a Capstone instance for a specific binary."""

    def __init__(self, arch: str, bits: int, endian: str):
        self.arch = arch
        self.bits = bits
        self.endian = endian
        self.md, self.fixed_size = create_disassembler(arch, bits, endian)
        # fast path: no operand detail (~8x cheaper per instruction)
        self.md.detail = False
        self._md_detail = None

    @property
    def md_detail(self):
        """Lazily created detail-mode decoder for operand inspection."""
        if self._md_detail is None:
            self._md_detail, _ = create_disassembler(self.arch, self.bits, self.endian)
            self._md_detail.detail = True
        return self._md_detail

    @classmethod
    def for_binary(cls, binary) -> "Disassembler":
        return cls(binary.arch, binary.bits, binary.endian)

    # ------------------------------------------------------------------
    def disasm(self, data: bytes, va: int, detail: bool = False, count: int = 0) -> Iterator[Insn]:
        """Yield normalized instructions for a byte buffer.

        ``detail=False`` (default) uses the fast mnemonic/op_str path;
        ``detail=True`` enables full capstone operand analysis.
        ``count`` caps the number of instructions per C decode round
        (bounds peak memory on huge buffers).
        """
        if detail:
            for ci in self.md_detail.disasm(data, va, count=count):
                yield from_capstone(ci, self.arch)
        else:
            for ci in self.md.disasm(data, va, count=count):
                yield from_capstone_fast(ci, self.arch)

    def disasm_one(self, data: bytes, va: int, detail: bool = False) -> Optional[Insn]:
        for ins in self.disasm(data[:64], va, detail=detail):
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

    def build_pool(self, data: bytes, va: int) -> dict[int, Insn]:
        """Decode a whole section once into an address -> Insn pool.

        Uses one streaming capstone call (fast path) instead of a
        generator per instruction. Note the variable-length-ISA caveat:
        bytes that are actually inline data decode into garbage insns;
        those simply stay unreachable during CFG walks.
        """
        pool: dict[int, Insn] = {}
        n = len(data)
        step = self.fixed_size or 1
        pos = 0
        # decode in count-capped rounds so the transient C-side instruction
        # array stays bounded (a full multi-MB decode would allocate it
        # eagerly and dominate peak RSS)
        round_insns = 16384
        while pos < n:
            stop = pos
            for ins in self.disasm(data[pos:], va + pos, count=round_insns):
                pool[ins.addr] = ins
                stop = ins.addr - va + ins.size
            if stop == pos:
                stop = pos + step  # undecodable bytes: skip and resync
            pos = stop
        return pool

    # ------------------------------------------------------------------
    def recursive(
        self,
        entry: int,
        read_va: Callable[[int, int], bytes],
        in_code: Callable[[int], bool],
        *,
        max_insns: int = 200_000,
        max_jump_table: int = 1024,
        is_noreturn: Optional[Callable[[int], bool]] = None,
        pool: Optional[dict[int, Insn]] = None,
        table_ok: Optional[Callable[[int], bool]] = None,
    ) -> "RecursiveResult":
        """Recursive-descent disassembly starting at *entry*.

        Follows direct jumps, both arms of conditional jumps and simple
        jump tables. Calls are recorded (their targets returned in
        ``call_targets``) but not entered.

        When *pool* (an address -> Insn map covering the executable
        sections, e.g. from :meth:`build_pool`) is given, instructions
        are looked up there instead of decoding on the fly.

        *table_ok* optionally vetoes jump-table base addresses (e.g. to
        require a non-writable section); without it any address with two
        or more in-code pointers is accepted.
        """
        insns: dict[int, Insn] = {}
        call_targets: set[int] = set()
        data_refs: list[Insn] = []
        jump_tables: dict[int, list[int]] = {}
        noreturn_calls: set[int] = set()
        work = [entry]
        seen_starts: set[int] = set()
        ptr_size = 8 if self.bits == 64 else 4
        if pool is not None:
            def at(va: int) -> Optional[Insn]:
                return pool.get(va)
        else:
            decoder = _StreamDecoder(self, read_va)
            at = decoder.at

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
                ins = at(cur)
                if ins is None or ins.size == 0:
                    break
                insns[cur] = ins
                if ins.mem_ref is not None and not ins.is_jump:
                    data_refs.append(ins)
                if ins.is_call:
                    if ins.target is not None and in_code(ins.target):
                        call_targets.add(ins.target)
                    if (
                        ins.target is not None
                        and is_noreturn is not None
                        and is_noreturn(ins.target)
                    ):
                        # calls to exit()/abort()/__stack_chk_fail() do not
                        # fall through; continuing here would swallow the
                        # next function's bytes.
                        noreturn_calls.add(ins.addr)
                        break
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
                            ins.mem_ref, read_va, in_code, ptr_size, max_jump_table,
                            table_ok,
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
            noreturn_calls=noreturn_calls,
            truncated=len(insns) >= max_insns,
        )

    def _read_jump_table(
        self,
        table_va: int,
        read_va: Callable[[int, int], bytes],
        in_code: Callable[[int], bool],
        ptr_size: int,
        max_entries: int,
        table_ok: Optional[Callable[[int], bool]] = None,
    ) -> list[int]:
        """Read an absolute-address jump table (non-PIC switch tables).

        A lone in-code pointer is *not* a table -- it is a PLT stub or
        an indirect thunk through a GOT slot / function pointer -- so at
        least two consecutive entries are required.
        """
        if table_ok is not None and not table_ok(table_va):
            return []
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
        if len(targets) < 2:
            return []
        return targets


@dataclass(slots=True)
class RecursiveResult:
    entry: int
    insns: dict[int, Insn]
    call_targets: set[int] = field(default_factory=set)
    data_refs: list[Insn] = field(default_factory=list)
    jump_tables: dict[int, list[int]] = field(default_factory=dict)
    noreturn_calls: set[int] = field(default_factory=set)
    truncated: bool = False
