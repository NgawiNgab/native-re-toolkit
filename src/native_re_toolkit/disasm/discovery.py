"""Function discovery: symbols first, then prologue heuristics for gaps."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..loader.binary import Binary
from .cfg import Function, build_function
from .engine import Disassembler

# (pattern, mask, strength, alignment)
_PROLOGUES: dict[str, list[tuple[bytes, bytes, str, int]]] = {
    "x86_64": [
        (b"\xf3\x0f\x1e\xfa", b"\xff\xff\xff\xff", "strong", 4),   # endbr64
        (b"\x55\x48\x89\xe5", b"\xff\xff\xff\xff", "strong", 4),   # push rbp; mov rbp,rsp
        (b"\x55\x48\x8b\xec", b"\xff\xff\xff\xff", "strong", 4),   # push rbp; mov rbp,rsp (alt)
        (b"\x48\x83\xec", b"\xff\xff\xff", "weak", 16),            # sub rsp, imm8
        (b"\x48\x81\xec", b"\xff\xff\xff", "weak", 16),            # sub rsp, imm32
        (b"\x41\x57\x41\x56", b"\xff\xff\xff\xff", "weak", 16),    # push r15; push r14
        (b"\x41\x56\x41\x55", b"\xff\xff\xff\xff", "weak", 16),    # push r14; push r13
    ],
    "x86": [
        (b"\x55\x8b\xec", b"\xff\xff\xff", "strong", 4),           # push ebp; mov ebp,esp
        (b"\x55\x89\xe5", b"\xff\xff\xff", "strong", 4),           # push ebp; mov ebp,esp (alt)
        (b"\x83\xec", b"\xff\xff", "weak", 16),                    # sub esp, imm8
    ],
    "arm64": [
        (b"\xd5\x03\x23\x3f", b"\xff\xff\xff\xff", "strong", 4),   # paciasp
        (b"\x00\x00\x80\xa9", b"\x00\x00\x80\xff", "strong", 4),   # stp .., .., [sp, #-..]!
        (b"\x00\x00\x00\xa9", b"\x00\x00\x80\xff", "weak", 4),     # stp .., .., [sp, #..]
    ],
    "arm": [
        (b"\x00\x00\x2d\xe9", b"\x00\x00\xff\xff", "strong", 4),   # push {..} / stmfd sp!, {..}
    ],
}


@dataclass
class DiscoveryResult:
    functions: dict[int, Function] = field(default_factory=dict)
    from_symbols: int = 0
    from_heuristics: int = 0

    @property
    def total(self) -> int:
        return len(self.functions)


def _match(data: bytes, pos: int, pattern: bytes, mask: bytes) -> bool:
    if pos + len(pattern) > len(data):
        return False
    for i, (p, m) in enumerate(zip(pattern, mask)):
        if data[pos + i] & m != p & m:
            return False
    return True


class _ClaimMap:
    """Per-section byte map of claimed (already attributed) bytes."""

    def __init__(self, binary: Binary):
        self.binary = binary
        self.maps: dict[str, bytearray] = {
            s.name: bytearray(len(s.data)) for s in binary.executable_sections()
        }
        self.sections = {s.name: s for s in binary.executable_sections()}

    def claim(self, va: int, size: int) -> None:
        sec = self.binary.section_at(va)
        if sec is None or sec.name not in self.maps:
            return
        start = va - sec.vaddr
        end = min(start + size, len(self.maps[sec.name]))
        m = self.maps[sec.name]
        for i in range(start, end):
            m[i] = 1

    def is_claimed(self, va: int) -> bool:
        sec = self.binary.section_at(va)
        if sec is None or sec.name not in self.maps:
            return True  # outside code: treat as claimed
        off = va - sec.vaddr
        if off >= len(self.maps[sec.name]):
            return True
        return bool(self.maps[sec.name][off])

    def any_claimed(self, va: int, size: int) -> bool:
        sec = self.binary.section_at(va)
        if sec is None or sec.name not in self.maps:
            return True
        off = va - sec.vaddr
        m = self.maps[sec.name]
        return any(m[off : off + size])


def discover_functions(
    binary: Binary,
    dis: Disassembler | None = None,
    *,
    prologue_scan: bool = True,
    max_functions: int = 200_000,
) -> DiscoveryResult:
    """Recover functions from *binary*.

    Strategy: (1) recursive descent from every known function symbol,
    entry point and PLT stub, following direct call targets; (2) scan
    the remaining executable gaps for common function prologues.
    """
    if dis is None:
        dis = Disassembler.for_binary(binary)

    def in_code(va: int) -> bool:
        sec = binary.section_at(va)
        return sec is not None and sec.executable

    def read_va(va: int, n: int) -> bytes:
        return binary.read_va(va, n)

    result = DiscoveryResult()
    claims = _ClaimMap(binary)

    # ---- phase 1: known symbols --------------------------------------
    seeds: list[tuple[int, str]] = []
    for sym in binary.function_symbols():
        if in_code(sym.value):
            seeds.append((sym.value, sym.name))
    if binary.entry and in_code(binary.entry):
        seeds.append((binary.entry, "entry"))
    for stub_va, name in binary.plt_imports.items():
        seeds.append((stub_va, f"{name}@plt"))
    for sym in binary.exports:
        if sym.value and in_code(sym.value):
            seeds.append((sym.value, sym.name))

    queue: list[tuple[int, str]] = sorted(set(seeds))
    queued = set(queue)
    while queue and result.total < max_functions:
        addr, name = queue.pop(0)
        if claims.is_claimed(addr) or not in_code(addr):
            continue
        fn = build_function(dis, read_va, in_code, addr, name or f"sub_{addr:08x}")
        if not fn.insns:
            continue
        for ia in fn.insns:
            claims.claim(ia, fn.insns[ia].size)
        result.functions[addr] = fn
        result.from_symbols += 1
        for target in fn.calls:
            if target not in queued and in_code(target) and not claims.is_claimed(target):
                symname = binary.name_for_address(target)
                if target in binary.plt_imports:
                    symname = f"{binary.plt_imports[target]}@plt"
                queue.append((target, symname or ""))
                queued.add(target)

    # ---- phase 2: prologue scan over the gaps -------------------------
    if prologue_scan:
        patterns = _PROLOGUES.get(binary.arch, [])
        if patterns:
            _scan_gaps(binary, dis, in_code, read_va, claims, patterns, result, max_functions)

    return result


def _scan_gaps(
    binary: Binary,
    dis: Disassembler,
    in_code,
    read_va,
    claims: _ClaimMap,
    patterns,
    result: DiscoveryResult,
    max_functions: int,
) -> None:
    rejected: set[int] = set()
    for sec in binary.executable_sections():
        data = sec.data
        cmap = claims.maps.get(sec.name)
        if cmap is None or not data:
            continue
        pos = 0
        n = len(data)
        while pos < n and result.total < max_functions:
            # skip claimed region quickly
            if cmap[pos]:
                pos += 1
                continue
            matched = None
            for pattern, mask, strength, align in patterns:
                if (sec.vaddr + pos) % align != 0:
                    continue
                if _match(data, pos, pattern, mask):
                    matched = (pattern, strength)
                    break
            if matched is None:
                pos += 1
                continue
            cand_va = sec.vaddr + pos
            if cand_va in rejected or claims.is_claimed(cand_va):
                pos += 1
                continue
            fn = build_function(
                dis, read_va, in_code, cand_va, f"sub_{cand_va:08x}", discovered=True
            )
            ok = _looks_like_function(fn, claims)
            if ok:
                for ia in fn.insns:
                    claims.claim(ia, fn.insns[ia].size)
                result.functions[cand_va] = fn
                result.from_heuristics += 1
                pos = fn.end - sec.vaddr
            else:
                rejected.add(cand_va)
                pos += 1


def _looks_like_function(fn: Function, claims: _ClaimMap) -> bool:
    """Accept/reject a prologue-scan candidate."""
    if len(fn.insns) < 2:
        return False
    if not fn.blocks:
        return False
    # must not overlap already-claimed bytes
    for ia, ins in fn.insns.items():
        if claims.any_claimed(ia, ins.size):
            return False
    # last block must terminate with ret/jump (i.e. decode ended cleanly)
    last_block = max(fn.blocks.values(), key=lambda b: b.end)
    last = last_block.insns[-1]
    if not (last.is_ret or last.is_jump or last.is_privileged_or_trap):
        # allow fallthrough into nothing only for tiny thunks
        if len(fn.insns) < 3:
            return True
        return False
    return True
