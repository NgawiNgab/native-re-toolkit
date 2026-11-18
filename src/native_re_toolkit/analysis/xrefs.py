"""Cross-reference analysis.

Builds the xref database from recovered functions:

* ``call``      - direct call instruction -> target function
* ``jump``      - direct jump to another function (tail calls, etc.)
* ``data_read`` / ``data_write`` - RIP-relative (or absolute) memory
  references, resolved to strings, symbols, GOT imports when possible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..loader.binary import Binary
from ..disasm.cfg import Function
from .strings import StringRef, string_covering


@dataclass(frozen=True)
class Xref:
    src: int                  # address of the referencing instruction
    dst: int                  # referenced address
    kind: str                 # 'call' | 'jump' | 'data_read' | 'data_write'
    src_function: int = 0     # entry of the function containing src
    dst_name: Optional[str] = None    # resolved symbol/string preview


@dataclass
class XrefDB:
    xrefs: list[Xref] = field(default_factory=list)
    _to: dict[int, list[Xref]] = field(default_factory=dict)
    _from: dict[int, list[Xref]] = field(default_factory=dict)

    def add(self, xref: Xref) -> None:
        self.xrefs.append(xref)
        self._to.setdefault(xref.dst, []).append(xref)
        self._from.setdefault(xref.src, []).append(xref)

    def to(self, dst: int) -> list[Xref]:
        return self._to.get(dst, [])

    def from_(self, src: int) -> list[Xref]:
        return self._from.get(src, [])

    def calls_to(self, dst: int) -> list[Xref]:
        return [x for x in self._to.get(dst, []) if x.kind == "call"]

    def __len__(self) -> int:
        return len(self.xrefs)


def build_xrefs(
    binary: Binary,
    functions: dict[int, Function],
    strings: Optional[list[StringRef]] = None,
) -> XrefDB:
    """Compute the full xref database for the recovered *functions*."""
    db = XrefDB()
    strings = strings if strings is not None else []
    # function starts for quick membership checks
    func_starts = set(functions)

    for fn in functions.values():
        for addr in sorted(fn.insns):
            ins = fn.insns[addr]
            if ins.is_call and ins.target is not None:
                name = _resolve_code_name(binary, ins.target)
                db.add(Xref(src=addr, dst=ins.target, kind="call",
                            src_function=fn.start, dst_name=name))
            elif ins.is_jump and ins.target is not None and ins.target not in fn.insns:
                # jump outside this function: tail call / thunk / interprocedural
                name = _resolve_code_name(binary, ins.target)
                db.add(Xref(src=addr, dst=ins.target, kind="jump",
                            src_function=fn.start, dst_name=name))
            if ins.mem_ref is not None and not (ins.is_jump and ins.indirect):
                xref = _resolve_data_ref(binary, strings, ins, fn)
                if xref is not None:
                    db.add(xref)
            elif not ins.is_branch and ins.imms:
                xref = _resolve_imm_ref(binary, strings, ins, fn)
                if xref is not None:
                    db.add(xref)
    return db


def _resolve_code_name(binary: Binary, va: int) -> Optional[str]:
    name = binary.name_for_address(va)
    if name:
        return name
    if va in binary.plt_imports:
        return binary.plt_imports[va] + "@plt"
    return None


def _resolve_imm_ref(
    binary: Binary,
    strings: list[StringRef],
    ins,
    fn: Function,
) -> Optional[Xref]:
    """Immediate operands that happen to be mapped addresses (non-PIE).

    Common in x86/x86-64 non-PIE code, e.g. ``mov edi, 0x402004`` loading
    a string address. Only immediates pointing into mapped sections count.
    """
    for va in ins.imms:
        if va < 0x1000:
            continue
        if va in binary.got_imports:
            return Xref(src=ins.addr, dst=va, kind="data_read", src_function=fn.start,
                        dst_name=binary.got_imports[va] + "@got")
        s = string_covering(strings, va)
        if s is not None:
            preview = s.escaped if len(s.escaped) <= 48 else s.escaped[:45] + "..."
            return Xref(src=ins.addr, dst=va, kind="data_read", src_function=fn.start,
                        dst_name=f'"{preview}"')
        name = binary.name_for_address(va)
        if name:
            return Xref(src=ins.addr, dst=va, kind="data_read", src_function=fn.start,
                        dst_name=name)
        sec = binary.section_at(va)
        if sec is not None and not sec.executable:
            return Xref(src=ins.addr, dst=va, kind="data_read", src_function=fn.start)
    return None


def _resolve_data_ref(
    binary: Binary,
    strings: list[StringRef],
    ins,
    fn: Function,
) -> Optional[Xref]:
    va = ins.mem_ref
    if va is None:
        return None
    kind = "data_write" if ins.mem_write else "data_read"
    # through the GOT? -> imported symbol
    if va in binary.got_imports:
        return Xref(src=ins.addr, dst=va, kind=kind, src_function=fn.start,
                    dst_name=binary.got_imports[va] + "@got")
    s = string_covering(strings, va)
    if s is not None:
        preview = s.value if len(s.value) <= 48 else s.value[:45] + "..."
        return Xref(src=ins.addr, dst=va, kind=kind, src_function=fn.start,
                    dst_name=f'"{preview}"')
    name = binary.name_for_address(va)
    if name:
        return Xref(src=ins.addr, dst=va, kind=kind, src_function=fn.start,
                    dst_name=name)
    if binary.section_at(va) is not None:
        return Xref(src=ins.addr, dst=va, kind=kind, src_function=fn.start)
    return None
