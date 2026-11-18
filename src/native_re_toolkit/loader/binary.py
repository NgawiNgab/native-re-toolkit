"""Format-independent binary abstraction.

Every loader (ELF, PE, Mach-O) produces a :class:`Binary` subclass that
exposes a common view: sections, symbols, imports/exports, relocations
and virtual-address <-> file-offset translation.
"""

from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field
from typing import Iterator, Optional


@dataclass(slots=True)
class Section:
    """A mapped section/segment of the binary."""

    name: str
    vaddr: int          # virtual address where the section is loaded
    vsize: int          # in-memory size
    offset: int         # offset within the file
    size: int           # raw size within the file (may be < vsize, e.g. .bss)
    flags: str          # permission letters, e.g. "r-x", "rw-"
    data: bytes = b""

    @property
    def end(self) -> int:
        return self.vaddr + self.vsize

    @property
    def file_end(self) -> int:
        return self.offset + self.size

    @property
    def executable(self) -> bool:
        return "x" in self.flags

    @property
    def writable(self) -> bool:
        return "w" in self.flags

    @property
    def readable(self) -> bool:
        return "r" in self.flags

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.end

    def va_to_offset(self, va: int) -> Optional[int]:
        if not self.contains_va(va):
            return None
        delta = va - self.vaddr
        if delta >= self.size:
            return None  # in zero-filled tail (e.g. .bss)
        return self.offset + delta


@dataclass(slots=True)
class Symbol:
    """A named address: function, object or undefined (imported) symbol."""

    name: str
    value: int = 0
    size: int = 0
    type: str = "unknown"     # 'func' | 'object' | 'section' | 'file' | 'tls' | ...
    bind: str = "local"       # 'local' | 'global' | 'weak'
    imported: bool = False    # undefined symbol, satisfied at load time
    section: str = ""

    @property
    def is_function(self) -> bool:
        return self.type == "func"


@dataclass(slots=True)
class Relocation:
    """A relocation entry."""

    offset: int               # where the relocation applies (VA)
    type: str                 # platform specific name, e.g. R_X86_64_JUMP_SLOT
    symbol: Optional[str] = None
    addend: int = 0


class Binary:
    """Common read-only view over a native binary."""

    format: str = "unknown"
    arch: str = "unknown"     # 'x86', 'x86_64', 'arm', 'arm64', 'mips', ...
    bits: int = 0             # 32 or 64
    endian: str = "little"
    entry: int = 0
    image_base: int = 0

    def __init__(self, path: str):
        self.path = str(path)
        self.sections: list[Section] = []
        self.symbols: list[Symbol] = []
        #: library name -> imported symbol names
        self.imports: dict[str, list[str]] = {}
        self.exports: list[Symbol] = []
        self.relocations: list[Relocation] = []
        #: GOT/PLT-slot address -> imported symbol name (filled by loader)
        self.got_imports: dict[int, str] = {}
        #: PLT stub address -> imported symbol name (filled lazily)
        self.plt_imports: dict[int, str] = {}
        self._sorted_sections: list[Section] = []
        self._section_starts: list[int] = []
        self._sym_by_addr: dict[int, Symbol] = {}
        self._sym_by_name: dict[str, Symbol] = {}
        self._sym_addrs: list[int] = []

    # ------------------------------------------------------------------
    # post-parse bookkeeping
    # ------------------------------------------------------------------
    def finalize(self) -> "Binary":
        """Build lookup indexes after the loader populated the lists."""
        self._sorted_sections = sorted(self.sections, key=lambda s: s.vaddr)
        self._section_starts = [s.vaddr for s in self._sorted_sections]
        for sym in self.symbols:
            if sym.value and not sym.imported and sym.name:
                # Prefer function symbols and larger sizes on collisions.
                cur = self._sym_by_addr.get(sym.value)
                if cur is None or (sym.is_function and not cur.is_function):
                    self._sym_by_addr[sym.value] = sym
                self._sym_by_name.setdefault(sym.name, sym)
        self._sym_addrs = sorted(self._sym_by_addr)
        return self

    # ------------------------------------------------------------------
    # basic info
    # ------------------------------------------------------------------
    @property
    def sha256(self) -> str:
        h = hashlib.sha256()
        with open(self.path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    @property
    def file_size(self) -> int:
        import os

        return os.path.getsize(self.path)

    @property
    def all_import_names(self) -> list[str]:
        names: list[str] = []
        for lib_imports in self.imports.values():
            names.extend(lib_imports)
        return names

    def imported_function_names(self) -> list[str]:
        """Names of undefined symbols plus IAT/import-table entries."""
        names = set(self.all_import_names)
        names.update(s.name for s in self.symbols if s.imported)
        return sorted(names)

    # ------------------------------------------------------------------
    # address translation
    # ------------------------------------------------------------------
    def section_at(self, va: int) -> Optional[Section]:
        """Return the section containing virtual address *va*, if any."""
        i = bisect.bisect_right(self._section_starts, va) - 1
        if i >= 0:
            sec = self._sorted_sections[i]
            if sec.contains_va(va):
                return sec
        # Slow path: sections can overlap in rare/obfuscated files.
        for sec in self._sorted_sections:
            if sec.contains_va(va):
                return sec
        return None

    def jump_table_ok(self, va: int) -> bool:
        """True when *va* can plausibly host an absolute jump table:
        a readable section that is neither executable nor writable
        (.rodata / .rdata / __const). This rejects GOT slots, PLT stubs
        and function pointers, which hold single code pointers, not
        switch tables."""
        sec = self.section_at(va)
        return (
            sec is not None
            and sec.readable
            and not sec.executable
            and not sec.writable
        )

    def va_to_offset(self, va: int) -> Optional[int]:
        sec = self.section_at(va)
        if sec is None:
            return None
        return sec.va_to_offset(va)

    def offset_to_va(self, offset: int) -> Optional[int]:
        for sec in self.sections:
            if sec.offset <= offset < sec.file_end:
                return sec.vaddr + (offset - sec.offset)
        return None

    def read_va(self, va: int, size: int) -> bytes:
        """Read *size* bytes at virtual address *va* (may cross sections)."""
        out = bytearray()
        cur = va
        remaining = size
        while remaining > 0:
            sec = self.section_at(cur)
            if sec is None:
                break
            delta = cur - sec.vaddr
            take = min(remaining, sec.size - delta)
            if take <= 0:
                # zero-filled tail (.bss): emit zeros
                ztake = min(remaining, sec.vsize - delta)
                if ztake <= 0:
                    break
                out.extend(b"\x00" * ztake)
                cur += ztake
                remaining -= ztake
                continue
            out.extend(sec.data[delta : delta + take])
            cur += take
            remaining -= take
        return bytes(out)

    def read_c_string(self, va: int, max_len: int = 4096) -> Optional[str]:
        """Read a NUL-terminated ASCII string at *va*; None if not printable."""
        sec = self.section_at(va)
        if sec is None:
            return None
        delta = va - sec.vaddr
        if delta >= sec.size:
            return None
        chunk = sec.data[delta : delta + max_len]
        nul = chunk.find(b"\x00")
        if nul < 0:
            return None
        raw = chunk[:nul]
        if not raw:
            return None
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not all(c in ("\t", "\n", "\r") or 0x20 <= ord(c) < 0x7F for c in text):
            return None
        return text

    # ------------------------------------------------------------------
    # symbols
    # ------------------------------------------------------------------
    def symbol_at(self, va: int) -> Optional[Symbol]:
        return self._sym_by_addr.get(va)

    def symbol_named(self, name: str) -> Optional[Symbol]:
        return self._sym_by_name.get(name)

    def function_symbols(self) -> list[Symbol]:
        return [s for s in self.symbols if s.is_function and not s.imported and s.value]

    def name_for_address(self, va: int) -> Optional[str]:
        """Best-effort symbolic name for an address.

        Resolution order: exact symbol, PLT stub map, ``symbol+offset``
        for the nearest preceding symbol within a sane window.
        """
        sym = self._sym_by_addr.get(va)
        if sym is not None:
            return sym.name
        if va in self.plt_imports:
            return self.plt_imports[va] + "@plt"
        if va in self.got_imports:
            return self.got_imports[va] + "@got"
        starts = self._sym_addrs
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0:
            base = starts[i]
            sym = self._sym_by_addr[base]
            delta = va - base
            limit = sym.size if sym.size else 0x1000
            if 0 < delta < limit:
                return f"{sym.name}+0x{delta:x}"
        return None

    # ------------------------------------------------------------------
    # iteration helpers
    # ------------------------------------------------------------------
    def executable_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable]

    def iter_section_bytes(self, sec: Section) -> Iterator[tuple[int, bytes]]:
        yield sec.vaddr, sec.data

    def describe(self) -> dict:
        """Compact JSON-able summary of the binary."""
        return {
            "path": self.path,
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "entry": self.entry,
            "image_base": self.image_base,
            "file_size": self.file_size,
            "sections": len(self.sections),
            "symbols": len(self.symbols),
            "imports": sum(len(v) for v in self.imports.values()),
            "exports": len(self.exports),
        }
