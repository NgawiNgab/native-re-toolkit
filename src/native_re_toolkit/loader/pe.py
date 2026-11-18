"""PE loader built on pefile."""

from __future__ import annotations

import pefile

from ..errors import LoaderError
from .binary import Binary, Section, Symbol

_MACHINE_MAP = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x01C0: ("arm", 32),
    0x01C4: ("armv7", 32),
    0xAA64: ("arm64", 64),
    0x01F0: ("powerpc", 32),
}

# IMAGE_SCN_CHARACTERISTICS
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000

_DLL_CHARS = [
    (0x0020, "high_entropy_va"),
    (0x0040, "dynamic_base"),       # ASLR
    (0x0080, "force_integrity"),
    (0x0100, "nx_compat"),
    (0x0400, "no_isolation"),
    (0x1000, "no_seh"),
    (0x2000, "no_bind"),
    (0x4000, "wdm_driver"),
    (0x8000, "terminal_server_aware"),
    (0x4000, "guard_cf"),
]


class PEBinary(Binary):
    format = "pe"

    def __init__(self, path: str):
        super().__init__(path)
        self.security: dict[str, bool | str] = {}
        self.dll_characteristics: int = 0
        self.subsystem: str = ""
        self.pe_type: str = ""
        self.overlay_offset: int = 0
        self.overlay_size: int = 0
        try:
            pe = pefile.PE(path, fast_load=False)
        except Exception as exc:
            raise LoaderError(f"failed to parse PE {path}: {exc}") from exc
        try:
            self._parse_headers(pe)
            self._parse_sections(pe)
            self._parse_imports(pe)
            self._parse_exports(pe)
            self._parse_overlay(pe)
        finally:
            pe.close()
        self.finalize()

    def _parse_headers(self, pe: pefile.PE) -> None:
        machine = pe.FILE_HEADER.Machine
        self.arch, self.bits = _MACHINE_MAP.get(machine, (f"machine_0x{machine:x}", 0))
        self.endian = "little"
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        characteristics = pe.FILE_HEADER.Characteristics
        self.pe_type = "dll" if characteristics & 0x2000 else "exe"
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        self.subsystem = {2: "gui", 3: "console", 1: "native"}.get(subsystem, str(subsystem))
        for mask, name in _DLL_CHARS:
            self.security[name] = bool(self.dll_characteristics & mask)
        self.security["nx"] = self.security.get("nx_compat", False)
        self.security["aslr"] = self.security.get("dynamic_base", False)

    def _parse_sections(self, pe: pefile.PE) -> None:
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", "replace")
            chars = sec.Characteristics
            flags = (
                ("r" if chars & _SCN_MEM_READ else "-")
                + ("w" if chars & _SCN_MEM_WRITE else "-")
                + ("x" if chars & _SCN_MEM_EXECUTE else "-")
            )
            self.sections.append(
                Section(
                    name=name,
                    vaddr=self.image_base + sec.VirtualAddress,
                    vsize=sec.Misc_VirtualSize,
                    offset=sec.PointerToRawData,
                    size=sec.SizeOfRawData,
                    flags=flags,
                    data=sec.get_data() or b"",
                )
            )

    def _parse_imports(self, pe: pefile.PE) -> None:
        entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
        entries += list(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or [])
        for entry in entries:
            dll = entry.dll.decode("ascii", "replace") if isinstance(entry.dll, bytes) else str(entry.dll)
            names: list[str] = []
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("ascii", "replace")
                else:
                    name = f"ordinal_{imp.ordinal}"
                names.append(name)
                # IAT slot address -> name lets the xref engine resolve
                # call qword ptr [rip+disp] targets.
                if imp.address:
                    self.got_imports[imp.address] = name
            self.imports.setdefault(dll, []).extend(names)
            for name in names:
                self.symbols.append(Symbol(name=name, imported=True, type="func"))

    def _parse_exports(self, pe: pefile.PE) -> None:
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_dir is None:
            return
        for entry in export_dir.symbols:
            name = entry.name.decode("ascii", "replace") if entry.name else f"ordinal_{entry.ordinal}"
            va = self.image_base + entry.address
            sym = Symbol(name=name, value=va, type="func", bind="global")
            self.exports.append(sym)
            self.symbols.append(sym)

    def _parse_overlay(self, pe: pefile.PE) -> None:
        try:
            offset = pe.get_overlay_data_start_offset()
        except Exception:
            offset = None
        if offset is not None:
            self.overlay_offset = offset
            self.overlay_size = self.file_size - offset


def load(path: str) -> PEBinary:
    return PEBinary(path)
