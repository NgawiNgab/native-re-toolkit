"""Minimal pure-Python Mach-O parser.

Supports 32/64-bit Mach-O headers and LC_SEGMENT/LC_SEGMENT_64 section
enumeration plus LC_SYMTAB-based symbol extraction. Fat (universal)
binaries are detected; the first contained image is parsed.
"""

from __future__ import annotations

import struct

from ..errors import LoaderError
from .binary import Binary, Section, Symbol

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19

_CPU_MAP = {
    (7, False): ("x86", 32),          # CPU_TYPE_I386
    (0x01000007, False): ("x86_64", 64),
    (12, False): ("arm", 32),         # CPU_TYPE_ARM
    (0x0100000C, False): ("arm64", 64),
    (18, False): ("ppc", 32),
    (0x01000012, False): ("ppc64", 64),
}

_VM_PROT_READ = 1
_VM_PROT_WRITE = 2
_VM_PROT_EXEC = 4

_S_ATTR_PURE_INSTRUCTIONS = 0x80000000
_S_ATTR_SOME_INSTRUCTIONS = 0x00000400


class MachOBinary(Binary):
    format = "macho"

    def __init__(self, path: str):
        super().__init__(path)
        with open(path, "rb") as fh:
            self._file = fh.read()
        data = self._file
        if len(data) < 4:
            raise LoaderError(f"truncated Mach-O: {path}")
        (magic_be,) = struct.unpack_from(">I", data, 0)
        if magic_be in (FAT_MAGIC, FAT_CIGAM):
            data = self._fat_first_slice(data)
        self._parse(data)
        self.finalize()

    # ------------------------------------------------------------------
    def _fat_first_slice(self, data: bytes) -> bytes:
        (magic,) = struct.unpack_from(">I", data, 0)
        swap = magic == FAT_CIGAM
        fmt = "<" if swap else ">"
        (nfat,) = struct.unpack_from(fmt + "I", data, 4)
        if nfat < 1:
            raise LoaderError("fat Mach-O with no architectures")
        # struct fat_arch { cpu, subtype, offset, size, align }
        _, _, off, size, _ = struct.unpack_from(fmt + "IIIII", data, 8)
        return data[off : off + size]

    def _parse(self, data: bytes) -> None:
        (magic_le,) = struct.unpack_from("<I", data, 0)
        if magic_le in (MH_MAGIC, MH_MAGIC_64):
            fmt = "<"
        elif magic_le in (MH_CIGAM, MH_CIGAM_64):
            fmt = ">"
        else:
            raise LoaderError("bad Mach-O magic")
        is64 = magic_le in (MH_MAGIC_64, MH_CIGAM_64)
        if is64:
            _, cputype, _sub, filetype, ncmds, sizeofcmds, _flags, _res = struct.unpack_from(
                fmt + "IiiIIIII", data, 0
            )
            cmd_off = 32
        else:
            _, cputype, _sub, filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(
                fmt + "IiiIIII", data, 0
            )
            cmd_off = 28
        self.bits = 64 if is64 else 32
        self.endian = "little" if fmt == "<" else "big"
        self.arch, _ = _CPU_MAP.get((cputype, False), (f"cpu_{cputype}", self.bits))
        self.macho_filetype = filetype
        self._fmt = fmt
        self._data = data

        symtab_info = None
        off = cmd_off
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(fmt + "II", data, off)
            if cmdsize < 8:
                break
            if cmd == LC_SEGMENT_64:
                self._parse_segment64(data, off, fmt)
            elif cmd == LC_SEGMENT:
                self._parse_segment32(data, off, fmt)
            elif cmd == LC_SYMTAB:
                symtab_info = struct.unpack_from(fmt + "IIII", data, off + 8)
            off += cmdsize
        if symtab_info:
            self._parse_symtab(data, fmt, symtab_info, is64)

    def _section_flags(self, initprot: int, sect_flags: int) -> str:
        r = "r" if initprot & _VM_PROT_READ else "-"
        w = "w" if initprot & _VM_PROT_WRITE else "-"
        x = "x" if (initprot & _VM_PROT_EXEC) or (
            sect_flags & (_S_ATTR_PURE_INSTRUCTIONS | _S_ATTR_SOME_INSTRUCTIONS)
        ) else "-"
        return r + w + x

    def _parse_segment64(self, data: bytes, off: int, fmt: str) -> None:
        (segname, vmaddr, vmsize, fileoff, _filesize, _maxprot, initprot, nsects, _flags) = (
            struct.unpack_from(fmt + "16sQQQQiiII", data, off + 8)
        )
        sect_off = off + 72
        for i in range(nsects):
            base = sect_off + i * 80
            if base + 80 > len(data):
                break
            (sectname, _seg, addr, size, offset, _align, _reloff, _nreloc, sflags) = (
                struct.unpack_from(fmt + "16s16sQQIIII", data, base)
            )
            name = sectname.split(b"\x00")[0].decode("ascii", "replace")
            raw = data[offset : offset + size] if offset + size <= len(data) else b""
            self.sections.append(
                Section(
                    name=name,
                    vaddr=addr,
                    vsize=size,
                    offset=offset,
                    size=len(raw),
                    flags=self._section_flags(initprot, sflags),
                    data=raw,
                )
            )
        if segname.split(b"\x00")[0] == b"__TEXT":
            self.image_base = vmaddr

    def _parse_segment32(self, data: bytes, off: int, fmt: str) -> None:
        (segname, vmaddr, vmsize, fileoff, _filesize, _maxprot, initprot, nsects, _flags) = (
            struct.unpack_from(fmt + "16sIIIIiiII", data, off + 8)
        )
        sect_off = off + 56
        for i in range(nsects):
            base = sect_off + i * 68
            if base + 68 > len(data):
                break
            (sectname, _seg, addr, size, offset, _align, _reloff, _nreloc, sflags) = (
                struct.unpack_from(fmt + "16s16sIIIIII", data, base)
            )
            name = sectname.split(b"\x00")[0].decode("ascii", "replace")
            raw = data[offset : offset + size] if offset + size <= len(data) else b""
            self.sections.append(
                Section(
                    name=name,
                    vaddr=addr,
                    vsize=size,
                    offset=offset,
                    size=len(raw),
                    flags=self._section_flags(initprot, sflags),
                    data=raw,
                )
            )

    def _parse_symtab(self, data: bytes, fmt: str, info, is64: bool) -> None:
        symoff, nsyms, stroff, strsize = info
        entsize = 16 if is64 else 12
        for i in range(nsyms):
            base = symoff + i * entsize
            if base + entsize > len(data):
                break
            if is64:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                    fmt + "IBBHQ", data, base
                )
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                    fmt + "IBBHI", data, base
                )
            if not n_strx or n_strx >= strsize:
                continue
            strbase = stroff + n_strx
            end = data.find(b"\x00", strbase)
            if end < 0:
                continue
            name = data[strbase:end].decode("utf-8", "replace")
            if not name:
                continue
            # N_TYPE field: 0xe = N_SECT (defined), 0x0 = N_UNDF
            ntype = n_type & 0x0E
            imported = ntype == 0
            self.symbols.append(
                Symbol(
                    name=name,
                    value=n_value,
                    type="func" if n_type & 0x10 or not imported else "unknown",
                    bind="global",
                    imported=imported,
                )
            )


def load(path: str) -> MachOBinary:
    return MachOBinary(path)
