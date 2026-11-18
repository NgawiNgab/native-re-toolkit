"""Binary format detection based on magic bytes."""

from __future__ import annotations

import os
import struct

from ..errors import FormatError

ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    0xFEEDFACE,  # 32-bit big-endian-in-file (host order)
    0xCEFAEDFE,  # 32-bit little-endian-in-file (CIGAM)
    0xFEEDFACF,  # 64-bit (MAGIC_64)
    0xCFFAEDFE,  # 64-bit swapped (CIGAM_64)
    0xCAFEBABE,  # fat binary
    0xBEBAFECA,  # fat binary swapped
}


def detect_bytes(data: bytes) -> str:
    """Detect binary format from the leading bytes of a file.

    Returns one of: ``'elf'``, ``'pe'``, ``'macho'``, ``'unknown'``.
    """
    if len(data) >= 4 and data[:4] == ELF_MAGIC:
        return "elf"
    if len(data) >= 0x40 and data[:2] == b"MZ":
        # PE/COFF: e_lfanew at 0x3c points to the PE signature.
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return "pe"
        # Plain DOS MZ executable - not supported, but recognized as PE-family.
        return "unknown"
    if len(data) >= 4:
        (magic_be,) = struct.unpack_from(">I", data, 0)
        (magic_le,) = struct.unpack_from("<I", data, 0)
        if magic_be in MACHO_MAGICS or magic_le in MACHO_MAGICS:
            return "macho"
    return "unknown"


def detect(path: str | os.PathLike) -> str:
    """Detect the binary format of a file on disk."""
    with open(path, "rb") as fh:
        head = fh.read(0x1000)
    return detect_bytes(head)


def require_known(path: str | os.PathLike) -> str:
    """Like :func:`detect` but raises :class:`FormatError` when unknown."""
    fmt = detect(path)
    if fmt == "unknown":
        raise FormatError(f"unrecognized binary format: {path}")
    return fmt
