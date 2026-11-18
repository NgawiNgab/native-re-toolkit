"""Binary loading: format detection and unified access."""

from __future__ import annotations

from ..errors import FormatError
from .binary import Binary, Relocation, Section, Symbol  # noqa: F401
from .detect import detect, detect_bytes  # noqa: F401


def open_binary(path: str) -> Binary:
    """Open *path* and return a parsed :class:`Binary`.

    The concrete loader is chosen from magic bytes; raises
    :class:`FormatError` for unknown formats.
    """
    fmt = detect(path)
    if fmt == "elf":
        from .elf import load

        return load(path)
    if fmt == "pe":
        from .pe import load

        return load(path)
    if fmt == "macho":
        from .macho import load

        return load(path)
    raise FormatError(f"unrecognized binary format: {path}")
