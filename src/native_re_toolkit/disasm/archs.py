"""Architecture -> Capstone mapping."""

from __future__ import annotations

import capstone

from ..errors import UnsupportedArchError

# arch -> (cs_arch, {bits/endian -> cs_mode}, fixed_insn_size)
_ARCH_TABLE: dict[str, tuple[int, dict[tuple[int, str], int], int | None]] = {
    "x86_64": (capstone.CS_ARCH_X86, {(64, "little"): capstone.CS_MODE_64}, None),
    "x86": (
        capstone.CS_ARCH_X86,
        {
            (32, "little"): capstone.CS_MODE_32,
            (16, "little"): capstone.CS_MODE_16,
            (64, "little"): capstone.CS_MODE_64,
        },
        None,
    ),
    "arm": (
        capstone.CS_ARCH_ARM,
        {
            (32, "little"): capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
            (32, "big"): capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN,
        },
        4,
    ),
    "arm64": (
        capstone.CS_ARCH_ARM64,
        {
            (64, "little"): capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
            (64, "big"): capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN,
        },
        4,
    ),
    "mips": (
        capstone.CS_ARCH_MIPS,
        {
            (32, "little"): capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN,
            (32, "big"): capstone.CS_MODE_MIPS32 | capstone.CS_MODE_BIG_ENDIAN,
            (64, "little"): capstone.CS_MODE_MIPS64 | capstone.CS_MODE_LITTLE_ENDIAN,
            (64, "big"): capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN,
        },
        4,
    ),
    "ppc": (
        capstone.CS_ARCH_PPC,
        {
            (32, "big"): capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN,
            (32, "little"): capstone.CS_MODE_32 | capstone.CS_MODE_LITTLE_ENDIAN,
            (64, "big"): capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN,
            (64, "little"): capstone.CS_MODE_64 | capstone.CS_MODE_LITTLE_ENDIAN,
        },
        4,
    ),
    "sparc": (
        capstone.CS_ARCH_SPARC,
        {
            (32, "big"): capstone.CS_MODE_BIG_ENDIAN,
            (32, "little"): capstone.CS_MODE_LITTLE_ENDIAN,
        },
        4,
    ),
    "sparc64": (
        capstone.CS_ARCH_SPARC,
        {(64, "big"): capstone.CS_MODE_V9 | capstone.CS_MODE_BIG_ENDIAN},
        4,
    ),
}


def create_disassembler(arch: str, bits: int, endian: str) -> tuple["capstone.Cs", int | None]:
    """Return a configured ``capstone.Cs`` and the fixed instruction size.

    ``fixed_insn_size`` is ``None`` for variable-length ISAs (x86).
    Raises :class:`UnsupportedArchError` when the combination is unknown.
    """
    entry = _ARCH_TABLE.get(arch)
    if entry is None:
        raise UnsupportedArchError(f"architecture not supported: {arch!r}")
    cs_arch, modes, fixed = entry
    # NB: do not use ``or``-chains here; CS_MODE_* values can be 0.
    mode = modes.get((bits, endian))
    if mode is None:
        mode = modes.get((bits, "little"))
    if mode is None:
        mode = modes.get((32, "little"))
    if mode is None:
        raise UnsupportedArchError(
            f"no capstone mode for {arch}/{bits}/{endian}"
        )
    md = capstone.Cs(cs_arch, mode)
    md.detail = True
    return md, fixed


def is_fixed_width(arch: str) -> bool:
    entry = _ARCH_TABLE.get(arch)
    return bool(entry and entry[2])
