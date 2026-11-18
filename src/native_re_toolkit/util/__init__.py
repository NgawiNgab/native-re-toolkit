"""Small shared utilities."""

from .hexdump import hexdump  # noqa: F401
from .pattern import anchor_of, find_pattern_all, verify_at  # noqa: F401


def fmt_addr(va: int, bits: int = 64) -> str:
    width = 16 if bits == 64 else 8
    return f"0x{va:0{width}x}"


def human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"
