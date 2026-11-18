"""Hexdump formatting."""

from __future__ import annotations


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    """Classic ``hexdump -C`` style output."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart[: 3 * 8 - 1] + " " + hexpart[3 * 8 - 1 :] if len(chunk) > 8 else hexpart
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexpart:<49}  |{ascii_part}|")
    return "\n".join(lines)
