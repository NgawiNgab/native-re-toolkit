"""String extraction from binary sections (ASCII, UTF-16LE/BE)."""

from __future__ import annotations

from dataclasses import dataclass

from ..loader.binary import Binary, Section

# space..tilde plus common whitespace that legitimately appears inside
# C string literals (tab, LF, CR)
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


@dataclass
class StringRef:
    va: int
    offset: int
    value: str
    encoding: str          # 'ascii' | 'utf16le' | 'utf16be'
    section: str

    @property
    def escaped(self) -> str:
        """Value with control characters escaped for display."""
        return (
            self.value.replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.va:#x} [{self.encoding}] {self.escaped}"


def _is_printable_run(data: bytes, start: int, min_len: int) -> int:
    """Return the length of the printable run starting at *start*."""
    i = start
    n = len(data)
    while i < n and data[i] in _PRINTABLE:
        i += 1
    run = i - start
    if run >= min_len:
        # must be terminated (NUL or end of data) to count as a string
        if i >= n or data[i] == 0:
            return run
    return 0


def _scan_ascii(sec: Section, min_len: int, out: list[StringRef]) -> None:
    data = sec.data
    n = len(data)
    i = 0
    while i < n:
        if data[i] in _PRINTABLE:
            run = _is_printable_run(data, i, min_len)
            if run:
                value = data[i : i + run].decode("ascii")
                out.append(
                    StringRef(
                        va=sec.vaddr + i,
                        offset=sec.offset + i,
                        value=value,
                        encoding="ascii",
                        section=sec.name,
                    )
                )
                i += run
                continue
        i += 1


def _scan_utf16(sec: Section, min_len: int, out: list[StringRef], little: bool) -> None:
    data = sec.data
    n = len(data)
    enc = "utf16le" if little else "utf16be"
    lo, hi = (0, 1) if little else (1, 0)
    i = 0
    while i + 1 < n:
        if data[i + hi] == 0 and data[i + lo] in _PRINTABLE:
            start = i
            chars = []
            while i + 1 < n and data[i + hi] == 0 and data[i + lo] in _PRINTABLE:
                chars.append(data[i + lo])
                i += 2
            if len(chars) >= min_len:
                terminated = (i + 1 >= n) or (data[i] == 0 and (i + 1 >= n or data[i + 1] == 0))
                if terminated:
                    out.append(
                        StringRef(
                            va=sec.vaddr + start,
                            offset=sec.offset + start,
                            value=bytes(chars).decode("ascii"),
                            encoding=enc,
                            section=sec.name,
                        )
                    )
            continue
        i += 2


def extract_strings(
    binary: Binary,
    *,
    min_len: int = 4,
    encodings: tuple[str, ...] = ("ascii", "utf16le", "utf16be"),
    include_executable: bool = False,
) -> list[StringRef]:
    """Extract strings from all (non-executable) sections of *binary*."""
    out: list[StringRef] = []
    for sec in binary.sections:
        if sec.executable and not include_executable:
            continue
        if not sec.data:
            continue
        if "ascii" in encodings:
            _scan_ascii(sec, min_len, out)
        if "utf16le" in encodings:
            _scan_utf16(sec, min_len, out, little=True)
        if "utf16be" in encodings:
            _scan_utf16(sec, min_len, out, little=False)
    out.sort(key=lambda s: s.va)
    return out


def build_string_map(strings: list[StringRef]) -> dict[int, StringRef]:
    """Index strings by their address, and also by interior addresses.

    Compilers sometimes emit overlapping strings (e.g. suffix reuse), so
    only exact starts are indexed; callers wanting interior hits should
    use :func:`string_covering`.
    """
    return {s.va: s for s in strings}


def string_covering(strings: list[StringRef], va: int) -> StringRef | None:
    """Find the string that *starts at* or *contains* address *va*."""
    best: StringRef | None = None
    for s in strings:
        if s.va <= va < s.va + len(s.value) + 1:
            if best is None or s.va > best.va:
                best = s
    return best
