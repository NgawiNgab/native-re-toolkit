"""Byte-signature engine with wildcard support.

Pattern syntax (text form)::

    "48 8d ?? 24 0f ?? f0"     -- ?? = any byte
    "e8 ?? ?? ?? 00"           -- typical for masked constants
    "4?" / "?f"                -- nibble wildcards

Compiled to (values, mask) byte pairs; matching uses an anchor heuristic
(longest run of exact bytes located with ``bytes.find``, then verified).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Iterable, Optional

from ..errors import AnalysisError
from ..loader.binary import Binary


@dataclass
class Signature:
    name: str
    pattern: bytes          # expected values (masked)
    mask: bytes             # 0xff = exact, 0x00 = wildcard, 0xf0/0x0f = nibble
    description: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.pattern)


@dataclass
class SigMatch:
    name: str
    va: int                 # virtual address (or file offset if no section)
    offset: int             # file offset
    length: int
    section: str
    tags: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "va": self.va,
            "offset": self.offset,
            "length": self.length,
            "section": self.section,
            "tags": self.tags,
            "description": self.description,
        }


def parse_pattern(text: str) -> tuple[bytes, bytes]:
    """Parse a text pattern like ``'48 8d ?f 24'`` into (values, mask)."""
    values = bytearray()
    mask = bytearray()
    for tok in text.split():
        if len(tok) != 2:
            raise AnalysisError(f"bad pattern token: {tok!r}")
        hi, lo = tok[0], tok[1]
        v = 0
        m = 0
        if hi == "?":
            pass
        else:
            try:
                v |= int(hi, 16) << 4
                m |= 0xF0
            except ValueError:
                raise AnalysisError(f"bad pattern nibble: {tok!r}")
        if lo == "?":
            pass
        else:
            try:
                v |= int(lo, 16)
                m |= 0x0F
            except ValueError:
                raise AnalysisError(f"bad pattern nibble: {tok!r}")
        values.append(v)
        mask.append(m)
    if not values:
        raise AnalysisError("empty pattern")
    return bytes(values), bytes(mask)


def compile_pattern(text: str, name: str = "", **kwargs) -> Signature:
    values, mask = parse_pattern(text)
    return Signature(name=name, pattern=values, mask=mask, **kwargs)


def _anchor(pattern: bytes, mask: bytes) -> tuple[int, bytes]:
    """Find the longest run of exact bytes to use as a search anchor."""
    best_start, best_len, cur_start, cur_len = 0, 0, 0, 0
    for i, m in enumerate(mask):
        if m == 0xFF:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_len = 0
    if best_len == 0:
        return 0, b""  # no exact bytes at all
    return best_start, pattern[best_start : best_start + best_len]


def _verify(data: bytes, pos: int, pattern: bytes, mask: bytes) -> bool:
    for i in range(len(pattern)):
        if data[pos + i] & mask[i] != pattern[i]:
            return False
    return True


def find_all(data: bytes, sig: Signature, *, max_hits: int = 1000) -> list[int]:
    """Return all offsets in *data* where *sig* matches."""
    hits: list[int] = []
    plen = len(sig.pattern)
    if plen == 0 or len(data) < plen:
        return hits
    anchor_off, anchor = _anchor(sig.pattern, sig.mask)
    if anchor:
        start = 0
        while len(hits) < max_hits:
            idx = data.find(anchor, start)
            if idx < 0:
                break
            cand = idx - anchor_off
            if cand >= 0 and cand + plen <= len(data):
                if _verify(data, cand, sig.pattern, sig.mask):
                    hits.append(cand)
            start = idx + 1
    else:
        # fully masked pattern: brute force (slow but correct)
        for cand in range(0, len(data) - plen + 1):
            if _verify(data, cand, sig.pattern, sig.mask):
                hits.append(cand)
                if len(hits) >= max_hits:
                    break
    return hits


def load_signatures(path: Optional[str] = None) -> list[Signature]:
    """Load a signature pack (JSON). Defaults to the bundled pack."""
    if path is None:
        with resources.files("native_re_toolkit.data").joinpath("signatures.json").open(
            "r", encoding="utf-8"
        ) as fh:
            doc = json.load(fh)
    else:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    sigs = []
    for entry in doc.get("signatures", []):
        values, mask = parse_pattern(entry["pattern"])
        sigs.append(
            Signature(
                name=entry["name"],
                pattern=values,
                mask=mask,
                description=entry.get("description", ""),
                tags=entry.get("tags", []),
            )
        )
    return sigs


def scan_binary(
    binary: Binary,
    signatures: Iterable[Signature],
    *,
    include_executable: bool = True,
    max_hits_per_sig: int = 100,
) -> list[SigMatch]:
    """Scan all sections of *binary* with *signatures*."""
    matches: list[SigMatch] = []
    sigs = list(signatures)
    for sec in binary.sections:
        if not sec.data:
            continue
        if sec.executable and not include_executable:
            continue
        for sig in sigs:
            for off in find_all(sec.data, sig, max_hits=max_hits_per_sig):
                matches.append(
                    SigMatch(
                        name=sig.name,
                        va=sec.vaddr + off,
                        offset=sec.offset + off,
                        length=sig.length,
                        section=sec.name,
                        tags=sig.tags,
                        description=sig.description,
                    )
                )
    matches.sort(key=lambda m: (m.va, m.name))
    return matches


def scan_bytes(data: bytes, signatures: Iterable[Signature], base_va: int = 0) -> list[SigMatch]:
    """Scan a raw buffer."""
    matches = []
    for sig in signatures:
        for off in find_all(data, sig):
            matches.append(
                SigMatch(
                    name=sig.name,
                    va=base_va + off,
                    offset=off,
                    length=sig.length,
                    section="",
                    tags=sig.tags,
                    description=sig.description,
                )
            )
    return matches


# ----------------------------------------------------------------------
# optional YARA integration
# ----------------------------------------------------------------------
def yara_scan(path: str, rule_source: str):
    """Scan *path* with a YARA rule source string.

    Requires the optional ``yara-python`` dependency
    (``pip install native-re-toolkit[yara]``).
    Returns a list of ``{rule, tags, matches:[{offset, identifier}]}``.
    """
    try:
        import yara
    except ImportError as exc:  # pragma: no cover
        raise AnalysisError(
            "yara-python not installed; install with: pip install native-re-toolkit[yara]"
        ) from exc
    rules = yara.compile(source=rule_source)
    out = []
    for m in rules.match(path):
        strings = []
        for s in m.strings:
            for inst in s.instances:
                strings.append({"offset": inst.offset, "identifier": s.identifier})
        out.append({"rule": m.rule, "tags": list(m.tags), "matches": strings})
    return out
