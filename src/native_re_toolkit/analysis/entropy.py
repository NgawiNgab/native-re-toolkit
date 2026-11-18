"""Shannon entropy and packing heuristics."""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..loader.binary import Binary


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    n = len(data)
    ent = 0.0
    # bytes.count with a 1-byte pattern is a C-speed memchr pass;
    # 256 passes beat a Python-level per-byte loop by ~50x.
    for i in range(256):
        c = data.count(bytes((i,)))
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


@dataclass(slots=True)
class SectionEntropy:
    name: str
    vaddr: int
    size: int
    entropy: float
    flags: str
    verdict: str    # 'normal' | 'high' | 'likely_packed'


@dataclass(slots=True)
class EntropyReport:
    sections: list[SectionEntropy]
    file_entropy: float
    overlay_offset: int
    overlay_size: int
    packed_suspect: bool

    def to_dict(self) -> dict:
        return {
            "file_entropy": round(self.file_entropy, 4),
            "packed_suspect": self.packed_suspect,
            "overlay_offset": self.overlay_offset,
            "overlay_size": self.overlay_size,
            "sections": [
                {
                    "name": s.name,
                    "vaddr": s.vaddr,
                    "size": s.size,
                    "entropy": round(s.entropy, 4),
                    "flags": s.flags,
                    "verdict": s.verdict,
                }
                for s in self.sections
            ],
        }


HIGH_ENTROPY_THRESHOLD = 7.2
ELEVATED_ENTROPY_THRESHOLD = 6.5


def analyze_entropy(binary: Binary) -> EntropyReport:
    """Per-section entropy with a simple packer heuristic.

    A section with entropy >= 7.2 bits/byte that is also executable or
    writable is flagged as a packing/encryption suspect. Read-only data
    sections with high entropy are reported but treated less seriously
    (they may legitimately hold compressed resources).
    """
    results: list[SectionEntropy] = []
    suspect = False
    for sec in binary.sections:
        if not sec.data:
            continue
        ent = shannon_entropy(sec.data)
        if ent >= HIGH_ENTROPY_THRESHOLD:
            verdict = "likely_packed"
            if sec.executable or sec.writable:
                suspect = True
        elif ent >= ELEVATED_ENTROPY_THRESHOLD:
            verdict = "high"
        else:
            verdict = "normal"
        results.append(
            SectionEntropy(
                name=sec.name,
                vaddr=sec.vaddr,
                size=sec.size,
                entropy=ent,
                flags=sec.flags,
                verdict=verdict,
            )
        )
    with open(binary.path, "rb") as fh:
        file_ent = shannon_entropy(fh.read())
    overlay_offset = getattr(binary, "overlay_offset", 0)
    overlay_size = getattr(binary, "overlay_size", 0)
    return EntropyReport(
        sections=results,
        file_entropy=file_ent,
        overlay_offset=overlay_offset,
        overlay_size=overlay_size,
        packed_suspect=suspect,
    )
