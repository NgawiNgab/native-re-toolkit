"""Anchored wildcard-pattern search over byte buffers.

Patterns are (values, mask) pairs: a position matches when
``(data[i] & mask[i]) == (values[i] & mask[i])`` for every i.
The scanner locates the longest run of exact bytes with ``bytes.find``
and verifies the full pattern at each candidate offset.
"""

from __future__ import annotations


def anchor_of(values: bytes, mask: bytes) -> tuple[int, bytes]:
    """Find the longest run of exact (0xff-masked) bytes for anchoring."""
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
        return 0, b""
    return best_start, values[best_start : best_start + best_len]


def verify_at(data: bytes, pos: int, values: bytes, mask: bytes) -> bool:
    for i in range(len(values)):
        if data[pos + i] & mask[i] != values[i]:
            return False
    return True


def find_pattern_all(
    data: bytes,
    values: bytes,
    mask: bytes,
    *,
    max_hits: int = 100000,
) -> list[int]:
    """All offsets in *data* matching the (values, mask) pattern."""
    hits: list[int] = []
    plen = len(values)
    if plen == 0 or len(data) < plen:
        return hits
    anchor_off, anchor = anchor_of(values, mask)
    if anchor:
        start = 0
        find = data.find
        while len(hits) < max_hits:
            idx = find(anchor, start)
            if idx < 0:
                break
            cand = idx - anchor_off
            if cand >= 0 and cand + plen <= len(data):
                if verify_at(data, cand, values, mask):
                    hits.append(cand)
            start = idx + 1
    else:
        # fully masked pattern: brute force
        for cand in range(0, len(data) - plen + 1):
            if verify_at(data, cand, values, mask):
                hits.append(cand)
                if len(hits) >= max_hits:
                    break
    return hits
