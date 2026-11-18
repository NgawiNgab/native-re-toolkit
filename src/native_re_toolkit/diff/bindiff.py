"""Function-level binary diffing.

Matching strategy, in order:
1. identical symbol names (when both sides have symbols)
2. identical addresses (for stripped builds of the same layout)
3. exact mnemonic-sequence hash
4. fuzzy match via difflib similarity on the mnemonic sequence

The result classifies every function pair as identical / changed /
added / removed.
"""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from ..loader.binary import Binary
from ..disasm.cfg import Function
from ..disasm.discovery import discover_functions


@dataclass(slots=True)
class FunctionPair:
    status: str                      # 'identical' | 'changed' | 'added' | 'removed'
    old: Optional[Function]
    new: Optional[Function]
    similarity: float = 0.0
    match_method: str = ""           # 'name' | 'address' | 'hash' | 'fuzzy' | ''


@dataclass(slots=True)
class DiffReport:
    pairs: list[FunctionPair] = field(default_factory=list)
    old_only_count: int = 0
    new_only_count: int = 0

    @property
    def identical(self) -> list[FunctionPair]:
        return [p for p in self.pairs if p.status == "identical"]

    @property
    def changed(self) -> list[FunctionPair]:
        return [p for p in self.pairs if p.status == "changed"]

    @property
    def added(self) -> list[FunctionPair]:
        return [p for p in self.pairs if p.status == "added"]

    @property
    def removed(self) -> list[FunctionPair]:
        return [p for p in self.pairs if p.status == "removed"]

    def summary(self) -> dict:
        return {
            "old_functions": self.old_only_count,
            "new_functions": self.new_only_count,
            "matched": len(self.identical) + len(self.changed),
            "identical": len(self.identical),
            "changed": len(self.changed),
            "added": len(self.added),
            "removed": len(self.removed),
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "pairs": [
                {
                    "status": p.status,
                    "similarity": round(p.similarity, 4),
                    "match_method": p.match_method,
                    "old": (
                        {
                            "start": p.old.start,
                            "name": p.old.name,
                            "insns": p.old.num_insns,
                            "blocks": p.old.num_blocks,
                        }
                        if p.old
                        else None
                    ),
                    "new": (
                        {
                            "start": p.new.start,
                            "name": p.new.name,
                            "insns": p.new.num_insns,
                            "blocks": p.new.num_blocks,
                        }
                        if p.new
                        else None
                    ),
                }
                for p in self.pairs
            ],
        }


def _mnemonic_hash(fn: Function) -> str:
    seq = ",".join(fn.mnemonic_sequence())
    return hashlib.sha1(seq.encode()).hexdigest()


def _similarity(a: Function, b: Function) -> float:
    sa = a.mnemonic_sequence()
    sb = b.mnemonic_sequence()
    if not sa or not sb:
        return 0.0
    if sa == sb:
        return 1.0
    return difflib.SequenceMatcher(None, sa, sb, autojunk=False).ratio()


# Tiny functions produce deceptively high mnemonic similarity; require a
# much stricter ratio to pair them.
_SMALL_FUNCTION_INSNS = 15
_SMALL_FUNCTION_THRESHOLD = 0.9


def _effective_threshold(a: Function, b: Function, base: float) -> float:
    if min(a.num_insns, b.num_insns) < _SMALL_FUNCTION_INSNS:
        return max(base, _SMALL_FUNCTION_THRESHOLD)
    return base


def diff_functions(
    old_funcs: dict[int, Function],
    new_funcs: dict[int, Function],
    *,
    fuzzy_threshold: float = 0.55,
    identical_threshold: float = 0.999,
) -> DiffReport:
    report = DiffReport(old_only_count=len(old_funcs), new_only_count=len(new_funcs))
    old_unmatched = dict(old_funcs)
    new_unmatched = dict(new_funcs)

    def pop_pair(o_addr: int, n_addr: int, method: str, similarity: float) -> None:
        o = old_unmatched.pop(o_addr)
        n = new_unmatched.pop(n_addr)
        status = "identical" if similarity >= identical_threshold else "changed"
        report.pairs.append(FunctionPair(status, o, n, similarity, method))

    # 1. match by name (both sides named, non-empty)
    old_by_name = {f.name: a for a, f in old_unmatched.items() if f.name and not f.name.startswith("sub_")}
    new_by_name = {f.name: a for a, f in new_unmatched.items() if f.name and not f.name.startswith("sub_")}
    for name in sorted(set(old_by_name) & set(new_by_name)):
        oa, na = old_by_name[name], new_by_name[name]
        if oa in old_unmatched and na in new_unmatched:
            sim = _similarity(old_unmatched[oa], new_unmatched[na])
            pop_pair(oa, na, "name", sim)

    # 2. match by identical address (same-layout stripped builds).
    # Address equality is strong positional evidence, so the base
    # threshold applies (not the stricter small-function one).
    for addr in sorted(set(old_unmatched) & set(new_unmatched)):
        o_fn, n_fn = old_unmatched[addr], new_unmatched[addr]
        sim = _similarity(o_fn, n_fn)
        if sim >= fuzzy_threshold:
            pop_pair(addr, addr, "address", sim)

    # 3. exact mnemonic-hash match
    old_hashes: dict[str, list[int]] = {}
    for a, f in old_unmatched.items():
        old_hashes.setdefault(_mnemonic_hash(f), []).append(a)
    for n_addr in sorted(list(new_unmatched)):
        h = _mnemonic_hash(new_unmatched[n_addr])
        cands = old_hashes.get(h)
        if cands:
            o_addr = cands.pop(0)
            pop_pair(o_addr, n_addr, "hash", 1.0)

    # 4. fuzzy matching on the remainder
    old_remaining = sorted(old_unmatched)
    for n_addr in sorted(list(new_unmatched)):
        if n_addr not in new_unmatched:
            continue
        n_fn = new_unmatched[n_addr]
        best_addr, best_sim = None, 0.0
        for o_addr in old_remaining:
            if o_addr not in old_unmatched:
                continue
            o_fn = old_unmatched[o_addr]
            # cheap pre-filter: instruction counts within 3x
            hi, lo = max(o_fn.num_insns, n_fn.num_insns), min(o_fn.num_insns, n_fn.num_insns)
            if lo == 0 or hi / lo > 3:
                continue
            sim = _similarity(o_fn, n_fn)
            if sim > best_sim:
                best_addr, best_sim = o_addr, sim
        if best_addr is not None and best_sim >= _effective_threshold(
            old_unmatched[best_addr], n_fn, fuzzy_threshold
        ):
            pop_pair(best_addr, n_addr, "fuzzy", best_sim)
            old_remaining.remove(best_addr)

    # whatever is left: removed / added
    for o_addr in sorted(old_unmatched):
        report.pairs.append(FunctionPair("removed", old_unmatched[o_addr], None, 0.0))
    for n_addr in sorted(new_unmatched):
        report.pairs.append(FunctionPair("added", None, new_unmatched[n_addr], 0.0))

    report.pairs.sort(key=lambda p: (p.status, (p.old or p.new).start))
    return report


def diff_binaries(
    old: Binary,
    new: Binary,
    *,
    old_functions: Optional[dict[int, Function]] = None,
    new_functions: Optional[dict[int, Function]] = None,
    fuzzy_threshold: float = 0.55,
) -> DiffReport:
    """Convenience wrapper: discover functions on both sides and diff."""
    if old_functions is None:
        old_functions = discover_functions(old).functions
    if new_functions is None:
        new_functions = discover_functions(new).functions
    # ignore PLT thunks in diffs (they are mechanical)
    old_f = {a: f for a, f in old_functions.items() if not f.name.endswith("@plt")}
    new_f = {a: f for a, f in new_functions.items() if not f.name.endswith("@plt")}
    return diff_functions(old_f, new_f, fuzzy_threshold=fuzzy_threshold)
