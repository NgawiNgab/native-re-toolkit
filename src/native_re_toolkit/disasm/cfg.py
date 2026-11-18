"""Control-flow graph construction and function recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .engine import Disassembler, RecursiveResult
from .insn import Insn


@dataclass
class BasicBlock:
    start: int
    end: int                    # exclusive
    insns: list[Insn] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)   # block start addresses
    edge_kinds: dict[int, str] = field(default_factory=dict)  # dst -> kind

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class Function:
    start: int
    name: str = ""
    insns: dict[int, Insn] = field(default_factory=dict)
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    edges: list[tuple[int, int, str]] = field(default_factory=list)
    calls: set[int] = field(default_factory=set)          # direct call targets
    data_refs: list[Insn] = field(default_factory=list)   # insns with mem_ref
    jump_tables: dict[int, list[int]] = field(default_factory=dict)
    discovered: bool = False    # True when found by heuristics (no symbol)
    truncated: bool = False

    @property
    def end(self) -> int:
        return max((b.end for b in self.blocks.values()), default=self.start)

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def num_insns(self) -> int:
        return len(self.insns)

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    def mnemonic_sequence(self) -> list[str]:
        return [self.insns[a].mnemonic for a in sorted(self.insns)]

    def to_dot(self) -> str:
        """Render the CFG in Graphviz DOT format."""
        lines = [f'digraph "{self.name or hex(self.start)}" {{', "  node [shape=box,fontname=monospace];"]
        for b in sorted(self.blocks.values(), key=lambda x: x.start):
            body = "\\l".join(f"{i.addr:x}: {i.mnemonic} {i.op_str}".rstrip() for i in b.insns)
            lines.append(f'  b{b.start:x} [label="{body}\\l"];')
        for src, dst, kind in self.edges:
            style = "solid" if kind in ("jump", "fallthrough") else "dashed"
            lines.append(f"  b{src:x} -> b{dst:x} [label=\"{kind}\", style={style}];")
        lines.append("}")
        return "\n".join(lines)


def build_cfg(result: RecursiveResult) -> tuple[dict[int, BasicBlock], list[tuple[int, int, str]]]:
    """Split recursive-descent output into basic blocks and CFG edges."""
    insns = result.insns
    if not insns:
        return {}, []
    addrs = sorted(insns)

    # leaders: function entry, branch targets, fallthrough after branches
    leaders: set[int] = {result.entry}
    for a in addrs:
        ins = insns[a]
        nxt = a + ins.size
        if ins.is_branch or ins.is_privileged_or_trap:
            if ins.target is not None and ins.target in insns:
                leaders.add(ins.target)
            if nxt in insns:
                leaders.add(nxt)
        if ins.addr in result.jump_tables:
            for t in result.jump_tables[ins.addr]:
                if t in insns:
                    leaders.add(t)

    blocks: dict[int, BasicBlock] = {}
    cur: Optional[BasicBlock] = None
    for a in addrs:
        if a in leaders or cur is None:
            cur = BasicBlock(start=a, end=a)
            blocks[a] = cur
        ins = insns[a]
        cur.insns.append(ins)
        cur.end = ins.end

    edges: list[tuple[int, int, str]] = []
    block_list = sorted(blocks.values(), key=lambda b: b.start)
    for idx, b in enumerate(block_list):
        last = b.insns[-1]
        next_start: Optional[int] = block_list[idx + 1].start if idx + 1 < len(block_list) else None

        def add_edge(dst: Optional[int], kind: str) -> None:
            if dst is not None and dst in blocks:
                b.successors.append(dst)
                b.edge_kinds[dst] = kind
                edges.append((b.start, dst, kind))

        if last.is_ret:
            continue
        if last.is_jump and not last.is_conditional:
            if last.addr in result.jump_tables:
                for t in result.jump_tables[last.addr]:
                    add_edge(t, "jump_table")
            else:
                add_edge(last.target, "jump")
            continue
        if last.is_jump and last.is_conditional:
            add_edge(last.target, "cond_true")
            # fallthrough: prefer the block starting right after
            fall = last.end if last.end in blocks else next_start
            add_edge(fall, "cond_false")
            continue
        if last.is_privileged_or_trap:
            continue
        # calls and ordinary instructions fall through
        fall = last.end if last.end in blocks else next_start
        add_edge(fall, "fallthrough")
    return blocks, edges


def build_function(
    dis: Disassembler,
    read_va,
    in_code,
    entry: int,
    name: str = "",
    discovered: bool = False,
) -> Function:
    """Full function recovery: recursive descent + CFG."""
    result = dis.recursive(entry, read_va, in_code)
    blocks, edges = build_cfg(result)
    fn = Function(
        start=entry,
        name=name,
        insns=result.insns,
        blocks=blocks,
        edges=edges,
        calls=set(result.call_targets),
        data_refs=result.data_refs,
        jump_tables=result.jump_tables,
        discovered=discovered,
        truncated=result.truncated,
    )
    return fn
