"""Command line interface: ``nrt`` / ``python -m native_re_toolkit``."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Optional

from . import __version__
from .analysis.entropy import analyze_entropy
from .analysis.impcat import classify_imports
from .analysis.signatures import load_signatures, scan_binary
from .analysis.strings import extract_strings
from .analysis.xrefs import build_xrefs
from .diff.bindiff import diff_binaries
from .disasm.cfg import build_function
from .disasm.discovery import discover_functions
from .disasm.engine import Disassembler
from .errors import NRTError
from .loader import Binary, open_binary
from .report import build_report, report_html, report_json, report_text
from .util import fmt_addr, hexdump, human_size


def _json_out(obj) -> None:
    print(json.dumps(obj, indent=2, default=_json_default))


def _json_default(o):
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, set):
        return sorted(o)
    return str(o)


def _resolve_target(binary: Binary, text: str) -> int:
    """Resolve a CLI target: hex/decimal address or symbol name."""
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 0)
    except ValueError:
        pass
    sym = binary.symbol_named(text)
    if sym is not None and sym.value:
        return sym.value
    # maybe a PLT import name
    for va, name in binary.plt_imports.items():
        if name == text or f"{name}@plt" == text:
            return va
    raise NRTError(f"cannot resolve address or symbol: {text!r}")


# ----------------------------------------------------------------------
# subcommands
# ----------------------------------------------------------------------
def cmd_info(args) -> int:
    b = open_binary(args.binary)
    info = b.describe()
    info["sha256"] = b.sha256
    info["security"] = dict(getattr(b, "security", {}))
    info["libraries"] = getattr(b, "libraries", sorted(b.imports))
    if getattr(b, "overlay_size", 0):
        info["overlay_size"] = b.overlay_size
    if args.json:
        _json_out(info)
    else:
        print(f"file:      {info['path']}")
        print(f"format:    {info['format']} ({info['bits']}-bit, {info['endian']}-endian)")
        print(f"arch:      {info['arch']}")
        print(f"entry:     {fmt_addr(info['entry'], info['bits'])}")
        print(f"base:      {fmt_addr(info['image_base'], info['bits'])}")
        print(f"size:      {human_size(info['file_size'])}")
        print(f"sha256:    {info['sha256']}")
        sec = info.get("security") or {}
        if sec:
            flags = "  ".join(f"{k}={'Y' if v else 'N'}" for k, v in sec.items())
            print(f"security:  {flags}")
        if info["libraries"]:
            print(f"libraries: {', '.join(info['libraries'])}")
        print(f"sections:  {info['sections']}   symbols: {info['symbols']}   "
              f"imports: {info['imports']}   exports: {info['exports']}")
        if info.get("overlay_size"):
            print(f"overlay:   {info['overlay_size']} bytes appended after image")
    return 0


def cmd_sections(args) -> int:
    b = open_binary(args.binary)
    rows = [
        {
            "name": s.name, "vaddr": s.vaddr, "vsize": s.vsize,
            "offset": s.offset, "size": s.size, "flags": s.flags,
        }
        for s in b.sections
    ]
    if args.json:
        _json_out(rows)
    else:
        print(f"{'NAME':<16} {'VADDR':<18} {'VSIZE':<10} {'OFFSET':<10} {'SIZE':<10} FLAGS")
        for s in rows:
            print(f"{s['name']:<16} {fmt_addr(s['vaddr'], b.bits):<18} "
                  f"{s['vsize']:<10} {s['offset']:<10} {s['size']:<10} {s['flags']}")
    return 0


def cmd_symbols(args) -> int:
    b = open_binary(args.binary)
    syms = b.symbols
    if args.funcs_only:
        syms = [s for s in syms if s.is_function or s.imported]
    if args.json:
        _json_out([
            {"name": s.name, "value": s.value, "size": s.size, "type": s.type,
             "bind": s.bind, "imported": s.imported}
            for s in syms
        ])
    else:
        for s in syms:
            tag = "IMPORT" if s.imported else fmt_addr(s.value, b.bits)
            print(f"{tag:<18} {s.type:<8} {s.name}")
    return 0


def cmd_imports(args) -> int:
    b = open_binary(args.binary)
    if args.classify or args.json:
        classes = classify_imports(b.imported_function_names())
        if args.json:
            _json_out({"imports": {k: sorted(v) for k, v in b.imports.items()},
                       "categories": classes})
        else:
            for cat, names in classes.items():
                print(f"[{cat}] ({len(names)})")
                for n in sorted(names):
                    print(f"  {n}")
        return 0
    for lib, names in b.imports.items():
        print(f"{lib}:")
        for n in sorted(names):
            print(f"  {n}")
    return 0


def cmd_exports(args) -> int:
    b = open_binary(args.binary)
    rows = [{"name": s.name, "value": s.value} for s in b.exports]
    if args.json:
        _json_out(rows)
    else:
        for r in rows:
            print(f"{fmt_addr(r['value'], b.bits)} {r['name']}")
    return 0


def _disasm_function(b: Binary, va: int, args) -> int:
    dis = Disassembler.for_binary(b)

    def in_code(x):
        sec = b.section_at(x)
        return sec is not None and sec.executable

    fn = build_function(dis, b.read_va, in_code, va, b.name_for_address(va) or "")
    if args.json:
        _json_out({
            "function": {"start": fn.start, "name": fn.name,
                         "blocks": fn.num_blocks, "insns": fn.num_insns},
            "instructions": [
                {"addr": i.addr, "bytes": i.data.hex(),
                 "mnemonic": i.mnemonic, "op_str": i.op_str}
                for i in (fn.insns[a] for a in sorted(fn.insns))
            ],
        })
        return 0
    print(f"function {fn.name or '?'} @ {fmt_addr(fn.start, b.bits)} "
          f"({fn.num_blocks} blocks, {fn.num_insns} insns)")
    for a in sorted(fn.insns):
        i = fn.insns[a]
        raw = i.data.hex().ljust(24)
        print(f"  {fmt_addr(a, b.bits)}  {raw} {i.mnemonic} {i.op_str}".rstrip())
    return 0


def cmd_disasm(args) -> int:
    b = open_binary(args.binary)
    if args.function is not None:
        va = _resolve_target(b, args.function)
        return _disasm_function(b, va, args)
    # raw linear disassembly at address/offset
    va = _resolve_target(b, args.target)
    sec = b.section_at(va)
    if sec is None:
        raise NRTError(f"address {va:#x} is not mapped")
    dis = Disassembler.for_binary(b)
    count = args.count
    data = b.read_va(va, count * 16 if count else 4096)
    insns = dis.linear(data, va, max_insns=count or 256, on_error="stop")
    rows = [
        {"addr": i.addr, "bytes": i.data.hex(), "mnemonic": i.mnemonic, "op_str": i.op_str}
        for i in insns.values()
    ]
    if args.json:
        _json_out(rows)
    else:
        for r in rows:
            print(f"{fmt_addr(r['addr'], b.bits)}  {r['bytes'].ljust(24)} {r['mnemonic']} {r['op_str']}".rstrip())
    return 0


def cmd_functions(args) -> int:
    b = open_binary(args.binary)
    res = discover_functions(b, prologue_scan=not args.no_heuristics)
    fns = sorted(res.functions.values(), key=lambda f: f.start)
    if args.json:
        _json_out({
            "total": res.total,
            "from_symbols": res.from_symbols,
            "from_heuristics": res.from_heuristics,
            "functions": [
                {"start": f.start, "name": f.name, "blocks": f.num_blocks,
                 "insns": f.num_insns, "discovered": f.discovered}
                for f in fns
            ],
        })
    else:
        print(f"{res.total} functions ({res.from_symbols} from symbols, "
              f"{res.from_heuristics} from heuristics)")
        for f in fns:
            mark = "*" if f.discovered else " "
            print(f" {mark}{fmt_addr(f.start, b.bits)}  {f.num_blocks:>4} blk {f.num_insns:>5} insn  {f.name}")
    return 0


def cmd_cfg(args) -> int:
    b = open_binary(args.binary)
    va = _resolve_target(b, args.function)
    dis = Disassembler.for_binary(b)

    def in_code(x):
        sec = b.section_at(x)
        return sec is not None and sec.executable

    fn = build_function(dis, b.read_va, in_code, va, b.name_for_address(va) or "")
    if args.dot:
        print(fn.to_dot())
        return 0
    if args.json:
        _json_out({
            "function": fn.start, "name": fn.name,
            "blocks": [
                {"start": blk.start, "end": blk.end,
                 "successors": blk.successors,
                 "insns": [i.addr for i in blk.insns]}
                for blk in sorted(fn.blocks.values(), key=lambda x: x.start)
            ],
            "edges": [
                {"src": s, "dst": d, "kind": k} for s, d, k in fn.edges
            ],
        })
        return 0
    print(f"function {fn.name or '?'} @ {fmt_addr(fn.start, b.bits)}: "
          f"{fn.num_blocks} blocks, {len(fn.edges)} edges")
    for blk in sorted(fn.blocks.values(), key=lambda x: x.start):
        succ = ", ".join(f"{fmt_addr(s, b.bits)}({blk.edge_kinds.get(s, '')})" for s in blk.successors)
        print(f"  block {fmt_addr(blk.start, b.bits)}..{fmt_addr(blk.end, b.bits)} "
              f"({len(blk.insns)} insns) -> {succ or '(exit)'}")
    return 0


def cmd_strings(args) -> int:
    b = open_binary(args.binary)
    encodings = tuple(args.encoding.split(",")) if args.encoding else ("ascii", "utf16le", "utf16be")
    strings = extract_strings(b, min_len=args.min_len, encodings=encodings,
                              include_executable=args.exec_sections)
    if args.json:
        _json_out([
            {"va": s.va, "offset": s.offset, "encoding": s.encoding,
             "section": s.section, "value": s.value}
            for s in strings
        ])
    else:
        for s in strings:
            print(f"{fmt_addr(s.va, b.bits)} [{s.encoding:<7}] {s.escaped}")
    return 0


def cmd_xrefs(args) -> int:
    b = open_binary(args.binary)
    res = discover_functions(b)
    strings = extract_strings(b)
    db = build_xrefs(b, res.functions, strings)
    if args.to is not None:
        dst = _resolve_target(b, args.to)
        hits = db.to(dst)
        if args.json:
            _json_out([asdict(x) for x in hits])
        else:
            name = b.name_for_address(dst) or ""
            print(f"xrefs to {fmt_addr(dst, b.bits)} {name}: {len(hits)}")
            for x in hits:
                srcname = b.name_for_address(x.src_function) or fmt_addr(x.src_function, b.bits)
                print(f"  {x.kind:<10} from {fmt_addr(x.src, b.bits)} in {srcname}")
        return 0
    if args.json:
        _json_out([asdict(x) for x in db.xrefs])
    else:
        for x in db.xrefs[: args.limit]:
            dst_name = f"  ; {x.dst_name}" if x.dst_name else ""
            print(f"{fmt_addr(x.src, b.bits)} {x.kind:<10} {fmt_addr(x.dst, b.bits)}{dst_name}")
        if len(db.xrefs) > args.limit:
            print(f"... ({len(db.xrefs) - args.limit} more, use --limit or --json)")
    return 0


def cmd_scan(args) -> int:
    if args.list:
        sigs = load_signatures(args.pack)
        for s in sigs:
            print(f"{s.name:<24} [{', '.join(s.tags)}] {s.description}")
        return 0
    b = open_binary(args.binary)
    sigs = load_signatures(args.pack)
    matches = scan_binary(b, sigs)
    if args.json:
        _json_out([m.to_dict() for m in matches])
    else:
        print(f"{len(matches)} signature matches")
        for m in matches:
            print(f"{fmt_addr(m.va, b.bits)} {m.name:<24} [{', '.join(m.tags)}]")
    return 0


def cmd_yara(args) -> int:
    from .analysis.signatures import yara_scan

    with open(args.rules, "r", encoding="utf-8") as fh:
        source = fh.read()
    results = yara_scan(args.binary, source)
    if args.json:
        _json_out(results)
    else:
        for r in results:
            print(f"rule {r['rule']} [{', '.join(r['tags'])}]: {len(r['matches'])} matches")
            for m in r["matches"][:20]:
                print(f"  +0x{m['offset']:x} {m['identifier']}")
    return 0


def cmd_entropy(args) -> int:
    b = open_binary(args.binary)
    rep = analyze_entropy(b)
    if args.json:
        _json_out(rep.to_dict())
    else:
        print(f"file entropy: {rep.file_entropy:.4f}  "
              f"packed_suspect={rep.packed_suspect}  overlay={rep.overlay_size} bytes")
        for s in rep.sections:
            print(f"  {s.name:<16} {fmt_addr(s.vaddr, b.bits)} {s.size:>8} bytes  "
                  f"{s.entropy:6.3f}  {s.verdict}")
    return 0


def cmd_diff(args) -> int:
    old = open_binary(args.old)
    new = open_binary(args.new)
    rep = diff_binaries(old, new, fuzzy_threshold=args.threshold)
    if args.json:
        _json_out(rep.to_dict())
    else:
        s = rep.summary()
        print(f"old: {old.describe()['path']}  ({s['old_functions']} functions)")
        print(f"new: {new.describe()['path']}  ({s['new_functions']} functions)")
        print(f"matched={s['matched']} identical={s['identical']} "
              f"changed={s['changed']} added={s['added']} removed={s['removed']}")
        for p in rep.changed:
            print(f"  CHANGED  {(p.old.name or fmt_addr(p.old.start, old.bits)):<32} "
                  f"similarity={p.similarity:.3f} ({p.match_method})")
        for p in rep.added:
            print(f"  ADDED    {p.new.name or fmt_addr(p.new.start, new.bits)}")
        for p in rep.removed:
            print(f"  REMOVED  {p.old.name or fmt_addr(p.old.start, old.bits)}")
    return 0


def cmd_hexdump(args) -> int:
    b = open_binary(args.binary)
    va = _resolve_target(b, args.target)
    data = b.read_va(va, args.length)
    if not data:
        off = int(args.target, 0) if not args.target.startswith("0x") else int(args.target, 16)
        with open(args.binary, "rb") as fh:
            fh.seek(off)
            data = fh.read(args.length)
        va = off
    print(hexdump(data, base=va))
    return 0


def cmd_report(args) -> int:
    b = open_binary(args.binary)
    rep = build_report(b, with_disasm=args.full)
    if args.format == "json":
        out = report_json(rep)
    elif args.format == "html":
        out = report_html(rep)
    else:
        out = report_text(rep)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


# ----------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nrt",
        description="native-re-toolkit: static analysis of native binaries (ELF/PE/Mach-O)",
    )
    p.add_argument("--version", action="version", version=f"native-re-toolkit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, binary_arg=True):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
        if binary_arg:
            sp.add_argument("binary", help="path to the binary")
        sp.add_argument("--json", action="store_true", help="JSON output")
        return sp

    add("info", cmd_info, "file identification, security features")

    sp = add("sections", cmd_sections, "list sections")

    sp = add("symbols", cmd_symbols, "list symbols")
    sp.add_argument("--funcs-only", action="store_true")

    sp = add("imports", cmd_imports, "list imports")
    sp.add_argument("--classify", action="store_true", help="group by capability")

    add("exports", cmd_exports, "list exports")

    sp = add("disasm", cmd_disasm, "disassemble at address or symbol")
    sp.add_argument("target", nargs="?", default="0", help="address (0x..) or symbol")
    sp.add_argument("--function", "-f", help="disassemble whole function (address or name)")
    sp.add_argument("--count", "-n", type=int, default=32, help="instruction count (linear mode)")

    sp = add("functions", cmd_functions, "discover functions")
    sp.add_argument("--no-heuristics", action="store_true", help="symbols only")

    sp = add("cfg", cmd_cfg, "control-flow graph of a function")
    sp.add_argument("function", help="address or symbol name")
    sp.add_argument("--dot", action="store_true", help="emit Graphviz DOT")

    sp = add("strings", cmd_strings, "extract strings")
    sp.add_argument("--min-len", type=int, default=4)
    sp.add_argument("--encoding", help="comma list: ascii,utf16le,utf16be")
    sp.add_argument("--exec-sections", action="store_true", help="also scan code sections")

    sp = add("xrefs", cmd_xrefs, "cross-references")
    sp.add_argument("--to", help="only xrefs to this address/symbol")
    sp.add_argument("--limit", type=int, default=200)

    sp = add("scan", cmd_scan, "signature scan (crypto constants, etc.)")
    sp.add_argument("--pack", help="custom signature pack JSON")
    sp.add_argument("--list", action="store_true", help="list available signatures")

    sp = add("yara", cmd_yara, "scan with a YARA rules file (needs yara-python)")
    sp.add_argument("rules", help="path to .yar rules file")

    add("entropy", cmd_entropy, "entropy / packing analysis")

    sp = add("diff", cmd_diff, "function-level binary diff", binary_arg=False)
    sp.add_argument("old", help="old binary")
    sp.add_argument("new", help="new binary")
    sp.add_argument("--threshold", type=float, default=0.55, help="fuzzy match threshold")

    sp = add("hexdump", cmd_hexdump, "hexdump at address or offset")
    sp.add_argument("target", help="address (0x..) or symbol")
    sp.add_argument("--length", "-l", type=int, default=128)

    sp = add("report", cmd_report, "full analysis report")
    sp.add_argument("--format", choices=["text", "json", "html"], default="text")
    sp.add_argument("--output", "-o", help="write to file")
    sp.add_argument("--full", action="store_true", help="include full disassembly")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except NRTError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
