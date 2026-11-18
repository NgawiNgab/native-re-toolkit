"""Report building and rendering (JSON / HTML / text)."""

from __future__ import annotations

import html as html_mod
import json
from typing import Optional

from .. import __version__
from ..analysis.entropy import analyze_entropy
from ..analysis.impcat import classify_imports
from ..analysis.signatures import load_signatures, scan_binary
from ..analysis.strings import extract_strings
from ..analysis.xrefs import build_xrefs
from ..disasm.discovery import discover_functions
from ..loader.binary import Binary


def build_report(
    binary: Binary,
    *,
    with_disasm: bool = False,
    max_strings: int = 500,
    max_functions: int = 2000,
    scan_sigs: bool = True,
    min_string_len: int = 4,
) -> dict:
    """Run the full analysis pipeline and return a JSON-able report."""
    discovery = discover_functions(binary)
    functions = discovery.functions
    strings = extract_strings(binary, min_len=min_string_len)
    xrefs = build_xrefs(binary, functions, strings)
    entropy = analyze_entropy(binary)
    sig_matches = scan_binary(binary, load_signatures()) if scan_sigs else []
    import_classes = classify_imports(binary.imported_function_names())

    func_entries = []
    for fn in sorted(functions.values(), key=lambda f: f.start)[:max_functions]:
        entry = {
            "start": fn.start,
            "end": fn.end,
            "name": fn.name,
            "blocks": fn.num_blocks,
            "instructions": fn.num_insns,
            "calls": sorted(fn.calls),
            "discovered": fn.discovered,
        }
        if with_disasm:
            entry["disasm"] = [
                {
                    "addr": i.addr,
                    "bytes": i.data.hex(),
                    "mnemonic": i.mnemonic,
                    "op_str": i.op_str,
                }
                for i in (fn.insns[a] for a in sorted(fn.insns))
            ]
        func_entries.append(entry)

    security = dict(getattr(binary, "security", {}))
    return {
        "tool": {"name": "native-re-toolkit", "version": __version__},
        "binary": binary.describe(),
        "sha256": binary.sha256,
        "security": security,
        "libraries": getattr(binary, "libraries", sorted(binary.imports)),
        "imports": {k: sorted(v) for k, v in sorted(binary.imports.items())},
        "import_categories": import_classes,
        "exports": [
            {"name": s.name, "value": s.value} for s in binary.exports[:1000]
        ],
        "sections": [
            {
                "name": s.name,
                "vaddr": s.vaddr,
                "vsize": s.vsize,
                "offset": s.offset,
                "size": s.size,
                "flags": s.flags,
            }
            for s in binary.sections
        ],
        "entropy": entropy.to_dict(),
        "functions": {
            "total": len(functions),
            "from_symbols": discovery.from_symbols,
            "from_heuristics": discovery.from_heuristics,
            "list": func_entries,
        },
        "strings": {
            "total": len(strings),
            "list": [
                {
                    "va": s.va,
                    "offset": s.offset,
                    "encoding": s.encoding,
                    "section": s.section,
                    "value": s.value,
                }
                for s in strings[:max_strings]
            ],
            "truncated": len(strings) > max_strings,
        },
        "xrefs": {
            "total": len(xrefs.xrefs),
            "calls": sum(1 for x in xrefs.xrefs if x.kind == "call"),
            "data_reads": sum(1 for x in xrefs.xrefs if x.kind == "data_read"),
            "data_writes": sum(1 for x in xrefs.xrefs if x.kind == "data_write"),
        },
        "signature_matches": [m.to_dict() for m in sig_matches],
    }


def report_json(report: dict, *, indent: int = 2) -> str:
    return json.dumps(report, indent=indent, sort_keys=False, default=_json_default)


def _json_default(o):
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, set):
        return sorted(o)
    return str(o)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>native-re-toolkit report - {title}</title>
<style>
 body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; margin: 2rem; background: #fafafa; color: #222; }}
 h1 {{ font-size: 1.5rem; }} h2 {{ font-size: 1.15rem; border-bottom: 2px solid #ddd; padding-bottom: .2rem; margin-top: 2rem; }}
 table {{ border-collapse: collapse; width: 100%; font-size: .85rem; }}
 th, td {{ border: 1px solid #ddd; padding: .3rem .5rem; text-align: left; }}
 th {{ background: #eee; }}
 code, .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; }}
 .warn {{ color: #b00; font-weight: 600; }}
 .ok {{ color: #070; }}
 .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: .5rem; }}
 .card {{ background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: .6rem .8rem; }}
 .card .k {{ font-size: .75rem; color: #666; }} .card .v {{ font-size: 1.1rem; font-weight: 600; }}
 details {{ margin: .3rem 0; }} summary {{ cursor: pointer; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def _esc(x) -> str:
    return html_mod.escape(str(x))


def report_html(report: dict) -> str:
    """Render a standalone HTML report."""
    b = report["binary"]
    parts: list[str] = []
    parts.append(f"<h1>native-re-toolkit report</h1>")
    parts.append(f"<p class='mono'>{_esc(b['path'])}</p>")
    cards = [
        ("Format", f"{b['format'].upper()} {b['bits']}-bit"),
        ("Architecture", b["arch"]),
        ("Entry point", f"0x{b['entry']:x}"),
        ("File size", b["file_size"]),
        ("Functions", report["functions"]["total"]),
        ("Strings", report["strings"]["total"]),
        ("Xrefs", report["xrefs"]["total"]),
        ("File entropy", report["entropy"]["file_entropy"]),
    ]
    parts.append("<div class='grid'>" + "".join(
        f"<div class='card'><div class='k'>{_esc(k)}</div><div class='v'>{_esc(v)}</div></div>"
        for k, v in cards
    ) + "</div>")

    sec = report.get("security", {})
    if sec:
        parts.append("<h2>Security features</h2><table><tr><th>Feature</th><th>Status</th></tr>")
        for k, v in sec.items():
            cls = "ok" if v else "warn"
            parts.append(f"<tr><td>{_esc(k)}</td><td class='{cls}'>{_esc(v)}</td></tr>")
        parts.append("</table>")

    ent = report["entropy"]
    parts.append("<h2>Sections &amp; entropy</h2><table><tr><th>Name</th><th>VirtAddr</th><th>Size</th><th>Flags</th><th>Entropy</th><th>Verdict</th></tr>")
    for s in ent["sections"]:
        cls = "warn" if s["verdict"] == "likely_packed" else ""
        parts.append(
            f"<tr class='{cls}'><td>{_esc(s['name'])}</td><td class='mono'>0x{s['vaddr']:x}</td>"
            f"<td>{s['size']}</td><td class='mono'>{_esc(s['flags'])}</td>"
            f"<td>{s['entropy']:.3f}</td><td>{_esc(s['verdict'])}</td></tr>"
        )
    parts.append("</table>")

    cats = report.get("import_categories", {})
    if cats:
        parts.append("<h2>Import categories</h2>")
        for cat, names in cats.items():
            parts.append(
                f"<details><summary><b>{_esc(cat)}</b> ({len(names)})</summary>"
                f"<p class='mono'>{_esc(', '.join(names[:80]))}</p></details>"
            )

    sigs = report.get("signature_matches", [])
    if sigs:
        parts.append("<h2>Signature matches</h2><table><tr><th>Address</th><th>Signature</th><th>Tags</th></tr>")
        for m in sigs:
            parts.append(
                f"<tr><td class='mono'>0x{m['va']:x}</td><td>{_esc(m['name'])}</td>"
                f"<td>{_esc(', '.join(m['tags']))}</td></tr>"
            )
        parts.append("</table>")

    fns = report["functions"]["list"]
    parts.append(f"<h2>Functions ({report['functions']['total']})</h2>")
    parts.append("<table><tr><th>Address</th><th>Name</th><th>Blocks</th><th>Insns</th><th>Source</th></tr>")
    for f in fns:
        src = "heuristic" if f["discovered"] else "symbol"
        parts.append(
            f"<tr><td class='mono'>0x{f['start']:x}</td><td class='mono'>{_esc(f['name'])}</td>"
            f"<td>{f['blocks']}</td><td>{f['instructions']}</td><td>{src}</td></tr>"
        )
    parts.append("</table>")

    strs = report["strings"]["list"]
    parts.append(f"<h2>Strings (showing {len(strs)} of {report['strings']['total']})</h2>")
    parts.append("<table><tr><th>Address</th><th>Encoding</th><th>Value</th></tr>")
    for s in strs:
        parts.append(
            f"<tr><td class='mono'>0x{s['va']:x}</td><td>{_esc(s['encoding'])}</td>"
            f"<td class='mono'>{_esc(s['value'][:120])}</td></tr>"
        )
    parts.append("</table>")

    parts.append(f"<hr><p><small>Generated by native-re-toolkit {report['tool']['version']}</small></p>")
    title = _esc(b["path"].rsplit("/", 1)[-1])
    return _HTML_TEMPLATE.format(title=title, body="\n".join(parts))


def report_text(report: dict) -> str:
    """Compact text summary for the terminal."""
    b = report["binary"]
    lines = [
        f"== {b['path']} ==",
        f"format={b['format']} arch={b['arch']} bits={b['bits']} entry=0x{b['entry']:x} size={b['file_size']}",
        f"sha256={report['sha256']}",
    ]
    sec = report.get("security", {})
    if sec:
        flags = ", ".join(f"{k}={'Y' if v else 'N'}" for k, v in sec.items())
        lines.append(f"security: {flags}")
    lines.append(
        f"functions={report['functions']['total']} "
        f"(symbols={report['functions']['from_symbols']}, heuristics={report['functions']['from_heuristics']})"
    )
    lines.append(f"strings={report['strings']['total']} xrefs={report['xrefs']['total']}")
    lines.append(
        f"file_entropy={report['entropy']['file_entropy']:.3f} "
        f"packed_suspect={report['entropy']['packed_suspect']} "
        f"overlay={report['entropy']['overlay_size']} bytes"
    )
    sigs = report.get("signature_matches", [])
    if sigs:
        lines.append(f"signature_matches={len(sigs)}")
        for m in sigs[:20]:
            lines.append(f"  0x{m['va']:x}  {m['name']}  [{', '.join(m['tags'])}]")
    cats = report.get("import_categories", {})
    if cats:
        lines.append("import_categories: " + ", ".join(f"{k}({len(v)})" for k, v in cats.items()))
    return "\n".join(lines)
