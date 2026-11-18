# Changelog

## 0.1.0 (2026-11-17)

Initial release.

- Loaders: ELF (pyelftools; PLT/GOT resolution, security features),
  PE (pefile; imports/exports, overlay, DllCharacteristics),
  minimal pure-Python Mach-O (headers, sections, symtab, fat binaries).
- Disassembly: Capstone fast path (~8x cheaper than detail mode) with
  linear sweep, recursive descent, jump-table recovery, noreturn-call
  handling, per-section instruction pools with streaming fallback.
- Function discovery: symbols + entry + PLT stubs, prologue heuristics
  and call-target harvesting for stripped binaries.
- Analysis: strings (ASCII/UTF-16LE/BE), xref database (calls, jumps,
  RIP-relative and absolute data refs with string/GOT resolution),
  entropy + packer heuristic, import capability classification,
  wildcard byte-signature engine with bundled crypto-constants pack,
  optional YARA bridge.
- Function-level binary diffing (name/address/hash/fuzzy matching).
- Reports: text, JSON, standalone HTML.
- CLI: `nrt` with 15 subcommands; `nrt.pyz` single-file distribution.
- 118 regression tests; fixtures compiled from C sources at test time.
