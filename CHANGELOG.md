# Changelog

## Unreleased

Fixed (regressed only on CET/IBT toolchain layouts, e.g. Ubuntu defaults
`-fcf-protection=full` + `.plt.sec`; CI on ubuntu-latest caught these):

- **ELF loader**: IBT `.plt.sec` stubs are keyed by their `endbr64`
  entry, not by the `jmp *GOT` four bytes later. Wrong keys meant calls
  resolved to `_init+0x60`-style names instead of `printf@plt`, and
  `__stack_chk_fail` was not recognized as noreturn — letting `main`'s
  CFG fall through into `_start` and dropping it from discovery.
- **Disassembly**: capstone-fused prefix mnemonics (`notrack jmp`,
  `bnd jmp`, `repz ret`) are normalized before classification; without
  this, IBT switch dispatch (`notrack jmp [reg*8+base]`) was invisible,
  so jump tables were not recovered and `repz ret` did not terminate a
  block.
- **CFG**: absolute jump tables now require a non-writable,
  non-executable host section and at least two entries — GOT slots and
  function pointers are no longer misread as one-entry "tables" that
  pulled the PLT resolver into stub functions.
- Tests: 9 new IBT regression tests (insn-level + fixture-level with
  `-fcf-protection=full -Wl,-z,ibtplt` builds, skipped on toolchains
  without ibtplt support).

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
