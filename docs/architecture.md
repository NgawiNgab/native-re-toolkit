# Architecture

## Package layout

```
src/native_re_toolkit/
├── loader/            # binary format parsing
│   ├── detect.py      #   magic-byte format detection
│   ├── binary.py      #   Binary/Section/Symbol/Relocation model + VA mapping
│   ├── elf.py         #   ELF via pyelftools (+ PLT/GOT resolution)
│   ├── pe.py          #   PE via pefile (+ overlay)
│   └── macho.py       #   minimal pure-Python Mach-O (incl. fat)
├── disasm/
│   ├── archs.py       #   arch/bits/endian -> capstone mapping
│   ├── insn.py        #   normalized Insn; fast (op_str) + detail paths
│   ├── engine.py      #   linear sweep, streaming RD, instruction pools
│   ├── cfg.py         #   BasicBlock/Function, CFG edges, DOT export
│   └── discovery.py   #   function discovery (symbols + heuristics)
├── analysis/
│   ├── strings.py     #   ASCII/UTF-16 extraction + StringIndex
│   ├── xrefs.py       #   xref database (call/jump/data_read/data_write)
│   ├── entropy.py     #   Shannon entropy, packer heuristic, overlay
│   ├── impcat.py      #   import capability classification
│   └── signatures.py  #   wildcard byte patterns, bundled pack, YARA bridge
├── diff/bindiff.py    #   function-level binary diffing
├── report/            #   JSON / HTML / text reports
├── util/              #   hexdump, anchored pattern search
└── cli.py             #   the `nrt` command
```

## Data flow

```
bytes on disk
   │  loader.detect / open_binary
   ▼
Binary ── sections, symbols, imports, relocations, PLT/GOT maps
   │
   ├─► Disassembler.build_pool()      one streaming decode per exec section
   │
   ├─► discover_functions()           seeds: symbols, entry, PLT stubs
   │      │                             phase 2: prologue patterns + call targets
   │      ▼
   │   Function[]  (recursive-descent over pool → basic blocks → CFG)
   │
   ├─► extract_strings()              ASCII / UTF-16LE / UTF-16BE
   │
   ├─► build_xrefs(functions, strs)   call/jump/data refs, name resolution
   │
   ├─► scan_binary()                  signature pack matching
   │
   └─► analyze_entropy()              per-section entropy, overlay
   │
   ▼
report (JSON / HTML / text)
```

## Key design decisions

### Two disassembly paths

Capstone's operand detail (`Cs.detail = True`) costs roughly 8x more than
plain decoding. The default path decodes with `detail = False` and
recovers semantics from mnemonic tables plus Intel-syntax `op_str`
parsing (branch targets, RIP-relative references, absolute references,
immediates). The detail path remains available (`disasm(..., detail=True)`)
and was used to validate the fast path: on 300k instructions of
`python3.11` the paths diverge on 0.06% of instructions, all benign
(segment-relative `fs:[0x28]` canary reads, which the fast path
deliberately does not report as flat addresses).

### Instruction pool

Whole-program analysis decodes each executable section **once** into an
`addr -> Insn` pool (`Disassembler.build_pool`), with count-capped decode
rounds to bound the transient C-side instruction array. Recursive descent
then walks the pool. Fallback: if fewer than 95% of known function symbols
land on pool instruction boundaries (a sign of heavy inline data on
variable-length ISAs), discovery switches back to per-function streaming
decode.

### Function discovery

1. Seeds: STT_FUNC symbols, entry point, exported symbols, PLT stubs
   (mapped to import names by disassembling PLT sections and following
   the indirect jumps to JUMP_SLOT GOT entries).
2. Recursive descent from seeds; direct call targets become new seeds.
3. Gap scan over unclaimed executable bytes with anchored prologue
   patterns (`endbr64`, `push rbp; mov rbp,rsp`, ...). Candidates are
   validated by a clean-termination check and non-overlap with claimed
   bytes.
4. Call targets harvested from heuristically accepted functions get a
   second-chance pass (finds prologue-less helpers such as
   `deregister_tm_clones` and single-instruction stubs).

Calls to known noreturn functions (`exit`, `abort`, `__stack_chk_fail`,
...) terminate the current block; without this, recursive descent runs
past them into the next function's bytes.

### Cross-references

* Direct `call` targets → `call` xrefs (PLT stubs resolved to names).
* Direct jumps leaving the function → `jump` xrefs (tail calls).
* RIP-relative memory operands → `data_read`/`data_write` xrefs, resolved
  against GOT imports, the string index and symbols.
* Absolute immediates pointing into mapped sections (non-PIE addressing,
  e.g. `mov edi, 0x402004`) → `data_read` xrefs with the same resolution.

### Diffing

Matching order: identical names → identical addresses (same-layout
stripped builds) → exact mnemonic-sequence hash → fuzzy
`difflib.SequenceMatcher` ratio. Tiny functions (< 15 instructions) need
≥ 0.9 similarity to pair; larger ones use the configurable threshold
(default 0.55). This avoids pairing mechanically similar stubs.
PLT thunks are excluded from diffs.
