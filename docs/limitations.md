# Known limitations

Being honest about what static analysis can and cannot do. Entries marked
*(tested)* have regression tests; the rest are inherent or untested edges.

## Loader

- **ELF**: import names cannot be attributed to specific `DT_NEEDED`
  libraries (ELF records no such mapping); they are grouped under a
  synthetic `(undefined)` bucket. Symbol versioning is stripped
  (`printf@GLIBC_2.2.5` → `printf`). Relocation addends are parsed but
  not applied.
- **PE**: no import-by-ordinal name resolution (reported as
  `ordinal_N`). Bound imports and forwarded exports are not resolved.
  Driver/WDM binaries parse but are untested.
- **Mach-O**: minimal parser — headers, `LC_SEGMENT(64)` sections,
  `LC_SYMTAB` symbols. No dyld chained fixups, no Objective-C metadata,
  no code-signature parsing. Fat binaries: only the first slice is
  parsed. *(tested on synthetic binaries only — no Mach-O compiler in
  CI)*
- Raw blobs, firmware images, and archives (.a/.lib) are not loadable.

## Disassembly & function recovery

- Architectures with full support: **x86 / x86-64**. ARM64 and ARM are
  classified (branches/calls/rets) but data-reference recovery is
  limited (no `adrp`+`add` pairing). MIPS/PPC/SPARC use generic
  group-based classification; other architectures raise
  `UnsupportedArchError`. Only x86-64 is covered by the regression
  suite (that is what the CI toolchain compiles).
- **Stripped binaries**: prologue heuristics recover ≥ 80% of
  compiler-generated functions on the gcc fixtures *(tested)*. Expect
  misses for: handwritten assembly without prologues, alignment stubs
  like a lone `ret`, and functions only reachable via indirect calls.
- **Inline data in code sections** (jump tables embedded in `.text`,
  switch tables in `.rodata` are fine) can desynchronize the linearly
  decoded instruction pool. The pool is validated against symbol
  boundaries (95% coverage) and discovery falls back to streaming
  decode below that, but heavily obfuscated code may still confuse it.
- **Jump tables**: recovered for the absolute-addressing form
  (`jmp [reg*8 + table]`, non-PIE; the IBT `notrack` variant is
  handled). The table must live in a non-writable, non-executable
  section and have at least two entries — single GOT/function pointers
  are deliberately not treated as tables. PIC/PIE offset tables
  (`movsxd`+`add`) are not yet resolved — those switch cases appear as
  an unresolved indirect jump. *(tested for the absolute form, with and
  without IBT)*
- **Indirect calls** (vtables, callbacks, `call rax`) have no target
  xref — inherent to static analysis.
- Obfuscated control flow (opaque predicates, self-modifying code,
  exception-based flow) is out of scope.

## Cross-references

- Data xrefs cover RIP-relative and absolute-immediate references on
  x86/x86-64. References computed at runtime (pointers in registers
  built by arithmetic) are not tracked.
- `mem_write` classification on the fast path uses a mnemonic-based
  heuristic; `cmp`/`test`/`push` are corrected, exotic read-modify-write
  instructions may be misclassified.
- String xrefs resolve via the string index; strings inside writable
  sections that were not extracted (too short, non-printable) yield
  unnamed data xrefs.

## Strings

- ASCII runs must be NUL-terminated to count; unterminated runs at
  section end are accepted, mid-section unterminated runs are dropped.
  This intentionally differs from GNU `strings` (fewer false positives,
  occasionally missing trailing fragments).
- UTF-16 requires 2-byte alignment to the section start and ASCII-range
  code units; wide strings outside the ASCII range are not detected.
- Very short strings (< min-len, default 4) are skipped — false
  negatives by design.

## Signatures

- Constant-table signatures prove the *constants* are present, not that
  the algorithm is used (e.g. a CRC32 table may be linked but dead).
- The bundled pack covers common tables; it does not include
  per-library code signatures (FLIRT). Custom packs are supported via
  `nrt scan --pack`.
- Wildcard-only prefixes are slow (brute force); give patterns a solid
  anchor run.

## Diffing

- Similarity is mnemonic-sequence based: instruction scheduling and
  operand changes are ignored. Two functions that differ only in an
  immediate (e.g. a format string address) are reported *identical* —
  this is deliberate, but means "changed" ≈ "structurally changed".
- Tiny functions (< 15 instructions) need ≥ 0.9 similarity to pair;
  below that they are reported as added+removed rather than changed.
- In stripped pairs, same-address matching can report a replaced
  function as "changed" when it was semantically removed+added.
- Fuzzy matching is O(n·m) over the unmatched remainder — on two huge
  stripped binaries with little overlap this is the slowest part.

## Performance / scale

- Measured (sandbox: 2 vCPU, 3.8 GB RAM): 6.5 MiB `python3.11` (830k
  instructions) takes ~9 s and peaks at ~1.1 GB RSS for the full
  pipeline. Persistent structures dominate memory; expect roughly
  1.2-1.5 KB per decoded instruction. Very large binaries (> 50 MB of
  code) may exceed small-machine RAM — analyze per-function
  (`nrt disasm --function`) in that case, which streams instead of
  pooling.
- `--full` JSON/HTML reports embed all instructions and can be huge.

## Testing coverage notes

- All 118 tests run on x86-64 Linux. PE/Mach-O tests use synthetic
  binaries (no cross-compiler in CI); real-world PE/Mach-O quirks
  (authenticode, resource sections, fat slices beyond the first) are
  untested.
- The YARA bridge is optional and exercised only when `yara-python` is
  installed.
