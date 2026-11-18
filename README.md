# native-re-toolkit

Static analysis toolkit for native binaries (ELF, PE, Mach-O) written in
Python on top of [Capstone](https://www.capstone-engine.org/). Built for
reverse-engineering workflows: load a binary, recover its functions and
control-flow graphs, follow cross-references, extract strings, hunt for
cryptographic constants, measure entropy, and diff two builds of the same
program.

> **Ringkasan (ID):** toolkit analisis statis binary native — disassembly,
> recovery fungsi + CFG, xref, ekstraksi string, scan signature konstanta
> crypto, deteksi packer via entropi, dan diffing antar versi binary.
> Lihat *Quick start* di bawah; dokumentasi lengkap di [`docs/`](docs/).

## Features

- **Loaders**: ELF (via pyelftools) with PLT/GOT resolution and security
  feature detection (NX, PIE, RELRO, canary, stripped), PE (via pefile)
  with overlay detection and DllCharacteristics, minimal pure-Python
  Mach-O parser (incl. fat binaries).
- **Disassembly**: Capstone-backed; linear sweep and recursive descent
  with jump-table support; fast-path classification that is ~8x cheaper
  than full operand detail.
- **Function recovery**: symbol-driven seeds, entry point, PLT stubs,
  call-target following, plus prologue heuristics for stripped binaries
  (validated at ≥80% recovery of compiler-generated functions on the
  bundled fixtures).
- **CFG**: basic blocks with typed edges (`cond_true`/`cond_false`,
  `jump`, `jump_table`, `fallthrough`), Graphviz DOT export.
- **Xrefs**: call/jump/data references with resolution to symbols, PLT
  names, GOT imports and strings (RIP-relative *and* absolute addressing).
- **Strings**: ASCII + UTF-16LE/BE extraction with NUL-termination rules.
- **Signatures**: wildcard byte patterns (`48 8d ?? 24`, nibble wildcards
  `4?`/`?f`), bundled pack of well-known crypto constants (SHA-256, SHA-1,
  MD5, AES S-boxes, ChaCha20 sigma, CRC32, Base64 alphabet); optional
  YARA bridge (`pip install native-re-toolkit[yara]`).
- **Entropy**: per-section Shannon entropy with packer heuristics and
  PE overlay reporting.
- **Diffing**: function-level binary diff (name → address → exact
  mnemonic-hash → fuzzy similarity matching; size-aware thresholds to
  avoid false pairs on tiny functions).
- **Reports**: JSON, standalone HTML, and terminal text.
- **Import classification**: capability buckets (network, crypto,
  process execution, injection, registry, anti-debug, ...).

## Install

```bash
git clone https://github.com/NgawiNgab/native-re-toolkit.git
cd native-re-toolkit
./bootstrap.sh          # venv + deps + fixture build + test suite
```

Or install the release artifacts directly:

```bash
pip install dist/native_re_toolkit-*.whl      # library + `nrt` command
python nrt.pyz info /bin/ls                   # zero-install single file
```

Optional extras: `pip install native-re-toolkit[yara]` (YARA scanning),
`pip install native-re-toolkit[dev]` (pytest).

## Quick start

```bash
nrt info /bin/ls                     # format, arch, security features
nrt functions /bin/ls                # recovered functions (* = heuristic)
nrt disasm --function main ./hello   # full function disassembly
nrt cfg ./hello main --dot | dot -Tpng > cfg.png
nrt strings --min-len 6 ./hello
nrt xrefs --to printf ./hello        # who calls printf?
nrt scan ./suspect.bin               # crypto-constant signatures
nrt entropy ./packed.bin             # packer heuristic + overlay
nrt diff ./v1 ./v2                   # function-level diff
nrt report ./hello --format html -o report.html
```

Every command accepts `--json` for machine-readable output.

### Python API

```python
from native_re_toolkit import open_binary
from native_re_toolkit.disasm.discovery import discover_functions
from native_re_toolkit.analysis.strings import extract_strings
from native_re_toolkit.analysis.xrefs import build_xrefs

b = open_binary("./hello")
res = discover_functions(b)
strings = extract_strings(b)
db = build_xrefs(b, res.functions, strings)

main = b.symbol_named("main")
fn = res.functions[main.value]
print(hex(fn.start), fn.num_blocks, "blocks")
for x in db.calls_to(main.value):
    print(f"called from {hex(x.src)}")
```

## Performance

Full pipeline (load → discovery+CFG → strings → xrefs), measured in this
repo's CI-like environment (2 vCPU sandbox, Python 3.11):

| Binary | Size | Time | Peak RSS | Functions | Instructions |
|---|---|---|---|---|---|
| hello (fixture) | 15.6 KiB | ~0.01 s | ~33 MB | 15 | 190 |
| python3.11 | 6.5 MiB | ~9.3 s | ~1.1 GB | 3,290 | 830,622 |

See [`docs/benchmarks.md`](docs/benchmarks.md) for details and
`scripts/bench.py` to reproduce.

## Documentation

- [`docs/usage.md`](docs/usage.md) — CLI reference
- [`docs/architecture.md`](docs/architecture.md) — design and data model
- [`docs/limitations.md`](docs/limitations.md) — known limitations,
  false-positive/negative notes
- [`docs/benchmarks.md`](docs/benchmarks.md) — performance measurements

## Development

```bash
./bootstrap.sh                 # idempotent environment setup
.venv/bin/python -m pytest     # 118 regression tests (gcc-built fixtures)
.venv/bin/python scripts/bench.py /bin/ls
```

Test fixtures are compiled from C sources in `tests/fixtures/src` at test
time (skipped gracefully when gcc is absent); PE and Mach-O loader tests
use synthetic binaries built in `tests/synth.py`.

## License

MIT. Bundled dependencies keep their own licenses (capstone: BSD-3,
pyelftools: public domain, pefile: MIT); see `NOTICE` in release archives.
