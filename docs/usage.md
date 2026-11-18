# CLI usage

All commands accept `--json` for machine-readable output (unless noted).
Addresses can be given in hex (`0x401146`) or as symbol names (`main`,
`printf@plt` via `--to`/`--function` resolution).

## nrt info BINARY

Format, architecture, entry point, image base, SHA-256, security features
(NX, PIE, RELRO, stack canary, stripped), linked libraries, overlay size.

## nrt sections BINARY

Section table: virtual address/size, file offset/size, permission flags.

## nrt symbols BINARY [--funcs-only]

All symbols (value, type, binding); `--funcs-only` keeps functions and
imports.

## nrt imports BINARY [--classify]

Imported symbols per library. `--classify` groups them into capability
categories (network, crypto, process execution, memory injection,
registry, anti-debug, persistence, screen/input).

## nrt exports BINARY

Exported symbols (PE exports, dynamic symbols of shared objects).

## nrt disasm BINARY [TARGET] [-n COUNT]

Linear disassembly starting at TARGET (address or symbol).
`nrt disasm BINARY --function FUNC` instead disassembles the whole
function recovered by recursive descent.

## nrt functions BINARY [--no-heuristics]

Recovered functions with block/instruction counts. `*` marks
heuristic-only (prologue/call-target) discoveries; `--no-heuristics`
restricts to symbol-driven recovery.

## nrt cfg BINARY FUNCTION [--dot]

Basic blocks and typed CFG edges of a function. `--dot` emits Graphviz
DOT (pipe into `dot -Tpng`).

## nrt strings BINARY [--min-len N] [--encoding ascii,utf16le,utf16be] [--exec-sections]

String extraction. By default scans non-executable sections only;
`--exec-sections` includes code (more false positives).

## nrt xrefs BINARY [--to TARGET] [--limit N]

Full xref listing, or only references to one address/symbol with `--to`.
Entry format: `SRC kind DST ; resolved-name`.

## nrt scan BINARY [--pack FILE] [--list]

Wildcard byte-signature scan. The bundled pack covers SHA-256/SHA-1/MD5
constants, AES S-boxes, ChaCha20 sigma, CRC32-IEEE table and the Base64
alphabet. `--list` prints the pack. Custom packs are JSON:

```json
{
  "version": 1,
  "signatures": [
    {"name": "my_sig", "pattern": "48 8d ?? 24 0f", "tags": ["demo"],
     "description": "example"}
  ]
}
```

Pattern syntax: hex bytes, `??` wildcard byte, `4?`/`?f` nibble wildcards.

## nrt yara BINARY RULES.yar

Scan with a YARA rules file. Requires the optional dependency:
`pip install native-re-toolkit[yara]`.

## nrt entropy BINARY

Per-section Shannon entropy, packer heuristic (executable/writable
sections above 7.2 bits/byte), PE overlay size.

## nrt diff OLD NEW [--threshold F]

Function-level diff. Output classifies matched pairs as
identical/changed (with similarity and match method), plus added and
removed functions.

## nrt hexdump BINARY TARGET [-l N]

Hexdump starting at an address or symbol.

## nrt report BINARY [--format text|json|html] [-o FILE] [--full]

Full analysis report. `--full` embeds the complete disassembly of every
function (large!).

## Exit codes

`0` success, `1` analysis/IO error, `2` argument parsing error.
