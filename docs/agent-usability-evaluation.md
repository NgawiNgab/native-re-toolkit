# Agent-usability evaluation of native-re-toolkit

**Date:** 2026-11-17 · **Evaluator:** Arena coding agent (using the toolkit as its only
analysis tool) · **Toolkit version:** 0.1.0 + IBT fixes (commit `1f3a784`)

**Method:** two live investigations conducted exclusively through the toolkit's
CLI and Python API, treating the targets as unknown. All decisions were driven by
tool output; every claim below is backed by a reproduced command. Target A was
authored for this session and set aside before analysis (staged-unknown; latent
bias acknowledged). Target B is a distro binary whose internals were not
pre-analyzed.

---

## Investigation A — `/tmp/re-eval/crackme` (staged-unknown target)

Task: *what does this program do, and what input makes it succeed?*

Target: x86-64 ELF, PIE, **stripped**, IBT (`.plt.sec`), 14.2 KiB.

### Decision log (each step chose the next)

| # | Command | Evidence gained | Next-step decision |
|---|---|---|---|
| 1 | `nrt info crackme` | ELF/x86-64/PIE/**stripped**, entry `0x11e0` | need heuristic navigation |
| 2 | `nrt entropy crackme` | file entropy 1.50, all sections normal | not packed → static analysis viable |
| 3 | `nrt imports crackme --classify` | `strcmp`, `memcmp`, `strlen`, `puts`, `printf` | two comparison paths; input-checking program |
| 4 | `nrt strings crackme` | `usage: %s <key>`, `sup3r_s3cret_key`, `nice try`, `ACCESS GRANTED/DENIED`, `DEBUG: maintenance shell engaged` | hypothesis: key-checker with a decoy |
| 5 | `nrt xrefs crackme --to 0x2033` | `data_read from 0x1190 in 0x10e0` | `0x10e0` is the success/failure hub (main) |
| 6 | `nrt xrefs crackme --json` + filter | all 7 string refs originate in fn `0x10e0` | disassemble `0x10e0` |
| 7 | `nrt disasm crackme --function 0x10e0` | full logic: argc check → argv[2] vs `0x2015` → argv[1] vs decoy (`je`→"nice try") → `strlen==12` → 4-byte XOR loop keyed by dword at `0x2084` → `memcmp` vs 12 bytes at `0x2078` → GRANTED/DENIED | extract bytes at `0x2078`/`0x2084` |
| 8 | `nrt hexdump crackme 0x2078 -l 16` | `7c 04 4e 16 68 54 45 03 54 5c 04 53 | 37 37 37 37` | XOR-decode: `enc[i]^0x37` |
| 9 | `nrt xrefs crackme --json` (call kind) | `0x10d0=strcmp@plt`, `0x10a0=strlen@plt`, `0x1090=puts@plt`, `0x10c0=memcmp@plt`, `0x10b0=printf@plt` | semantic confirmation of step 7 |
| 10 | `nrt hexdump crackme 0x2015 -l 8` | `64 62 67 00` = `"dbg"` | hidden debug arg identified |

### Result (execution-verified)

```
decoded key: K3y!_cr4ck3d
$ ./crackme 'K3y!_cr4ck3d'   → ACCESS GRANTED   (exit 0)
$ ./crackme 'sup3r_s3cret_key' → nice try        (exit 1)  ← decoy confirmed
$ ./crackme 'AAAAAAAAAAAA'   → ACCESS DENIED    (exit 1)
```

Recovered facts, all from tool output: 12-char key, XOR `0x37`, encoded bytes at
`0x2078`, key dword at `0x2084`, decoy path via `strcmp`, hidden `"dbg"` argv[2]
(argv[2] compare target recovered by RIP-relative address math: `0x10fe` insn →
`0x1105+0xf10=0x2015`). Manual intervention: zero. Wall time: every command < 0.5 s.

---

## Investigation B — `/usr/bin/cksum` (genuinely unanalyzed target)

Task: *which digest algorithms does this binary implement? Locate the evidence.*

x86-64 ELF, PIE, stripped, 139 KiB, `.text` 92,942 bytes.

| # | Command | Evidence |
|---|---|---|
| 1 | `nrt scan /usr/bin/cksum` | `sha256_init_state` constants at `0x1e260` |
| 2 | `nrt strings ... --json` | algorithm names: `sysv, sha1, sha224, sha256, sha384, sha512, blake2b` at `0x19253..` |
| 3 | `nrt xrefs /usr/bin/cksum --to 0x1e260` | **0 hits — unexpected** |
| 4 | `nrt functions /usr/bin/cksum` | only **89 functions** for 93 KiB of `.text` → suspicion: discovery gap |
| 5 | Python API: linear-decode all of `.text`, filter `mem_ref` to `0x1e2xx` | found refs, e.g. `0x9b40: movdqa xmm0, [rip+0x14718] → 0x1e260`; referencing insns **not covered by any discovered function** |
| 6 | `nrt disasm /usr/bin/cksum 0x9b20 -n 12` | `0x9b40` is a complete leaf function (loads 32 constant bytes into `[rdi]`, `ret`) = textbook `sha256_init` |
| 7 | byte-level checks (file scan for `E8`-rel32 → `0x9b40`, 4/8-byte pointers, relocation addends) | **no direct caller, no stored pointer, no reloc** — dispatch mechanism unresolved (offset-table dispatch or an ICF-original kept unreferenced) |

**Root cause of the step-3 dead end:** `.text` coverage of the discovery was only
**9.4%** (8,783/92,942 bytes). This binary is non-IBT, so no `endbr64`; `-O2` leaf
functions like `0x9b40` start with `movdqa` — none of the prologue patterns match;
and the callers are behind computed/indirect dispatch, so call-target harvesting
never reaches them either. The xref DB silently covers only discovered functions —
nothing in the CLI warns about this.

**Recovery:** the Python API's whole-section linear scan (step 5) plus CLI linear
`disasm <addr>` (step 6) bypassed discovery entirely and completed the evidence
chain. **Finding (high confidence):** cksum implements SHA-256 (constants `0x1e260`,
init at `0x9b40`) alongside sysv/sha1/sha224/sha384/sha512/blake2b (name strings).
**Finding (medium confidence):** `0x9b40` has no in-file caller — likely dispatched
via computed offsets or retained after identical-code folding; exact mechanism
unresolved with current features (no data→data xrefs, no offset-table recovery).

---

## Capability scorecard (demonstrated, not assumed)

| Criterion | Verdict | Evidence |
|---|---|---|
| 1. Discover commands/capabilities | ✅ Good | `--help` lists 15 subcommands; per-command `--help` works |
| 2. Consume outputs unaided | ⚠️ Mostly | text output self-describing; **JSON schemas undocumented and inconsistent** (`strings`→`va`/`value`, `sections`→`vaddr`/`vsize`, `functions --json`→4-key object, not a list); two `KeyError`s before inspecting raw JSON |
| 3. Navigate strings→addr→xref→fn→disasm | ✅ Yes | `strings` → `xrefs --to` → `disasm --function <hex>`; hex addresses accepted as function targets; RIP-relative string xrefs resolve to quoted text |
| 4. Choose next steps from findings | ✅ Yes | each output contained actionable addresses/names; no dead ends in A |
| 5. Iterative hypothesis refinement | ✅ Yes | decoy hypothesis refuted by xref semantics (`strcmp` equal → "nice try"); XOR-key hypothesis formed from disasm, confirmed by execution |
| 6. Final report w/ evidence+confidence | ✅ Yes | addresses, byte evidence, executed verification, confidence split (see B) |
| 7. Context efficiency | ⚠️ Mostly | outputs concise; `--json` + filters worked; **no `--limit` on `functions`/`disasm --function`; full `report` would flood context on large binaries** |

## Friction points (all observed live)

- **F1 (severe):** silent discovery gaps. On stripped non-IBT PIE `-O2` code,
  coverage was 9.4% of `.text`; xrefs then return "0 hits" for targets that ARE
  referenced, with no warning. An agent can draw wrong negative conclusions.
- **F2 (high):** JSON schemas undocumented and inconsistent between commands.
- **F3 (high):** no whole-code reference search (`xrefs` covers discovered
  functions only). Recovery required the Python API — fine for agents, but the
  CLI-only path dead-ends here.
- **F4 (medium):** strings shorter than `--min-len` (default 4) vanish; the xref
  to `"dbg"` at `0x2015` appeared with an empty name. Address math + hexdump
  recovered it, but that needs agent experience.
- **F5 (medium):** no data→data xrefs: string→table→code chains (option/dispatch
  tables) cannot be followed.
- **F6 (low):** cosmetic: `function ? @` header for unnamed functions; call xref
  to an internal function shows `dst_name=None` instead of `sub_…`.
- **F7 (low):** signature scan cannot match immediates in code (runtime-generated
  tables, e.g. CRC polynomials) — a true negative here, but a real gap.
- **F8 (low):** no analysis caching — every CLI call re-runs discovery (0.3 s on
  cksum, ~8 s on python3.11-scale binaries). Python API avoids it.
- **F9 (info):** `strings` surfaced `S7777` — a fragment overlapping the encoded
  key tail and the XOR-key dword. Harmless, mildly confusing.

## What worked well (demonstrated)

- IBT/`.plt.sec` binary fully handled: PLT stubs resolved to `name@plt`, noreturn
  boundaries correct, functions clean (2-insn stubs).
- End-to-end CLI navigation on a stripped binary with **zero manual steps**,
  finishing in an execution-verified credential recovery.
- Decoy/negative evidence is first-class: xref semantics distinguished
  "compared-equal → rejected" from "memcmp-equal → granted".
- Python API is a genuine escape hatch (whole-section scans, raw models) and
  composes with the CLI.
- Fast enough for interactive agent loops on small/medium binaries (all commands
  < 1 s on 14–139 KiB targets).

## Verdict

**Agent-usable today for small/medium binaries and symbol-rich targets — with a
caveat that must be fixed before trusting it on stripped, table-driven code:**
the toolkit never says how much of the code it actually recovered, so "no xref /
no function" is currently indistinguishable from "not discovered". With a
coverage metric and consistent JSON schemas, the demonstrated workflow
(discover → strings → xrefs → disasm → extract → verify) is fully automatable;
the API already covers the gaps when the CLI runs out.

## Prioritized improvements (not implemented — evaluation only)

- **P0-1** Report discovery coverage (`%` of each exec section claimed) in
  `functions`/`report` output, and a `coverage_warning` field in `xrefs --json`
  when the query target lies outside covered code. (Kills F1's silent negatives.)
- **P0-2** Normalize and document JSON schemas (one key convention: `va` or
  `vaddr` everywhere; `functions --json` returns a list; add `--schema` or a
  `docs/json-schema.md`). (F2)
- **P1-1** `xrefs --to` accepts a string/substring (`--to-string "ACCESS"`); add
  linear whole-section reference scan so `xrefs` is correct independent of
  function discovery. (F3)
- **P1-2** Data→data xrefs: scan non-exec sections for pointers to code/strings;
  surface `{table_addr → [targets]}` — also seeds discovery from
  function-pointer tables. (F5, F1)
- **P1-3** `--limit`/`--max-insns` on `functions` and `disasm --function`; size
  hints in `report --json`. (context efficiency, F-part of 7)
- **P2-1** Immediate-constant signature mode (search constants inside code, e.g.
  `0xEDB88320`), clearly labeled as code-constant matches. (F7)
- **P2-2** Consistent naming: `disasm --function` shows/accepts `sub_XXXX`;
  xref `dst_name` falls back to `sub_XXXX` for internal callees. (F6)
- **P2-3** For unnamed short-string xref targets, print a hex/ASCII preview of
  the referenced bytes instead of an empty name. (F4)
- **P3** Optional analysis cache (`nrt analyze --cache` / mtime-keyed), mainly
  for repeated queries on >5 MB binaries. (F8)
