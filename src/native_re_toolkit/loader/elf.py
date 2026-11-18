"""ELF loader built on pyelftools."""

from __future__ import annotations

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.dynamic import DynamicSection

from ..errors import LoaderError
from .binary import Binary, Relocation, Section, Symbol

# elftools EM_ constants -> canonical arch names
_MACHINE_MAP = {
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_ARM": "arm",
    "EM_AARCH64": "arm64",
    "EM_MIPS": "mips",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_SPARC": "sparc",
    "EM_SPARCV9": "sparc64",
    "EM_RISCV": "riscv",
    "EM_S390": "s390",
    "EM_LOONGARCH": "loongarch",
}

_ST_TYPE_MAP = {
    "STT_FUNC": "func",
    "STT_OBJECT": "object",
    "STT_SECTION": "section",
    "STT_FILE": "file",
    "STT_TLS": "tls",
    "STT_GNU_IFUNC": "gnu_ifunc",
    "STT_NOTYPE": "notype",
}

_ST_BIND_MAP = {
    "STB_LOCAL": "local",
    "STB_GLOBAL": "global",
    "STB_WEAK": "weak",
}


def _section_flags(sh_flags: int) -> str:
    # SHF_WRITE=0x1, SHF_ALLOC=0x2, SHF_EXECINSTR=0x4
    r = "r" if sh_flags & 0x2 else "-"
    w = "w" if sh_flags & 0x1 else "-"
    x = "x" if sh_flags & 0x4 else "-"
    return r + w + x


class ELFBinary(Binary):
    format = "elf"

    def __init__(self, path: str):
        super().__init__(path)
        self.elf_type: str = ""
        self.osabi: str = ""
        self.libraries: list[str] = []
        self.interpreter: str = ""
        self.security: dict[str, bool | str] = {}
        with open(path, "rb") as fh:
            try:
                ef = ELFFile(fh)
            except Exception as exc:  # pragma: no cover - defensive
                raise LoaderError(f"failed to parse ELF {path}: {exc}") from exc
            self._parse_header(ef)
            self._parse_sections(ef)
            self._parse_symbols(ef)
            self._parse_dynamic(ef)
            self._parse_relocations(ef)
            self._parse_program_headers(ef)
        self._resolve_plt()
        self.finalize()

    # ------------------------------------------------------------------
    def _parse_header(self, ef: ELFFile) -> None:
        machine = ef["e_machine"]
        self.arch = _MACHINE_MAP.get(machine, str(machine))
        self.bits = 64 if ef.elfclass == 64 else 32
        self.endian = "little" if ef.little_endian else "big"
        self.entry = ef["e_entry"]
        self.elf_type = ef["e_type"]
        self.osabi = ef["e_ident"].get("EI_OSABI", "")
        if self.elf_type == "ET_EXEC":
            # image base = lowest PT_LOAD vaddr (page-aligned)
            loads = [
                seg["p_vaddr"]
                for seg in ef.iter_segments()
                if seg["p_type"] == "PT_LOAD"
            ]
            self.image_base = min(loads) if loads else 0
        else:
            self.image_base = 0

    def _parse_sections(self, ef: ELFFile) -> None:
        for sec in ef.iter_sections():
            sh = sec.header
            if not sh["sh_flags"] & 0x2:  # keep only SHF_ALLOC sections
                continue
            size = sh["sh_size"]
            offset = sh["sh_offset"]
            try:
                data = sec.data() if sec["sh_type"] != "SHT_NOBITS" else b""
            except Exception:
                data = b""
            self.sections.append(
                Section(
                    name=sec.name,
                    vaddr=sh["sh_addr"],
                    vsize=size,
                    offset=offset,
                    size=len(data),
                    flags=_section_flags(sh["sh_flags"]),
                    data=data,
                )
            )

    def _parse_symbols(self, ef: ELFFile) -> None:
        seen: set[tuple[str, int, bool]] = set()
        for sec in ef.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                name = sym.name
                if not name:
                    continue
                # strip ELF symbol versioning: "printf@GLIBC_2.2.5" -> "printf"
                if "@" in name:
                    name = name.split("@", 1)[0]
                if not name:
                    continue
                st_info = sym["st_info"]
                stype = _ST_TYPE_MAP.get(st_info["type"], "unknown")
                sbind = _ST_BIND_MAP.get(st_info["bind"], "local")
                undefined = sym["st_shndx"] == "SHN_UNDEF"
                key = (name, sym["st_value"], undefined)
                if key in seen:
                    continue
                seen.add(key)
                section_name = ""
                if not undefined and isinstance(sym["st_shndx"], int):
                    try:
                        section_name = ef.get_section(sym["st_shndx"]).name
                    except Exception:
                        section_name = ""
                self.symbols.append(
                    Symbol(
                        name=name,
                        value=sym["st_value"],
                        size=sym["st_size"],
                        type=stype,
                        bind=sbind,
                        imported=undefined,
                        section=section_name,
                    )
                )

    def _parse_dynamic(self, ef: ELFFile) -> None:
        for sec in ef.iter_sections():
            if not isinstance(sec, DynamicSection):
                continue
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    self.libraries.append(tag.needed)
                    self.imports.setdefault(tag.needed, [])
        # ELF does not record which library provides each undefined
        # symbol; group them under a synthetic bucket so consumers still
        # see the names.
        undef = sorted(
            {s.name for s in self.symbols if s.imported and s.name}
        )
        if undef:
            self.imports.setdefault("(undefined)", []).extend(undef)
        interp = ef.get_section_by_name(".interp")
        if interp is not None:
            raw = interp.data().rstrip(b"\x00")
            self.interpreter = raw.decode("utf-8", "replace")

    def _parse_relocations(self, ef: ELFFile) -> None:
        symtab = ef.get_section_by_name(".symtab")
        dynsym = ef.get_section_by_name(".dynsym")
        for sec in ef.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            # choose the symbol table this relocation section links to
            linked = None
            link = sec["sh_link"]
            try:
                cand = ef.get_section(link)
                if isinstance(cand, SymbolTableSection):
                    linked = cand
            except Exception:
                linked = None
            if linked is None:
                linked = dynsym if dynsym is not None else symtab
            for rel in sec.iter_relocations():
                rtype = rel["r_info_type"]
                sym_idx = rel["r_info_sym"]
                sym_name = None
                if sym_idx and linked is not None:
                    try:
                        sym_name = linked.get_symbol(sym_idx).name
                    except Exception:
                        sym_name = None
                addend = rel["r_addend"] if rel.is_RELA() else 0
                self.relocations.append(
                    Relocation(
                        offset=rel["r_offset"],
                        type=str(rtype),
                        symbol=sym_name,
                        addend=addend,
                    )
                )
                # JUMP_SLOT-style relocations describe GOT entries for
                # imported functions. Type numbers are arch specific; for
                # x86-64 JUMP_SLOT==7, i386 JUMP_SLOT==7, aarch64
                # JUMP_SLOT==1026, arm JUMP_SLOT==22. We accept any
                # relocation that references a named, undefined symbol and
                # lands in a writable data section.
                if sym_name and self._is_import_reloc(sym_name):
                    self.got_imports[rel["r_offset"]] = sym_name

    def _is_import_reloc(self, name: str) -> bool:
        sym = next((s for s in self.symbols if s.name == name and s.imported), None)
        return sym is not None

    def _parse_program_headers(self, ef: ELFFile) -> None:
        gnu_stack = None
        gnu_relro = False
        for seg in ef.iter_segments():
            ptype = seg["p_type"]
            if ptype == "PT_GNU_STACK":
                gnu_stack = seg
            elif ptype == "PT_GNU_RELRO":
                gnu_relro = True
        # NX: stack not executable
        nx = True
        if gnu_stack is not None:
            nx = not bool(gnu_stack["p_flags"] & 0x1)  # PF_X
        pie = self.elf_type == "ET_DYN"
        self.security["nx"] = nx
        self.security["pie"] = pie
        self.security["relro"] = gnu_relro
        # BIND_NOW -> full RELRO
        dyn = None
        for sec in ef.iter_sections():
            if isinstance(sec, DynamicSection):
                dyn = sec
                break
        bind_now = False
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_FLAGS" and tag["d_val"] & 0x8:
                    bind_now = True
                if tag.entry.d_tag == "DT_BIND_NOW":
                    bind_now = True
        self.security["bind_now"] = bind_now
        self.security["full_relro"] = bool(gnu_relro and bind_now)
        self.security["canary"] = any(
            s.name == "__stack_chk_fail" and s.imported for s in self.symbols
        ) or "__stack_chk_fail" in self.all_import_names
        self.security["stripped"] = not any(
            isinstance(sec, SymbolTableSection) and sec.name == ".symtab"
            for sec in ef.iter_sections()
        )

    # ------------------------------------------------------------------
    def _resolve_plt(self) -> None:
        """Map PLT stub addresses to imported symbol names.

        Works by disassembling the PLT sections and following the
        RIP-relative indirect jumps to GOT slots, which we know from
        JUMP_SLOT relocations.

        Stub layouts handled:
          * classic ``.plt``:      ``jmp *GOT[rip]; push N; jmp ...``
          * ``.plt.got``:          ``jmp *GOT[rip]`` (no lazy resolver)
          * IBT ``.plt.sec``:      ``endbr64; jmp *GOT[rip]; nopw``
        For the IBT form the stub *entry* is the endbr64 four bytes ahead
        of the jump, so the recorded address is rewound accordingly --
        callers branch to the endbr64, not to the jmp.
        """
        if not self.got_imports or self.arch not in ("x86", "x86_64"):
            return
        try:
            from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
            from capstone.x86_const import X86_OP_MEM

            mode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True
        except Exception:
            return
        _ENDBR = (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb")  # endbr64 / endbr32
        for sec in self.sections:
            if sec.name not in (".plt", ".plt.sec", ".plt.got", ".iplt"):
                continue
            try:
                for insn in md.disasm(sec.data, sec.vaddr):
                    # jmp *disp(%rip) / jmp *disp(%eip)
                    if insn.mnemonic != "jmp":
                        continue
                    ops = insn.operands
                    if not ops:
                        continue
                    op = ops[0]
                    if op.type != X86_OP_MEM:
                        continue
                    # RIP register ids: 41 = RIP, 16 = EIP in capstone5/x86
                    target = insn.address + insn.size + op.mem.disp
                    if target not in self.got_imports:
                        continue
                    stub = insn.address
                    off = insn.address - sec.vaddr
                    if off >= 4 and bytes(sec.data[off - 4 : off]) in _ENDBR:
                        stub -= 4  # IBT .plt.sec stub: entry is the endbr
                    self.plt_imports[stub] = self.got_imports[target]
            except Exception:
                continue


def load(path: str) -> ELFBinary:
    return ELFBinary(path)
