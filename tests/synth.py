"""Synthetic minimal PE32+ and Mach-O binaries for loader tests."""

from __future__ import annotations

import struct


def build_min_pe(with_overlay: bool = False) -> bytes:
    """A minimal but structurally valid PE32+ (x86-64) executable.

    Layout: DOS header -> PE header @0x80 -> .text @0x200 -> .rdata @0x400.
    """
    file_alignment = 0x200
    section_alignment = 0x1000
    image_base = 0x140000000

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)  # e_lfanew

    pe = bytearray()
    pe += b"PE\x00\x00"
    # COFF header
    pe += struct.pack(
        "<HHIIIHH",
        0x8664,          # Machine: AMD64
        2,               # NumberOfSections
        0,               # TimeDateStamp
        0,               # PointerToSymbolTable
        0,               # NumberOfSymbols
        0xF0,            # SizeOfOptionalHeader (PE32+ = 240)
        0x0022,          # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    # Optional header (PE32+)
    opt = bytearray()
    opt += struct.pack("<HBB", 0x20B, 0, 0)                 # Magic, linker ver
    opt += struct.pack("<III", 0x200, 0x200, 0)             # sizes
    opt += struct.pack("<II", 0x1000, 0x1000)               # EntryPoint, BaseOfCode
    opt += struct.pack("<Q", image_base)                    # ImageBase
    opt += struct.pack("<II", section_alignment, file_alignment)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)         # versions
    opt += struct.pack("<I", 0)                             # Win32VersionValue
    opt += struct.pack("<I", 0x3000)                        # SizeOfImage
    opt += struct.pack("<I", 0x200)                         # SizeOfHeaders
    opt += struct.pack("<I", 0)                             # CheckSum
    opt += struct.pack("<HH", 3, 0x8160)                    # Subsystem, DllCharacteristics
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)                        # LoaderFlags, NumberOfRvaAndSizes
    opt += bytes(16 * 8)                                    # data directories
    assert len(opt) == 0xF0
    pe += opt

    def section_header(name, vsize, va, rawsize, rawptr, chars):
        n = name.encode().ljust(8, b"\x00")
        return struct.pack("<8sIIIIIIHHI", n, vsize, va, rawsize, rawptr, 0, 0, 0, 0, chars)

    pe += section_header(".text", 0x100, 0x1000, 0x200, 0x200, 0x60000020)
    pe += section_header(".rdata", 0x80, 0x2000, 0x200, 0x400, 0x40000040)

    headers = dos + pe
    assert len(headers) <= 0x200
    headers = headers.ljust(0x200, b"\x00")

    text = bytearray(0x200)
    # mov eax, 42 ; ret
    text[0:6] = b"\xb8\x2a\x00\x00\x00\xc3"

    rdata = bytearray(0x200)
    rdata[0:9] = b"Hello PE\x00"

    blob = bytes(headers + text + rdata)
    if with_overlay:
        blob += b"OVERLAY-DATA!" * 8  # 104 bytes of appended overlay
    return blob


def build_min_macho() -> bytes:
    """A minimal 64-bit Mach-O with one __text section."""
    fmt = "<"
    header = struct.pack(
        fmt + "IiiIIIII",
        0xFEEDFACF,     # MH_MAGIC_64
        0x01000007,     # CPU_TYPE_X86_64
        3,              # CPU_SUBTYPE_X86_64_ALL
        2,              # MH_EXECUTE
        1,              # ncmds
        72 + 80,        # sizeofcmds (segment_command_64 + section_64)
        0,              # flags
        0,              # reserved
    )
    vmaddr = 0x100000000
    code_off = 32 + 72 + 80  # header + segment + section
    seg = struct.pack(
        fmt + "II16sQQQQiiII",
        0x19,           # LC_SEGMENT_64
        72 + 80,
        b"__TEXT".ljust(16, b"\x00"),
        vmaddr,         # vmaddr
        0x1000,         # vmsize
        0,              # fileoff
        0x200,          # filesize
        5,              # maxprot r-x
        5,              # initprot r-x
        1,              # nsects
        0,              # flags
    )
    code = b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3"  # push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
    sect = struct.pack(
        fmt + "16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\x00"),
        b"__TEXT".ljust(16, b"\x00"),
        vmaddr + code_off,  # addr
        len(code),          # size
        code_off,           # offset
        4,                  # align
        0, 0,               # reloff, nreloc
        0x80000400,         # flags: PURE | SOME instructions
        0, 0, 0,            # reserved
    )
    blob = header + seg + sect + code
    return blob
