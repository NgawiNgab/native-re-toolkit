"""Format detection tests."""

import struct

from native_re_toolkit.loader.detect import detect_bytes
from tests.synth import build_min_macho, build_min_pe


def test_detect_elf():
    assert detect_bytes(b"\x7fELF" + b"\x00" * 60) == "elf"


def test_detect_pe():
    assert detect_bytes(build_min_pe()) == "pe"


def test_detect_macho():
    assert detect_bytes(build_min_macho()) == "macho"


def test_detect_macho_fat():
    # fat header with one x86_64 slice pointing at an embedded thin macho
    thin = build_min_macho()
    off = 0x1000
    fat = struct.pack(">II", 0xCAFEBABE, 1)
    fat += struct.pack(">IIIII", 0x01000007, 3, off, len(thin), 12)
    fat = fat.ljust(off, b"\x00") + thin
    assert detect_bytes(fat) == "macho"


def test_detect_unknown():
    assert detect_bytes(b"#!/bin/sh\necho hi\n") == "unknown"
    assert detect_bytes(b"") == "unknown"
    assert detect_bytes(b"MZ" + b"\x00" * 10) == "unknown"  # DOS stub w/o PE


def test_detect_mz_without_pe_signature():
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x200)
    data[0x200:0x204] = b"NE\x00\x00"  # not PE
    assert detect_bytes(bytes(data)) == "unknown"
