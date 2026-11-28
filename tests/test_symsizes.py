"""Data symbols sized to their objects (forks/symsizes.py), on a small program built here: strings and small data."""

import struct

from decompnet.forks import symsizes

TEXT, RODATA, SDATA, SDATA2 = 0x80003100, 0x80010000, 0x80020000, 0x80030000
SBSS = SDATA + 0x100  # (.sbss: no bytes in the program)
R13, R2 = SDATA + 0x8000, SDATA2 + 0x8000


def _lis(rd, imm):
    return (15 << 26) | (rd << 21) | imm


def _ori(ra, rs, imm):
    return (24 << 26) | (rs << 21) | (ra << 16) | imm


def _d(op, rd, ra, address, base):
    return (op << 26) | (rd << 21) | (ra << 16) | ((address - base) & 0xFFFF)


def _dol(code: list[int], sections: dict[int, bytes]) -> bytes:
    """A DOL: one text section, then each data section given (address -> bytes)."""
    body = struct.pack(f">{len(code)}I", *code)
    offs, addrs, sizes = [0] * 18, [0] * 18, [0] * 18
    out = bytearray(0x100)
    offs[0], addrs[0], sizes[0] = len(out), TEXT, len(body)
    out += body
    for i, (address, data) in enumerate(sections.items(), start=7):
        offs[i], addrs[i], sizes[i] = len(out), address, len(data)
        out += data
    struct.pack_into(">18I", out, 0x00, *offs)
    struct.pack_into(">18I", out, 0x48, *addrs)
    struct.pack_into(">18I", out, 0x90, *sizes)
    struct.pack_into(">I", out, 0xE0, TEXT)
    return bytes(out)


def _start() -> list[int]:
    return [_lis(13, R13 >> 16), _ori(13, 13, R13 & 0xFFFF), _lis(2, R2 >> 16), _ori(2, 2, R2 & 0xFFFF)]


def test_the_small_data_bases_are_read_from_the_start_up_code():
    assert symsizes.small_bases(_dol(_start(), {})) == {13: R13, 2: R2}


def test_strings_are_one_symbol_each_with_their_nul_and_text_tables_and_numbers_stay():
    run = b"Hello\0\0\0" + b"World!!\0" + b"abcd\0\0\0\0"  # three literals, each at the next 4-byte boundary
    table = b"abcde\0" + b"\0" * 10 + b"fghij\0" + b"\0" * 10  # char names[2][16]: zeros past the boundary
    two = b"@\0\0\0\0\0\0\0"  # 2.0: reads "@" and zeros
    short = b"abcdefg"  # sized without its NUL by dtk
    rodata = run + table + two + short + b"\0" + b"\0" * 8
    syms = "\r\n".join([
        f"lbl_{RODATA:08X} = .rodata:0x{RODATA:08X}; // type:object size:0x18 scope:local",
        f"names = .rodata:0x{RODATA + 0x18:08X}; // type:object size:0x20",
        f"two = .rodata:0x{RODATA + 0x38:08X}; // type:object size:0x8",
        f"short_s = .rodata:0x{RODATA + 0x40:08X}; // type:object size:0x7",
        f"after = .rodata:0x{RODATA + 0x48:08X}; // type:object size:0x8",
    ]) + "\r\n"
    new, changes = symsizes.resize(syms, _dol(_start(), {RODATA: rodata}))
    assert [name for name, _, _ in changes] == [f"lbl_{RODATA:08X}", "short_s"]
    lines = new.split("\r\n")  # (its line endings kept)
    assert lines[:3] == [
        f"lbl_{RODATA:08X} = .rodata:0x{RODATA:08X}; // type:object size:0x6 scope:local data:string",
        f"lbl_{RODATA + 8:08X} = .rodata:0x{RODATA + 8:08X}; // type:object size:0x8 scope:local data:string",
        f"lbl_{RODATA + 16:08X} = .rodata:0x{RODATA + 16:08X}; // type:object size:0x5 scope:local data:string"]
    assert "names = .rodata:0x80010018; // type:object size:0x20" in lines
    assert "two = .rodata:0x80010038; // type:object size:0x8" in lines
    assert "short_s = .rodata:0x80010040; // type:object size:0x8 data:string" in lines


def test_a_small_variable_is_as_big_as_the_codes_loads_and_stores_of_it():
    code = _start() + [
        _d(32, 3, 13, SBSS, R13),  # lwz: a 4-byte variable dtk padded to 8
        _d(38, 3, 13, SBSS + 8, R13),  # stb: a bool
        _d(14, 3, 13, SBSS + 0x10, R13),  # addi: its address is taken (an array, a struct passed by pointer): stays
        _d(32, 3, 13, SBSS + 0x10, R13),
        _d(44, 3, 13, SBSS + 0x18, R13), _d(44, 3, 13, SBSS + 0x1A, R13),  # two halves: a struct of 4
        _d(48, 1, 2, SDATA2, R2),  # lfs: a float, zeros after it
        _d(48, 1, 2, SDATA2 + 8, R2),  # lfs of a float with something after it: that's data of its own
        _d(32, 3, 13, SDATA, R13),  # a pointer to it in data takes its address too
        0x4E800020,
    ]
    sdata2 = struct.pack(">ffff", 1.5, 0.0, 2.5, 7.0)
    sdata = struct.pack(">II", 0, 0)
    pointer = struct.pack(">I", SDATA)
    syms = "\n".join(f"{n} = {sec}:0x{a:08X}; // type:object size:0x{z:X}" for n, sec, a, z in [
        ("word", ".sbss", SBSS, 8), ("flag", ".sbss", SBSS + 8, 8), ("arr", ".sbss", SBSS + 0x10, 8),
        ("pair", ".sbss", SBSS + 0x18, 8), ("half", ".sdata2", SDATA2, 8), ("full", ".sdata2", SDATA2 + 8, 8),
        ("pointed", ".sdata", SDATA, 8)]) + "\n"
    new, changes = symsizes.resize(syms, _dol(code, {SDATA: sdata, SDATA2: sdata2, RODATA: pointer}))
    assert {name: what.split(" (")[0] for name, _, what in changes} == {
        "word": "0x8 -> 0x4", "flag": "0x8 -> 0x1", "pair": "0x8 -> 0x4", "half": "0x8 -> 0x4"}
    assert "flag = .sbss:0x80020108; // type:object size:0x1" in new
    # a name refused before (a file's C was written to the padded size) is left as it is
    assert "word" not in {name for name, _, _ in symsizes.resize(syms, _dol(code, {SDATA2: sdata2}), keep={"word"})[1]}


def test_a_variable_reached_from_a_lis_is_counted_but_only_small_data_is_resized():
    big = 0x80040000
    code = _start() + [_lis(3, (big + 0x8000) >> 16), _d(32, 0, 3, big, (big + 0x8000) & 0xFFFF0000), 0x4E800020]
    used, taken = symsizes.accesses(_dol(code, {}))
    assert (big, 4) in used and not taken
    syms = f"g_big = .bss:0x{big:08X}; // type:object size:0x10\n"
    assert symsizes.resize(syms, _dol(code, {}))[1] == []  # (a struct's tail fields are its type's, not its uses')
