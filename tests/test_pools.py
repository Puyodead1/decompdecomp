"""Where a GameCube game's files begin and end, read from the compiler's literal pools (forks/pools.py, #ADDON 6 §7):
functions loading one pooled constant are one file's, two copies of a value are two files' pools. Read from the
original's objects as dtk splits them (with its note of each symbol's address in the game)."""

import struct
from pathlib import Path

from decompnet.forks import pools

LFS, LWZ, ADDI, STW, BL = 48 << 26, 32 << 26, 14 << 26, 36 << 26, 18 << 26 | 1
R_REL24, R_SDA21, R_ADDR32 = 10, 109, 1


def _split(path: Path, text_at: int, funcs, sdata2_at: int, consts, code: dict[int, int], relocs, externs=(),
           data_relocs=()) -> Path:
    """A split object as dtk writes one: .text at text_at (funcs: (name, offset, size)), .sdata2 at sdata2_at
    (consts: (name, offset, bytes)), `code`: instruction words by offset, relocations (offset, symbol name, type),
    undefined symbols (externs), .data relocations to constants (a table pointing at one), and the VIRT note."""
    text = bytearray(max([o + s for _, o, s in funcs] + [4]))
    for at, word in code.items():
        text[at:at + 4] = word.to_bytes(4, "big")
    sdata2 = b"".join(v for _, _, v in sorted(consts, key=lambda c: c[1]))
    data = bytes(4 * max(1, len(data_relocs)))
    # symbols: null, then functions (.text = 1), constants (.sdata2 = 2), externs
    syms = [("", 0, 0, 0, 0, 0)]
    virt = [0]
    for name, off, size in funcs:
        syms.append((name, off, size, 0x12, 1, 0))
        virt.append(text_at + off)
    for name, off, value in consts:
        syms.append((name, off, len(value), 0x11, 2, 0))
        virt.append(sdata2_at + off)
    for name in externs:
        syms.append((name, 0, 0, 0x10, 0, 0))
        virt.append(0)
    index = {s[0]: i for i, s in enumerate(syms) if s[0]}
    strtab, symtab = b"\0", b""
    for name, value, size, info, shndx, _ in syms:
        symtab += struct.pack(">IIIBBH", len(strtab) if name else 0, value, size, info, 0, shndx)
        strtab += name.encode() + b"\0" if name else b""
    rela = b"".join(struct.pack(">IIi", at, index[name] << 8 | kind, 0) for at, name, kind in relocs)
    drela = b"".join(struct.pack(">IIi", i * 4, index[name] << 8 | R_ADDR32, 0) for i, name in enumerate(data_relocs))
    vdesc = b"".join(struct.pack(">I", v) for v in virt)
    note = struct.pack(">III", 6, len(vdesc), 0x56495254) + b"Split\0\0\0" + vdesc
    shstr = b"\0.text\0.sdata2\0.data\0.rela.text\0.rela.data\0.symtab\0.strtab\0.shstrtab\0.note.split\0"
    # (name, type, flags, data, link, info, entsize): .text 1, .sdata2 2, .data 3, .rela.text 4, .rela.data 5,
    # .symtab 6, .strtab 7, .shstrtab 8, .note.split 9
    sections = [(".text", 1, 6, bytes(text), 0, 0, 0), (".sdata2", 1, 2, sdata2, 0, 0, 0), (".data", 1, 3, data, 0, 0, 0),
                (".rela.text", 4, 0, rela, 6, 1, 12), (".rela.data", 4, 0, drela, 6, 3, 12),
                (".symtab", 2, 0, symtab, 7, 1, 16), (".strtab", 3, 0, strtab, 0, 0, 0),
                (".shstrtab", 3, 0, shstr, 0, 0, 0), (".note.split", 7, 0, note, 0, 0, 0)]
    body, headers = b"", [bytes(40)]
    for name, kind, flags, blob, link, info, entsize in sections:
        headers.append(struct.pack(">IIIIIIIIII", shstr.index(name.encode() + b"\0"), kind, flags, 0, 52 + len(body),
                                   len(blob), link, info, 4, entsize))
        body += blob + bytes(-len(blob) % 4)
    head = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 1, 20, 1, 0, 0, 52 + len(body), 0, 52, 0, 0,
                                                            40, len(headers), 8)
    path.write_bytes(head + body + b"".join(headers))
    return path


ONE, ZERO, MAGIC = struct.pack(">f", 1.0), struct.pack(">f", 0.0), bytes.fromhex("4330000080000000")
ROWS = [("lbl_80400000", ".sdata2", 0x80400000, 4), ("lbl_80400004", ".sdata2", 0x80400004, 4),
        ("lbl_80400008", ".sdata2", 0x80400008, 8), ("lbl_80400010", ".sdata2", 0x80400010, 4),
        ("lbl_80400014", ".sdata2", 0x80400014, 8), ("lbl_80400020", ".sdata2", 0x80400020, 4),
        ("g_table", ".data", 0x80410000, 4)]


def _game(tmp_path):
    """Seven functions in one stretch (dtk's auto unit): a, b and c share a constant (one file); c and e each convert
    an int to a float with their own copy of 0x4330000080000000 (two files); f takes a constant's address (it's a
    variable then), g stores to one."""
    funcs = [("fn_a", 0x00, 8), ("fn_b", 0x08, 8), ("fn_c", 0x10, 8), ("fn_d", 0x18, 8), ("fn_e", 0x20, 8),
             ("fn_f", 0x28, 8), ("fn_g", 0x30, 8)]
    consts = [("lbl_80400000", 0, ONE), ("lbl_80400004", 4, ZERO), ("lbl_80400008", 8, MAGIC),
              ("lbl_80400010", 0x10, ONE), ("lbl_80400014", 0x14, MAGIC), ("lbl_80400020", 0x20, ZERO)]
    code = {0x00: LFS, 0x08: LFS, 0x10: LFS, 0x14: LFS, 0x18: BL, 0x20: LFS, 0x24: LFS, 0x28: ADDI, 0x30: STW}
    relocs = [(0x02, "lbl_80400000", R_SDA21), (0x0A, "lbl_80400000", R_SDA21), (0x12, "lbl_80400000", R_SDA21),
              (0x16, "lbl_80400008", R_SDA21), (0x18, "fn_e", R_REL24), (0x22, "lbl_80400014", R_SDA21),
              (0x26, "lbl_80400010", R_SDA21), (0x2A, "lbl_80400004", R_SDA21), (0x32, "lbl_80400020", R_SDA21)]
    obj = _split(tmp_path / "auto_text.o", 0x80001000, funcs, 0x80400000, consts, code, relocs)
    return obj, {n: 0x80001000 + o for n, o, _ in funcs}


def test_functions_loading_one_constant_are_one_file_and_two_copies_two_files(tmp_path):
    obj, at = _game(tmp_path)
    found = pools.read([obj, tmp_path / "missing.o"], ROWS)
    assert found.users[0x80400000] == {at["fn_a"], at["fn_b"], at["fn_c"]}
    assert 0x80400004 not in found.users and 0x80400020 not in found.users  # (an address taken, a store: variables)
    assert found.values[0x80400008] == MAGIC and (at["fn_d"], at["fn_e"]) in found.calls
    assert found.together() == [(at["fn_a"], at["fn_c"], 0x80400000)]
    # 1.0f: fn_a..fn_c's copy, then fn_e's; the int-to-float double: fn_c's, then fn_e's
    assert found.apart() == [(at["fn_c"], at["fn_e"], 0x80400000, 0x80400010),
                             (at["fn_c"], at["fn_e"], 0x80400008, 0x80400014)]


def test_a_constant_another_file_names_is_found_by_its_address(tmp_path):
    """The objects of two files: the second loads the first's constant by the name dtk gives it."""
    one = _split(tmp_path / "one.o", 0x80001000, [("fn_a", 0, 8)], 0x80400000, [("lbl_80400000", 0, ONE)],
                 {0: LFS}, [(2, "lbl_80400000", R_SDA21)])
    two = _split(tmp_path / "two.o", 0x80001008, [("fn_b", 0, 8)], 0x80400010, [], {0: LFS},
                 [(2, "lbl_80400000", R_SDA21)], externs=["lbl_80400000"])
    found = pools.read([one, two], ROWS)
    assert found.together() == [(0x80001000, 0x80001008, 0x80400000)]
    table = _split(tmp_path / "table.o", 0x80001010, [("fn_t", 0, 8)], 0x80400020, [], {}, [],
                   externs=["lbl_80400000"], data_relocs=["lbl_80400000"])
    assert pools.read([one, two, table], ROWS).together() == []  # (a table points at it: a variable)


def test_cuts_fall_where_the_pools_say_and_never_inside_one_files_constants(tmp_path):
    obj, at = _game(tmp_path)
    found = pools.read([obj], ROWS)
    starts = sorted(at.values())
    lo, hi = 0x80001000, 0x80001038
    # the file ends after fn_c (its last use of the first copies) and the next starts by fn_e: fn_d calls fn_e, so
    # it goes with fn_e
    assert pools.cuts(starts, lo, hi, found, most=100) == [lo, at["fn_d"], hi]
    assert pools.cuts(starts, lo, hi, None, most=3) == [lo, at["fn_d"], at["fn_g"], hi]
    # fn_a..fn_c are one file however few functions a file may have; the rest are cut every 2
    assert pools.cuts(starts, lo, hi, found, most=2) == [lo, at["fn_d"], at["fn_f"], hi]
    assert pools.cuts([], lo, hi, found, most=2) == [lo, hi]
