"""A switch's jump table is data, so objdiff's 100% doesn't see a case sent to the wrong body (forks/jumptables.py).

A GameCube function read 100% while its cases 28 to 30 ran the code of 29, 25 and 26: swapped case labels compile
to the same instructions, and only the table, relocations in .data pointing back into the function, shows them. The
objects here are written by hand, the way MWCC and dtk lay them out (big-endian PowerPC, RELA): a function whose
code loads a table with lis/addi @ha/@l, and the table's words pointing into it.
"""

import json
import struct
from pathlib import Path

from decompnet.forks import jumptables, objdiff

R_PPC_ADDR32, R_PPC_ADDR16_LO, R_PPC_ADDR16_HA = 1, 4, 6
TEXT, DATA = 1, 2  # section indexes in every object written here


def _elf(path: Path, text_size: int, data_size: int, symbols: list[tuple], code_relocs: list[tuple],
         data_relocs: list[tuple]) -> Path:
    """A big-endian PowerPC ELF object with .text and .data (zeros: only symbols and relocations matter).
    `symbols`: (name, value, size, kind, section), kind "func" | "object" | "label" | "undef", after the null and
    the two section symbols (indexes 1: .text, 2: .data), so the first is symbol 3. Relocations: (offset,
    symbol index, type, addend)."""
    names, strtab = {}, b"\0"
    for name, *_ in symbols:
        names[name] = len(strtab)
        strtab += name.encode() + b"\0"
    rows = [(0, 0, 0, 0, 0, 0), (0, 0, 0, 3, 0, TEXT), (0, 0, 0, 3, 0, DATA)]
    info = {"func": (1 << 4) | 2, "object": 1, "label": 0, "undef": 1 << 4}
    rows += [(names[n], value, size, info[kind], 0, sec if kind != "undef" else 0)
             for n, value, size, kind, sec in symbols]
    local = [r for r in rows if r[3] >> 4 == 0]
    assert rows[:len(local)] == local, "locals first"
    symtab = b"".join(struct.pack(">IIIBBH", *r) for r in rows)

    def rela(rs):
        return b"".join(struct.pack(">IIi", off, (sym << 8) | kind, add) for off, sym, kind, add in rs)

    shstr = b"\0.text\0.data\0.rela.text\0.rela.data\0.symtab\0.strtab\0.shstrtab\0"

    def at(name: bytes) -> int:
        return shstr.index(b"\0" + name + b"\0") + 1

    bodies = [bytes(text_size), bytes(data_size), rela(code_relocs), rela(data_relocs), symtab, strtab, shstr]
    offsets, pos = [], 52
    for b in bodies:
        offsets.append(pos)
        pos += len(b)
    shoff = (pos + 3) & ~3
    sh = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
          (at(b".text"), 1, 6, 0, offsets[0], text_size, 0, 0, 4, 0),
          (at(b".data"), 1, 3, 0, offsets[1], data_size, 0, 0, 4, 0),
          (at(b".rela.text"), 4, 0, 0, offsets[2], len(bodies[2]), 5, TEXT, 4, 12),
          (at(b".rela.data"), 4, 0, 0, offsets[3], len(bodies[3]), 5, DATA, 4, 12),
          (at(b".symtab"), 2, 0, 0, offsets[4], len(symtab), 6, len(local), 4, 16),
          (at(b".strtab"), 3, 0, 0, offsets[5], len(strtab), 0, 0, 1, 0),
          (at(b".shstrtab"), 3, 0, 0, offsets[6], len(shstr), 0, 0, 1, 0)]
    header = b"ELF" + bytes([1, 2, 1]) + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 1, 20, 1, 0, 0, shoff, 0, 52,
                                                                     0, 0, 40, len(sh), 7)
    blob = header + b"".join(bodies)
    blob += bytes(shoff - len(blob)) + b"".join(struct.pack(">IIIIIIIIII", *h) for h in sh)
    path.write_bytes(blob)
    return path


def _load(sym: int) -> list[tuple]:
    """The code's lis/addi of a table at +0x8 (relocations @ha and @l)."""
    return [(0x8, sym, R_PPC_ADDR16_HA, 0), (0xC, sym, R_PPC_ADDR16_LO, 0)]


def _object(path: Path, cases: list[int], size: int = 0x40, *, label_syms: bool = False) -> Path:
    """One function `f` loading a jump table at +0x8 whose entries point at `cases` (offsets in f): through
    section symbols, as MWCC writes it, or (`label_syms`) through named symbols, a jumptable_ and a lbl_."""
    if label_syms:
        syms = [("jumptable_80001000", 0, 4 * len(cases), "object", DATA), (".L_x", 0, 0, "label", TEXT),
                ("f", 0, size, "func", TEXT)]
        return _elf(path, size, 4 * len(cases), syms, _load(3),
                    [(4 * k, 4, R_PPC_ADDR32, c) for k, c in enumerate(cases)])
    return _elf(path, size, 4 * len(cases), [("f", 0, size, "func", TEXT)], _load(DATA),
                [(4 * k, TEXT, R_PPC_ADDR32, c) for k, c in enumerate(cases)])


def _split(folder: Path, cases: list[int], size: int = 0x40) -> tuple[Path, Path]:
    """The original as dtk splits code no file covers: a code-only object loading jumptable_80001000, which a
    data object of its own defines, its words naming f plus an offset."""
    folder.mkdir(parents=True, exist_ok=True)
    code = _elf(folder / "text.o", size, 0, [("f", 0, size, "func", TEXT), ("jumptable_80001000", 0, 0, "undef", 0)],
                _load(4), [])
    data = _elf(folder / "data.o", 0, 4 * len(cases) + 8,
                [("jumptable_80001000", 0, 4 * len(cases), "object", DATA), ("other_80001010", 4 * len(cases), 8,
                                                                            "object", DATA),
                 ("f", 0, 0, "undef", 0)],
                [], [(4 * k, 5, R_PPC_ADDR32, c) for k, c in enumerate(cases)] + [(4 * len(cases), 5, R_PPC_ADDR32,
                                                                                    0x3C)])
    return code, data


def test_a_table_sending_cases_elsewhere_is_found(tmp_path):
    orig = _object(tmp_path / "orig.o", [0x20, 0x28, 0x30, 0x20], label_syms=True)
    same = _object(tmp_path / "same.o", [0x20, 0x28, 0x30, 0x20])
    swapped = _object(tmp_path / "swapped.o", [0x20, 0x30, 0x28, 0x20])
    assert jumptables.conflicts(orig, same, "f") == []
    found = jumptables.conflicts(orig, swapped, "f")
    assert len(found) == 1 and [k for k, _, _ in found[0].entries] == [1, 2]
    assert "entry 1 goes to +0x28 in the original, +0x30 in yours" in found[0].describe()


def test_one_word_into_the_function_is_no_table(tmp_path):
    """A constructor loading its class's vtable, whose first word is the function itself: no switch."""
    vtable = _object(tmp_path / "orig.o", [0], label_syms=True)
    assert jumptables.tables(jumptables._index(vtable), "f") == []
    assert jumptables.conflicts(vtable, _object(tmp_path / "yours.o", [0x20]), "f") == []


def test_a_table_of_another_length_is_found(tmp_path):
    orig = _object(tmp_path / "orig.o", [0x20, 0x28, 0x30], label_syms=True)
    longer = _object(tmp_path / "longer.o", [0x20, 0x28, 0x30, 0x38])
    assert jumptables.conflicts(orig, longer, "f")[0].entries == [(3, None, 0x38)]


def test_a_table_in_another_original_object_is_read_there(tmp_path):
    """dtk's code-only objects load their tables from a data object: without the project's other objects there's
    no verdict, with them the table is read where it is, and a data symbol right after it isn't part of it."""
    code, data = _split(tmp_path / "orig", [0x20, 0x28, 0x30])
    right = _object(tmp_path / "right.o", [0x20, 0x28, 0x30])
    wrong = _object(tmp_path / "wrong.o", [0x20, 0x30, 0x28])
    assert jumptables.conflicts(code, wrong, "f") == []
    assert jumptables.conflicts(code, right, "f", [code, data]) == []
    found = jumptables.conflicts(code, wrong, "f", [code, data])
    assert [k for k, _, _ in found[0].entries] == [1, 2]


def test_a_coff_object_gives_no_verdict(tmp_path):
    coff = tmp_path / "orig.obj"
    coff.write_bytes(b"\x4c\x01" + bytes(60))
    assert jumptables.conflicts(coff, _object(tmp_path / "yours.o", [0x20]), "f") == []


def test_a_wrong_table_is_not_a_match_anywhere(tmp_path):
    """The per-function diff says why, and the progress report the sync reads counts it as not matched."""
    (tmp_path / "orig").mkdir()
    (tmp_path / "build").mkdir()
    _object(tmp_path / "orig" / "u.o", [0x20, 0x28], label_syms=True)
    _object(tmp_path / "build" / "u.o", [0x28, 0x20])
    (tmp_path / "objdiff.json").write_text(json.dumps({"units": [
        {"name": "u", "target_path": "orig/u.o", "base_path": "build/u.o"}]}))
    rep = {"measures": {"total_functions": 2, "matched_functions": 2, "total_code": "128", "matched_code": "128",
                        "matched_code_percent": 100.0, "matched_functions_percent": 100.0},
           "units": [{"name": "u", "measures": {"total_functions": 2, "matched_functions": 2, "total_code": "128",
                                                "matched_code": "128"},
                      "functions": [{"name": "f", "size": "64", "fuzzy_match_percent": 100.0},
                                    {"name": "g", "size": "64", "fuzzy_match_percent": 100.0}]}]}
    rep = objdiff.subtract_jump_tables(tmp_path, rep)
    f, g = rep["units"][0]["functions"]
    assert f["fuzzy_match_percent"] < 100 and g["fuzzy_match_percent"] == 100.0
    assert rep["measures"]["matched_functions"] == 1 and rep["measures"]["matched_code"] == "64"
    assert rep["measures"]["matched_code_percent"] == 50.0
    assert rep["units"][0]["measures"]["matched_functions"] == 1

    d = objdiff.FunctionDiff("f", 100.0, [], 64, {}, [], {},
                             literals=jumptables.conflicts(tmp_path / "orig" / "u.o", tmp_path / "build" / "u.o", "f"))
    assert not d.matched
    assert "switch sends cases to other code" in d.why_not()
    assert "jump table 1 (loaded at +0x8)" in d.literals_note()
