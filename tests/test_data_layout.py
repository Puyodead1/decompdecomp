"""A file whose data is the original's bytes, only named or cut differently (datadiff.same_layout): a GameCube game's
helpers were handed data jobs no C could finish, one 1,632-byte .bss variable in the project's symbols that the C
declares as four, and one 72-byte string label that the compiler emits as five literals. The link decides those."""

import os
import struct
from pathlib import Path
from types import SimpleNamespace

from decompnet.app.datajobs import DataJobs
from decompnet.app.forkengine import ForkEngine
from decompnet.forks.datadiff import layout, same_layout

STRINGS = b"Loading\0Pause\0\0\0Quit\0\0\0\0Options\0Continue\0\0\0\0Retry\0\0\0\0\0\0\0\0\0\0\0"  # 68 bytes
R_PPC_ADDR32 = 1


def _obj(path: Path, rodata: bytes, bss: int, syms, relocs=(), text: bytes = b"") -> Path:
    """A small big-endian PowerPC ELF object: .rodata (its bytes), .bss (a size), .text, global symbols (name, section:
    1 .rodata, 2 .bss, 7 .text (a function), 0 undefined; value; size) and .rodata's relocations (offset, symbol's
    index from 1, type, addend)."""
    shstr = b"\0.rodata\0.bss\0.rela.rodata\0.symtab\0.strtab\0.shstrtab\0.text\0"
    strtab, symtab = b"\0", bytes(16)
    for name, shndx, value, size in syms:
        info = 0x12 if shndx == 7 else 0x11 if shndx else 0x10
        symtab += struct.pack(">IIIBBH", len(strtab), value, size, info, 0, shndx)
        strtab += name.encode() + b"\0"
    rela = b"".join(struct.pack(">IIi", at, sym << 8 | kind, add) for at, sym, kind, add in relocs)
    # (name, type, flags, data, link, info, entsize); .bss's data is only its size
    sections = [(".rodata", 1, 2, rodata, 0, 0, 0), (".bss", 8, 3, bss, 0, 0, 0), (".rela.rodata", 4, 0, rela, 4, 1, 12),
                (".symtab", 2, 0, symtab, 5, 1, 16), (".strtab", 3, 0, strtab, 0, 0, 0),
                (".shstrtab", 3, 0, shstr, 0, 0, 0), (".text", 1, 6, text, 0, 0, 0)]
    body, headers = b"", [bytes(40)]
    for name, kind, flags, data, link, info, entsize in sections:
        size = data if isinstance(data, int) else len(data)
        headers.append(struct.pack(">IIIIIIIIII", shstr.index(name.encode() + b"\0"), kind, flags, 0, 52 + len(body),
                                   size, link, info, 4, entsize))
        if not isinstance(data, int):
            body += data + bytes(-len(data) % 4)
    head = b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 1, 20, 1, 0, 0, 52 + len(body), 0, 52, 0, 0,
                                                            40, len(headers), 6)
    path.write_bytes(head + body + b"".join(headers))
    return path


def _original(tmp_path: Path, rodata: bytes = STRINGS + bytes(4), bss: int = 1632, relocs=(), syms=()) -> Path:
    """The project's split: the strings one 72-byte label (the last 4 bytes the linker's alignment), .bss one variable."""
    return _obj(tmp_path / "target.o", rodata, bss, [("lbl_80401000", 1, 0, 72), ("g_carPos", 2, 0, 1632), *syms],
                relocs)


def _yours(tmp_path: Path, rodata: bytes = STRINGS, bss: int = 1632, relocs=(), syms=()) -> Path:
    """The compiled C: five literals and four variables, the same bytes."""
    names = [("@101", 1, 0, 8), ("@102", 1, 8, 8), ("@103", 1, 16, 8), ("@104", 1, 24, 20), ("@105", 1, 44, 24)]
    names += [("g_pos", 2, 0, 1024), ("g_rot", 2, 1024, 512), ("g_speed", 2, 1536, 64), ("g_count", 2, 1600, 32)]
    return _obj(tmp_path / "base.o", rodata, bss, [*names, *syms], relocs)


def test_the_originals_bytes_named_and_cut_differently_are_alike(tmp_path):
    assert same_layout(_original(tmp_path), _yours(tmp_path))


def test_a_different_byte_size_or_padding_is_not(tmp_path):
    target = _original(tmp_path)
    assert not same_layout(target, _yours(tmp_path, rodata=STRINGS.replace(b"Pause", b"Pawse")))
    assert not same_layout(target, _yours(tmp_path, bss=1600))
    assert not same_layout(target, None)
    assert not same_layout(_original(tmp_path, rodata=STRINGS + b"\0\0\0\1"), _yours(tmp_path))  # (not padding)


def test_pointers_must_point_at_the_same_place_whatever_they_name(tmp_path):
    """One into the object is its section and offset (dtk's lbl_ or the compiler's @NNN); one out of it is a name."""
    target = _original(tmp_path, relocs=[(0, 2, R_PPC_ADDR32, 1024)])  # (g_carPos+1024)
    assert same_layout(target, _yours(tmp_path, relocs=[(0, 7, R_PPC_ADDR32, 0)]))  # (g_rot)
    assert not same_layout(target, _yours(tmp_path, relocs=[(0, 6, R_PPC_ADDR32, 0)]))  # (g_pos)
    assert not same_layout(target, _yours(tmp_path))
    out = [("OSReport", 0, 0, 0)]
    target = _original(tmp_path, relocs=[(4, 3, R_PPC_ADDR32, 0)], syms=out)
    assert same_layout(target, _yours(tmp_path, relocs=[(4, 10, R_PPC_ADDR32, 0)], syms=out))
    assert not same_layout(target, _yours(tmp_path, relocs=[(4, 10, R_PPC_ADDR32, 0)], syms=[("printf", 0, 0, 0)]))


def test_a_function_only_yours_has_moves_the_code_after_it(tmp_path):
    """20 files of a GameCube game each emitted a 56-byte copy of a static helper the original only ever inlined: every
    function matched, and the tables of function pointers after it pointed 56 bytes further into the code."""
    code = [("Draw", 7, 0, 8), ("Step", 7, 8, 8)]
    target = _obj(tmp_path / "t.o", bytes(4), 0, code, [(0, 2, R_PPC_ADDR32, 0)], text=bytes(16))
    base = _obj(tmp_path / "b.o", bytes(4), 0, [("Draw", 7, 8, 8), ("Step", 7, 16, 8), ("PlayerManager_Link", 7, 0, 8)],
                [(0, 2, R_PPC_ADDR32, 0)], text=bytes(24))
    assert not same_layout(target, base)
    cost, lines = layout(target, base)
    assert cost >= 8 and "functions only yours has" in lines[0] and "PlayerManager_Link (8 bytes at 0x0)" in lines[0]
    assert any("1 pointer into .text point 8 bytes further in yours" in line for line in lines), lines


def test_a_string_the_original_aligns_is_said_plainly(tmp_path):
    target = _obj(tmp_path / "t.o", b"HI\0\0" + bytes(4) + b"ERR\0", 0, [])
    base = _obj(tmp_path / "b.o", b"HI\0\0ERR\0", 0, [])
    cost, lines = layout(target, base)
    assert cost and lines[0] == ".rodata: 12 bytes in the original, 8 in yours"
    assert lines[1].startswith(".rodata+0x4 is the first byte that differs") and "4 zero bytes there before" in lines[1]


def test_a_file_with_nothing_to_write_by_name_and_another_layout_is_a_job(tmp_path):
    """A GameCube game's such files were nobody's job and never linked; the original's bytes are no job until their
    link fails."""
    jobs = DataJobs(None)
    alike = SimpleNamespace(target=_original(tmp_path), base=_yours(tmp_path))
    assert jobs._bytes_left(alike) == 0
    assert jobs._bytes_left(alike, alike=False) > 0  # (its link failed: a job again)
    other = tmp_path / "other"
    other.mkdir()
    aligned = SimpleNamespace(target=_obj(other / "t.o", b"HI\0\0" + bytes(4) + b"ERR\0", 0, []),
                              base=_obj(other / "b.o", b"HI\0\0ERR\0", 0, []))
    assert jobs._bytes_left(aligned) > 0


def _engine():
    eng = object.__new__(ForkEngine)
    eng._held = lambda proj, unit: set()
    return eng


def _report(*units):
    return {"units": [{"name": name, "metadata": {"source_path": f"src/{name}.c"},
                       "measures": {"total_code": 100, "matched_code": code, "total_data": 72, "matched_data": data}}
                      for name, code, data in units]}


def test_a_file_whose_data_is_the_originals_bytes_is_linked(tmp_path):
    """objdiff counts its data unmatched (it pairs data by name), and the link is what decides."""
    alike = SimpleNamespace(target=_original(tmp_path), base=_yours(tmp_path))
    other = tmp_path / "other"
    other.mkdir()
    differs = SimpleNamespace(target=_original(other), base=_yours(other, bss=1600))
    units = {"alike": alike, "differs": differs, "code": alike, "done": alike}
    fp = SimpleNamespace(link_states=lambda: {f"src/{n}.c": ("NonMatching",) for n in units}, unit=units.get)
    rep = _report(("alike", 100, 0), ("differs", 100, 0), ("code", 90, 0), ("done", 100, 72))
    assert _engine().link_candidates({"id": 1}, fp, rep) == ["src/alike.c", "src/done.c"]


def test_a_link_failure_from_before_the_split_config_changed_is_forgotten(tmp_path):
    """A GameCube game's briefs kept "multiply-defined ... in auto_08_..._bss.o" from before its files were given their
    data, an object no longer built, and its helpers took it for a link step they had to fix."""
    splits = tmp_path / "config" / "GAME" / "splits.txt"
    splits.parent.mkdir(parents=True)
    splits.write_text("input.c:\n")
    os.utime(splits, (1000, 1000))
    cfg = {"link_failed": {"src/input.c": "multiply-defined: 'ngcPad'", "src/math3d.c": "multiply-defined",
                           "src/old.c": "recorded before failures had a time"},
           "link_failed_at": {"src/input.c": 900.0, "src/math3d.c": 1100.0}}
    assert ForkEngine.link_failures(tmp_path, cfg) == {"src/math3d.c": "multiply-defined"}
    assert ForkEngine.link_failures(tmp_path / "elsewhere", {"link_failed": {"a.c": "x"}, "link_failed_at": {"a.c": 1}}) \
        == {"a.c": "x"}  # (no split config: every failure stands)
