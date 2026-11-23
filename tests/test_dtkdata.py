"""Each file's data in a dtk-template project that gave its files only code (forks/dtkdata.py; tests/test_gc.py gives
the GameCube demo's files theirs and checks the game still builds)."""

from decompnet.forks import dtkdata
from decompnet.forks.dtksplits import FileSplit, Splits

HEADER = "Sections:\n\t.text       type:code align:4\n\t.rodata     type:rodata align:8\n\t.data       type:data align:8\n" \
         "\t.bss        type:bss align:8"


def files():
    return [FileSplit("a.c", {".text": (0x100, 0x200)}), FileSplit("b.c", {".text": (0x200, 0x300)}),
            FileSplit("c.c", {".text": (0x300, 0x400)}), FileSplit("d.c", {".text": (0x400, 0x500), ".bss": (0x2000, 0x2010)})]


SYMS = {
    "a1": (".data", 0x1000, 8),       # only a's code
    "loose": (".data", 0x1008, 4),    # no code's: stays with the file before it
    "b0": (".data", 0x100C, 4),       # b's and c's, not a's: b starts here, snapped to an aligned symbol
    "b1": (".data", 0x1010, 8),
    "c1": (".data", 0x1018, 8),
    "g": (".data", 0x1020, 8),        # only a's, but after c's: a global placed out of code order, nobody's part
    "d_own": (".bss", 0x2000, 0x10),  # (d's already)
    "a_bss": (".bss", 0x2010, 4),
    "r0": (".rodata", 0x3000, 4),     # before a's first: a's part starts aligned, here
    "r1": (".rodata", 0x3004, 4),
}
USES = {"a.c": {"a1", "g", "a_bss", "r1", "memcpy"}, "b.c": {"b0", "b1"}, "c.c": {"b0", "c1"}, "d.c": {"d_own"}}


def test_each_file_gets_the_stretch_its_code_uses_in_link_order():
    """A GameCube game's files covered only .text, so objdiff compared 0 bytes of data, each finished file was linked,
    and its C's constants collided with dtk's auto units: every link failed."""
    given = dtkdata.parts(files(), SYMS, USES)
    assert given == {
        "a.c": {".rodata": (0x3000, 0x3008), ".data": (0x1000, 0x1010), ".bss": (0x2010, 0x2014)},
        "b.c": {".data": (0x1010, 0x1018)},
        "c.c": {".data": (0x1018, 0x1020)},
    }


def test_a_linked_file_gets_nothing_and_its_data_stays_out_of_the_others():
    """A linked file's object is built from its C: data given to it was defined twice (an undefined RTTI record when
    a GameCube game's first try gave a linked file some)."""
    given = dtkdata.parts(files(), SYMS, USES, skip={"b.c"})
    assert "b.c" not in given
    assert given["a.c"][".data"] == (0x1000, 0x1010) and given["c.c"][".data"] == (0x1018, 0x1020)


def test_a_cut_with_no_aligned_symbol_gives_the_next_file_nothing():
    syms = {"a1": (".data", 0x1000, 4), "b1": (".data", 0x1004, 4), "z": (".data", 0x1010, 4)}
    given = dtkdata.parts(files()[:2], syms, {"a.c": {"a1"}, "b.c": {"b1"}})
    assert given == {"a.c": {".data": (0x1000, 0x1004)}}


def test_the_parts_go_into_splits_in_the_sections_order():
    sp = Splits(HEADER, files())
    n = dtkdata.apply(sp.header, sp.files, dtkdata.parts(sp.files, SYMS, USES))
    assert n == 3
    text = sp.render()
    assert list(sp.files[0].sections) == [".text", ".rodata", ".data", ".bss"]
    assert Splits.parse(text).files[0].sections == sp.files[0].sections


def test_link_asks_for_data_only_for_files_that_have_none(tmp_path, monkeypatch):
    """link: a finished file whose splits give it no data section gets its data before it's linked; one that has
    data already, or that splits.txt doesn't list, doesn't ask."""
    from pathlib import Path
    from types import SimpleNamespace

    from decompnet.app.forkengine import ForkEngine

    splits = tmp_path / "splits.txt"
    splits.write_text(Splits(HEADER, files()).render())
    fp = SimpleNamespace(kind=lambda: "dtk", linkable=lambda: True, src_dir=lambda: "src", root=tmp_path)
    forks = ForkEngine.__new__(ForkEngine)
    monkeypatch.setattr(ForkEngine, "_modules", lambda self, fp, cfg: {"main": SimpleNamespace(splits=Path(splits))})
    assert forks._code_only(fp, {}, ["src/a.c", "src/d.c", "src/x.c"]) == ["src/a.c"]
    assert forks._code_only(fp, {}, []) == []
