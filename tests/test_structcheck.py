"""Copies of one struct that disagree across a project's files (structcheck.py)."""

from decompnet import structcheck


def test_two_copies_of_a_struct_that_cant_both_be_right_are_told(tmp_path):
    """A reviewer found a PLAYER whose slots[] was off from the layout another file's function showed: four 0x30-byte
    entries at 0x1BC. Views of the same bytes (an element of an array, a field inside a struct-typed field, a gap)
    agree; overlapping fields of another size don't."""
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "player.h").write_text(
        "typedef struct { float x, y, z; } Vec3;\ntypedef struct { int a[12]; } Popup;\n"
        "typedef struct { char pad_0[0x1bc]; Popup popups[4]; Vec3 cursor; } PLAYER;\n")
    (tmp_path / "src" / "a.c").write_text(
        "typedef struct { char pad_0[0x190]; int slots[16]; } PLAYER;\nvoid f(PLAYER *p) { p->slots[1] = 0; }\n")
    (tmp_path / "src" / "b.c").write_text(
        '#include "player.h"\n'
        "typedef struct { char pad_0[0x1bc]; int first; } PLAYER2;\n"
        "void g(PLAYER *p) { struct Local { int n; } l; l.n = 0; }\n")
    said = structcheck.conflicts(tmp_path, "src/a.c")
    assert len(said) == 1 and said[0].startswith("struct PLAYER: ")
    assert "slots[16] (0x4 bytes each) at 0x190" in said[0] and "popups[4] (0x30 bytes each) at 0x1bc" in said[0]
    # a view inside one element, and a struct a function keeps its locals in, aren't copies that disagree
    (tmp_path / "src" / "a.c").write_text(
        "typedef struct { char pad_0[0x1ec]; int b; } PLAYER;\nvoid f(PLAYER *p) { struct Local { char n; } l; }\n")
    assert structcheck.conflicts(tmp_path, "src/a.c") == []
