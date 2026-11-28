"""What a file linked from its C needs from a dtk-template project's config (forks/linklayout.py, #ADDON 5): the
functions nothing refers to kept by force_active: in config.yml (the linker drops them from a compiled file), and the
next file's section aligned where the compiled file ends short of it by padding (align: in symbols.txt). And padding
arrays (gap_...) written in the C instead go (forks/cleanup.py)."""

from types import SimpleNamespace

from decompnet.app.forkengine import ForkEngine
from decompnet.forks import cleanup, linklayout
from tests.test_data_layout import R_PPC_ADDR32, _obj

CONFIG = """# Made by decompdecomp. See config.example.yml for every option.
object_base: orig/GAME
object: sys/main.dol
symbols: config/GAME/symbols.txt
splits: config/GAME/splits.txt
detect_objects: true
"""


def test_force_active_is_added_and_the_rest_of_the_config_stays_as_written():
    added = linklayout.with_force_active(CONFIG, ["TRKOpenFile", "TRKPositionFile"])
    assert added.startswith(CONFIG) and added.endswith("force_active:\n- TRKOpenFile\n- TRKPositionFile\n")
    assert linklayout.force_active(added) == ["TRKOpenFile", "TRKPositionFile"]
    assert linklayout.with_force_active(added, ["TRKOpenFile"]) == added
    more = linklayout.with_force_active(added + "# the end\n", ["__start"])
    assert linklayout.force_active(more) == ["TRKOpenFile", "TRKPositionFile", "__start"]
    assert more.endswith("# the end\n") and "# Made by decompdecomp" in more
    flow = linklayout.with_force_active("force_active: [a]\nhash: x\n", ["b"])
    assert linklayout.force_active(flow) == ["a", "b"] and "hash: x" in flow
    indented = linklayout.with_force_active("force_active:\n  - TRKOpenFile\n# tables\nextract: []\n", ["__OSDBJump"])
    assert indented == "force_active:\n  - TRKOpenFile\n  - __OSDBJump\n# tables\nextract: []\n"


def test_a_function_no_relocation_points_at_needs_force_active(tmp_path):
    """A debugger file's two functions nothing calls were kept by its assembly and dropped once it was compiled."""
    trk = _obj(tmp_path / "trk.o", b"\0" * 8, 0, [("TRKOpenFile", 7, 0, 8), ("TRKReadFile", 7, 8, 8),
                                                 ("TRKPositionFile", 7, 16, 8), ("gap_03_80094FA4_text", 7, 24, 4)],
               text=bytes(28))
    table = _obj(tmp_path / "table.o", bytes(4), 0, [("TRKReadFile", 0, 0, 0)], relocs=[(0, 1, R_PPC_ADDR32, 0)])
    refs = linklayout.references([trk, table, tmp_path / "missing.o"])
    assert "TRKReadFile" in refs
    assert linklayout.unreferenced(trk, refs) == ["TRKOpenFile", "TRKPositionFile"]  # (not dtk's padding label)


def test_the_objects_are_those_dtk_links_not_whatever_obj_holds(tmp_path):
    build = tmp_path / "build" / "GAME"
    build.mkdir(parents=True)
    assert linklayout.linked_objects(build) is None
    (build / "config.json").write_text('{"units": [{"object": "build/GAME/obj/a.o", "name": "a.c"}], '
                                       '"modules": [{"units": [{"object": "build/GAME/m/obj/b.o"}]}]}')
    assert linklayout.linked_objects(build) == [tmp_path / "build/GAME/obj/a.o", tmp_path / "build/GAME/m/obj/b.o"]


def test_the_next_files_alignment_makes_up_for_padding_the_compiled_file_lacks():
    """The OS's error file ended 0x10 short of the reboot file's 32-aligned buffer: every later .bss symbol moved."""
    syms = ("__OSErrorTable = .bss:0x802EEDB0; // type:object size:0x40 scope:global\n"
            "Header = .bss:0x802EEE00; // type:object size:0x20 scope:local\n"
            "SaveStart = .bss:0x802EEE20; // type:object size:0x4 scope:local align:4\n")
    now = linklayout.split_align(syms, ".bss", 0x802EEE00, 0x802EEE40)
    assert now == 8
    assert linklayout.needed_align(0x802EEDF0, 0x802EEE00, now) == 32
    assert linklayout.needed_align(0x802EEDF8, 0x802EEE00, now) == 16
    assert linklayout.needed_align(0x802EEDFC, 0x802EEE00, now) is None  # (8 gets there already)
    assert linklayout.needed_align(0x802EED80, 0x802EEDB0, 8) is None  # (0x30 before a 16-aligned one: not padding)
    new, name = linklayout.with_align(syms, ".bss", 0x802EEE00, 32)
    assert name == "Header" and "Header = .bss:0x802EEE00; // type:object size:0x20 scope:local align:32\n" in new
    assert linklayout.split_align(new, ".bss", 0x802EEE00, 0x802EEE40) == 32
    assert linklayout.with_align(new, ".bss", 0x802EEE00, 32) is None
    again = linklayout.with_align(syms.replace("\n", "\r\n"), ".bss", 0x802EEE20, 16)[0]  # (its line endings kept)
    assert "SaveStart = .bss:0x802EEE20; // type:object size:0x4 scope:local align:16\r\n" in again


def test_a_compiled_section_short_by_zeros_at_its_end_is_found(tmp_path):
    target = _obj(tmp_path / "target.o", b"ab\0\0" + bytes(12), 0x40, [])
    assert linklayout.short_ends(target, _obj(tmp_path / "base.o", b"ab\0\0", 0x30, [])) == {".rodata": 12, ".bss": 16}
    assert linklayout.short_ends(target, _obj(tmp_path / "same.o", b"ab\0\0" + bytes(12), 0x40, [])) == {}
    other = _obj(tmp_path / "other.o", b"abcd" + bytes(12), 0x40, [])
    assert linklayout.short_ends(other, _obj(tmp_path / "b2.o", b"ab", 0x40, [])) == {}  # (data at its end, not zeros)


GAPS = """#include "common.h"

/* .sbss */
s32 g_targetGameState;
u8 gap_10_803C70B1_sbss[3];
u8 g_bExitStateGamePlay;
static u8 gap_08_802EED80_bss[48] = {0};
u8 g_both, gap_0[2];

void f(void) {
    u8 gap_local[2];
    g_bExitStateGamePlay = gap_local[0];
}
"""


def test_padding_arrays_are_found_and_removed():
    assert [name for _, _, name in cleanup.gaps(GAPS)] == ["gap_10_803C70B1_sbss", "gap_08_802EED80_bss"]
    text, gone = cleanup.without_gaps(GAPS)
    assert gone == ["gap_10_803C70B1_sbss", "gap_08_802EED80_bss"]
    assert "gap_10" not in text and "gap_08" not in text and "u8 g_both, gap_0[2];" in text and "gap_local" in text
    assert "s32 g_targetGameState;\nu8 g_bExitStateGamePlay;\n" in text
    one, gone = cleanup.without_gaps(GAPS, only={"gap_08_802EED80_bss"})
    assert gone == ["gap_08_802EED80_bss"] and "gap_10_803C70B1_sbss" in one


def _project(tmp_path, base_bss: int, trk_refs=()):
    """A dtk project: os.c (.text, .bss 0x30 up to 0x80001040), then reboot.c whose .bss starts 32-aligned."""
    root = tmp_path / "game"
    config = root / "config" / "GAME"
    config.mkdir(parents=True)
    (config / "config.yml").write_text(CONFIG, encoding="utf-8")
    (config / "splits.txt").write_text(
        "Sections:\n\t.text       type:code align:4\n\t.bss        type:bss align:64\n\n"
        "os.c:\n\t.text       start:0x80000000 end:0x80000010\n\t.bss        start:0x80001010 end:0x80001040\n\n"
        "reboot.c:\n\t.text       start:0x80000010 end:0x80000020\n\t.bss        start:0x80001040 end:0x80001060\n",
        encoding="utf-8")
    (config / "symbols.txt").write_text(
        "OSError = .text:0x80000000; // type:function size:0x8 scope:global\n"
        "OSUnused = .text:0x80000008; // type:function size:0x8 scope:global\n"
        "__OSErrorTable = .bss:0x80001010; // type:object size:0x20 scope:global\n"
        "Header = .bss:0x80001040; // type:object size:0x20 scope:local\n", encoding="utf-8")
    objs = tmp_path / "obj"
    objs.mkdir()
    os_target = _obj(objs / "os.o", b"", 0x30, [("OSError", 7, 0, 8), ("OSUnused", 7, 8, 8)], text=bytes(16))
    os_base = _obj(objs / "os_base.o", b"", base_bss, [("OSError", 7, 0, 8), ("OSUnused", 7, 8, 8)], text=bytes(16))
    caller = _obj(objs / "reboot.o", bytes(4), 0x20, [("OSError", 0, 0, 0)], relocs=[(0, 1, R_PPC_ADDR32, 0)])
    units = [SimpleNamespace(name="main/os", source="src/os.c", target=os_target, base=os_base),
             SimpleNamespace(name="main/reboot", source="src/reboot.c", target=caller, base=None)]
    fp = SimpleNamespace(root=root, kind=lambda: "dtk", linkable=lambda: True, units=lambda: units,
                         src_dir=lambda: "src", versions=lambda: ["GAME"])
    return fp, config


def test_a_link_gets_what_its_file_needs_and_keeps_it_only_for_the_files_that_link(tmp_path):
    fp, config = _project(tmp_path, base_bss=0x20)
    eng = object.__new__(ForkEngine)
    cfg = {"version": "GAME"}
    needs = eng._link_needs(fp, cfg, ["src/os.c", "src/reboot.c"])
    assert needs == {"src/os.c": {"force": ["OSUnused"],
                                  "align": [(config / "symbols.txt", ".bss", 0x80001040, 32, "Header")]}}
    files = {p: p.read_bytes() for p in eng._layout_paths(fp, cfg)}
    eng._write_layout(files, needs, ["src/os.c"])
    assert linklayout.force_active((config / "config.yml").read_text()) == ["OSUnused"]
    assert "Header = .bss:0x80001040; // type:object size:0x20 scope:local align:32" in (config / "symbols.txt").read_text()
    eng._write_layout(files, needs, [])  # (os.c didn't link: the config as it was)
    assert {p: p.read_bytes() for p in files} == files
    said = ForkEngine._layout_said(needs, ["src/os.c"])
    assert "force_active: OSUnused" in said and "Header (.bss 0x80001040) aligned to 32" in said
    assert ForkEngine._layout_said(needs, ["src/reboot.c"]) == ""
    fp2, _ = _project(tmp_path / "2", base_bss=0x30)  # (no padding missing: only what nothing calls)
    assert eng._link_needs(fp2, cfg, ["src/os.c"]) == {"src/os.c": {"force": ["OSUnused"], "align": []}}
