"""A game's library code gets one file per object of the user's own library archives, named as the console's decomps
name it (forks/libunits.py): a GameCube game's OS, GX, MSL and TRK code sat in a few big files of 10 to 30 objects
each, where a hand-split copy has dolphin/os/OSAlarm.c, MSL_C/printf.c, TRK_MINNOW_DOLPHIN/nubinit.c."""

from pathlib import Path

from decompnet.consoles.gc_wii import GAMECUBE, WII
from decompnet.forks import libunits
from tests.test_pools import _split


def _words(seed: int, n: int = 8) -> list[int]:
    """n instruction words no other function has (no relocations: all of them are its code)."""
    return [0x38600000 | (seed << 8) | i for i in range(n)]


def _object(path: Path, funcs: list[tuple[str, list[int]]], at: int = 0x80001000) -> Path:
    """An object whose .text holds `funcs` one after another (dtk's note says they're at `at`)."""
    layout, code, off = [], {}, 0
    for name, words in funcs:
        layout.append((name, off, 4 * len(words)))
        for i, w in enumerate(words):
            code[off + 4 * i] = w
        off += 4 * len(words)
    return _split(path, at, layout, 0x80400000, [], code, [])


def _archive(path: Path, members: dict[str, Path]) -> Path:
    out = b"!<arch>\n"
    for name, obj in members.items():
        data = obj.read_bytes()
        out += f"{name}/".ljust(16).encode() + b"0".ljust(12) + b"0".ljust(6) * 2 + b"644".ljust(8) \
            + str(len(data)).ljust(10).encode() + b"`\n" + data + b"\n" * (len(data) & 1)
    path.write_bytes(out)
    return path


ALARM = [("OSInitAlarm", _words(1)), ("OSSetAlarm", _words(2)), ("InsertAlarm", [0x4E800020, 0x60000000])]
FONT = [("OSGetFontEncode", _words(3, 16))]  # (one function: 64 bytes or more says it's the object's)


def _kit(tmp_path: Path) -> list[Path]:
    lib = tmp_path / "sdk" / "HW2" / "lib"
    lib.mkdir(parents=True)
    members = {"OSAlarm.o": _object(tmp_path / "OSAlarm.o", ALARM), "OSFont.o": _object(tmp_path / "OSFont.o", FONT)}
    # (a debug build beside it: its objects are the same library's)
    return [_archive(lib / "os.a", members), _archive(lib / "osD.a", members)]


def test_a_run_of_one_objects_functions_is_its_file_named_as_its_archive_names_it(tmp_path):
    archives = _kit(tmp_path)
    assert {libunits.library_name(a) for a in archives} == {"os"}
    # the game: its own code, OSAlarm.o's three (the short one renamed: its code says too little), OSFont.o's, its own
    game = _object(tmp_path / "auto_text.o", [("fn_80001000", _words(9)), ("fn_80001020", ALARM[0][1]),
                                               ("fn_80001040", ALARM[1][1]), ("fn_80001060", ALARM[2][1]),
                                               ("fn_80001068", FONT[0][1]), ("fn_800010A8", _words(10))])
    functions = libunits.game_functions([game])
    assert [f.addr for f in functions] == [0x80001000, 0x80001020, 0x80001040, 0x80001060, 0x80001068, 0x800010A8]
    runs = libunits.runs(functions, archives)
    assert [(r.start, r.last, r.member, r.found) for r in runs] == [
        (0x80001020, 0x80001060, libunits.Member("os", "OSAlarm"), 2),  # (InsertAlarm by its size, after OSSetAlarm)
        (0x80001068, 0x80001068, libunits.Member("os", "OSFont"), 1)]
    starts = [f.addr for f in functions]
    pieces = libunits.pieces(starts, 0x80001000, 0x800010C8, runs, GAMECUBE.library_file, None, 200)
    assert pieces == [(0x80001000, 0x80001020, None), (0x80001020, 0x80001068, "dolphin/os/OSAlarm.c"),
                      (0x80001068, 0x800010A8, "dolphin/os/OSFont.c"), (0x800010A8, 0x800010C8, None)]
    # a name the project has already goes to no second file; a short function alone says too little
    short = _object(tmp_path / "short.o", [("fn_a", _words(9)), ("fn_b", ALARM[0][1]), ("fn_c", _words(11))])
    assert libunits.runs(libunits.game_functions([short]), archives) == []
    assert [n for *_, n in libunits.pieces(starts, 0x80001000, 0x800010C8, runs, GAMECUBE.library_file, None, 200,
                                           {"dolphin/os/OSFont.c"})] == [None, "dolphin/os/OSAlarm.c", None]


def test_an_object_found_in_two_places_gets_no_file(tmp_path):
    archives = _kit(tmp_path)
    game = _object(tmp_path / "auto_text.o", [("fn_a", ALARM[0][1]), ("fn_b", FONT[0][1]), ("fn_c", ALARM[1][1])])
    runs = libunits.runs(libunits.game_functions([game]), archives)
    assert [r.member.name for r in runs] == ["OSFont"]


def test_each_console_names_its_libraries_files_as_its_decomps_do():
    assert GAMECUBE.library_file(libunits.Member("gx", "GXInit")) == "dolphin/gx/GXInit.c"
    assert GAMECUBE.library_file(libunits.Member("MSL_C", "printf")) == "MSL_C/printf.c"
    assert GAMECUBE.library_file(libunits.Member("TRK_MINNOW_DOLPHIN", "nubinit")) == "TRK_MINNOW_DOLPHIN/nubinit.c"
    assert GAMECUBE.library_file(libunits.Member("thp", "THPDec")) == "thp/THPDec.c"
    assert GAMECUBE.library_file(libunits.Member("Runtime", "New", cpp=True)) == "Runtime/New.cpp"
    assert WII.library_file(libunits.Member("wpad", "WPAD")) == "revolution/wpad/WPAD.c"
    for name, stem in [("MSL_C.PPCEABI.bare.H.a", "MSL_C"), ("Runtime.PPCEABI.H.a", "Runtime"), ("G2D.a", "G2D")]:
        assert libunits.library_name(Path(name)) == stem
    assert libunits.member_name("OSAlarm.o") == "OSAlarm"
