"""V.Flash (consoles/vflash/): the game's firmware and modules from every form of the user's copy, each function's
extent and relocations from its code, and the project's tools (the original's objects, what GCC compiles renamed).

Small homemade programs only: the disc is the demo's (projects/demo-vflash/build.py writes the image), the code is
hand-encoded ARM.
"""

import importlib.util
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decompnet import consoles, toolchains
from decompnet.consoles.vflash import analysis, disc, scratch
from decompnet.forks.project import ForkError

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "src" / "decompnet" / "consoles" / "vflash" / "project_template" / "tools"
sys.path.insert(0, str(TOOLS))
import delink  # noqa: E402
import names  # noqa: E402

_spec = importlib.util.spec_from_file_location("demo_vflash", ROOT / "projects" / "demo-vflash" / "build.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

BUILD = 0x1234ABCD
BASE = 0x10000000


# ---------------------------------------------------------------------------------------------------- the game's files


def _vff(kind: bytes, code: bytes, at: int, entry: int = 0, build: int = BUILD) -> bytes:
    head = bytearray(0x100)
    data = head + code
    vectors = (0x40, 0x1000FF00, 0x40) if kind == b"vfF0" else (entry, 0, 0)
    struct.pack_into("<4sI2I2I2I3II4I", data, 0, kind, build, 0, 0, at + len(data), 0x100, 0, 0, *vectors, 1, at,
                     len(data), 0, 0)
    if kind == b"vfF0":
        struct.pack_into("<8I8I", data, 0x40, *([0xE59FF018] * 8), *([entry or at + 0x100] * 8))
    return bytes(data)


FA = _vff(b"vfF0", bytes.fromhex("0ef0a0e1") * 4, 0x10A00000)
MODULE = _vff(b"vfD0", bytes.fromhex("0ef0a0e1") * 2, 0x10400000, 0x10400100)
OTHER = _vff(b"vfD0", bytes.fromhex("0ef0a0e1") * 3, 0x10400000, 0x10400100, build=0x0BADF00D)


def _boot(fa: bytes) -> bytes:
    boot = bytearray(disc.BOOT_FA_OFFSET)
    struct.pack_into("<4sIII", boot, 0, b"BOOT", len(boot) + len(fa), 0x10C00000, 0x10)
    return bytes(boot) + fa


def _container(data: bytes) -> bytes:
    stream = struct.pack("<4I", len(data), disc.ZLIB_KIND, disc.CONTAINER_MAGIC, 0) + zlib.compress(data)
    out = bytearray()
    for i, at in enumerate(range(0, len(stream), disc.CONTAINER_PAYLOAD)):
        payload = stream[at:at + disc.CONTAINER_PAYLOAD].ljust(disc.CONTAINER_PAYLOAD, b"\0")
        out += payload + struct.pack("<4I", 0, 0, i, zlib.crc32(payload))
    return bytes(out)


def _output_bin(files: dict[str, bytes]) -> bytes:
    table = bytearray()
    names_ = [(f"\\{n.replace('/', chr(92))};1".encode() + b"\0\0", d) for n, d in files.items()]
    end = 4 + sum(12 + len(n) for n, _ in names_)
    sector = (end + 2047) // 2048
    blobs = bytearray()
    for n, d in names_:
        table += struct.pack("<3I", sector + len(blobs) // 2048, len(d), len(n)) + n
        blobs += d + bytes(-len(d) % 2048)
    head = struct.pack("<I", end) + table
    return head + bytes(sector * 2048 - len(head)) + blobs


def _iso(tmp_path: Path, files: dict[str, bytes], name: str = "game.iso") -> Path:
    path = tmp_path / name
    path.write_bytes(demo.iso({**files, "0ID_99000_000/README.TXT": b"x"},
                              sorted({p.split("/")[0] for p in files} | {"0ID_99000_000"}), "99000_000"))
    return path


def test_every_form_of_the_disc_gives_the_same_game(tmp_path):
    """An ISO, a raw .bin with its .cue, the disc's folder and its BOOT.BIN in that folder are the same game:
    FA, its module, the product, the same sha1 (what tells projects and rooms it's the same game)."""
    files = {"0SYSTEM/BOOT.BIN": _boot(FA), "APP01/A01.VFF": MODULE, "APP01/T01.VFF": b"///dummy"}
    iso = _iso(tmp_path, files)
    raw = tmp_path / "game.bin"
    data = iso.read_bytes()
    raw.write_bytes(b"".join(disc.SYNC + bytes(3) + b"\x01" + data[at:at + 2048] + bytes(288)
                             for at in range(0, len(data), 2048)))
    cue = tmp_path / "game.cue"
    cue.write_text('FILE "game.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\n')
    folder = tmp_path / "disc"
    (folder / "0ID_99000_000").mkdir(parents=True)
    for p, d in files.items():
        (folder / p).parent.mkdir(parents=True, exist_ok=True)
        (folder / p).write_bytes(d)
    games = [disc.check(disc.load(p)) for p in (iso, raw, cue, folder, folder / "0SYSTEM" / "BOOT.BIN")]
    for g in games:
        assert g.fa.vff == FA and [m.name for m in g.modules] == ["A01"] and not g.notes
        assert g.product == "99000_000" and g.sha1() == games[0].sha1()
    assert games[0].fa.entry == 0x10A00100 and games[0].modules[0].entry == 0x10400100
    for p in (iso, raw, cue, folder):
        assert consoles.identify(p).id == "vflash", p  # (before the PS2's, which takes any ISO 9660 disc)
        assert scratch.identity(p) == games[0].sha1()


def test_the_packed_modules_of_output_bin_are_found_and_unpacked(tmp_path):
    """One game keeps its modules in OUTPUT.BIN, each compressed: a disc with it gives them as plain modules."""
    pack = _output_bin({"DAPP/GZ1A.VFF": _container(MODULE), "DAPP_RES/TITLE.PTX": _container(b"picture")})
    g = disc.check(disc.load(_iso(tmp_path, {"0SYSTEM/BOOT.BIN": _boot(FA), "OUTPUT/OUTPUT.BIN": pack})))
    assert [(m.name, m.vff) for m in g.modules] == [("GZ1A", MODULE)] and not g.notes


def test_a_copy_of_a_module_is_one_module_and_another_games_is_left_out(tmp_path):
    """A disc that keeps the same module in two folders has one module; two modules of one name in different
    folders are told apart by the folder; a module of another FA build can't be analysed with this one's."""
    other_build = _vff(b"vfD0", bytes(8), 0x10400000, 0x10400100, build=0x0BADF00D)
    g = disc.check(disc.load(_iso(tmp_path, {"0SYSTEM/BOOT.BIN": _boot(FA), "APP01/F02.VFF": MODULE,
                                             "APP02/F02.VFF": OTHER.replace(struct.pack("<I", 0x0BADF00D), struct.pack("<I", BUILD)),
                                             "KW/KW1.VFF": MODULE, "ZZ/X.VFF": other_build})))
    assert [m.name for m in g.modules] == ["F02", "APP02F02"]
    assert any("X belongs to another game" in n for n in g.notes)


def test_what_isnt_all_of_a_game_says_what_to_add(tmp_path):
    only_module = tmp_path / "A01.VFF"
    only_module.write_bytes(MODULE)
    with pytest.raises(ForkError, match="no FA"):
        scratch.game_info(only_module)
    lone = tmp_path / "BOOT.BIN"
    lone.write_bytes(_boot(FA))
    assert any("no game modules" in n for n in disc.check(disc.load(lone)).notes)
    not_a_game = tmp_path / "x.bin"
    not_a_game.write_bytes(bytes(0x20000))
    with pytest.raises(disc.DiscError, match="isn't a V.Flash"):
        disc.load(not_a_game)


def test_a_version_is_the_discs_product_and_revision(tmp_path):
    g = disc.Game(label="93060_002", product="93060_000")
    assert scratch.version_of(g, tmp_path / "x.iso") == "93060_002"
    assert scratch.version_of(disc.Game(label="SOMETHING", product="93160_000"), tmp_path / "x.iso") == "93160_000"
    assert scratch.version_of(disc.Game(label="disc"), tmp_path / "My Game (USA).iso") == "mygameusa"


# ---------------------------------------------------------------------------------------------------- analysis


def _b(at: int, target: int, link: bool = False, cond: int = 0xE) -> int:
    return cond << 28 | 0b101 << 25 | int(link) << 24 | ((target - at - 8) >> 2) & 0xFFFFFF


def _program() -> list[int]:
    """Hand-encoded ARM at BASE: A (calls B, calls through a pointer, loads a data address), C (nothing calls it),
    D (a switch, then a tail call to E after restoring lr), E, B."""
    a = lambda off: BASE + off  # noqa: E731
    return [
        0xE92D4010, _b(a(0x04), a(0x58), link=True), 0xE1A0E00F, 0xE594F000, 0xE59F0000, 0xE8BD8010,  # A
        BASE + 0x100,  # A's pool: the address of data
        0xE3A00000, 0xE1A0F00E,  # C
        0xE92D4010, 0xE3500001, 0x979FF100, _b(a(0x30), a(0x48)), a(0x3C), a(0x44),  # D: its table
        0xE3A00001, 0xE8BD8010, 0xE8BD8010,  # D's cases
        0xE8BD4010, _b(a(0x4C), a(0x50)),  # D: ldmfd sp!, {r4, lr}; b E
        0xE92D4010, 0xE8BD8010,  # E
        0xE1A0F00E,  # B
    ]


def _analysed():
    code = struct.pack(f"<{len(_program())}I", *_program())
    regions = [(BASE, code), (BASE + 0x100, bytes(16))]
    owns = lambda x: BASE <= x < BASE + 0x110  # noqa: E731
    return analysis.analyse("FA", regions, {BASE, BASE + 0x24}, {BASE}, owns), code


def test_each_function_is_its_code_and_its_pool_and_the_ones_ghidra_missed_are_found():
    fns, _ = _analysed()
    assert [(f.addr - BASE, f.size) for f in fns] == [(0x00, 0x1C), (0x1C, 0x08), (0x24, 0x2C), (0x50, 0x08), (0x58, 4)]
    assert [f.name for f in fns][:2] == ["func_10000000", "func_1000001C"]


def test_references_become_relocations_as_gcc_writes_them():
    """A bl names its function; the pool's address names the data; a switch's table and a branch inside the
    function are against its own section; a tail call names the function it goes to."""
    fns, _ = _analysed()
    a, _, d, *_ = fns
    assert a.relocs == [(0x04, analysis.R_ARM_PC24, "func_10000058", analysis.BRANCH_IMM_ANY),
                        (0x18, analysis.R_ARM_ABS32, "D_10000100", 0)]
    assert d.relocs == [(0x0C, analysis.R_ARM_PC24, None, (0x24 - 8) >> 2),
                        (0x10, analysis.R_ARM_ABS32, None, 0x18), (0x14, analysis.R_ARM_ABS32, None, 0x20),
                        (0x28, analysis.R_ARM_PC24, "func_10000050", analysis.BRANCH_IMM_ANY)]


def test_a_modules_names_say_which_module_and_its_calls_to_fa_name_fas():
    code = struct.pack("<3I", 0xE92D4010, _b(0x10400004, 0x10A00100, link=True), 0xE8BD8010)
    fns = analysis.analyse("GZ1A", [(0x10400000, code)], {0x10400000}, set(), lambda x: 0x10400000 <= x < 0x10400100,
                           {0x10A00100: "func_10A00100"}, lambda x: 0x10A00000 <= x < 0x10B00000)
    assert fns[0].name == "func_GZ1A_10400000" and fns[0].relocs[0][2] == "func_10A00100"


# ---------------------------------------------------------------------------------------------------- the project's tools


def _object(monkeypatch=None) -> tuple[bytes, list[dict]]:
    fns, code = _analysed()
    rows = [{"name": f.name, "addr": f.addr, "offset": f.addr - BASE, "size": f.size, "relocs": [list(r) for r in f.relocs]}
            for f in fns]
    return delink.obj(rows, code), rows


def _symbols(data: bytes) -> dict:
    import io

    e = ELFFile(io.BytesIO(data))
    return e, list(e.get_section_by_name(".symtab").iter_symbols())


def test_the_originals_object_has_a_section_per_function_and_its_pools_marked_as_data():
    data, rows = _object()
    e, syms = _symbols(data)
    assert [s.name for s in e.iter_sections() if s.name.startswith(".text.")] == [f".text.{r['name']}" for r in rows]
    marks = [(s.name, s["st_value"], e.get_section(s["st_shndx"]).name) for s in syms if s.name in ("$a", "$d")]
    assert ("$d", 0x18, ".text.func_10000000") in marks
    assert ("$d", 0x10, ".text.func_10000024") in marks and ("$a", 0x18, ".text.func_10000024") in marks
    rel = e.get_section_by_name(".rel.text.func_10000000")
    named = [syms[r["r_info_sym"]].name for r in rel.iter_relocations()]
    assert named == ["func_10000058", "D_10000100"]
    text = e.get_section_by_name(".text.func_10000000").data()
    assert struct.unpack_from("<I", text, 4)[0] & 0xFFFFFF == analysis.BRANCH_IMM_ANY  # (what binutils 2.14 leaves)
    assert struct.unpack_from("<I", text, 0x18)[0] == 0


def test_what_gcc_compiles_gets_the_originals_names_and_its_pools_marked(monkeypatch):
    """C++ mangles a function written by address (_Z13func_10000000v): it gets the original's name, and the section
    GCC gave it too; a constructor, which has no name of its own, pairs by a mangled real name. The words of its pool
    that hold addresses get the mapping symbols binutils 2.14 doesn't write, every relocation still naming what it
    named."""
    monkeypatch.setattr(delink, "mapping", lambda words, size: [])  # (an object as binutils 2.14 writes it)
    rows = [{"name": "_Z13func_10000000v", "addr": BASE, "offset": 0, "size": 0x1C,
             "relocs": [[0x04, 1, "_ZN8ResourceC1Ev", 0xFFFFFE], [0x18, 2, "D_10000100", 0]]}]
    code = struct.pack(f"<{len(_program())}I", *_program())
    compiled = delink.obj(rows, code)
    info = {"units": {"FA/text_10000000": [{"name": "func_10000000", "addr": BASE, "relocs": []}]}}
    wanted = {**names.wanted(info, Path("/nonexistent/functions.json")), "_ZN8ResourceC1Ev": "_ZN8ResourceC1Ev"}
    e, syms = _symbols(names.mark_data(names.rename(compiled, wanted)))
    assert "func_10000000" in [s.name for s in syms] and ".text.func_10000000" in [s.name for s in e.iter_sections()]
    assert ("$d", 0x18) in [(s.name, s["st_value"]) for s in syms]
    rel = e.get_section_by_name(".rel.text.func_10000000")
    assert [syms[r["r_info_sym"]].name for r in rel.iter_relocations()] == ["_ZN8ResourceC1Ev", "D_10000100"]


def test_a_symbols_own_name_is_read_from_gccs_mangling():
    assert names.c_name("_ZN4Town6UpdateEv") == "Update"
    assert names.c_name("_Z13func_10A715C4i") == "func_10A715C4"
    assert names.c_name("_ZNK4Town4SizeEv") == "Size"
    assert names.c_name("tanh") == "tanh" and names.c_name("_ZN8ResourceC1Ev") == "Resource"
    assert names.key("_ZN4Town18func_GZ1A_1047b800Ei") == "func_GZ1A_1047B800"
    assert names.key("func_10A715C4") == "func_10A715C4"


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    conf = root / "config" / "v1"
    conf.mkdir(parents=True)
    rows = {"FA/text_10000000": [{"name": "func_10000000", "addr": BASE, "offset": 0, "size": 8,
                                  "relocs": [[4, 2, "D_10000100", 0]]}],
            "GZ1A/text_10400000": [{"name": "func_GZ1A_10400000", "addr": 0x10400000, "offset": 0, "size": 4, "relocs": []}]}
    (conf / "functions.json").write_text(json.dumps({"programs": {}, "units": rows}))
    return root


def test_rename_symbol_keeps_real_names_by_the_name_by_address(tmp_path):
    root = _project(tmp_path)
    scratch.rename(root, "v1", "func_GZ1A_10400000", "Level_Run")
    scratch.rename(root, "v1", "D_10000100", "g_score")
    assert json.loads((root / "config" / "v1" / "names.json").read_text()) == \
        {"D_10000100": "g_score", "func_GZ1A_10400000": "Level_Run"}
    with pytest.raises(ForkError, match="called Level_Run now"):
        scratch.rename(root, "v1", "func_GZ1A_10400000", "Other")
    with pytest.raises(ForkError, match="holds an address"):
        scratch.rename(root, "v1", "func_10000000", "func_10000000_copy")
    assert scratch.address_of(root, "v1", "Level_Run") == ("GZ1A", 0x10400000)


def test_a_file_builds_with_flags_of_its_own(tmp_path):
    """The maths library was built with -O1, the rest with -O3: a file's own flags go in flags.json, after the
    project's (GCC takes the last), and only what the project's don't have."""
    root = tmp_path / "proj"
    (root / "tools").mkdir(parents=True)
    (root / "config" / "v1").mkdir(parents=True)
    (root / "tools" / "configure.py").write_text((TOOLS / "configure.py").read_text())

    class Fp:
        manifest = {"version": "v1"}
    fp = Fp()
    fp.root = root
    tc, flags = scratch.file_flags(fp, "src/FA/text_10A715C4.cpp")
    assert tc == "gcc-3.2.3-arm-elf" and flags[0] == "-O3" and "-fno-rtti" in flags
    assert "-fno-rtti" not in scratch.file_flags(fp, "src/FA/text_10A715C4.c")[1]
    scratch.set_file_flags(fp, "src/FA/text_10A715C4.c", [*scratch.file_flags(fp, "x.c")[1], "-O1"])
    assert scratch.file_flags(fp, "src/FA/text_10A715C4.c")[1][-1] == "-O1"
    assert json.loads((root / "config" / "v1" / "flags.json").read_text()) == {"src/FA/text_10A715C4.c": ["-O1"]}


@pytest.mark.skipif(toolchains.installed("gcc-3.2.3-arm-elf") is None, reason="needs GCC 3.2.3 for ARM")
def test_gcc_3_2_3s_object_pairs_with_the_originals_cut(tmp_path):
    """A function compiled by GCC 3.2.3 as the game was, and the same function cut out of a program linked from it,
    read the same: the section, the name, the relocated words (objdiff needs nothing else to call it a match)."""
    import subprocess

    gcc = toolchains.path("gcc-3.2.3-arm-elf") / "bin"
    (tmp_path / "f.c").write_text("extern int D_10000100; int g(int);\n"
                                  "int func_10000000(int x) { return g(x + D_10000100) + 3; }\n")
    flags = ["-O3", "-mcpu=arm9tdmi", "-fomit-frame-pointer", "-mno-apcs-frame", "-msoft-float"]
    subprocess.run([gcc / "arm-elf-gcc", "-c", "-ffunction-sections", *flags, "-o", "f.o", "f.c"], cwd=tmp_path, check=True)
    obj = (tmp_path / "f.o").read_bytes()
    e, syms = _symbols(names.mark_data(obj))
    text = e.get_section_by_name(".text.func_10000000").data()
    assert ("$d", len(text) - 4) in [(s.name, s["st_value"]) for s in syms]  # (D_10000100's address, in the pool)


def test_flag_search_tries_what_v_flash_games_were_built_with(tmp_path):
    """The maths library's -O1 and the C++'s -O2 with -frename-registers are among the variants of a file's flags."""
    from decompnet.app.engine import RomNetwork

    net = RomNetwork(tmp_path / "app.db", tmp_path)
    base = ["-O3", "-mcpu=arm9tdmi", "-fomit-frame-pointer", "-mno-apcs-frame", "-msoft-float", "-fno-rtti"]
    variants = net.flag_variants("gcc-3.2.3-arm-elf", base)
    assert variants[0] == base and [*base[:0], "-O1", *base[1:]] in variants
    assert [*base, "-frename-registers"] in variants and all("-G0" not in v for v in variants)


def test_only_what_no_compiler_emits_is_set_aside():
    """The CPU's mode and caches (mrs, msr, mcr p15) are the vendor's assembly; a GCC switch (its table read as
    instructions) or the firmware's jump veneers are not pieces of functions here: decompdecomp cut them itself."""
    fns, code = _analysed()
    d = fns[2]
    vflash = consoles.get("vflash")
    assert vflash.asm_reason(code[d.addr - BASE:d.addr - BASE + d.size]) is None
    assert "mrs" in vflash.asm_reason(struct.pack("<2I", 0xE10F0000, 0xE1A0F00E))


def test_a_function_reads_as_assembly_m2c_takes():
    """Calls and tail calls by name, branches and pool loads to labels, the pool's address by the data's name, a
    switch's table as labels of its cases, and a call through a pointer as blx (ARMv4 writes it mov lr, pc first)."""
    from decompnet.consoles.vflash import asm

    fns, code = _analysed()
    a, _, d, *_ = fns
    text_a = asm.function_asm(a.name, code[:a.size], a.addr, a.relocs)
    assert "glabel func_10000000" in text_a and "    bl func_10000058" in text_a
    assert "    blx r12" in text_a and "    ldr r0, =D_10000100" in text_a  # (a label there read as a variable)
    text_d = asm.function_asm(d.name, code[d.addr - BASE:d.addr - BASE + d.size], d.addr, d.relocs)
    assert "    .word .L1000003C\n    .word .L10000044" in text_d and "    b func_10000050" in text_d
    assert "    bls .L" not in text_d and ".L10000048:" in text_d


@pytest.mark.skipif(toolchains.installed("m2c") is None, reason="needs m2c")
def test_m2c_drafts_a_v_flash_function(tmp_path):
    from decompnet import seeds
    from decompnet.consoles.vflash import asm

    fns, code = _analysed()
    a = fns[0]
    out = seeds.run_m2c(asm.function_asm(a.name, code[:a.size], a.addr, a.relocs), a.name, "arm-gcc-c", strict=True)
    assert "func_10000000(" in out and "func_10000058()" in out


def test_a_library_function_is_the_games_but_for_what_the_link_decides():
    from decompnet.consoles.vflash import libraries

    code = struct.pack("<3I", _b(0, 0x40, link=True), 0xE8BD8010, 0)
    game = struct.pack("<3I", _b(0, 0x1234, link=True), 0xE8BD8010, BASE + 0x100)
    relocs = [(0, libraries.R_ARM_PC24), (8, libraries.R_ARM_ABS32)]
    assert libraries._same(code, game, relocs)
    assert not libraries._same(code, game.replace(struct.pack("<I", 0xE8BD8010), struct.pack("<I", 0xE8BD8030)), relocs)
    assert not libraries._same(code, game[:8], relocs)


def test_a_library_files_functions_are_one_source_file_named_by_their_place(tmp_path):
    """The game's functions from the first a library file matched to its last are that file's unit; when there are
    as many as the file has between the two, the one the game's makers changed is named by its place too."""
    from decompnet.consoles.vflash import libraries

    lib = libraries.LIBRARIES[0]
    c = libraries.Compiled(lib, tmp_path / "inflate.c", {"inflateReset": (b"", []), "inflateInit2_": (b"", []),
                                                         "inflate": (b"", [])})
    fns = [analysis.Function(BASE + 4 * i, 4, f"func_{BASE + 4 * i:08X}") for i in range(5)]
    found = {BASE + 4: (c, "inflateReset"), BASE + 12: (c, "inflate")}
    units, rest, names = libraries.units("FA", fns, found)
    assert list(units) == ["FA/lib/zlib/inflate"] and [f.addr for f in units["FA/lib/zlib/inflate"][1]] == [BASE + 4, BASE + 8, BASE + 12]
    assert names == {BASE + 4: "inflateReset", BASE + 8: "inflateInit2_", BASE + 12: "inflate"}
    assert [f.addr for f in rest] == [BASE, BASE + 16]


@pytest.mark.skipif(toolchains.installed("gcc-3.2.3-arm-elf") is None, reason="needs GCC 3.2.3 for ARM")
def test_an_import_takes_the_modules_chosen_and_the_rest_later(tmp_path, monkeypatch):
    """A game's modules repeat its engine's code and each takes Ghidra a minute: the import analyses the ones chosen
    and keeps the others' programs, so the project analyses them later without the disc."""
    import subprocess

    built = ROOT / "projects" / "demo-vflash" / "build" / "demoquest.iso"
    if not built.exists():
        subprocess.run([sys.executable, str(ROOT / "projects" / "demo-vflash" / "build.py")], check=True)
    monkeypatch.setattr(scratch, "_ghidra", lambda images, log: {})  # (the entries alone: no Ghidra in the test)
    monkeypatch.setattr(scratch, "_libraries", lambda images, programs, log: {})
    assert [p["name"] for p in scratch.parts_of(built)] == ["A01"]
    root = tmp_path / "proj"
    scratch.create(root, built, parts=[], log=lambda *_: None)
    assert scratch.game_parts(root, "99000_000") == [{"name": "A01", "analysed": False, "functions": 0,
                                                     "bytes": (root / "orig/99000_000/A01.elf").stat().st_size}]
    assert not list((root / "src").glob("A01/*"))
    said = scratch.add_modules(root, "99000_000", ["A01"], log=lambda *_: None)
    assert said.startswith("the game modules A01:")
    info = json.loads((root / "config/99000_000/functions.json").read_text())
    assert "A01" in info["programs"] and not info["unanalysed"]
    a01 = [f for u, fns in info["units"].items() if u.startswith("A01/") for f in fns]
    assert a01 and any(r[2] == "func_10A0031C" for f in a01 for r in f["relocs"])  # (clamp_s32, FA's, by FA's name)
    assert list((root / "src").glob("A01/*.cpp"))
    assert scratch.add_modules(root, "99000_000", ["A01"], log=lambda *_: None) is None


def test_a_rebuild_takes_matched_code_and_tells_a_wrong_name(tmp_path, monkeypatch):
    """tools/rebuild.py puts a matched function's compiled code at its place, its relocations resolved by name: the
    same names make the same program; a call naming another function (which objdiff doesn't tell) doesn't."""
    import rebuild

    fns, code = _analysed()
    prog = disc.Image("FA", "vfF0", 0, BASE, BASE + 0x100, 0, 0, 0, [(BASE, code + bytes(0x100 - len(code)))])
    (tmp_path / "orig").mkdir()
    (tmp_path / "orig" / "FA.elf").write_bytes(prog.to_elf())
    spans = scratch.elf_offsets(prog)
    rows = [{"name": f.name, "addr": f.addr, "offset": scratch.file_offset(spans, f.addr), "size": f.size,
             "relocs": [list(r) for r in f.relocs]} for f in fns]
    (tmp_path / "config" / "v1").mkdir(parents=True)
    (tmp_path / "config" / "v1" / "functions.json").write_text(json.dumps(
        {"programs": {"FA": {"elf": "orig/FA.elf"}}, "units": {"FA/text_10000000": rows}}))
    (tmp_path / "objdiff.json").write_text(json.dumps({"units": [{"name": "FA/text_10000000", "base_path": "base.o"}]}))
    monkeypatch.setattr(rebuild, "ROOT", tmp_path)
    for row in rows:  # (the compiled object: as the original's, its words at the relocations as GCC leaves them)
        row["offset"] = row["addr"] - BASE
    (tmp_path / "base.o").write_bytes(delink.obj(rows, code))
    rebuilt, originals, taken = rebuild.rebuild("v1")
    assert rebuilt == originals and "func_10000000" in taken
    rows[0]["relocs"][0][2] = "func_10000050"  # (A's call names E, not B)
    (tmp_path / "base.o").write_bytes(delink.obj(rows, code))
    rebuilt, originals, _ = rebuild.rebuild("v1")
    assert rebuilt != originals


def test_a_modules_function_with_another_programs_code_is_a_copy():
    """The same code calling FA's same functions is a copy, whatever its own addresses (a module's calls to its own
    functions: their copies); calling another of FA's functions, it isn't; nor is a function the same as another of
    its own program's (a constructor's two copies are two functions)."""
    call = lambda at, to: struct.pack("<3I", 0xE92D4010, _b(at + 4, to, link=True), 0xE8BD8010)  # noqa: E731
    programs = {"FA": call(0x10A00000, 0x10A00100) * 2, "A01": call(0x10400000, 0x10A00100) + call(0x1040000C, 0x10400200),
                "A02": call(0x10400000, 0x10A00104) + call(0x1040000C, 0x10400300)}

    def fn(program, addr, offset, target):
        name = analysis.address_name(program, addr)
        return {"name": name, "addr": addr, "offset": offset, "size": 12,
                "relocs": [[4, analysis.R_ARM_PC24, analysis.address_name("FA" if target >= 0x10A00000 else program, target),
                            analysis.BRANCH_IMM_ANY]]}
    info = {"units": {"FA/text_10A00000": [fn("FA", 0x10A00000, 0, 0x10A00100), fn("FA", 0x10A0000C, 12, 0x10A00100)],
                      "A01/text_10400000": [fn("A01", 0x10400000, 0, 0x10A00100), fn("A01", 0x1040000C, 12, 0x10400200)],
                      "A02/text_10400000": [fn("A02", 0x10400000, 0, 0x10A00104), fn("A02", 0x1040000C, 12, 0x10400300)]}}
    found = scratch.copies(info, lambda program, off, size: programs[program][off:off + size], {})
    assert found == {"func_A01_10400000": "func_10A00000", "func_A02_1040000C": "func_A01_1040000C"}


def test_a_draft_declares_what_another_functions_draft_declared_inside_itself():
    """A draft's declarations go inside its own body: one the file has inside another function's doesn't reach it,
    so it declares its own (autopilot's drafts on a V.Flash game failed by the thousand, "used prior to
    declaration"); one the file has at file scope stands."""
    from decompnet.forks import drafts

    draft = "extern M2C_UNK D_10BDD31C;\nextern s32 g_score;\n\nM2C_UNK *func_B(void) {\n    return &D_10BDD31C;\n}\n"
    span = (draft.index("M2C_UNK *func_B"), len(draft))
    file_text = ("extern s32 g_score;\n\nM2C_UNK *func_A(void) {\n    extern M2C_UNK D_10BDD31C;\n"
                 "    return &D_10BDD31C;\n}\n")
    out = drafts.self_contained(draft, span, file_text)
    assert "extern M2C_UNK D_10BDD31C;" in out and "g_score" not in out


def test_a_header_with_m2cs_macros_gets_the_ones_drafts_use_since(tmp_path):
    """A project's common.h got m2c's macros once; ARM drafts use SECOND_REG too, which it lacked ("undeclared"):
    it's added to a header that has the rest, once."""
    from decompnet import seeds
    from decompnet.forks import drafts

    header = tmp_path / "common.h"
    header.write_text("#ifndef COMMON_H\n#define COMMON_H\n" + seeds.M2C_MACROS + "#endif\n")
    assert drafts.add_m2c_macros(header) and "#define SECOND_REG(x)" in header.read_text()
    assert not drafts.add_m2c_macros(header)
    fresh = tmp_path / "fresh.h"
    fresh.write_text("#ifndef COMMON_H\n#define COMMON_H\n#endif\n")
    assert drafts.add_m2c_macros(fresh) and "M2C_DEFINES" in fresh.read_text() and "SECOND_REG" in fresh.read_text()


def test_a_projects_untouched_old_tools_are_updated(tmp_path):
    """A project made with an older template's configure.py (C++ without -fpermissive, where m2c's drafts failed by
    the hundred) gets the template's; one changed by hand is left alone."""
    import subprocess

    old = subprocess.run(["git", "show", "v1.0.6-alpha.3+puyo.7:src/decompnet/consoles/vflash/project_template/tools/"
                          "configure.py"], cwd=ROOT, capture_output=True, text=True)
    if old.returncode:
        pytest.skip("needs the repository's history")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "configure.py").write_text(old.stdout)
    assert scratch.refresh_tools(tmp_path) == ["tools/configure.py"]
    assert '"-fpermissive"' in (tmp_path / "tools" / "configure.py").read_text()
    (tmp_path / "tools" / "configure.py").write_text(old.stdout + "# mine\n")
    assert scratch.refresh_tools(tmp_path) == []
