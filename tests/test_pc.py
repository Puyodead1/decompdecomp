"""PC (Windows) from scratch: a project generated for the user's .exe from Ghidra's analysis, worked on like a fork.

Demo Quest PC (projects/demo-pc) is built like a PC game of its time: Visual C++ 6.0 /O2, linked at 0x400000 without
relocations, with __stdcall and __fastcall functions, a jump table and a hand-written assembly helper. Importing it
must find every function with its exact extent, and agents' C must be judged by the project's own build and objdiff.
Visual C++ is proprietary, so the end-to-end part runs only where `msvc` was installed with its license accepted.
"""

import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.app import tools
from decompnet.forks import csource, ghidra, scratch_pe
from decompnet.network import NetworkError

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "projects" / "demo-pc"
EXE, MAP = DEMO / "build" / "demoquest.exe", DEMO / "build" / "demoquest.map"
GAME = ROOT / "projects" / "demo-n64" / "original" / "game.c"

needs_tools = pytest.mark.skipif(
    any(toolchains.installed(t) is None for t in ("msvc", "objdiff-cli")) or not ghidra.available()
    or (toolchains.get("wibo").supported and toolchains.installed("wibo") is None),
    reason="needs Visual C++ (msvc, proprietary), Ghidra and objdiff")


def test_decorated_names():
    assert scratch_pe.decorate("func_00401000", "__cdecl", 0, 2) == "_func_00401000"
    assert scratch_pe.decorate("func_00401000", "__stdcall", 0, 0) == "_func_00401000"  # Ghidra's default: nothing popped
    assert scratch_pe.decorate("func_00401000", "__stdcall", 8, 2) == "_func_00401000@8"
    assert scratch_pe.decorate("func_00401000", "__fastcall", 0, 2) == "@func_00401000@8"
    assert scratch_pe.decorate("func_00401000", "__fastcall", 4, 3) == "@func_00401000@12"
    assert scratch_pe.decorate("func_00401000", "__thiscall", 4, 2) == "@func_00401000@12"  # this, unused edx, one int


def _test_pe() -> scratch_pe.PE:
    section = scratch_pe.Section(".text", 0x401000, 0x100, 0, 0x100, True)
    return scratch_pe.PE(bytes([0x90]) * 0x100, 0x400000, 0x2000, 0x401050, 0, [section])


def test_incremental_link_jump_table_is_not_given_to_agents():
    data = bytearray([0xCC] * 0x200)
    data[:6] = b"\xE8\x0B\x00\x00\x00\xC3"  # call the first linker thunk; ret
    data[6:0x10] = b"\x90" * 10
    for offset in range(0x10, 0x38, 5):
        addr = 0x401000 + offset
        data[offset:offset + 5] = b"\xE9" + struct.pack("<i", 0x401100 - (addr + 5))
    data[0x100] = 0xC3
    section = scratch_pe.Section(".text", 0x401000, len(data), 0, len(data), True)
    pe = scratch_pe.PE(bytes(data), 0x400000, 0x2000, 0x401000, 0, [section])
    found = [
        {"entry": 0x401000, "end": 0x401006, "name": "entry", "source": "IMPORTED"},
        {"entry": 0x401100, "end": 0x401101, "name": "GameLogic", "source": "USER_DEFINED"},
    ]

    functions = scratch_pe.analyse(pe, found)

    assert [f.addr for f in functions if not f.generated] == [0x401000, 0x401100]
    assert [f.addr for f in functions if f.generated] == list(range(0x401010, 0x401038, 5))
    assert all(f.size == 5 for f in functions if f.generated)
    assert functions[0].relocs == [(1, scratch_pe.REL32, "_GameLogic", 0)]


def test_missed_functions_are_split_at_returns_and_linker_padding():
    data = bytearray([0xCC] * 0x80)
    data[0:1] = b"\xC3"
    data[0x10:0x18] = b"\x55\x8B\xEC\x5D\xC3\xCC\xCC\xCC"
    data[0x18:0x1E] = b"\xB8\x01\x00\x00\x00\xC3"
    data[0x30:0x31] = b"\xC3"
    section = scratch_pe.Section(".text", 0x401000, len(data), 0, len(data), True)
    pe = scratch_pe.PE(bytes(data), 0x400000, 0x2000, 0x401000, 0, [section])
    found = [
        {"entry": 0x401000, "end": 0x401001, "name": "First", "source": "USER_DEFINED"},
        {"entry": 0x401030, "end": 0x401031, "name": "Last", "source": "USER_DEFINED"},
    ]

    functions = scratch_pe.analyse(pe, found)

    assert [(f.addr, f.size) for f in functions] == [
        (0x401000, 1), (0x401010, 5), (0x401018, 6), (0x401030, 1),
    ]


def test_a_zero_at_the_end_of_missed_code_is_not_trimmed_as_padding():
    data = bytearray([0xCC] * 0x40)
    data[0] = 0xC3
    data[0x10:0x15] = b"\xE9\x01\x00\x00\x00"
    data[0x20] = 0xC3
    section = scratch_pe.Section(".text", 0x401000, len(data), 0, len(data), True)
    pe = scratch_pe.PE(bytes(data), 0x400000, 0x2000, 0x401000, 0, [section])
    found = [
        {"entry": 0x401000, "end": 0x401001, "name": "First", "source": "USER_DEFINED"},
        {"entry": 0x401020, "end": 0x401021, "name": "Last", "source": "USER_DEFINED"},
    ]

    functions = scratch_pe.analyse(pe, found)

    missed = next(f for f in functions if f.addr == 0x401010)
    assert missed.size == 5


def test_only_individually_identified_msvc_functions_are_not_given_to_agents():
    found = [
        {"entry": 0x401000, "end": 0x401010, "name": "FUN_00401000", "source": "DEFAULT"},
        {"entry": 0x401020, "end": 0x401030, "name": "FID_conflict:_printf", "source": "ANALYSIS"},
        {"entry": 0x401030, "end": 0x401040, "name": "_printf", "source": "DEFAULT", "thunk": True},
        {"entry": 0x401040, "end": 0x401050, "name": "___tmainCRTStartup", "source": "ANALYSIS"},
        {"entry": 0x401050, "end": 0x401060, "name": "entry", "source": "IMPORTED"},
        {"entry": 0x401060, "end": 0x401070, "name": "FUN_00401060", "source": "DEFAULT"},
    ]
    functions = scratch_pe.analyse(_test_pe(), found)
    assert [f.addr for f in functions if not f.library] == [0x401000, 0x401030, 0x401050, 0x401060]
    assert [f.addr for f in functions if f.library] == [0x401020, 0x401040]
    assert functions[1].name == "_printf"  # compiled calls resolve to the library symbol, not func_00401020
    assert functions[2].name == "_printf"  # calls through the linker thunk use its destination's symbol too


def test_only_32_bit_x86_programs():
    assert not scratch_pe.is_pe(b"MZ" + bytes(0x3E))
    head = bytearray(0x200)
    head[:2], head[0x3C:0x40], head[0x80:0x84] = b"MZ", struct.pack("<I", 0x80), b"PE\0\0"
    struct.pack_into("<H", head, 0x84, 0x14C)
    struct.pack_into("<H", head, 0x98, 0x10B)
    assert scratch_pe.is_pe(bytes(head))
    struct.pack_into("<H", head, 0x84, 0x8664)  # x64
    assert not scratch_pe.is_pe(bytes(head))


def test_visual_c_2005_is_picked_from_its_rich_header():
    plain = b"DanS" + bytes(12) + struct.pack("<II", (125 << 16) | 50727, 3)
    key = b"test"
    rich = bytes(b ^ key[i % 4] for i, b in enumerate(plain)) + b"Rich" + key
    program = bytearray(0x200)
    program[:2], program[0x3C:0x40] = b"MZ", struct.pack("<I", 0x180)
    program[0x80:0x80 + len(rich)] = rich
    program[0x180:0x184] = b"PE\0\0"
    assert scratch_pe.guess_compiler(bytes(program))[0] == "8.0-sp1"


def test_pc_configure_accepts_visual_c_2005_lowercase_directories(tmp_path):
    project = tmp_path / "project"
    shutil.copytree(scratch_pe.TEMPLATE, project)
    config = project / "config" / "game"
    config.mkdir(parents=True)
    (config / "functions.json").write_text('{"units": []}', encoding="utf-8")
    msvc = tmp_path / "msvc" / "8.0-sp1"
    (msvc / "bin").mkdir(parents=True)
    (msvc / "bin" / "cl.exe").touch()
    (msvc / "include").mkdir()
    configure = project / "tools" / "configure.py"
    configure.write_text(configure.read_text(encoding="utf-8").replace('MSVC_VERSION = "6.0"',
                                                                        'MSVC_VERSION = "8.0-sp1"'), encoding="utf-8")
    subprocess.run([sys.executable, str(configure), "game", "--msvc", str(tmp_path / "msvc")], cwd=project, check=True)
    ninja = (project / "build.ninja").read_text(encoding="utf-8").lower()
    assert str(msvc / "bin" / "cl.exe").lower() in ninja and str(msvc / "include").lower() in ninja


def test_pc_compiler_settings_are_read_and_changed(tmp_path, monkeypatch):
    project = tmp_path / "project"
    shutil.copytree(scratch_pe.TEMPLATE, project)
    pack = tmp_path / "msvc"
    (pack / "8.0-sp1").mkdir(parents=True)
    monkeypatch.setattr(toolchains, "path", lambda name: pack if name == "msvc" else None)

    assert scratch_pe.compiler_settings(project) == ("MSVC/6.0", scratch_pe.DEFAULT_CL_FLAGS)
    selected = ["/O2", "/MT", "/EHsc", "/W4", "/D_CRT_SECURE_NO_WARNINGS"]
    assert scratch_pe.set_compiler_settings(project, "MSVC/8.0-sp1", selected) == (
        "MSVC/8.0-sp1", ["/nologo", "/c", *selected])
    assert scratch_pe.compiler_settings(project) == ("MSVC/8.0-sp1", ["/nologo", "/c", *selected])
    with pytest.raises(scratch_pe.ForkError, match="before linking"):
        scratch_pe.set_compiler_settings(project, "MSVC/8.0-sp1", [*selected, "/link", "/INCREMENTAL:NO"])


def test_pc_scratch_compiler_settings_are_editable_from_the_app(tmp_path, monkeypatch):
    from decompnet.app.engine import RomNetwork
    from decompnet.forks.project import ForkProject

    net = RomNetwork(tmp_path / "decomp.db", tmp_path / "ws")
    root = tmp_path / "ws" / "pc"
    shutil.copytree(scratch_pe.TEMPLATE, root)
    manifest = {"created": "from scratch", "platform": "win32", "version": "game",
                "setup": [["python", "tools/configure.py", "game", "--msvc", "/old"], ["ninja", "prepare"]]}
    (root / ".decomp.wtf.json").write_text(json.dumps(manifest), encoding="utf-8")
    cfg = {"kind": "fork", "origin": "scratch", "platform": "win32", "version": "game",
           "fork_kind": "manifest", "ready": True, "compiler": "MSVC/6.0"}
    net.forks._register("pc", "PC game", "test", root, cfg, "test")
    pack = tmp_path / "msvc"
    (pack / "8.0-sp1").mkdir(parents=True)
    monkeypatch.setattr(toolchains, "path", lambda name: pack if name == "msvc" else None)
    monkeypatch.setattr(scratch_pe, "tool_args", lambda: ["--msvc", str(pack)])
    monkeypatch.setattr(ForkProject, "run", lambda self, command: (True, ""))
    monkeypatch.setattr(net.forks, "_build_all", lambda proj, fp, failed=None: (True, ""))
    monkeypatch.setattr(ForkProject, "failed_units", lambda self, failed: set())
    monkeypatch.setattr(ForkProject, "report", lambda self: {"units": [], "measures": {}})
    monkeypatch.setattr(net.forks, "sync", lambda slug, **kwargs: {})

    flags = ["/O2", "/MT", "/EHsc", "/W4", "/D_CRT_SECURE_NO_WARNINGS"]
    net.set_compiler("pc", "MSVC/8.0-sp1", flags)
    overview = net.overview("pc")
    assert overview["compiler"] == {"toolchain": "MSVC/8.0-sp1", "name": "Visual C++ 8.0-sp1",
                                    "flags": ["/nologo", "/c", *flags], "installed": True,
                                    "proprietary": True, "supported": True, "editable": True}
    saved = json.loads((root / ".decomp.wtf.json").read_text(encoding="utf-8"))
    assert saved["compiler"] == "MSVC/8.0-sp1" and saved["compiler_flags"] == ["/nologo", "/c", *flags]


def test_pc_global_header_requires_an_explicit_context_edit(tmp_path, monkeypatch):
    """A one-function declaration must not accidentally start a build of every generated PC unit."""
    from decompnet.app.engine import RomNetwork

    net = RomNetwork(tmp_path / "decomp.db", tmp_path / "ws")
    root = tmp_path / "ws" / "pc"
    shutil.copytree(scratch_pe.TEMPLATE, root)
    manifest = {"created": "from scratch", "platform": "win32", "version": "game"}
    (root / ".decomp.wtf.json").write_text(json.dumps(manifest), encoding="utf-8")
    cfg = {"kind": "fork", "origin": "scratch", "platform": "win32", "version": "game",
           "fork_kind": "manifest", "ready": True, "compiler": "MSVC/8.0-sp1"}
    net.forks._register("pc", "PC game", "test", root, cfg, "test")
    agent, _ = net.local_agent("pc-agent")
    shared = []
    monkeypatch.setattr(net.forks, "_edit_shared", lambda *args: shared.append(args) or "✅ shared header updated")

    with pytest.raises(NetworkError, match=r"rebuild the whole project.*use edit_context"):
        net.forks.edit_file(agent, "pc", "include/common.h", "", "struct OneFunction {};", "local type")
    assert not shared

    result = tools.call(net, agent, "pc", "edit_context",
                        {"old": "", "new": "struct Shared {};", "message": "shared type"})
    assert result.startswith("✅") and len(shared) == 1
    assert "edit_context" in tools.tool_names(fork=True)


def _map() -> dict[str, int]:
    """Symbol -> address of every function and variable, from the linker's map of the demo."""
    return {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r"^\s+\S+\s+(\S+)\s+([0-9a-f]{8}) ", MAP.read_text(), re.M)}


@pytest.fixture(scope="module")
def pc(tmp_path_factory):
    from decompnet.app.engine import RomNetwork

    if not EXE.exists():
        subprocess.run([sys.executable, str(DEMO / "build.py")], check=True)
    work = tmp_path_factory.mktemp("pc")
    net = RomNetwork(work / "app.db", work)
    slug = net.import_rom(EXE, confirmed=True, log=lambda *_: None)
    return net, slug


@needs_tools
def test_every_function_is_found_with_its_extent(pc):
    net, slug = pc
    ov = net.overview(slug)
    assert ov["kind"] == "fork" and ov["origin"] == "scratch" and ov["platform"] == "win32" and ov["ready"]
    syms = {a: s for s, a in _map().items() if not s.startswith("??") and a < 0x402000}
    rows = net.store.all("SELECT name, size FROM functions WHERE project_id=?", net.project_row(slug)["id"])
    assert len(rows) == len(syms) == 19  # clamp_s32, which nothing calls, too: Ghidra misses it, the gap doesn't
    for name, size in ((r["name"], r["size"]) for r in rows):
        addr = int(re.search(r"func_([0-9A-F]{8})", name).group(1), 16)
        assert addr in syms
        assert name.startswith("@") == syms[addr].startswith("@") and name.endswith("@8") == syms[addr].endswith("@8")
    root = Path(net.project_row(slug)["root"])
    files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
    assert files and not [f for f in files if f.startswith(("orig/", "build/"))]
    assert "config/demoquest/functions.json" in files and any(f.startswith("src/auto/") and f.endswith(".cpp") for f in files)


@needs_tools
def test_agents_match_functions(pc):
    net, slug = pc
    syms = _map()
    agent, _ = net.local_agent("pc-agent")
    header = (GAME.parent / "game.h").read_text().split("#define NULL ((void *)0)", 1)[1].rsplit("#endif", 1)[0]
    rename = {re.sub(r"^[_@]|@\d+$", "", s): (f"func_{a:08X}" if a < 0x402000 else f"D_{a:08X}")
              for s, a in syms.items() if not s.startswith("??") and s != "__fltused"}
    pattern = re.compile(r"\b(" + "|".join(sorted(rename, key=len, reverse=True)) + r")\b")
    sub = lambda text: pattern.sub(lambda m: rename[m.group(1)], text)
    header += "extern s32 g_settings[6];\n"
    assert net.forks.edit_context(agent, slug, "", sub(header), "the game's types").startswith("✅")
    source = GAME.read_text() + (DEMO / "pcmain.c").read_text()
    for name in ("clamp_s32", "player_take_damage", "entity_default_hp", "settings_get", "mix_score"):
        decorated = next(s for s in syms if re.sub(r"^[_@]|@\d+$", "", s) == name)
        res = net.attempt(agent, decorated.replace(name, rename[name]), sub(csource.get(source, name)), slug)
        assert res["matched"], res["text"]
    # C++: a class's method, whatever MSVC mangles its name to, pairs with the original's function
    abs_name = rename["abs_s32"]
    assert net.forks.edit_context(agent, slug, "", f"struct Num {{ static s32 {abs_name}(s32 v); }};\n",
                                  "a class").startswith("✅")
    res = net.attempt(agent, f"_{abs_name}", f"s32 Num::{abs_name}(s32 v) {{\n    return v < 0 ? -v : v;\n}}\n", slug)
    assert res["matched"], res["text"]
    other = f"_func_{syms['_entity_points']:08X}"
    wrong = net.attempt(agent, other, sub(csource.get(source, "entity_points")).replace("return 75;", "return 76;"),
                        slug)
    assert not wrong["matched"]
    net.release(agent, other, "", slug)
    root = Path(net.project_row(slug)["root"])
    assert "Match " in subprocess.run(["git", "log", "--oneline"], cwd=root, capture_output=True, text=True).stdout
