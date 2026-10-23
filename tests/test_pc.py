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
from decompnet.consoles.pc import scratch as scratch_pe
from decompnet.forks import csource, ghidra
from decompnet.forks.project import ForkError, ForkProject
from decompnet.network import NetworkError

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "projects" / "demo-pc"
EXE, MAP = DEMO / "build" / "demoquest.exe", DEMO / "build" / "demoquest.map"
GAME = ROOT / "projects" / "demo-n64" / "original" / "game.c"

needs_tools = pytest.mark.skipif(
    any(toolchains.installed(t) is None for t in ("msvc", "objdiff-cli")) or not ghidra.available()
    or (sys.platform != "win32" and toolchains.get("wibo").supported and toolchains.installed("wibo") is None),
    reason="needs Visual C++ (msvc, proprietary), Ghidra and objdiff")


def test_decorated_names():
    assert scratch_pe.decorate("func_00401000", "__cdecl", 0, 2) == "_func_00401000"
    assert scratch_pe.decorate("func_00401000", "__stdcall", 0, 0) == "_func_00401000"  # Ghidra's default: nothing popped
    assert scratch_pe.decorate("func_00401000", "__stdcall", 8, 2) == "_func_00401000@8"
    assert scratch_pe.decorate("func_00401000", "__fastcall", 0, 2) == "@func_00401000@8"
    assert scratch_pe.decorate("func_00401000", "__fastcall", 4, 3) == "@func_00401000@12"
    assert scratch_pe.decorate("func_00401000", "__thiscall", 4, 2) == "@func_00401000@12"  # this, unused edx, one int


def test_generated_pc_builds_quote_paths_and_only_process_successful_objects(tmp_path, monkeypatch):
    """The compiler and its includes may live in a Windows user folder with spaces or shell characters."""
    root = tmp_path / "Project with spaces ü"
    tools = Path(scratch_pe.__file__).with_name("project_template") / "tools"
    shutil.copytree(tools, root / "tools")
    source = root / "src/auto/sample.cpp"
    source.parent.mkdir(parents=True)
    source.write_text("int sample(void) { return 1; }\n")
    config = root / "config/TEST/functions.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"units": {"sample": {}}}))
    (root / "include").mkdir()
    compiler_root = tmp_path / "Compiler & tools $ ü"
    compiler = compiler_root / "6.0/Bin/CL.EXE"
    compiler.parent.mkdir(parents=True)
    (compiler_root / "6.0/Include").mkdir()
    record = root / "compiler-args.txt"
    monkeypatch.setenv("DECOMP_TEST_CL_ARGS", str(record))
    monkeypatch.delenv("DECOMP_TEST_CL_FAIL", raising=False)
    if sys.platform == "win32":
        subprocess.run([sys.executable, str(Path(__file__).with_name("fake_clr_compiler.py")), str(compiler)],
                       check=True, capture_output=True, timeout=30)
    else:
        compiler.write_text('#!/usr/bin/env python3\nimport os, sys\nfrom pathlib import Path\n'
                            'Path(os.environ["DECOMP_TEST_CL_ARGS"]).write_text("\\n".join(sys.argv[1:]))\n'
                            'if os.environ.get("DECOMP_TEST_CL_FAIL") == "1": sys.exit(3)\n'
                            'out = Path(next(arg[3:] for arg in sys.argv if arg.startswith("/Fo")))\n'
                            'out.parent.mkdir(parents=True, exist_ok=True)\nout.write_text("object")\n')
        compiler.chmod(0o755)
    # Only command routing is under test: no fake object ever reaches the real judge.
    (root / "tools/names.py").write_text('import sys\nfrom pathlib import Path\n'
                                        'out = Path(sys.argv[2])\nassert out.read_text() == "object"\n'
                                        'out.with_suffix(".named").write_text("processed")\n')
    subprocess.run([sys.executable, str(root / "tools/configure.py"), "TEST", "--msvc", str(compiler_root)],
                   check=True, capture_output=True, timeout=30)
    project = ForkProject(root)
    ok, output = project.run(["ninja", "all_source"], log=lambda _: None, timeout=30)
    assert ok, output
    obj = root / "build/TEST/src/auto/sample.obj"
    assert obj.with_suffix(".named").read_text() == "processed"
    args = record.read_text(encoding="utf-8-sig").splitlines()
    assert "/I" + str(compiler_root / "6.0/Include") in args and "/GX" in args
    obj.with_suffix(".named").unlink()
    obj.unlink()
    source.write_text("int sample(void) { return 2; }\n")  # also exercise configure.py's regeneration command
    monkeypatch.setenv("DECOMP_TEST_CL_FAIL", "1")
    ok, output = project.run(["ninja", "all_source"], log=lambda _: None, timeout=30)
    assert not ok and not obj.with_suffix(".named").exists(), output


def test_only_32_bit_x86_programs():
    assert not scratch_pe.is_pe(b"MZ" + bytes(0x3E))
    head = bytearray(0x200)
    head[:2], head[0x3C:0x40], head[0x80:0x84] = b"MZ", struct.pack("<I", 0x80), b"PE\0\0"
    struct.pack_into("<H", head, 0x84, 0x14C)
    struct.pack_into("<H", head, 0x98, 0x10B)
    assert scratch_pe.is_pe(bytes(head))
    struct.pack_into("<H", head, 0x84, 0x8664)  # x64
    assert not scratch_pe.is_pe(bytes(head))


def test_a_function_your_object_only_calls_is_not_in_your_build_not_a_match(monkeypatch):
    import json

    from decompnet.forks import objdiff

    # an object that calls F but doesn't define it (a unit whose definition went missing): objdiff lists the call's
    # undefined symbol under the function's name, with no size or code. The function's diff read 100% (its code
    # against nothing), the full report said not built, and every full measure reopened a function the next
    # compile "matched" again (63 times in 14 hours in one project)
    ins = [{"instruction": {"formatted": "mov eax, 1", "size": 5}}, {"instruction": {"formatted": "ret", "size": 1}}]
    left = {"symbols": [{"name": "?F@@YA_NXZ", "kind": "SYMBOL_FUNCTION", "size": "6", "instructions": ins}]}
    right = {"symbols": [{"name": "?F@@YA_NXZ", "kind": "SYMBOL_FUNCTION", "flags": {"global": True}},
                         {"name": "?G@@YAXXZ", "kind": "SYMBOL_FUNCTION", "size": "6", "instructions": ins}]}
    monkeypatch.setattr(objdiff, "_run", lambda *a, **k: json.dumps({"left": left, "right": right}))
    d = objdiff.diff(None, None, "?F@@YA_NXZ", cwd=Path("."))
    assert d.match_percent is None and not d.matched
    assert d.unit_scores["?F@@YA_NXZ"] is None
    # defined after its undefined copy: that's the one compared
    right["symbols"].append({"name": "?F@@YA_NXZ", "kind": "SYMBOL_FUNCTION", "size": "6", "match_percent": 100.0,
                             "instructions": ins})
    d = objdiff.diff(None, None, "?F@@YA_NXZ", cwd=Path("."))
    assert d.match_percent == 100.0 and d.matched


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
    assert ov["kind"] == "fork" and ov["origin"] == "scratch" and ov["platform"] == "pc" and ov["ready"]
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
    assert net.forks.edit_file(agent, slug, "include/common.h", "", sub(header), "the game's types").startswith("✅")
    source = GAME.read_text() + (DEMO / "pcmain.c").read_text()
    for name in ("clamp_s32", "player_take_damage", "entity_default_hp", "settings_get", "mix_score"):
        decorated = next(s for s in syms if re.sub(r"^[_@]|@\d+$", "", s) == name)
        res = net.attempt(agent, decorated.replace(name, rename[name]), sub(csource.get(source, name)), slug)
        assert res["matched"], res["text"]
    # C++: a class's method, whatever MSVC mangles its name to, pairs with the original's function
    abs_name = rename["abs_s32"]
    assert net.forks.edit_file(agent, slug, "include/common.h", "", f"struct Num {{ static s32 {abs_name}(s32 v); }};\n",
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


@needs_tools
def test_matched_functions_and_data_get_real_names(pc):
    """rename_symbol on a PC project (it said it couldn't: names came from addresses): the function keeps its
    decoration, its row and its match; data too; the C, the original's objects and read_data have the new names."""
    from decompnet import consoles

    net, slug = pc
    syms = _map()
    agent, _ = net.local_agent("pc-agent")
    pid = net.project_row(slug)["id"]
    root = Path(net.project_row(slug)["root"])
    clamp = f"func_{syms['_clamp_s32']:08X}"
    row = net.store.one("SELECT id, name, status FROM functions WHERE project_id=? AND name LIKE ?", pid, f"%{clamp}%")
    assert row["status"] == "matched"
    said = net.rename_symbol(agent, slug, row["name"], "clamp_value", "it clamps")  # (as the function list has it)
    assert said.startswith("✅"), said
    after = net.store.one("SELECT name, status, meta FROM functions WHERE id=?", row["id"])
    assert after["name"] == row["name"].replace(clamp, "clamp_value") and after["status"] == "matched"
    assert json.loads(after["meta"])["symbol"] == after["name"]
    sources = "".join(p.read_text() for p in (root / "src").rglob("*.cpp"))
    assert "clamp_value" in sources and clamp not in sources
    settings = f"D_{syms['_g_settings']:08X}"
    at = next(a for s, a in syms.items() if re.sub(r"^[_@]|@\d+$", "", s) == "settings_get")
    getter = net.store.one("SELECT name FROM functions WHERE project_id=? AND name LIKE ?", pid, f"%func_{at:08X}%")["name"]
    assert net.store.one("SELECT status FROM functions WHERE name=?", getter)["status"] == "matched"
    said = net.rename_symbol(agent, slug, settings, "g_settings")
    assert said.startswith("✅"), said
    assert net.store.one("SELECT status FROM functions WHERE name=?", getter)["status"] == "matched"
    assert json.loads((root / "config" / "demoquest" / "names.json").read_text()) == {
        clamp: "clamp_value", settings: "g_settings"}
    fp = ForkProject(root)
    assert consoles.get("pc").read_data(fp, "g_settings", 16).startswith(settings)
    with pytest.raises(NetworkError, match=r"used in the project already \(in (src|include)/"):  # (data: a file uses it)
        net.rename_symbol(agent, slug, "clamp_value", "g_settings")
    getter_c = re.sub(r"^[_@]|@\d+$", "", getter)
    with pytest.raises(NetworkError, match=f"it's the name of the function {re.escape(getter)}"):
        net.rename_symbol(agent, slug, "clamp_value", getter_c)
    # asked again, hours later (helpers did, often their own): done already, not an error
    assert net.rename_symbol(agent, slug, row["name"], "clamp_value").startswith("✅ func_")
    # looked up by the name the C gives it, not only the function list's decorated symbol
    assert net._function("clamp_value", slug)["id"] == row["id"]
    # and by the name it had when a helper was handed it, renamed since (twice: its newest name)
    assert net.rename_symbol(agent, slug, "clamp_value", "clamp_to_range").startswith("✅")
    found = net._function(row["name"], slug)
    assert found["id"] == row["id"] and "clamp_to_range" in found["name"]
    assert net._function("clamp_value", slug)["id"] == row["id"]


def test_a_program_built_with_a_newer_visual_cpp_is_told_apart():
    """GitHub #12: a 2010 game said only "Ghidra found no functions". Its Rich header could have said why."""
    vc6_game = [(0x0A, 8168, 120), (0x0B, 8168, 30), (0x01, 0, 200)]
    vs2008_game = [(0x83, 30729, 300), (0x84, 30729, 40), (0x91, 30729, 1)]
    vc71_with_a_newer_library = [(0x5F, 3077, 90), (0x6D, 50727, 2)]
    assert scratch_pe.newer_tools(vs2008_game)
    assert not scratch_pe.newer_tools(vc6_game)
    assert not scratch_pe.newer_tools(vc71_with_a_newer_library)  # the game's own compiler is in the pack
    assert not scratch_pe.newer_tools([])  # no Rich header: nothing to go by


def test_a_program_built_with_visual_cpp_2005_gets_8_0(monkeypatch):
    """Visual C++ 2005 (RTM and SP1 both leave build 50727) is in the pack: no longer "newer", and the guess."""
    vs2005_game = [(0x6D, 50727, 140), (0x6E, 50727, 60), (0x78, 50727, 1)]
    assert not scratch_pe.newer_tools(vs2005_game)
    monkeypatch.setattr(scratch_pe, "rich_builds", lambda data: vs2005_game)
    assert scratch_pe.guess_compiler(b"")[0] == "8.0-sp1"


def test_the_project_is_set_up_for_its_visual_cpp(tmp_path):
    """8.0 deprecated /GX for /EHsc, and 8.0 SP1's pack keeps bin/ and include/ in lowercase."""
    template = (scratch_pe.TEMPLATE / "tools" / "configure.py").read_text(encoding="utf-8")
    assert '"/GX"]' in scratch_pe.settings(template, "7.1") and 'MSVC_VERSION = "7.1"' in scratch_pe.settings(template, "7.1")
    eight = scratch_pe.settings(template, "8.0-sp1")
    assert '"/EHsc"]' in eight and '"/GX"' not in eight and 'MSVC_VERSION = "8.0-sp1"' in eight

    root = tmp_path / "game"
    for d in ("tools", "src", "include", "config/game"):
        (root / d).mkdir(parents=True)
    for f in ("ninja_syntax.py", "delink.py", "names.py"):
        (root / "tools" / f).write_text((scratch_pe.TEMPLATE / "tools" / f).read_text(encoding="utf-8"), encoding="utf-8")
    (root / "tools" / "configure.py").write_text(eight, encoding="utf-8")
    (root / "config" / "game" / "functions.json").write_text('{"units": {}}', encoding="utf-8")
    msvc = tmp_path / "msvc"
    (msvc / "8.0-sp1" / "bin").mkdir(parents=True)
    (msvc / "8.0-sp1" / "include").mkdir()
    (msvc / "8.0-sp1" / "bin" / "cl.exe").write_bytes(b"MZ")
    subprocess.run([sys.executable, "tools/configure.py", "game", "--msvc", str(msvc)], cwd=root, check=True)
    ninja = (root / "build.ninja").read_text(encoding="utf-8")
    unwrapped = re.sub(r" ?\$\n *", " ", ninja)  # (ninja_syntax wraps long lines)
    assert f"--compiler {msvc / '8.0-sp1' / 'bin' / 'cl.exe'}" in unwrapped
    assert f"--include {msvc / '8.0-sp1' / 'include'}" in unwrapped
    assert "/EHsc" in ninja
    # build.ninja is written again when a file is added or removed, not after every edit (half a minute on a big
    # game); and whole, from a temporary file
    regen = next(line for line in ninja.replace("$\n", "").splitlines() if line.startswith("build build.ninja:"))
    assert " src" in regen and " include" in regen and ".cpp" not in regen
    assert not (root / "build.ninja.tmp").exists()


GHIDRA_PROJECT = {"names": {0x492AB0: "_func_00492AB0", 0x4F6C80: "_func_004F6C80@4", 0x401000: "_func_00401000",
                            0x401020: "_func_00401020@8", 0x401040: "@func_00401040@8"},
                  "imports": {"Sleep": "__imp__Sleep@4"}}


def test_ghidras_c_becomes_a_draft_visual_cpp_compiles():
    """Autopilot on PC (m2c reads no x86): Ghidra's C with the project's names, conventions and declarations."""
    from decompnet.consoles.pc import ghidra_c

    row = {"entry": 0x401000, "refs": {
        "Sleep": {"at": 0, "kind": "import", "ret": "void", "args": ["DWORD"]},
        "FUN_00401020": {"at": 0x401020, "kind": "func", "ret": "int", "args": ["char *", "undefined4"]},
        "DAT_00402034": {"at": 0x402034, "kind": "data", "type": "undefined4", "size": 4},
        "_DAT_00402038": {"at": 0x402038, "kind": "data", "type": "Thing *", "size": 4}},
        "c": "\nint FUN_00401000(char *param_1)\n\n{\n  int iVar1;\n  Sleep(5);\n"
             "  iVar1 = FUN_00401020(param_1,DAT_00402034);\n  return iVar1 + (int)_DAT_00402038;\n}\n"}
    code, outer = ghidra_c.draft(row, GHIDRA_PROJECT)
    assert outer == 'extern "C" __declspec(dllimport) void __stdcall Sleep(DWORD);'
    assert code.startswith("int __cdecl func_00401000(char *param_1)\n{\n")
    assert "  int __stdcall func_00401020(char *, undefined4);\n" in code
    assert "  extern undefined4 D_00402034;\n" in code and "  extern void * D_00402038;\n" in code
    assert "func_00401020(param_1,D_00402034)" in code and "FUN_" not in code and "DAT_" not in code


def test_methods_and_unused_arguments_keep_the_originals_convention():
    """`mov eax, ecx; ret` is a method returning this (Ghidra: a __fastcall of one argument, the project: _f); a
    __stdcall pops its arguments even when Ghidra saw none used (`ret 4`)."""
    from decompnet.consoles.pc import ghidra_c

    method = {"entry": 0x492AB0, "refs": {},
              "c": "\nundefined4 __fastcall FUN_00492ab0(undefined4 param_1)\n\n{\n  return param_1;\n}\n"}
    code, outer = ghidra_c.draft(method, GHIDRA_PROJECT)
    assert outer == "struct M_00492AB0 { undefined4 func_00492AB0(void); };"
    assert code.startswith("undefined4 M_00492AB0::func_00492AB0(void)\n{\n  undefined4 param_1 = (undefined4)this;")
    stdcall = {"entry": 0x4F6C80, "refs": {}, "c": "\nvoid FUN_004f6c80(void)\n\n{\n  return;\n}\n"}
    assert ghidra_c.draft(stdcall, GHIDRA_PROJECT)[0].startswith("void __stdcall func_004F6C80(undefined4 unused_0)")


def test_what_cant_compile_as_it_is_gets_no_draft():
    from decompnet.consoles.pc import ghidra_c

    def c(body, refs=None, entry=0x401000):
        return ghidra_c.draft({"entry": entry, "refs": refs or {}, "c": f"\nint FUN_00401000(void)\n\n{{\n{body}\n}}\n"},
                              GHIDRA_PROJECT)
    assert c("  return in_EAX;") is None  # a register Ghidra couldn't place
    assert c("  return FUN_00409990();") is None  # a call no token said where to
    assert c("  return FUN_00401040(1);", {"FUN_00401040": {"at": 0x401040, "kind": "func", "ret": "int",
                                                            "args": ["int"]}}) is None  # arguments in registers
    assert c("  return 0;", entry=0x777777) is None  # not one of the project's functions
    assert ghidra_c.draft({"entry": 0x401000, "thunk": True, "refs": {}, "c": "\nvoid f(void)\n{\n}\n"}, GHIDRA_PROJECT) is None
    assert c("  return 0;") is not None


def test_ghidras_types_go_into_common_h_once():
    from decompnet.consoles.pc import ghidra_c, scratch

    once = ghidra_c.add_types(scratch.TYPES_H)
    assert "typedef unsigned int undefined4;" in once and once.rstrip().endswith("#endif")
    assert ghidra_c.add_types(once) is None


def test_visual_cpps_flag_variants():
    from decompnet.app.engine import RomNetwork

    variants = RomNetwork.flag_variants(None, "MSVC/8.0-sp1", ["/nologo", "/c", "/O2", "/W3", "/EHsc"])
    assert variants[0] == ["/nologo", "/c", "/O2", "/W3", "/EHsc"]
    assert ["/nologo", "/c", "/O1", "/W3", "/EHsc"] in variants  # another optimisation level, in its place
    assert ["/nologo", "/c", "/O2", "/W3", "/EHsc", "/Oy-"] in variants and len(variants) <= 12


def test_a_file_builds_with_flags_of_its_own(tmp_path):
    """Games built their parts with different flags: config/<version>/flags.json gives one file its own, after
    CL_FLAGS (Visual C++ takes the last of a kind), and changing it writes build.ninja again."""
    from types import SimpleNamespace

    template = (scratch_pe.TEMPLATE / "tools" / "configure.py").read_text(encoding="utf-8")
    root = tmp_path / "game"
    for d in ("tools", "src/auto", "include", "config/game"):
        (root / d).mkdir(parents=True)
    for f in ("ninja_syntax.py", "delink.py", "names.py"):
        (root / "tools" / f).write_text((scratch_pe.TEMPLATE / "tools" / f).read_text(encoding="utf-8"), encoding="utf-8")
    (root / "tools" / "configure.py").write_text(scratch_pe.settings(template, "8.0-sp1"), encoding="utf-8")
    (root / "config" / "game" / "functions.json").write_text('{"units": {}}', encoding="utf-8")
    (root / "src" / "auto" / "text_00401000.cpp").write_text("", encoding="utf-8")
    fp = SimpleNamespace(root=root, manifest={"version": "game"})
    assert scratch_pe.file_flags(fp, "src/auto/text_00401000.cpp") == ("MSVC/8.0-sp1", ["/nologo", "/c", "/O2", "/W3", "/EHsc"])
    rel = scratch_pe.set_file_flags(fp, "src/auto/text_00401000.cpp", ["/nologo", "/c", "/O2", "/W3", "/EHsc", "/O1", "/Oy-"])
    assert rel == "config/game/flags.json"
    assert json.loads((root / rel).read_text()) == {"src/auto/text_00401000.cpp": ["/O1", "/Oy-"]}
    assert scratch_pe.file_flags(fp, "src/auto/text_00401000.cpp")[1][-2:] == ["/O1", "/Oy-"]
    subprocess.run([sys.executable, "tools/configure.py", "game", "--msvc", str(tmp_path / "msvc")], cwd=root, check=True)
    ninja = (root / "build.ninja").read_text(encoding="utf-8").replace("$\n", "")
    assert "cflags = /O1 /Oy-" in ninja
    regen = next(line for line in ninja.splitlines() if line.startswith("build build.ninja:"))
    assert "config/game " in regen + " " and "config/game/flags.json" in regen
    # back to the project's flags: the file's own go
    scratch_pe.set_file_flags(fp, "src/auto/text_00401000.cpp", ["/nologo", "/c", "/O2", "/W3", "/EHsc"])
    assert json.loads((root / rel).read_text()) == {}
    # a project made before flags file by file is told so, not left half-changed
    (root / "tools" / "configure.py").write_text(template.replace("flags.json", "x"), encoding="utf-8")
    with pytest.raises(ForkError, match="older than flags file by file"):
        scratch_pe.set_file_flags(fp, "src/auto/text_00401000.cpp", ["/O1"])


def test_one_ghidra_at_a_time(monkeypatch, tmp_path):
    """Each Ghidra is a JVM of 2 GB and more: eight agents asking for drafts at once ran an 8 GB server out of memory."""
    import threading
    import time

    now, most = [0], [0]
    lock = threading.Lock()

    def run(*args, **kwargs):
        with lock:
            now[0] += 1
            most[0] = max(most[0], now[0])
        time.sleep(0.2)
        with lock:
            now[0] -= 1
        return subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(ghidra.subprocess, "run", run)
    exe = tmp_path / "a.exe"
    exe.write_bytes(b"MZ")

    def one():
        try:
            ghidra._run_script(exe, "DecompWtfExport.java", 10)
        except ForkError:  # (the fake Ghidra writes nothing)
            pass
    threads = [threading.Thread(target=one) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert most[0] == 1


def test_an_agents_draft_never_waits_for_ghidra(monkeypatch, tmp_path):
    """get_function on PC: drafts come from one Ghidra run over the whole program, made in the background; until
    then there's none (not a Ghidra of each agent's own), and asking again doesn't start another run."""
    import threading
    from types import SimpleNamespace

    from decompnet.consoles.pc import ghidra_c

    root = tmp_path / "game"
    (root / "config" / "v").mkdir(parents=True)
    (root / "orig").mkdir()
    (root / "orig" / "g.exe").write_bytes(b"MZ")
    (root / "config" / "v" / "functions.json").write_text(json.dumps({"units": {"u": [
        {"name": "_func_00401000", "addr": 0x401000, "size": 1, "relocs": []}]}}))
    fp = SimpleNamespace(root=root, manifest={"game": {"path": "orig/g.exe"}, "version": "v"})
    go, runs = threading.Event(), []

    def program_drafts(exe, addresses, out, timeout=0):
        runs.append(addresses)
        go.wait(5)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"entry": 0x401000, "refs": {}, "c": "\nvoid FUN_00401000(void)\n\n{\n  return;\n}\n"}) + "\n")
        return True
    monkeypatch.setattr(ghidra, "program_drafts", program_drafts)
    monkeypatch.setattr(ghidra_c, "_LOADED", {})
    assert ghidra_c.program_c(fp, "_func_00401000") is None
    assert ghidra_c.program_c(fp, "_func_00401000") is None
    go.set()
    for _ in range(100):
        if ghidra_c._LOADED.get(root):
            break
        threading.Event().wait(0.05)
    assert len(runs) == 1 and runs[0] == [0x401000]
    assert ghidra_c.program_c(fp, "_func_00401000").startswith("void __cdecl func_00401000(void)")



def test_a_ghidra_that_doesnt_run_leaves_no_drafts_and_says_why(monkeypatch, tmp_path):
    """Ghidra that didn't get to run raises (forks/ghidra.py, "Ghidra didn't run: ..."): the background run that
    makes the drafts says so in the log rather than dying with a traceback, and the next ask runs it again."""
    import threading

    from decompnet.consoles.pc import ghidra_c

    def program_drafts(exe, addresses, out, timeout=0):
        raise ForkError("Ghidra didn't run: no JDK")
    monkeypatch.setattr(ghidra, "program_drafts", program_drafts)
    said, done = [], threading.Event()
    ghidra_c._RUNNING[tmp_path] = done
    ghidra_c._make(tmp_path, tmp_path / "g.exe", [0x401000], tmp_path / "drafts.jsonl", done, said.append)
    assert done.is_set() and tmp_path not in ghidra_c._RUNNING
    assert said[-1] == "No machine drafts: Ghidra didn't run: no JDK"

def test_ghidras_unknown_purge_is_no_byte_count():
    """Ghidra says 0x7FFFFFFF for a purge it couldn't work out. A PC game had 91 functions named _f@2147483647, and
    their drafts made a list of 500 million unused parameters: the app ran an 8 GB server out of memory."""
    import time

    from decompnet.consoles.pc import ghidra_c

    assert scratch_pe.decorate("func_00401000", "__stdcall", 0x7FFFFFFF, 0) == "_func_00401000"
    assert scratch_pe.decorate("func_00401000", "__fastcall", 0x7FFFFFFF, 2) == "@func_00401000@8"
    project = {"names": {0x401000: "_func_00401000@2147483647"}, "imports": {}}
    t = time.monotonic()
    assert ghidra_c.draft({"entry": 0x401000, "refs": {}, "c": "\nvoid FUN_00401000(void)\n\n{\n  return;\n}\n"},
                          project) is None
    assert time.monotonic() - t < 1


def test_functions_ending_in_zero_bytes_arent_cut_short(tmp_path, monkeypatch):
    """Code Ghidra didn't make a function of ended where its bytes stopped being padding, zeros included: a PC game
    had 217 functions cut in the middle of their last instruction (a jmp e9 2b 21 00 00 as 3 bytes, a ret 8 as 2),
    which objdiff could never match. New projects end them at the last whole instruction; older ones are fixed."""
    from types import SimpleNamespace

    import capstone

    code = {0x401000: bytes.fromhex("e92b210000") + b"\xcc" * 11,  # jmp 0x403130, padding
            0x401010: bytes.fromhex("c20800") + b"\xcc" * 13}  # ret 8, padding
    blob = b"".join(code[a] for a in sorted(code))

    class FakePE:
        imports = {}

        def read(self, at, n):
            return blob[at - 0x401000:at - 0x401000 + n]

        def section_at(self, at):
            return SimpleNamespace(va=0x401000, size=len(blob), code=True)

        def contains(self, at):
            return False
    pe = FakePE()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    assert scratch_pe._whole(md, pe, 0x401000, 0x401003, 0x401010) == 0x401005
    assert scratch_pe._whole(md, pe, 0x401010, 0x401012, 0x401020) == 0x401013
    assert scratch_pe._whole(md, pe, 0x401000, 0x401005, 0x401010) == 0x401005  # whole already: as it was

    root = tmp_path / "game"
    (root / "config" / "v").mkdir(parents=True)
    (root / "orig").mkdir()
    (root / "orig" / "v.exe").write_bytes(b"MZ")
    (root / "config" / "v" / "functions.json").write_text(json.dumps({"exe": "orig/v.exe", "units": {
        "text_00401000": [{"name": "_func_00401000", "addr": 0x401000, "size": 3, "relocs": []},
                          {"name": "_func_00401010@8", "addr": 0x401010, "size": 2, "relocs": []}],
        "text_00403130": [{"name": "_func_00403130", "addr": 0x403130, "size": 1, "relocs": []}]}}))
    monkeypatch.setattr(scratch_pe, "read_pe", lambda data: pe)
    assert scratch_pe.fix_short_ends(root, "v") == ["_func_00401000", "_func_00401010@8"]
    fns = {f["name"]: f for u in json.loads((root / "config" / "v" / "functions.json").read_text())["units"].values()
           for f in u}
    assert fns["_func_00401000"]["size"] == 5 and fns["_func_00401000"]["relocs"] == [[1, 20, "_func_00403130", 0]]
    assert fns["_func_00401010@8"]["size"] == 3
    assert scratch_pe.fix_short_ends(root, "v") == []  # fixed already: nothing to change


def test_code_no_compiler_makes_is_set_aside():
    """Agents on a PC game built with /LTCG kept claiming code C can't give, and releasing it with notes: about one
    function in ten took an argument in a register Visual C++ never passes one in, and Ghidra had listed exception
    funclets and handler stubs, and jump tables, as functions of their own."""
    from decompnet.arch import x86

    def why(hexed):
        return x86.asm_reason(bytes.fromhex(hexed.replace(" ", "")))
    # an argument in eax: add eax,0x4000; push eax; call; add esp,4; ret
    assert "reads eax" in why("05 00 40 00 00 50 e8 35 ff ff ff 83 c4 04 c3")
    # `this` in esi: push ecx; movzx eax, word ptr [esi+0x5c]
    assert "reads esi" in why("51 0f b7 46 5c d9 ee c3")
    # an unwinding funclet: lea ecx,[ebp-0x58]; jmp <destructor>
    assert "part of the function before it" in why("8d 4d a8 e9 48 b7 f4 ff")
    # handler stubs: mov eax, <info>; jmp <handler>, and its /GS form
    assert "handler stub" in why("b8 30 86 96 00 e9 76 63 ff ff")
    assert "handler stub" in why("8b 54 24 08 8d 42 bc 8b 4a b8 33 c8 e8 42 26 ef ff b8 04 14 93 00 e9 e1 3d ef ff")
    assert "table of addresses" in why("80 8d 5b 00 86 8d 5b 00 8c 8d 5b 00 92 8d 5b 00")
    # what compiled code does
    assert why("8b 44 24 04 c3") is None  # mov eax,[esp+4]; ret
    assert why("8b c1 c3") is None  # mov eax,ecx; ret: a method returning this
    assert why("55 8b ec 56 8b 75 08 5e 5d c3") is None  # a frame, esi saved then loaded
    assert why("33 c0 c3") is None  # xor eax,eax: setting it
    assert why("55 57 33 ff 83 cd ff 8b c5 5f 5d c3") is None  # or ebp,-1: Visual C++'s ebp = -1
    assert why("6a 0c 68 98 15 93 00 e8 e2 88 00 00 8b 45 08 c3") is None  # __SEH_prolog4 sets ebp up for it
    assert why("e9 2b 21 00 00") is None and why("c2 08 00") is None


def test_two_functions_ghidra_took_for_one_are_split(tmp_path, monkeypatch):
    """`xor eax,eax; ret`, int3 padding to a 16-byte boundary, another `xor eax,eax; ret`: Ghidra made one 19-byte
    function of them, which no C matches. A PC game had 1,228 such, holding 4,433 functions; none ever matched."""
    from types import SimpleNamespace

    import capstone

    blob = bytes.fromhex("33c0c3") + b"\xcc" * 13 + bytes.fromhex("33c0c3") + b"\xcc" * 13 \
        + bytes.fromhex("ff2485") + b"\x00" * 4 + b"\xcc" * 9 + bytes.fromhex("33c0c3")  # a switch, then padding

    class FakePE:
        imports = {}

        def read(self, at, n):
            return blob[at - 0x401000:at - 0x401000 + n]

        def offset(self, at):
            return at - 0x401000

        def section_at(self, at):
            return SimpleNamespace(va=0x401000, size=len(blob), code=True)

        def contains(self, at):
            return False
    pe = FakePE()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    assert scratch_pe._split_point(md, pe, 0x401000, 0x401013) == 0x401003
    assert scratch_pe._split_point(md, pe, 0x401020, 0x401033) is None  # a switch: its table may follow padding
    root = tmp_path / "game"
    (root / "config" / "v").mkdir(parents=True)
    (root / "orig").mkdir()
    (root / "orig" / "v.exe").write_bytes(b"MZ")
    (root / "config" / "v" / "functions.json").write_text(json.dumps({"exe": "orig/v.exe", "units": {
        "text_00401000": [{"name": "_func_00401000", "addr": 0x401000, "size": 19, "relocs": []}]}}))
    monkeypatch.setattr(scratch_pe, "read_pe", lambda data: pe)
    assert scratch_pe.split_merged(root, "v") == ["_func_00401010"]
    unit = json.loads((root / "config" / "v" / "functions.json").read_text())["units"]["text_00401000"]
    assert [(f["name"], f["addr"], f["size"]) for f in unit] == [("_func_00401000", 0x401000, 3),
                                                                ("_func_00401010", 0x401010, 3)]
    assert scratch_pe.split_merged(root, "v") == []


def _coff_symbols(data: bytes) -> list[tuple[str, int]]:
    """(name, section) of each symbol of a COFF object, auxiliary records skipped."""
    sym_at, count = struct.unpack_from("<II", data, 8)
    strings_at, out, i = sym_at + 18 * count, [], 0
    while i < count:
        raw = data[sym_at + 18 * i:sym_at + 18 * i + 8]
        if raw[:4] == b"\0\0\0\0":
            off = strings_at + struct.unpack_from("<I", raw, 4)[0]
            raw = data[off:data.index(b"\0", off)]
        _, section, _, _, aux = struct.unpack_from("<IhHBB", data, sym_at + 18 * i + 8)
        out.append((raw.rstrip(b"\0").decode(), section))
        i += 1 + aux
    return out


def test_a_function_called_from_its_own_file_is_one_symbol_in_the_original_object(tmp_path):
    """A PC game's function called by another of its file had a second, undefined symbol of its name in the object
    cut from the program: objdiff paired it with that one, said it wasn't in the object, and reopened every agent's
    match of it (2,000 times in six hours, 78 functions). The call refers to the function, as MSVC's does."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("delink", scratch_pe.TEMPLATE / "tools" / "delink.py")
    delink = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(delink)
    exe = bytes.fromhex("c3cccccc") + bytes.fromhex("e800000000c3")  # ret; call (the one before) ; ret
    functions = [{"name": "_func_00401000", "offset": 0, "size": 1, "relocs": []},
                 {"name": "_func_00401004", "offset": 4, "size": 6,
                  "relocs": [[1, delink.REL32, "_func_00401000", -4], [1, delink.REL32, "_func_00402000", -4]]}]
    data = delink.coff(functions, exe)
    syms = _coff_symbols(data)
    assert [n for n, _ in syms].count("_func_00401000") == 1
    assert ("_func_00401000", 1) in syms and ("_func_00402000", 0) in syms  # (another file's: undefined)
    reloc_at = struct.unpack_from("<I", data, 20 + 40 + 24)[0]  # the second section's relocations
    assert struct.unpack_from("<IIH", data, reloc_at)[1] == 0  # the call: the first symbol, the function itself


def test_a_projects_untouched_old_tools_are_updated_and_changed_ones_kept(tmp_path, monkeypatch):
    """A project keeps the tools it was made with: one still as an older template left it (line endings aside) gets
    the template's, which cuts its original objects again, and the template's tools it lacks come with it;
    configure.py keeps its compiler; names.py keeps its time (every compile depends on it: on a big game, minutes of
    every core for the same objects); one changed by hand stays as it is."""
    import hashlib
    import os

    root = tmp_path / "game"
    (root / "tools").mkdir(parents=True)
    assert scratch_pe.refresh_tools(root) == []  # (no such tool: nothing to do)
    template = (scratch_pe.TEMPLATE / "tools" / "configure.py").read_text(encoding="utf-8")
    old_configure = scratch_pe.settings(template + "# an older one\n", "8.0-sp1")
    monkeypatch.setitem(scratch_pe.OLD_TOOLS, "tools/delink.py", {hashlib.sha1(b"old delinker\n").hexdigest()})
    monkeypatch.setitem(scratch_pe.OLD_TOOLS, "tools/names.py", {hashlib.sha1(b"old names\n").hexdigest()})
    monkeypatch.setitem(scratch_pe.OLD_TOOLS, "tools/configure.py",
                        {hashlib.sha1((template + "# an older one\n").encode()).hexdigest()})
    (root / "tools" / "delink.py").write_bytes(b"old delinker\r\n")  # (a project made on Windows)
    (root / "tools" / "names.py").write_bytes(b"old names\n")
    os.utime(root / "tools" / "names.py", ns=(1_600_000_000_000_000_000, 1_600_000_000_000_000_000))
    (root / "tools" / "configure.py").write_text(old_configure, encoding="utf-8")
    done = scratch_pe.refresh_tools(root)
    assert done[:3] == ["tools/delink.py", "tools/names.py", "tools/configure.py"]
    assert "tools/compile.py" in done and (root / "tools" / "compile.py").exists()
    for f in ("delink.py", "names.py"):
        assert (root / "tools" / f).read_bytes() == (scratch_pe.TEMPLATE / "tools" / f).read_bytes()
    assert (root / "tools" / "configure.py").read_text(encoding="utf-8") == scratch_pe.settings(template, "8.0-sp1")
    assert (root / "tools" / "names.py").stat().st_mtime_ns == 1_600_000_000_000_000_000
    (root / "tools" / "delink.py").write_text("my own delinker\n", encoding="utf-8")
    assert scratch_pe.refresh_tools(root) == []
    assert (root / "tools" / "delink.py").read_text(encoding="utf-8") == "my own delinker\n"


def test_every_tool_a_pc_project_was_made_with_is_known():
    """The template's tools as they are now aren't old (nothing to update); this server's PC project, made with
    earlier ones, had every one of them in OLD_TOOLS."""
    import hashlib

    for rel, old in scratch_pe.OLD_TOOLS.items():
        now = scratch_pe._as_template(rel, (scratch_pe.TEMPLATE / rel).read_text(encoding="utf-8"))
        assert hashlib.sha1(now.encode()).hexdigest() not in old, rel


def _tools_module(name: str):
    import importlib.util

    sys.path.insert(0, str(scratch_pe.TEMPLATE / "tools"))
    try:
        spec = importlib.util.spec_from_file_location(name, scratch_pe.TEMPLATE / "tools" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def test_a_real_name_pairs_with_the_original_and_names_its_objects(tmp_path):
    """names.json (rename_symbol's) gives a function and data real names: the original's objects carry them with
    their decoration, and what C++ compiles them to (mangled, a method, the old name by address) pairs with them."""
    names, delink = _tools_module("names"), _tools_module("delink")
    config = tmp_path / "functions.json"
    info = {"units": {"text_00401000": [
        {"name": "_func_00401000@8", "addr": 0x401000, "offset": 0, "size": 1, "relocs": []},
        {"name": "@func_00401010@8", "addr": 0x401010, "offset": 4, "size": 6,
         "relocs": [[1, delink.REL32, "_func_00401000@8", -4], [1, delink.DIR32, "_D_00403000", 0]]}]}}
    assert names.real_names(info, config) == {}
    (tmp_path / "names.json").write_text('{"func_00401000": "Town_Update", "D_00403000": "gPlayer"}')
    real = names.real_names(info, config)
    assert real == {"_func_00401000@8": "_Town_Update@8", "_D_00403000": "_gPlayer"}
    want = names.wanted(info, config)
    assert want[b"Town_Update"] == want[b"func_00401000"] == b"_Town_Update@8"
    assert want[b"gPlayer"] == want[b"D_00403000"] == b"_gPlayer"
    assert want[b"func_00401010"] == b"@func_00401010@8"
    for compiled, original in (("?Town_Update@@YGXHH@Z", "_Town_Update@8"), ("?Update@Town@@QAEXH@Z", None),
                               ("?gPlayer@@3HA", "_gPlayer"), ("?func_00401000@Town@@QAEXH@Z", "_Town_Update@8"),
                               ("_helper", None), ("??_C@_03ABC@abc?$AA@", None), ("__real@3f800000", None)):
        obj = delink.coff([{"name": compiled, "offset": 0, "size": 1, "relocs": []}], b"\xc3")
        assert _coff_symbols(names.rename(obj, want))[0][0] == (original or compiled), compiled
    obj = delink.coff(info["units"]["text_00401000"], bytes.fromhex("c3cccccc" + "e800000000c3"), real)
    syms = [n for n, _ in _coff_symbols(obj)]
    assert "_Town_Update@8" in syms and "_gPlayer" in syms and not [n for n in syms if "00401000" in n]


def test_rename_symbol_on_a_pc_project_keeps_names_json(tmp_path):
    root = tmp_path / "game"
    (root / "config" / "v").mkdir(parents=True)
    (root / "config" / "v" / "functions.json").write_text(json.dumps({"units": {"text_00401000": [
        {"name": "_func_00401000@8", "addr": 0x401000, "offset": 0, "size": 1, "relocs": [[1, 6, "_D_00403000", 0]]},
        {"name": "_WinMain@16", "addr": 0x401010, "offset": 4, "size": 1, "relocs": []}]}}))
    names = root / "config" / "v" / "names.json"
    saved = scratch_pe.rename(root, "v", "_func_00401000@8", "Town_Update")  # (as the function list shows it)
    assert saved == {names: "{}\n"} and json.loads(names.read_text()) == {"func_00401000": "Town_Update"}
    scratch_pe.rename(root, "v", "D_00403000", "gPlayer")
    scratch_pe.rename(root, "v", "Town_Update", "Town_Tick")  # a real name renamed again
    scratch_pe.rename(root, "v", "WinMain", "GameMain")  # a name Ghidra knew, by its address
    assert json.loads(names.read_text()) == {"D_00403000": "gPlayer", "func_00401000": "Town_Tick",
                                             "func_00401010": "GameMain"}
    assert scratch_pe.address_of(root, "v", "gPlayer") == 0x403000
    assert scratch_pe.address_of(root, "v", "_Town_Tick@8") == 0x401000
    assert scratch_pe.address_of(root, "v", "D_00403004") == 0x403004
    for old, new, why in (("func_00401000", "X", "is called Town_Tick now"), ("nope", "X", "isn't one of the game's"),
                          ("Town_Tick", "gPlayer", "is a symbol of the game already"),
                          ("Town_Tick", "func_00409000_tick", "holds an address")):
        with pytest.raises(ForkError, match=why):
            scratch_pe.rename(root, "v", old, new)
    from decompnet import consoles

    assert consoles.get("pc").source_name("@func_00401000@8") == "func_00401000"
    assert consoles.get("gc").source_name("fn_80003100") == "fn_80003100"
