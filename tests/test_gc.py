"""GameCube from scratch: a dtk-template project generated for the user's game, worked on like a fork.

Demo Quest GC (projects/demo-gc) is built like a GameCube game: CodeWarrior 1.3.2, linked by CodeWarrior's linker
with the standard DOL layout. Importing it must produce a project that rebuilds the program byte for byte, and
agents' C must be judged by the project's own build and objdiff. CodeWarrior is proprietary, so this runs only
where the `mwcc` toolchain was installed with its license accepted.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from decompnet import toolchains
from decompnet.app.engine import RomNetwork
from decompnet.forks import csource

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "projects" / "demo-gc"
DOL, ELF = DEMO / "build" / "main.dol", DEMO / "build" / "demoq_gc.elf"
GAME = ROOT / "projects" / "demo-n64" / "original" / "game.c"

pytestmark = pytest.mark.skipif(
    any(toolchains.installed(t) is None for t in ("mwcc", "dtk", "gc-wii-binutils", "objdiff-cli", "sjiswrap", "dtk-template"))
    or (sys.platform != "win32" and toolchains.get("wibo").supported and toolchains.installed("wibo") is None),
    reason="needs CodeWarrior (mwcc, proprietary) and the GameCube toolbelt")


@pytest.fixture(scope="module")
def gc(tmp_path_factory):
    if not DOL.exists():
        subprocess.run([sys.executable, str(DEMO / "build.py")], check=True)
    work = tmp_path_factory.mktemp("gc")
    net = RomNetwork(work / "app.db", work)
    slug = net.import_rom(DOL, confirmed=True, log=lambda *_: None)
    return net, slug


def test_project_rebuilds_the_program(gc):
    net, slug = gc
    ov = net.overview(slug)
    assert ov["kind"] == "fork" and ov["origin"] == "scratch" and ov["platform"] == "gc" and ov["ready"]
    assert ov["functions"] > 80
    root = Path(net.project_row(slug)["root"])
    res = subprocess.run([str(Path(sys.executable).parent / "ninja")], cwd=root, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout[-2000:]
    files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
    assert files and not [f for f in files if f.startswith(("orig/", "build/"))]


def test_agents_match_functions(gc):
    net, slug = gc
    syms = {s.name: s["st_value"] for s in ELFFile(open(ELF, "rb")).get_section_by_name(".symtab").iter_symbols()}
    agent, _ = net.local_agent("gc-agent")
    source = GAME.read_text()
    for name in ("clamp_s32", "abs_s32", "lerp"):
        auto = f"fn_{syms[name]:08X}"
        code = csource.get(source, name).replace(name + "(", auto + "(", 1).replace("f32", "float")
        res = net.attempt(agent, auto, code, slug)
        assert res["matched"], res["text"]
    wrong = net.attempt(agent, f"fn_{syms['player_take_damage']:08X}", f"void fn_{syms['player_take_damage']:08X}(int a) {{ }}", slug)
    assert not wrong["matched"]
    net.release(agent, f"fn_{syms['player_take_damage']:08X}", "", slug)
    root = Path(net.project_row(slug)["root"])
    assert "Match fn_" in subprocess.run(["git", "log", "--oneline"], cwd=root, capture_output=True, text=True).stdout


def test_a_compile_puts_a_trys_leftover_compiler_back_first(gc):
    """A GameCube game's file was built with a try's compiler long after the try (GC/2.0p1 for GC/1.2.5n): every
    compile there reopened its matches, 54 at once. Before a compile measures its file, a compiler that isn't the
    committed one, with no try on the file, is put back."""
    from decompnet.consoles.gc_wii import scratch

    net, slug = gc
    fp = net.forks.get(slug)[1]
    syms = {s.name: s["st_value"] for s in ELFFile(open(ELF, "rb")).get_section_by_name(".symtab").iter_symbols()}
    agent, _ = net.local_agent("gc-leftover")
    auto = f"fn_{syms['abs_s32']:08X}"
    source = net.forks.file_status(slug, auto).splitlines()[0][3:]
    committed = (fp.root / "configure.py").read_text()
    scratch.set_file_compiler(fp.root, fp.src_dir(), source, "GC/1.0", scratch.configured_compiler(fp.root))
    assert "GC/1.0" in (fp.root / "configure.py").read_text()
    code = csource.get(GAME.read_text(), "abs_s32").replace("abs_s32(", auto + "(", 1)
    res = net.attempt(agent, auto, code, slug)
    assert "GC/1.0" not in (fp.root / "configure.py").read_text()
    assert (fp.root / "configure.py").read_text() == committed
    assert net._function(auto, slug)["status"] == "matched", res["text"]


def test_a_try_that_isnt_kept_is_compiled_alone_with_the_verdict_the_build_gives(gc, monkeypatch):
    """A try that isn't kept (the permuter's, search_flags', a draft's) was written into the file, built with ninja,
    then written back and built again. Now CodeWarrior compiles it alone, from the unit's own command in build.ninja,
    in a folder of its own: the file isn't touched, and each verdict is the one building it in the project gives.
    What isn't a plain "not kept" (a build error here) is still built in the project."""
    from decompnet.app.forkengine import ForkEngine
    from decompnet.forks.project import ForkProject

    net, slug = gc
    fp = net.forks.get(slug)[1]
    syms = {s.name: s["st_value"] for s in ELFFile(open(ELF, "rb")).get_section_by_name(".symtab").iter_symbols()}
    agent, _ = net.local_agent("gc-trial")
    auto = f"fn_{syms['checksum_save']:08X}"
    real = csource.get(GAME.read_text(), "checksum_save").replace("checksum_save(", auto + "(", 1)
    tries = [real.replace("0x1234", "0x4321"), real.replace("(sum << 5) + sum", "(sum << 4) - sum"),
             f"u32 {auto}(const u8 *data, s32 len) {{ return len; }}", f"u32 {auto}(void) {{ return nothing; }}"]
    source = fp.root / net.forks.file_status(slug, auto).splitlines()[0][3:]
    alone, real_diff = [], ForkEngine._trial_diff

    def spied(self, *a, **kw):
        alone.append(d := real_diff(self, *a, **kw))
        return d

    monkeypatch.setattr(ForkEngine, "_trial_diff", spied)
    verdicts = []
    for code in tries:
        stamp = source.stat().st_mtime_ns
        res = net.forks.attempt(agent, slug, auto, code, keep=False)
        verdicts.append({k: res.get(k) for k in ("text", "score", "matched", "percent")})
        if alone[-1] is not None:
            assert source.stat().st_mtime_ns == stamp  # (compiled alone: the file as it was)
    assert [d is not None for d in alone] == [True, True, True, False], verdicts
    monkeypatch.setattr(ForkProject, "compile_command", lambda self, unit: None)  # the build's way, as before
    built = [net.forks.attempt(agent, slug, auto, code, keep=False) for code in tries]
    assert verdicts == [{k: res.get(k) for k in ("text", "score", "matched", "percent")} for res in built]
    assert "BUILD ERROR" in verdicts[-1]["text"] and all(v["score"] for v in verdicts[:3])
    net.release(agent, auto, "", slug)


def test_a_file_is_split_and_its_match_moves_along(gc):
    """split_file: the matched function and what follows it go to a new file; the game still builds identically
    and the match still counts (it runs after test_agents_match_functions)."""
    net, slug = gc
    syms = {s.name: s["st_value"] for s in ELFFile(open(ELF, "rb")).get_section_by_name(".symtab").iter_symbols()}
    fp = net.forks.get(slug)[1]
    at = syms["clamp_s32"]
    name = f"fn_{at:08X}"
    assert net._function(name, slug)["status"] == "matched"
    old = net.forks.file_status(slug, name).splitlines()[0][3:]
    agent, _ = net.local_agent("gc-splitter")
    # a compiler try's leftover in configure.py went into the split's commit: twice on a GameCube game, a file
    # stayed on GC/1.3 that no agent chose (there another file's entry; the demo has one file)
    from decompnet.consoles.gc_wii import scratch

    scratch.set_file_compiler(fp.root, fp.src_dir(), old, "GC/1.3", scratch.configured_compiler(fp.root))
    assert "configure.py" in fp.git("diff", "--name-only")[1].split()
    out = net.forks.split_file(agent, slug, old, f"0x{at:X}")
    assert out.startswith("✅"), out
    assert 'mw_version="GC/1.3"' not in fp.git("show", "HEAD:configure.py")[1]
    assert 'mw_version="GC/1.3"' not in (fp.root / "configure.py").read_text()
    new = f"src/auto/text_{at:08X}.c"
    assert (fp.root / new).exists() and f"{name}(" in (fp.root / new).read_text()
    left = (fp.root / old).read_text()  # (its definition went; its prototype stays, for what's left that calls it)
    assert not re.search(rf"\b{name}\([^;{{]*\)\s*{{", left) and re.search(rf"\b{name}\([^;{{]*\);", left), left
    assert net._function(name, slug)["status"] == "matched"
    assert net.forks.file_status(slug, name).startswith(f"## {new}")
    assert fp.verify()[0]
    assert "Split text_" in fp.git("log", "--format=%s", "-1")[1]


def test_code_without_a_file_gets_one(gc):
    """start_files: a stretch of code no file covers (here: a split file taken out again) gets a source file, the
    game still builds identically, and its functions can be worked on again."""
    net, slug = gc
    fp = net.forks.get(slug)[1]
    proj = net.project_row(slug)
    cfg = json.loads(proj["config"])
    asm_only = net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=? AND status='nosource'", proj["id"])["n"]
    from decompnet.forks import dtksplits

    mod = dtksplits.modules(fp.root, cfg["version"])["main"]
    sp = dtksplits.Splits.parse(mod.splits.read_text())
    gone = sp.files.pop()  # the last file: its code becomes an auto unit
    mod.splits.write_text(sp.render())
    conf = fp.root / "configure.py"
    conf.write_text(re.sub(rf'\s*Object\(NonMatching, "{re.escape(gone.name)}"\),', "", conf.read_text()))
    (fp.root / "src" / gone.name).unlink()
    fp.git("commit", "-qam", "Take a file out")  # (as committed: what isn't is a try's leftover, put back)
    assert fp.verify()[0]
    net.forks.check(slug, log=lambda *_: None)
    pid = proj["id"]
    assert net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=? AND status='nosource'", pid)["n"] > asm_only
    total = net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=?", pid)["n"]
    net._update_cfg(slug, lambda c: c.pop("uncovered", None))  # measured by a decompdecomp before 0.9.0
    assert net.forks.overview(slug)["uncovered"]["functions"] > 0  # the overview still offers the files
    plan = net.forks.code_without_files(slug, fp.report())
    assert [x[1] for x in plan["split"]] == [gone.name], plan
    res = net.forks.start_files(slug, log=lambda *_: None)
    assert res["split"] == [gone.name] and res["functions"] > 0, res
    assert (fp.root / "src" / gone.name).exists() and fp.verify()[0]
    # (the start-up code in .init stays assembly: it's hand-written)
    assert net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=? AND status='nosource'", pid)["n"] == asm_only
    assert net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=?", pid)["n"] == total


def test_start_up_code_no_file_can_hold_is_set_aside(gc):
    """A GameCube game's __start, memset, TRK_memset (dtk's auto_00_..._init) and __init_cpp_exceptions showed "to
    do" at 98.9%: no source file covers them and start_files gives none to code outside .text, so no agent was
    ever handed them, and they counted against the game forever. They're set aside now, as assembly is."""
    net, slug = gc
    pid = net.project_row(slug)["id"]
    rows = net.store.all("SELECT name, status, unit, meta FROM functions WHERE project_id=? AND unit LIKE '%\\_init' "
                         "ESCAPE '\\'", pid)
    assert rows, "the demo has start-up code in .init"
    for r in rows:
        assert r["status"] == "asm" and json.loads(r["meta"])["no_file"], dict(r)
    assert not net.store.one("SELECT 1 FROM functions WHERE project_id=? AND status='nosource'", pid)
    assert "start-up code" in json.loads(rows[0]["meta"])["asm_code"]


def test_a_stretch_gets_files_of_a_few_hundred_functions_and_a_file_too_big_is_cut(gc, monkeypatch):
    """A GameCube game's one stretch of 16,695 functions got one file, and every claim and compile then read all of
    them (minutes each, with 8 agents: they timed out). A stretch gets files of FILE_FUNCTIONS functions; a file an
    older decompdecomp made bigger is cut so, its C going with its functions, the game still built byte for byte."""
    from decompnet.app import forkengine
    from decompnet.consoles.gc_wii import scratch
    from decompnet.forks import dtksplits

    net, slug = gc
    fp = net.forks.get(slug)[1]
    proj = net.project_row(slug)
    mod = dtksplits.modules(fp.root, json.loads(proj["config"])["version"])["main"]
    sp = dtksplits.Splits.parse(mod.splits.read_text())
    syms = dtksplits.symbols(mod.symbols)

    def count(f):
        return len(forkengine.ForkEngine._starts(syms, *f.sections.get(".text", (0, 0))))

    gone = max((f for f in sp.files if ".text" in f.sections), key=count)
    assert count(gone) >= 3
    sp.files.remove(gone)
    mod.splits.write_text(sp.render())
    conf = fp.root / "configure.py"
    conf.write_text(re.sub(rf'\s*Object\(\w+, "{re.escape(gone.name)}"\),', "", conf.read_text()))
    (fp.root / "src" / gone.name).unlink()
    fp.git("commit", "-qam", "Take a file out")  # (as committed: what isn't is a try's leftover, put back)
    assert fp.verify()[0]
    net.forks.check(slug, log=lambda *_: None)

    monkeypatch.setattr(forkengine, "FILE_FUNCTIONS", 2)
    plan = net.forks.code_without_files(slug, fp.report())["split"]
    assert len(plan) == (count(gone) + 1) // 2 and all(n <= 2 for *_, n in plan)
    assert [(a, b) for _, _, a, b, _ in plan] == list(zip([plan[0][2], *(x[2] for x in plan[1:])],
                                                         [*(x[2] for x in plan[1:]), plan[-1][3]]))

    monkeypatch.setattr(forkengine, "FILE_FUNCTIONS", 10**6)  # (as an older decompdecomp did: one file)
    [whole] = net.forks.start_files(slug, log=lambda *_: None)["split"]
    monkeypatch.setattr(forkengine, "FILE_FUNCTIONS", 2)
    # the file's own compiler goes with its pieces: on the default one a GameCube game's SDK file stopped matching
    own = scratch.configured_compiler(fp.root)
    conf.write_text(conf.read_text().replace(f'Object(NonMatching, "{whole.split("src/", 1)[-1]}")',
                                             f'Object(NonMatching, "{whole.split("src/", 1)[-1]}", mw_version="{own}")'))
    assert f'mw_version="{own}"' in conf.read_text()
    fp.git("commit", "-qam", "The file's own compiler")
    assert net.forks._count_uncovered(fp.report())["big_files"] >= 1  # (the test before's file too)
    # a project counted by a decompdecomp before files too big were: the overview counts again, and offers the cut
    net._update_cfg(slug, lambda c: c.update(uncovered={"stretches": 0, "functions": 0}))
    assert net.forks.overview(slug)["uncovered"]["big_files"] >= 1
    logged = []
    res = net.forks.start_files(slug, log=logged.append)
    assert len([n for n in res["split"] if n.startswith(f"src/{Path(whole).parent.as_posix()}/")]) >= \
        (count(gone) + 1) // 2 - 1, res
    assert fp.verify()[0] and not forkengine.ForkEngine._big_units(fp.report()), logged
    assert all((fp.root / "src" / n.split("src/", 1)[-1]).exists() for n in res["split"])
    assert "Cut text_" in fp.git("log", "--format=%s", "-1")[1]
    # (the pieces follow their file's entry; the test before's file, on the default compiler, is cut too)
    entries = re.findall(r'Object\(NonMatching, "([^"]+)"(.*?)\)', conf.read_text())
    at = next(i for i, (n, _) in enumerate(entries) if n == whole.split("src/", 1)[-1])
    after = [settings for _, settings in entries[at + 1:at + (count(gone) + 1) // 2]]
    assert entries[at][1] == f', mw_version="{own}"' and after and all(x == entries[at][1] for x in after), entries


def test_autopilot_matches_from_machine_drafts(gc):
    """Drop a game, and before any agent: every function's machine draft is built and judged by the project's own
    build and objdiff. What matches is committed; what doesn't is kept as the best attempt, and the source file
    stays as it was."""
    net, slug = gc
    if toolchains.installed("m2c") is None:
        pytest.skip("needs m2c")
    proj = net.project_row(slug)
    root = Path(proj["root"])
    ids = net.forks.autopilot_prepare(slug)
    assert "M2C_DEFINES" in (root / "include" / "common.h").read_text()
    agent, _ = net.local_agent("autopilot")
    outcomes = {}
    for fid in ids[:25]:
        outcomes[fid] = net.forks.autopilot_one(agent, proj, fid)
    print(sorted(outcomes.values()))
    assert "match" in outcomes.values()
    assert subprocess.run(["git", "status", "--porcelain", "src"], cwd=root, capture_output=True, text=True).stdout == ""
    log = subprocess.run(["git", "log", "--format=%s"], cwd=root, capture_output=True, text=True).stdout
    assert "Match " in log
    tried = [fid for fid, o in outcomes.items() if o in ("near", "far")]
    if tried:  # a draft that didn't match is the function's best attempt, for the agents that come after
        row = net.store.one("SELECT best_agent_id, status FROM functions WHERE id=?", tried[0])
        assert row["status"] == "open" and row["best_agent_id"] == agent.id


def test_an_sdk_inline_that_is_asm_comes_from_the_users_sdk_never_an_agent(gc, tmp_path, monkeypatch):
    """A GameCube game's main inlined the SDK's OSInitFastCast, four GQR writes in an asm block: agents may write no
    assembly, and five set main aside. sdk_inline takes the function from the user's SDK headers, as their compiler
    reads them, and puts it in the file the way edit_file does; an agent's own asm is still refused."""
    from decompnet import kits
    from decompnet.kits import dolphin
    from decompnet.network import NetworkError

    net, slug = gc
    header = tmp_path / "include" / "os.h"
    header.parent.mkdir(parents=True)
    header.write_text("#define GQR_U8 0x0004\n#ifdef GEKKO\nstatic inline void InitCasts(void)\n{\n#ifdef __SN__\n"
                      "    asm volatile (\"\");\n#else\n    asm\n    {\n        li r3, GQR_U8\n        mtspr GQR2, r3\n"
                      "    }\n#endif\n}\n#else\nstatic inline void InitCasts(void) {}\n#endif\n")
    monkeypatch.setattr(kits, "headers", lambda kids: [(dolphin.DOLPHIN, header)] if "dolphin-sdk" in kids else [])
    monkeypatch.setattr(kits, "folders", lambda kid: [tmp_path])
    fp = net.forks.get(slug)[1]
    syms = {s.name: s["st_value"] for s in ELFFile(open(ELF, "rb")).get_section_by_name(".symtab").iter_symbols()}
    source = net.forks.file_status(slug, f"fn_{syms['lerp']:08X}").splitlines()[0][3:]
    agent, _ = net.local_agent("gc-sdk")
    with pytest.raises(NetworkError, match="sdk_inline"):
        net.forks.edit_file(agent, slug, source, "", "static inline void InitCasts(void) { asm { li r3, 4 } }")
    said = net.forks.sdk_inline(agent, slug, "InitCasts", source)
    assert said.startswith("✅"), said
    text = (fp.root / source).read_text()
    assert "li r3, 0x0004" in text and "mtspr GQR2, r3" in text and "include/os.h" in text
    assert "asm volatile" not in text and "{}" not in text.split("InitCasts", 1)[1][:40]  # (the Gekko's, as MWCC reads it)
    assert "Add the SDK's InitCasts" in subprocess.run(["git", "log", "-1", "--format=%s"], cwd=fp.root,
                                                         capture_output=True, text=True).stdout
    assert "defines InitCasts already" in net.forks.sdk_inline(agent, slug, "InitCasts", source)
    with pytest.raises(NetworkError, match="isn't an inline function"):
        net.forks.sdk_inline(agent, slug, "NoSuchThing", source)


def test_codewarriors_runtime_is_found_by_its_names_and_the_games_own_libc_is_not(gc):
    """The GameCube catalog of CodeWarrior's own libraries (consoles/gc_wii/libraries.toml) on a stripped program:
    dtk names the runtime's register helpers, so they're found and set aside; the demo's own malloc, memcpy, strlen
    and exit, nameless in a stripped program and not beside the runtime's, stay the game's, and so do zlib's."""
    net, slug = gc
    syms = {s["st_value"]: s.name for s in ELFFile(open(ELF, "rb")).get_section_by_name(".symtab").iter_symbols()
            if s["st_info"]["type"] == "STT_FUNC"}
    report = net.find_libraries(slug, log=lambda *_: None, fid=False)
    found = {lib["id"]: lib for lib in report["libraries"]}
    assert found["mw-runtime"]["aside"] and found["mw-runtime"]["kind"] == "runtime"
    taken = {f["name"] for lib in found.values() for f in lib["functions"]}
    assert {"__save_gpr", "__restore_gpr"} <= {f["name"] for f in found["mw-runtime"]["functions"]}
    assert "msl" not in found and "metrotrk" not in found  # (the demo links neither)
    # (dtk's signatures were read, and its own start-up code, libc and zlib aren't Nintendo's SDK)
    assert report["signatures"] > 500 and "dolphin-sdk" not in found
    rows = {r["name"]: r for r in net.store.all("SELECT name, vram, status FROM functions")}
    for name, r in rows.items():
        if syms.get(r["vram"]) in ("malloc", "memcpy", "strlen", "exit", "main", "clamp_s32", "adler32", "inflate"):
            assert name not in taken, syms[r["vram"]]
    assert rows["__save_gpr"]["status"] != "open"


def test_files_with_only_code_get_their_data(gc):
    """A game started from scratch gave its files only .text: their data stayed in dtk's auto units, so objdiff compared
    none of it, every file whose functions matched was linked, and each link failed (its C's constants and globals
    defined twice). give_data gives each file its stretch of each data section, and the game still builds identically."""
    from decompnet.forks import dtkdata, dtksplits

    net, slug = gc
    fp = net.forks.get(slug)[1]
    proj = net.project_row(slug)
    mod = dtksplits.modules(fp.root, json.loads(proj["config"])["version"])["main"]
    pid = proj["id"]
    matched = net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=? AND status='matched'", pid)["n"]

    def with_data():
        return {f.name for f in dtksplits.Splits.parse(mod.splits.read_text()).files
                if set(f.sections) & set(dtkdata.DATA)}

    res = net.forks.give_data(slug, log=lambda *_: None)
    assert not res.get("error"), res
    # (given here, or already by an earlier test's link: a file whose functions all match asks for it first)
    # (or by regive_data, which a link runs first and which works out every file's part)
    assert re.search(r"^Give \d+ files (their data|the data their code uses)", fp.git("log", "--format=%s")[1], re.M)
    assert {f.split("/", 1)[1] for f in res["files"]} <= with_data() and len(with_data()) > 1
    assert fp.verify()[0]
    assert net.store.one("SELECT COUNT(*) n FROM functions WHERE project_id=? AND status='matched'", pid)["n"] >= matched
    assert not fp.git("status", "--porcelain", "--", "config")[1].strip()  # (committed)
    assert net.forks.give_data(slug, log=lambda *_: None)["files"] == []  # (nothing left that the rules can place)


def test_data_symbols_are_sized_to_their_objects(gc):
    """dtk sized each data symbol by the distance to the next, so a 4-byte variable in .sbss was 8 and a run of strings
    one blob: no C matched them (a GameCube game: 14 symbols, a file's .data at 99.46% until its blob was cut at the
    NULs). A project is made with them sized; one made before is sized before a link, the game still byte for byte."""
    from decompnet.forks import dtksplits, symsizes

    net, slug = gc
    proj, fp, cfg = net.forks.get(slug)
    mod = dtksplits.modules(fp.root, cfg["version"])["main"]
    dol = mod.program.read_bytes()
    text = mod.symbols.read_bytes().decode()
    assert symsizes.resize(text, dol)[1] == []  # (made sized)
    used, taken = symsizes.accesses(dol)
    sizes = dtksplits.symbols(mod.symbols)
    starts = sorted(a for _, a, _ in sizes.values())
    small = next((n for n, (sec, a, z) in sizes.items() if sec in (".sbss", ".sdata") and z == 4 and a % 8 == 0
                  and a + 8 in starts and (a, 4) in used and a not in taken), None)
    if small is None:
        pytest.skip("the demo has no 4-byte variable in small data with room after it")
    padded = re.sub(rf"^({re.escape(small)} = .*?size:)0x4\b", r"\g<1>0x8", text, flags=re.M)
    mod.symbols.write_bytes(padded.encode())
    fp.git("commit", "-q", "-m", "an older copy of the app: padded", "--", str(mod.symbols.relative_to(fp.root)))
    lines = net.forks.size_symbols(slug, log=lambda *_: None)
    assert any(line.startswith(f"{small}: 0x8 -> 0x4") for line in lines), lines
    assert mod.symbols.read_bytes().decode() == text
    assert fp.git("log", "-1", "--format=%s")[1].startswith("Size 1 data symbols")
    assert fp.verify()[0]
    assert net.forks.size_symbols(slug, log=lambda *_: None) == []  # (nothing left to size)


def _refs_by_offset(obj: Path) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """(each function's (offset, name) in an object's .text, each relocation's (offset, symbol) in it)."""
    from elftools.elf.relocation import RelocationSection

    with obj.open("rb") as f:
        elf = ELFFile(f)
        tab = elf.get_section_by_name(".symtab")
        text = next(i for i, s in enumerate(elf.iter_sections()) if s.name == ".text")
        funcs = sorted((s["st_value"], s.name) for s in tab.iter_symbols()
                       if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == text)
        relocs = [(r["r_offset"], tab.get_symbol(r["r_info_sym"]).name) for sec in elf.iter_sections()
                  if isinstance(sec, RelocationSection) and sec.name == ".rela.text" for r in sec.iter_relocations()]
    return funcs, relocs


def test_data_follows_its_code_when_a_file_is_split(gc):
    """split_file moves code, not data: the new file's data stayed with the first part, and the next file's own
    data sat in the file before it (a GameCube game's OS strings in a game file's .data). regive_data gives it to the
    file whose code uses it; the game still builds byte for byte."""
    from decompnet.forks import dtkdata, dtksplits

    net, slug = gc
    proj, fp, cfg = net.forks.get(slug)
    mod = dtksplits.modules(fp.root, cfg["version"])["main"]
    net.forks.regive_data(slug, log=lambda *_: None)  # (whatever an earlier test's split left)
    assert net.forks.regive_data(slug, log=lambda *_: None) == []
    rows = dtksplits.symbol_rows(mod.symbols)
    address = dtkdata.resolver(rows)
    states = fp.link_states()
    found = None
    for f in dtksplits.Splits.parse(mod.splits.read_text()).files:
        rel = f"{fp.src_dir()}/{f.name}"
        data = {k: v for k, v in f.sections.items() if k in dtkdata.DATA}
        units = fp.units_for(rel)
        if not data or states.get(rel, ("",))[0] != "NonMatching" or not units or units[0].target is None:
            continue
        funcs, relocs = _refs_by_offset(units[0].target)
        for k, (start, _) in enumerate(funcs[1:], start=1):
            before = {address(s) for off, s in relocs if off < start}
            after = {a for off, s in relocs if off >= start and (a := address(s)) is not None}
            mine = sorted(a for a in after - before if any(lo <= a < hi for lo, hi in data.values()))
            if mine:
                found = (rel, f.sections[".text"][0] + start, mine[-1])
                break
        if found:
            break
    if found is None:
        pytest.skip("no file of the demo has data only its later functions use")
    rel, at, owned = found
    out = net.forks.split_file(None, slug, rel, f"0x{at:X}")
    assert out.startswith("✅"), out
    new = f"auto/text_{at:08X}.c" if "/" not in rel[len(fp.src_dir()) + 1:] else \
        f"{Path(rel[len(fp.src_dir()) + 1:]).parent.as_posix()}/text_{at:08X}.c"

    def holder():
        return next((f.name for f in dtksplits.Splits.parse(mod.splits.read_text()).files
                     for k, (lo, hi) in f.sections.items() if k in dtkdata.DATA and lo <= owned < hi), None)
    assert holder() == rel[len(fp.src_dir()) + 1:]  # (the split left it with the first part)
    moved = net.forks.regive_data(slug, log=lambda *_: None)
    assert f"{fp.src_dir()}/{new}" in moved, moved
    assert holder() == new
    assert fp.git("log", "-1", "--format=%s")[1].startswith(f"Give {len(moved)} files the data their code uses")
    assert fp.verify()[0]
    assert net.forks.regive_data(slug, log=lambda *_: None) == []


def test_a_files_data_that_matches_less_refuses_the_sizes():
    from decompnet.app.forkengine import ForkEngine

    def rep(**shares):
        return {"units": [{"name": n, "measures": {"matched_data": m, "total_data": t}} for n, (m, t) in shares.items()]}

    before = rep(a=(8, 8), b=(0, 8), c=(4, 8))
    after = rep(a=(4, 8), b=(4, 4), c=(4, 8), d=(0, 4))
    assert ForkEngine._less_data(before, after) == {"a"}
