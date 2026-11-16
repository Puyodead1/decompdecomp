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
    assert f"{name}(" not in (fp.root / old).read_text()
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


def test_a_stretch_gets_files_of_a_few_hundred_functions_and_a_file_too_big_is_cut(gc, monkeypatch):
    """A GameCube game's one stretch of 16,695 functions got one file, and every claim and compile then read all of
    them (minutes each, with 8 agents: they timed out). A stretch gets files of FILE_FUNCTIONS functions; a file an
    older decompdecomp made bigger is cut so, its C going with its functions, the game still built byte for byte."""
    from decompnet.app import forkengine
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
