"""Code no source file covers, nor can be given one: set aside, never left at "to do" (tests/test_gc.py runs it on the
GameCube demo, with CodeWarrior)."""

from pathlib import Path
from types import SimpleNamespace

from decompnet.app.forkengine import ForkEngine
from decompnet.forks.project import Unit


def test_which_code_can_never_have_a_file(tmp_path, monkeypatch):
    """A GameCube game's __start, memset and TRK_memset (dtk's auto_00_..._init) and __init_cpp_exceptions (an object
    configure.py lists no file for) showed "to do" at 98.9%, never handed to an agent and counted forever: start_files
    gives files only to .text stretches and to the files configure.py lists."""
    splits = tmp_path / "splits.txt"
    splits.write_text("Sections:\n\t.text type:code\n\ngame/player.c:\n\t.text start:0x80003400 end:0x80003500\n\n"
                      "__init_cpp_exceptions.cpp:\n\t.text start:0x80003500 end:0x80003540\n")
    def unit(name, source=None, auto=False):
        return Unit(name, Path(f"{name}.o"), None, source, False, None, auto=auto)

    units = [unit("main/auto_00_80003100_init", auto=True), unit("main/auto_01_80003600_text", auto=True),
             unit("main/game/player"),  # listed in configure.py, its file not made yet
             unit("main/__init_cpp_exceptions"),  # not listed
             unit("main/game/enemy", "src/game/enemy.c")]
    fp = SimpleNamespace(units=lambda: units, src_dir=lambda: "src", link_states=lambda: {"src/game/player.c": "x"},
                         root=tmp_path)
    forks = ForkEngine.__new__(ForkEngine)
    monkeypatch.setattr(ForkEngine, "get", lambda self, slug: ({}, fp, {}))
    monkeypatch.setattr(ForkEngine, "_modules", lambda self, fp, cfg: {"main": SimpleNamespace(splits=splits)})
    plan = forks.code_without_files("game", {"units": []}, never_only=True)
    assert plan["never"] == ["main/__init_cpp_exceptions", "main/auto_00_80003100_init"]
    assert plan["create"] == ["src/game/player.c"] and plan["split"] == []


def test_a_sync_says_the_share_of_code_only_when_it_moved():
    """A room's member measures after each of the host's commits: its feed was "sync 89.51% of code matches" every few
    seconds."""
    from decompnet.app.forkengine import progress_moved
    assert progress_moved(None, {"matched_code_percent": 89.51}) == "89.51% of code matches"
    assert progress_moved({"matched_code_percent": 89.511}, {"matched_code_percent": 89.509}) is None
    assert progress_moved({"matched_code_percent": 89.51}, {"matched_code_percent": 89.6}) == "89.60% of code matches"
    assert progress_moved({}, {}) == "0.00% of code matches"


def test_a_stored_best_follows_the_renames_made_since(tmp_path, monkeypatch):
    """A GameCube function at 99.3%: its best attempt, stored before SoundManager_CreateSource was renamed
    SoundManager_AllocSource, went back into its file at the next claim. CodeWarrior took the old name as an undeclared
    function, so it built, and no C could match: the call's relocation named another symbol."""
    import time

    from decompnet.app.engine import RomNetwork

    net = RomNetwork(tmp_path / "d.db", tmp_path)
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                         ("game", "Game", "", "ppc", 1, str(tmp_path), "{}")).lastrowid
        net._event(db, pid, None, "rename", "SoundManager_CreateSource → SoundManager_AllocSource")
        net._event(db, pid, None, "rename", "func_80012340 → Creature_Spawn")
        net._event(db, pid, None, "rename", "@48@__dt__4ItemFv → @48@__dt__4Item")  # (a thunk's: no source has it)
    forks = ForkEngine.__new__(ForkEngine)
    forks.net = net
    monkeypatch.setattr(ForkEngine, "get", lambda self, slug: (net.project_row(slug), None, {"platform": "gc"}))
    best = "void f(void) { SoundManager_CreateSource(1); func_80012340(); SoundManager_CreateSourceX(); }"
    fn = {"last_improved": 0}
    assert forks._with_renames("game", fn, best) == (
        "void f(void) { SoundManager_AllocSource(1); Creature_Spawn(); SoundManager_CreateSourceX(); }")
    # stored after the renames: as it was
    assert forks._with_renames("game", {"last_improved": time.time() + 1}, best) == best
    assert forks._with_renames("game", fn, None) is None


def test_the_best_attempts_diff_builds_it_with_the_renames_made_since(tmp_path, monkeypatch):
    """The diff view built a GameCube function's best as stored, and showed "The best attempt didn't compile":
    undefined identifier, a global's old name."""
    from contextlib import nullcontext
    from types import SimpleNamespace

    from decompnet.network import NetworkError

    placed = []

    def place(proj, fp, unit, fn, source, names):
        placed.append(source)
        raise NetworkError("stop here")

    forks = ForkEngine.__new__(ForkEngine)
    forks._with_renames = lambda slug, fn, text: text.replace("D_80301234", "g_identity")
    forks._place = place
    forks._tree = lambda proj: SimpleNamespace(shared=nullcontext, exclusive=nullcontext)
    forks._unit_lock = lambda proj, name: nullcontext()
    forks._meta = lambda fn: {}
    fp = SimpleNamespace(unit=lambda name: SimpleNamespace(name=name, complete=False, target=None))
    fn = {"name": "EventSeq_Move", "unit": "u", "best_source": "void EventSeq_Move(void) { m = D_80301234; }"}
    out = forks._best_diff({"slug": "game"}, fp, fn)
    assert out["error"] == "stop here"
    assert placed == ["void EventSeq_Move(void) { m = g_identity; }"]


def test_a_rename_rewrites_the_stored_c_too(tmp_path):
    """ROM mode's rename rewrote every best attempt and matched C (network.rename_symbol); project mode's only the
    files, so the stale best went back into its file at the next claim."""
    import threading
    from contextlib import nullcontext

    from decompnet.app.engine import RomNetwork

    conf = tmp_path / "config" / "v"
    conf.mkdir(parents=True)
    (conf / "symbols.txt").write_text("fn_80012340 = .text:0x80012340; // type:function size:0x8\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("void fn_80012340(void) {\n}\n")
    net = RomNetwork(tmp_path / "d.db", tmp_path / "home")
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                         ("p", "Game", "", "ppc", 1, str(tmp_path), "{}")).lastrowid
        for name, best, done in [("fn_80012300", "void a(void) { fn_80012340(); }", None),
                                 ("fn_80012400", None, "void b(void) { fn_80012340(); }"),
                                 ("fn_80012500", "void c(void) { fn_800123400(); }", None)]:
            db.execute("INSERT INTO functions(project_id,name,vram,size,n_insns,status,best_source,matched_source) "
                       "VALUES(?,?,?,?,?,?,?,?)", (pid, name, 0, 8, 2, "open", best, done))
    fp = SimpleNamespace(root=tmp_path, manifest={"version": "v"}, setup_commands=lambda version: [],
                         report=lambda: {"units": []})
    eng = ForkEngine.__new__(ForkEngine)
    eng.net, eng._build_locks, eng._mlock = net, {pid: threading.Lock()}, threading.Lock()
    eng._tree = lambda proj: SimpleNamespace(exclusive=lambda: nullcontext())
    eng._commit_paths = eng.sync = lambda *args, **kwargs: None
    eng.get = lambda slug: (net.project_row("p"), fp, {"platform": "gc", "version": "v"})
    assert eng.rename_symbol(None, "p", "fn_80012340", "Creature_Spawn").startswith("✅")
    rows = {r["name"]: r for r in net.store.all("SELECT * FROM functions")}
    assert rows["fn_80012300"]["best_source"] == "void a(void) { Creature_Spawn(); }"
    assert rows["fn_80012400"]["matched_source"] == "void b(void) { Creature_Spawn(); }"
    assert rows["fn_80012500"]["best_source"] == "void c(void) { fn_800123400(); }"  # (whole words only)


def test_a_sync_keeps_the_good_enough_mark():
    """A GameCube game's 37 functions marked good enough lost the mark at the next sync: "set aside", off the
    progress total (58 KB of its code), and no longer the user's mark to undo."""
    from decompnet.app.forkengine import kept_meta

    said = "good enough: you marked its best C (99.1%) as close enough, so agents leave it alone"
    mark = {"score": 40, "t": 1.0}
    assert kept_meta({"asm_code": said, "good_enough": mark, "held": 1}, True) == {"asm_code": said, "good_enough": mark}
    # dropped by a sync before: back, from its words
    again = kept_meta({"asm_code": said}, True, best_score=40)
    assert again["good_enough"]["score"] == 40 and again["asm_code"] == said
    # its code grew (pieces joined to it): open again, as any set-aside function
    assert kept_meta({"asm_code": said, "good_enough": mark}, False) == {}
    # set aside for another reason: no mark made up
    assert "good_enough" not in kept_meta({"asm_code": "hand-written assembly"}, True)
