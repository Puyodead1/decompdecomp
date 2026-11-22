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
