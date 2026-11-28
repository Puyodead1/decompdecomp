"""A link that can't go on says why, and doesn't redo what failed: a GameCube game's link retried the same 40
failing files after every match, a checksum check that failed before linking stopped every link without a word, a
commit that failed was let go, and a hung linker held the project for the build's whole half hour."""

import json
import os
import sys
import time
from types import SimpleNamespace

from decompnet.app import forkengine
from decompnet.app.forkengine import ForkEngine
from decompnet.forks import project
from decompnet.forks.project import ForkProject
from decompnet.network import NetworkError


def _engine(cfg: dict) -> SimpleNamespace:
    store = SimpleNamespace(one=lambda sql, *a: {"config": json.dumps(cfg)})
    e = SimpleNamespace(net=SimpleNamespace(store=store, _project=lambda slug: {"config": json.dumps(cfg)}),
                        link_failures=ForkEngine.link_failures)
    e._save_cfg = lambda proj, new: cfg.update(new)
    return e


def test_a_file_that_failed_waits_until_something_it_is_built_from_changes(tmp_path):
    (tmp_path / "src").mkdir()
    for name in ("a.c", "b.c", "c.c"):
        (tmp_path / "src" / name).write_text("")
    old = time.time() - 100
    for name in ("a.c", "b.c"):
        os.utime(tmp_path / "src" / name, (old, old))
    now = time.time()
    cfg = {"link_failed": {"src/a.c": "x", "src/b.c": "y"}, "link_failed_at": {"src/a.c": now, "src/b.c": now - 10}}
    fp = SimpleNamespace(root=tmp_path, src_dir=lambda: "src")
    todo = ["src/a.c", "src/b.c", "src/c.c"]
    assert ForkEngine._fresh_first(_engine(cfg), fp, cfg, todo) == ["src/c.c"]
    later = now + 5
    os.utime(tmp_path / "src" / "b.c", (later, later))  # (b.c edited since its link failed: tried, after c.c)
    assert ForkEngine._fresh_first(_engine(cfg), fp, cfg, todo) == ["src/c.c", "src/b.c"]
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "game.h").write_text("")
    os.utime(tmp_path / "include" / "game.h", (later, later))  # (a header changed: every file's tried again)
    assert ForkEngine._fresh_first(_engine(cfg), fp, cfg, todo) == ["src/c.c", "src/b.c", "src/a.c"]


def test_the_last_link_is_recorded_and_a_stop_is_said(tmp_path):
    cfg: dict = {}
    e = _engine(cfg)
    ForkEngine._note_link(e, {"id": 1}, error="the project's checksum check fails before linking anything")
    assert cfg["link_last"]["error"].startswith("the project's checksum check fails")
    assert "checksum" in ForkEngine.link_note(e, "game")
    ForkEngine._note_link(e, {"id": 1}, linked=["src/a.c"], failed={"src/b.c": "x"})
    assert cfg["link_last"]["linked"] == ["src/a.c"] and cfg["link_last"]["failed"] == ["src/b.c"]
    assert ForkEngine.link_note(e, "game") == ""


def test_a_commit_waits_out_a_locked_index_and_a_failed_one_is_said(monkeypatch):
    monkeypatch.setattr(forkengine.time, "sleep", lambda s: None)
    said = iter([(False, "fatal: Unable to create '.git/index.lock': File exists."), (True, ""), (True, "")])
    calls = []
    fp = SimpleNamespace(git=lambda *a: (calls.append(a[0]), next(said))[1], stale_git_lock=lambda: False)
    e = SimpleNamespace(_git_lock=lambda proj: __import__("contextlib").nullcontext())
    ForkEngine._commit_paths(e, {"slug": "game"}, fp, ["configure.py"], "Link a.c")
    assert calls == ["add", "add", "commit"]
    fp.git = lambda *a: (False, "error: pathspec 'x' did not match any file(s) known to git")
    try:
        ForkEngine._commit_paths(e, {"slug": "game"}, fp, ["x"], "m")
        raise AssertionError("a failed commit passed")
    except NetworkError as err:
        assert "couldn't be committed" in str(err)


def test_a_build_that_prints_nothing_for_too_long_is_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(project, "SILENT_SECONDS", 1)
    script = tmp_path / "hang.py"
    script.write_text("import time\nprint('[1/2] CC a.o', flush=True)\ntime.sleep(60)\n")
    start = time.monotonic()
    ok, out = ForkProject(tmp_path).run([sys.executable, str(script)], log=lambda *_: None, timeout=120)
    assert not ok and "printed nothing for 1 seconds" in out
    assert time.monotonic() - start < 30
