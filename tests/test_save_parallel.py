"""Opening a save compiles its functions ahead, on threads of their own; judging and recording stay one at a time."""

import json
import threading
from concurrent.futures import Future

import pytest

from decompnet import compiler
from decompnet.app import saves, workers
from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError

from .test_rom import ROM, built  # noqa: F401
from .test_saves import worked  # noqa: F401


def test_a_saves_compiles_run_ahead_but_judging_stays_on_the_restoring_thread(worked, tmp_path, monkeypatch):  # noqa: F811
    net, slug, _ = worked
    saves.save(net, slug, tmp_path / "saved")
    (tmp_path / "fresh").mkdir()
    fresh = RomNetwork(tmp_path / "fresh" / "decomp.db", tmp_path / "fresh")
    restoring = threading.get_ident()
    compiled_on, recorded_on = [], []
    compile_source, record = fresh._compile, fresh._record

    def compile_watched(*args):
        compiled_on.append(threading.get_ident())
        return compile_source(*args)

    def record_watched(*args, **kwargs):
        recorded_on.append(threading.get_ident())
        return record(*args, **kwargs)

    monkeypatch.setattr(fresh, "_compile", compile_watched)
    monkeypatch.setattr(fresh, "_record", record_watched)
    monkeypatch.setattr(workers, "WORKERS", 2)
    monkeypatch.setattr(workers, "pool", lambda: pytest.fail("the shared workers can be waiting for this project"))
    result = saves.restore(fresh, str(tmp_path / "saved"), ROM, log=lambda *_: None)
    assert result["matched"] == 1 and result["best"] == 1 and not result["lost"]
    assert any(thread != restoring for thread in compiled_on)
    assert recorded_on and set(recorded_on) == {restoring}
    assert fresh.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 0
    fn = fresh._function("clamp_s32", result["slug"])
    assert fn["status"] == "matched" and fresh._agent_name(fn["matched_agent_id"]) == "claude-opus-5.5-1"


@pytest.fixture
def inputs(tmp_path):
    """Four saved best attempts of a project with no game: what's compiled ahead, and with what."""
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,root,config) VALUES('game','Game',?,'{}')",
                         (str(tmp_path),)).lastrowid
        db.execute("INSERT INTO context_versions(project_id,version,header,created_at,unit) "
                   "VALUES(?,1,'header',0,'')", (pid,))
        for i in range(4):
            db.execute("INSERT INTO functions(project_id,name,vram,size,n_insns,status,unit) "
                       "VALUES(?,?,?,4,1,'open','')", (pid, f"f{i}", 4096 + i * 4))
    proj = dict(net.store.one("SELECT * FROM projects WHERE slug='game'"))
    rows = {row["name"]: dict(row) for row in net.store.all("SELECT * FROM functions")}
    saved = {name: {"vram": row["vram"], "best_by": "author"} for name, row in rows.items()}
    files = {f"best/{name}.c": f"void {name}(void) {{}}" for name in rows}
    return net, proj, rows, saved, files


@pytest.mark.parametrize("changed", ["config", "root", "name", "meta", "header", "source"])
def test_a_compile_made_ahead_is_not_used_once_what_it_compiled_changed(inputs, monkeypatch, changed):
    """A rename, a new header or compiler setting between the two would judge C the judge wasn't given."""
    net, proj, rows, _, _ = inputs
    fn, header, source = rows["f0"], "header", "void f0(void) {}"
    ahead = Future()
    ahead.set_result("ahead")
    monkeypatch.setattr(net, "_compile", lambda *args: "fresh")
    with net.compiled_ahead((net._compile_snapshot(proj, fn, header, source), ahead)):
        assert net._attempt_compilation(proj, header, source, fn) == "ahead"
        if changed in ("config", "root"):
            proj = {**proj, changed: "changed"}
        elif changed in ("name", "meta"):
            fn = {**fn, changed: "changed"}
        elif changed == "header":
            header = "changed"
        else:
            source = "changed"
        assert net._attempt_compilation(proj, header, source, fn) == "fresh"
    assert net._attempt_compilation(proj, "header", "void f0(void) {}", rows["f0"]) == "fresh"


def test_compiles_run_a_bounded_way_ahead_and_closing_cancels_the_rest(inputs, monkeypatch, tmp_path):
    net, proj, rows, saved, files = inputs
    submitted = []

    class Pool:
        def __init__(self, *args, **kwargs):
            pass

        def shutdown(self, **kwargs):
            pass

        def submit(self, *args):
            submitted.append(Future())
            return submitted[-1]

    monkeypatch.setattr(workers, "WORKERS", 2)
    monkeypatch.setattr(saves, "ThreadPoolExecutor", Pool)
    checks = saves._saved_checks(net, proj, tmp_path, files, rows, {}, saved, True, lambda: None)
    next(checks)
    assert len(submitted) == 2
    checks.close()
    assert all(future.cancelled() for future in submitted)


def test_a_pull_that_changed_only_metadata_compiles_nothing(inputs, monkeypatch, tmp_path):
    net, proj, rows, saved, files = inputs
    monkeypatch.setattr(saves, "ThreadPoolExecutor", lambda *a, **kw: pytest.fail("a metadata-only pull compiled"))
    monkeypatch.setattr(net, "_compile", lambda *args: pytest.fail("a metadata-only pull compiled"))
    result = saves._judge_saved(net, proj["slug"], tmp_path, {}, rows, saved, lambda _: None,
                                files=files, judge_code=False)
    assert result == {"matched": 0, "best": 4, "lost": []}


def test_a_compile_still_running_when_checking_stops_is_stopped(inputs, monkeypatch, tmp_path):
    """A cancelled restore must not leave compilers running for C nobody will judge."""
    net, proj, rows, saved, files = inputs
    started, finish = threading.Event(), threading.Event()

    def compile_waiting(*args):
        started.set()
        assert finish.wait(5)
        compiler._CANCEL_CHECK.get()()  # (what the compiler itself checks while it runs)

    monkeypatch.setattr(workers, "WORKERS", 1)
    monkeypatch.setattr(net, "_compile", compile_waiting)
    checks = saves._saved_checks(net, proj, tmp_path, files, rows, {}, saved, True, lambda: None)
    item = next(checks)
    assert started.wait(5)
    checks.close()
    finish.set()
    with pytest.raises(NetworkError, match="stopped"):
        item[-1][1].result(timeout=5)


def test_each_compile_ahead_has_its_functions_header_and_compiler_range(inputs, monkeypatch, tmp_path):
    net, proj, rows, saved, files = inputs
    cfg = {"compiler_ranges": [{"start": 4100, "end": 4104, "toolchain": "example", "flags": ["-O1"]}]}
    proj["config"] = json.dumps(cfg)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET unit='other' WHERE name='f1'")
        db.execute("INSERT INTO context_versions(project_id,version,header,created_at,unit) "
                   "VALUES(?,2,'other header',0,'other')", (proj["id"],))
    captured = {}

    def compile_capture(proj, header, source, fn):
        captured[fn["name"]] = (header, source, json.loads(proj["config"]), fn["vram"])
        return fn["name"]

    monkeypatch.setattr(net, "_compile", compile_capture)
    checks = saves._saved_checks(net, proj, tmp_path, files, rows, {}, saved, True, lambda: None)
    for item in checks:
        item[-1][1].result(timeout=5)
    assert captured["f0"] == ("header", files["best/f0.c"], cfg, 4096)
    assert captured["f1"] == ("other header", files["best/f1.c"], cfg, 4100)
