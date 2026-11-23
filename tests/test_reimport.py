"""Reimporting a ROM project replaces its analysis while preserving valid work."""

import json

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.consoles import Console
from decompnet.network import NetworkError
from decompnet.rom import Picked, split


def test_reimport_replaces_analysis_and_keeps_only_unchanged_matches(tmp_path, monkeypatch):
    root = tmp_path / "game"
    root.mkdir()
    (root / "old.z64").write_bytes(b"old")
    (root / "old.yaml").write_text("old split", encoding="utf-8")
    (root / "progress").mkdir()
    (root / "progress" / "save.json").write_text("saved work", encoding="utf-8")
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    cfg = {
        "kind": "rom", "platform": "n64", "big_endian": True, "gp": 0,
        "rom": {"file": "old.z64", "program": "old.z64", "sha1": "old"},
        "segments": [], "compiler": {"toolchain": "chosen-toolchain", "flags": ["-G0"], "timeout": 30},
        "auto_compiler": True, "export": {"path": "old/source"}, "autopilot": {"matched": 100},
        "collab": {"open": True},
    }
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,root,arch,config) VALUES(?,?,?,?,?)",
                         ("game", "old game", str(root), "mips", json.dumps(cfg))).lastrowid
        unchanged_id = db.execute(
            "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,status,matched_source,vram) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (pid, "clamp_s32", 4, 1, bytes.fromhex("24020001"), "[]", "matched",
             "void clamp_s32(void) {}", 0x80000000),  # renamed since import (polishing): paired by its address
        ).lastrowid
        changed_id = db.execute(
            "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,status,matched_source,vram) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (pid, "func_80000004", 4, 1, bytes.fromhex("24020001"), "[]", "matched",
             "void func_80000004(void) {}", 0x80000004),
        ).lastrowid
        db.execute("UPDATE functions SET last_checked=123,last_improved=120 WHERE id=?", (changed_id,))
        removed_id = db.execute("INSERT INTO functions(project_id,name,size,n_insns,vram,status,matched_source) "
                                "VALUES(?,?,?,?,?,?,?)", (pid, "func_80000008", 4, 1, 0x80000008, "matched",
                                                          "void func_80000008(void) { gone(); }")).lastrowid
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                   (pid, "clamp_s32", 0x80000000, 4, "func"))
        db.execute("INSERT INTO notes(project_id,function_id,text,created_at) VALUES(?,?,?,?)",
                   (pid, changed_id, "keep this note", 1))
        db.execute("INSERT INTO notes(project_id,function_id,text,created_at) VALUES(?,?,?,?)",
                   (pid, removed_id, "note on removed function", 2))
        db.execute("INSERT INTO context_versions(project_id,version,header,message,created_at,unit) "
                   "VALUES(?,?,?,?,?,?)", (pid, 1, "user header", "custom", 1, ""))
        for fid in (changed_id, removed_id):  # #241: saved compiler comparisons of code that changed or went
            db.execute("INSERT INTO compiler_tests VALUES(?,?,?,?)", (fid, "digest", 0.0, "{}"))
        # what was said about the unchanged one stays; what the analysis read is read again
        db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(
            {"naming": {"method": "operator"}, "plain": "int x;", "debug": {"stale": 1}}), unchanged_id))
        db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps({"naming": {"method": "operator"}}),
                                                               changed_id))

    game = tmp_path / "selected.z64"
    game.write_bytes(b"new rom")

    class TestConsole(Console):  # the connector's own split/judge/asm parts, with only the facts this test needs
        id = "n64"
        name = "Nintendo 64"
        arch = "mips"

        def read_game(self, file, name):
            return Picked("n64", b"new rom", "new.z64", {
                "title": "new game", "size": 7, "game_code": "ABCD", "region": "US",
                "compiler_guess": "KMC", "sha1": "new",
            }, True)

        def debug_info(self, program, known):
            return None

        def default_compiler(self, info, guess):
            return "detected-toolchain"

        def default_flags(self, toolchain, gp):
            return []

        def after_import(self, net, slug, chosen, log):
            assert chosen is True

    console = TestConsole()
    monkeypatch.setattr("decompnet.app.engine.importing.consoles.identify", lambda _: console)
    net.console = lambda _: console
    line_same = split.AsmLine(0, 0x80000000, 0x24020001, "addiu", "v0, zero, 1")
    line_changed = split.AsmLine(4, 0x80000004, 0x24020002, "addiu", "v0, zero, 2")
    line_new = split.AsmLine(8, 0x8000000C, 0x24020003, "addiu", "v0, zero, 3")
    functions = [
        split.RomFunction("func_80000000", 0x80000000, 4, "code", [line_same], root / "same.s"),
        split.RomFunction("func_80000004", 0x80000004, 4, "code", [line_changed], root / "changed.s"),
        split.RomFunction("func_8000000C", 0x8000000C, 8, "code", [line_new], root / "new.s"),
    ]

    def fake_split(workdir, *args, **kwargs):
        (workdir / "new.yaml").write_text("new split", encoding="utf-8")
        return split.SplitResult(functions, [], [split.Segment("code", 0, 16, 0x80000000)], {}, None, "", "")

    monkeypatch.setattr("decompnet.app.engine.importing.split.split_rom", fake_split)

    messages = []
    result = net.reimport_rom("game", game, confirmed=True, log=messages.append)
    assert result == {"slug": "game", "functions": 3, "matched": 1}
    assert messages[0] == "Starting reimport: reading the selected game and checking its format."
    assert any("New split ready: 3 functions" in message for message in messages)
    assert any("Replacing project files" in message for message in messages)
    assert any("reimport kept 1 matched functions" in message for message in messages)
    assert messages[-1] == "Reimport complete: 3 functions; 1 still match."
    assert (root / "progress" / "save.json").read_text(encoding="utf-8") == "saved work"
    assert (root / "new.z64").read_bytes() == b"new rom"
    assert (root / "new.yaml").read_text(encoding="utf-8") == "new split"
    assert not (root / "old.yaml").exists()
    unchanged = net.store.one("SELECT status, matched_source FROM functions WHERE id=?", unchanged_id)
    assert unchanged["status"] == "matched"
    assert unchanged["matched_source"] == "void clamp_s32(void) {}"
    assert json.loads(net.store.one("SELECT meta FROM functions WHERE id=?", unchanged_id)["meta"]) == \
        {"naming": {"method": "operator"}, "plain": "int x;"}
    assert not net.store.one("SELECT meta FROM functions WHERE id=?", changed_id)["meta"]
    assert net.store.one("SELECT name FROM functions WHERE id=?", unchanged_id)["name"] == "clamp_s32"
    assert net.store.one("SELECT address FROM symbols WHERE project_id=? AND name='clamp_s32'", pid)["address"] == 0x80000000
    assert not net.store.one("SELECT 1 FROM symbols WHERE project_id=? AND name='func_80000000'", pid)
    kept = net.store.one("SELECT text FROM notes WHERE text LIKE '%it matched with this C%'")["text"]
    assert "gone();" in kept and any("their C is kept in the project's notes" in m for m in messages)
    changed = net.store.one("SELECT status, matched_source, target, last_checked, last_improved "
                            "FROM functions WHERE id=?", changed_id)
    assert changed["status"] == "open" and changed["matched_source"] is None
    assert changed["target"] == bytes.fromhex("24020002")
    assert changed["last_checked"] is None and changed["last_improved"] is None
    assert net.store.one("SELECT text FROM notes WHERE function_id=?", changed_id)["text"] == "keep this note"
    assert net.store.one("SELECT 1 FROM functions WHERE project_id=? AND name=?",
                         pid, "func_80000008") is None
    orphaned_note = net.store.one("SELECT function_id, text FROM notes WHERE text LIKE '%removed function%'")
    assert orphaned_note["function_id"] is None
    assert orphaned_note["text"] == "[func_80000008 before reimport] note on removed function"
    assert net.store.one("SELECT 1 FROM functions WHERE project_id=? AND name=?", pid, "func_8000000C")
    saved = json.loads(net.project_row("game")["config"])
    assert saved["compiler"] == cfg["compiler"] and saved["auto_compiler"] is True
    assert net.project_row("game")["name"] == "old game"
    assert "export" not in saved and "autopilot" not in saved
    assert net.store.one("SELECT header FROM context_versions WHERE project_id=? ORDER BY version DESC LIMIT 1",
                         pid)["header"] == "user header"
    assert net.store.one("SELECT kind FROM events WHERE project_id=? ORDER BY id DESC LIMIT 1",
                         pid)["kind"] == "reimport"
    assert not list(tmp_path.glob(".game-reimport-backup-*"))
    assert net.store.one("SELECT 1 FROM compiler_tests WHERE function_id IN (?,?)", changed_id, removed_id) is None


def test_reimport_still_blocks_projects_with_an_active_room(tmp_path):
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    root = tmp_path / "game"
    root.mkdir()
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,name,root,arch,config) VALUES(?,?,?,?,?)",
                   ("game", "Game", str(root), "mips", json.dumps({
                       "kind": "rom", "platform": "n64", "collab": {"open": True},
                   })))

    class TestConsole:
        id = "n64"

    console = TestConsole()
    net.console = lambda _: console
    net.rooms["game"] = object()
    with pytest.raises(NetworkError, match="leave the shared room"):
        net.import_split(console, Picked("n64", b"rom", "game.z64", {}, True), reimport_slug="game")


def test_reimport_pairs_the_two_functions_an_overlay_puts_at_one_address():
    """A game's overlay loads at the same address as main code, so two functions can share one. Paired by address
    alone, the second was left unpaired and its name (held by the old twin) was inserted again."""
    from types import SimpleNamespace

    from decompnet.app.engine.importing import pair_old_functions

    old = [{"id": 1, "name": "func_00100000", "vram": 0x100000},
           {"id": 2, "name": "ovl_ntgui2_func_00100000", "vram": 0x100000},
           {"id": 3, "name": "agents_name", "vram": 0x200000}]
    new = [SimpleNamespace(name="ovl_ntgui2_func_00100000", vram=0x100000),
           SimpleNamespace(name="func_00100000", vram=0x100000),
           SimpleNamespace(name="func_00200000", vram=0x200000),
           SimpleNamespace(name="func_00300000", vram=0x300000)]
    paired = pair_old_functions(old, new)
    assert paired["func_00100000"]["id"] == 1 and paired["ovl_ntgui2_func_00100000"]["id"] == 2
    assert paired["func_00200000"]["id"] == 3  # renamed since: still paired by its address
    assert "func_00300000" not in paired  # new in this split
    assert len({o["id"] for o in paired.values()}) == len(paired)  # each old function pairs once


def test_reimport_keeps_agents_names_and_judges_c_whose_references_were_read_anew(tmp_path, monkeypatch):
    """A game lost 234 matches at once: its new split sized bss blocks over 177 addresses helpers had named (the names
    went, so matched C stopped linking), and a newer reader annotated references the old targets left as numbers
    (same bytes, other relocations), so the C was dropped unjudged."""
    root = tmp_path / "game"
    root.mkdir()
    (root / "old.z64").write_bytes(b"old")
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    cfg = {"kind": "rom", "platform": "n64", "big_endian": True, "gp": 0,
           "rom": {"file": "old.z64", "program": "old.z64", "sha1": "old"}, "segments": [],
           "compiler": {"toolchain": "chosen-toolchain", "flags": ["-G0"], "timeout": 30}}
    helper = net.authenticate(net.register_agent("claude-helper", "you"))
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,root,arch,config) VALUES(?,?,?,?,?)",
                         ("game", "old game", str(root), "mips", json.dumps(cfg))).lastrowid
        fid = db.execute(
            "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,status,matched_source,matched_agent_id,"
            "vram) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (pid, "race_update", 4, 1, bytes.fromhex("24020001"), "[]", "matched",
             "void race_update(void) { gRecords = 0; }", helper.id, 0x80000000)).lastrowid
        for name, address, kind in (("gRecords", 0x800C35A0, "data"), ("gSlotState", 0x800C35A0, "data"),
                                    ("gLapCount", 0x800D0000, "bss"), ("gStreamState", 0x800C02AE, "bss"),
                                    ("stream_state", 0x800C02AE, "bss")):
            db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,0,?)",
                       (pid, name, address, kind))
        db.execute("INSERT INTO context_versions(project_id,version,header,message,created_at,unit) "
                   "VALUES(?,1,'','',1,'')", (pid,))
    game = tmp_path / "selected.z64"
    game.write_bytes(b"new rom")

    class TestConsole(Console):
        id = "n64"
        name = "Nintendo 64"
        arch = "mips"

        def read_game(self, file, name):
            return Picked("n64", b"new rom", "new.z64", {"title": "new game", "size": 7, "game_code": "ABCD",
                                                         "region": "US", "compiler_guess": "KMC", "sha1": "new"}, True)

        def debug_info(self, program, known):
            return None

        def default_compiler(self, info, guess):
            return "detected-toolchain"

        def default_flags(self, toolchain, gp):
            return []

        def after_import(self, net, slug, chosen, log):
            pass

        def target_from_split(self, fn, resolve, big_endian, gp):
            from decompnet.rom.match import RomTarget
            return RomTarget(fn.name, fn.vram, bytes.fromhex("24020001"), [(0, 5, 0x800C35A0)], True, 0)

    console = TestConsole()
    monkeypatch.setattr("decompnet.app.engine.importing.consoles.identify", lambda _: console)
    net.console = lambda _: console
    line = split.AsmLine(0, 0x80000000, 0x24020001, "addiu", "v0, zero, 1")
    functions = [split.RomFunction("func_80000000", 0x80000000, 0, "code", [line], root / "f.s")]
    data = [split.DataSymbol("D_800C02AE", 0x800C02AE, None, 66514, "bss"),  # sized over gRecords
            split.DataSymbol("D_800CFFF0", 0x800CFFF0, None, 0x100, "bss")]  # gLapCount lies inside this one

    def fake_split(workdir, *args, **kwargs):
        return split.SplitResult(functions, data, [split.Segment("code", 0, 16, 0x80000000)], {}, None, "", "")

    monkeypatch.setattr("decompnet.app.engine.importing.split.split_rom", fake_split)
    judged = []

    def attempt(agent, name, source, project=None):
        judged.append((agent.name, name, source))
        return {"matched": False}

    net.attempt = attempt
    messages = []
    net.reimport_rom("game", game, confirmed=True, log=messages.append)
    rows = net.store.all("SELECT name, address, size FROM symbols WHERE project_id=?", pid)
    names, sizes = {r["name"]: r["address"] for r in rows}, {r["name"]: r["size"] for r in rows}
    assert names["gRecords"] == names["gSlotState"] == 0x800C35A0  # both names of one address
    assert sizes["gStreamState"] == sizes["stream_state"] == 66514  # both names of the block keep its size
    assert "D_800C02AE" not in sizes
    assert names["gLapCount"] == 0x800D0000 and names["D_800CFFF0"] == 0x800CFFF0  # inside a sized block
    table = net.symbols(pid)
    assert table.resolve("gRecords") == table.resolve("gSlotState") == 0x800C35A0  # (read back, both still resolve)
    assert table.resolve("gStreamState") == table.resolve("stream_state") == 0x800C02AE
    assert judged == [("claude-helper", "race_update", "void race_update(void) { gRecords = 0; }")]
    row = net.store.one("SELECT status, best_source FROM functions WHERE id=?", fid)
    assert row["status"] == "open" and row["best_source"] == "void race_update(void) { gRecords = 0; }"
    assert any("0 of 1 still match" in m for m in messages)
