"""A MIPS target of nothing but NOPs (a zero-filled stretch splat named a function) is set aside at import, in Check
again and in a project's objects: its bytes and symbol stay for the rebuild, but it never reaches the agents' queue,
and a claim on it is released."""

import json
from pathlib import Path

import pytest

from decompnet import consoles
from decompnet.app.engine import RomNetwork
from decompnet.rom import Picked, split

from .test_ps2_debug import (
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHT_PROGBITS,
    SHT_STRTAB,
    SHT_SYMTAB,
    STB_GLOBAL,
    STT_FUNC,
    _elf,
    _symbols,
)

MIPS = ["n64", "psx", "ps2", "psp"]


@pytest.mark.parametrize("platform", MIPS)
def test_only_whole_nop_words_are_set_aside_on_every_mips_console(platform):
    console = consoles.get(platform)
    order = "big" if console.big_endian else "little"
    for size in (4, 8, 64):
        assert "only NOPs" in console.asm_reason(bytes(size))
    # a NOP at the entry or in a return's delay slot is still compiled code
    for words in ((0x03E00008, 0), (0, 0x03E00008, 0, 0)):
        assert console.asm_reason(b"".join(w.to_bytes(4, order) for w in words)) is None
    assert console.asm_reason(b"") is None
    assert "only NOPs" not in (console.asm_reason(bytes(5)) or "")  # (not whole words)
    assert "only NOPs" not in (console.asm_reason((0x27BDFFE8).to_bytes(4, order)) or "")


@pytest.mark.parametrize("platform", MIPS)
def test_import_keeps_padding_and_its_symbol_but_never_queues_it(tmp_path, monkeypatch, platform):
    console = consoles.get(platform)
    order = "big" if console.big_endian else "little"
    image = bytes(4) + (0x03E00008).to_bytes(4, order) + bytes(4)
    functions = [
        split.RomFunction("padding", 0x80001000, 0, "main", [split.AsmLine(0, 0x80001000, 0, "nop", "")], Path()),
        split.RomFunction("empty", 0x80001004, 4, "main",
                          [split.AsmLine(4, 0x80001004, 0x03E00008, "jr", "$ra"),
                           split.AsmLine(8, 0x80001008, 0, "nop", "")], Path()),
    ]

    def fake_split(self, workdir, picked, **kwargs):
        return split.SplitResult(functions, [], [split.Segment("main", 0, len(image), 0x80001000)],
                                 {}, None, "", "")

    monkeypatch.setattr(type(console), "split_game", fake_split)
    monkeypatch.setattr(type(console), "after_import", lambda *args, **kwargs: None)
    monkeypatch.setattr(type(console), "debug_info", lambda *args, **kwargs: None)
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    picked = Picked(console.id, image, "rom.bin", {"title": "Padding demo", "size": len(image), "game_code": "",
                                                   "region": "US", "compiler_guess": "", "sha1": "demo"},
                    console.big_endian)
    slug = net.import_split(console, picked, toolchain=console.compilers[0].id, flags=["-O2"], log=lambda _: None)
    padding = net._function("padding", slug)
    assert padding["status"] == "asm" and padding["target"] == bytes(4)
    assert "only NOPs" in json.loads(padding["meta"])["asm_code"]
    assert net.symbols(padding["project_id"]).resolve("padding") == 0x80001000
    agent, _ = net.local_agent("demo-agent")
    assert net.claim_row(agent, slug)["name"] == "empty"

    # an unchanged reimport sets aside what an older import left open
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='open',meta=NULL WHERE id=?", (padding["id"],))
    net.import_split(console, picked, reimport_slug=slug, log=lambda _: None)
    assert net._function("padding", slug)["status"] == "asm"

    # Check again's pass does too, and releases a claim on it, not the others'
    with net.store.tx() as db:
        db.execute("UPDATE functions SET status='open',meta=NULL WHERE id=?", (padding["id"],))
    other, _ = net.local_agent("padding-agent")
    net.claim_row(other, slug, "padding")
    assert net.twins.set_aside_asm(net.project_row(slug)) == 1
    assert net._function("padding", slug)["target"] == bytes(4)
    assert not net.store.one("SELECT 1 FROM claims WHERE function_id=?", padding["id"])
    assert net.store.one("SELECT 1 FROM claims WHERE agent_id=?", agent.id)

    # the user giving it back to the agents outlasts both the pass and an unchanged reimport
    net.reopen("padding", slug)
    assert net.twins.set_aside_asm(net.project_row(slug)) == 0
    net.import_split(console, picked, reimport_slug=slug, log=lambda _: None)
    assert net._function("padding", slug)["status"] == "open"
    assert json.loads(net._function("padding", slug)["meta"])["reopened"]


def test_a_projects_padding_object_is_set_aside_without_its_consoles_abi(tmp_path, monkeypatch):
    from decompnet.app.twins import object_prints

    image = bytes(4) + bytes.fromhex("0800e00300000000")
    symtab, strtab = _symbols([("padding", 0, 4, STB_GLOBAL, STT_FUNC, 1),
                               ("empty", 4, 8, STB_GLOBAL, STT_FUNC, 1)])
    obj = _elf([(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, image, 0),
                (".symtab", SHT_SYMTAB, 0, 0, symtab, 3), (".strtab", SHT_STRTAB, 0, 0, strtab, 0)])
    prints = object_prints(obj)
    assert "only NOPs" in prints["padding"].asm and prints["empty"].asm == ""
    net = RomNetwork(tmp_path / "fork.db", tmp_path)
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,arch,root,config) VALUES('demo','demo','mips',?,?)",
                         (str(tmp_path), json.dumps({"kind": "fork", "platform": "ps2"}))).lastrowid
        ids = {name: db.execute("INSERT INTO functions(project_id,name,size,n_insns) VALUES(?,?,?,?)",
                               (pid, name, size, size // 4)).lastrowid for name, size in (("padding", 4), ("empty", 8))}
    monkeypatch.setattr(net.twins, "prints", lambda _: {ids[name]: p for name, p in prints.items()})
    agent, _ = net.local_agent("demo-agent")
    net.claim_row(agent, "demo", "padding")
    assert net.twins.set_aside_asm(net.project_row("demo")) == 1
    assert net._function("padding", "demo")["status"] == "asm"
    assert not net.store.one("SELECT 1 FROM claims WHERE function_id=?", ids["padding"])
    assert net.claim_row(agent, "demo")["name"] == "empty"
