"""An N64 game's libultra and n_audio are found without the user's SDK: the console ships their fingerprints
(consoles/n64/*.tsv: hashes, sizes and names, no code), which Find libraries compares with the game's functions as
the twins pass prints them, and sets what matches aside under the library's own names."""

from __future__ import annotations

import json
import re
import struct
from io import BytesIO
from pathlib import Path

import pytest

from decompnet import consoles, libid, toolchains
from decompnet.app.twins import object_prints, rom_print
from decompnet.consoles.n64 import signatures

N64 = consoles.get("n64")


def test_the_n64_ships_libultra_and_n_audio_fingerprints():
    tables = dict(N64.library_prints)
    assert set(tables) == {"libultra", "n_audio"}
    ultra = libid.read_fingerprints(Path(tables["libultra"]), "libultra")
    audio = libid.read_fingerprints(Path(tables["n_audio"]), "n_audio")
    assert len(ultra) > 2000 and len(audio) > 200
    assert ultra[0].origin == "decompals/ultralib e24c836796df"
    for p in ultra + audio:  # hashes, sizes and names: no code
        assert re.fullmatch(r"[0-9a-f]{40}", p.key) and p.size >= 32 and re.fullmatch(r"[A-Za-z_]\w*", p.name)
        assert p.builds and all(re.fullmatch(r"2\.0[I-L]/\w+", b) for b in p.builds)
    # (n_audio's table leaves out what the ultralib one names: two names on one fingerprint say neither)
    assert not {p.key for p in audio} & signatures.known(Path(tables["libultra"]))
    assert {lib.id for lib in N64.library_catalog()} == {"libultra", "n_audio"}
    assert all(lib.aside for lib in N64.library_catalog())


def _code(key, name, fingerprint, raw=b"\0" * 64):
    return libid.Code(key, name, None, raw, fingerprint=fingerprint)


def test_a_fingerprint_finds_its_function_and_names_it(tmp_path):
    catalog = libid.load(tmp_path / "none", console=N64.library_catalog())
    catalog.prints = [libid.Fingerprint("a" * 40, 64, "osSendMesg", "libultra", ("2.0K/libgultra", "2.0L/libgultra")),
                      libid.Fingerprint("b" * 40, 64, "n_alCSPSetSeq", "n_audio", ("2.0K/libgn_audio",)),
                      libid.Fingerprint("b" * 40, 64, "n_alSeqpSetSeq", "n_audio", ("2.0K/libgn_audio",))]
    codes = [_code(1, "func_80001000", "a" * 40), _code(2, "func_80002000", "b" * 40),
             _code(3, "func_80003000", "a" * 40, b"\0" * 32),  # another size: not it
             _code(4, "func_80004000", "c" * 40)]
    report = libid.identify(None, codes, catalog, arch="mips", big_endian=True)
    libs = {lib["id"]: lib for lib in report["libraries"]}
    assert libs["libultra"]["keys"] == [1] and libs["libultra"]["aside"]
    first = libs["libultra"]["functions"][0]
    assert first["real"] == "osSendMesg" and "2.0K-2.0L" in first["why"]
    # one fingerprint, two names: still n_audio's code, but neither name is its
    assert libs["n_audio"]["keys"] == [2] and "real" not in libs["n_audio"]["functions"][0]


def test_find_libraries_sets_libultra_aside_in_an_n64_project_without_an_sdk(tmp_path, monkeypatch):
    from decompnet import kits
    from decompnet.app.engine import RomNetwork

    monkeypatch.setattr(libid, "signature_folder", lambda: tmp_path / "sigs")
    monkeypatch.setattr(kits, "libraries", lambda kids: [])
    code = struct.pack(">12I", 0x27BDFFE8, 0xAFBF0014, 0x0C000000, 0x00000000, 0x3C040000, 0x24840000,
                       0x8FBF0014, 0x27BD0018, 0x03E00008, 0x00000000, 0, 0)
    relocs = [[8, 4, 0x80003000], [16, 5, 0x80100000], [20, 6, 0x80100000]]
    row = {"target": code, "relocs": json.dumps(relocs)}
    table = tmp_path / "ultra.tsv"
    table.write_text("# decompals/ultralib " + "e" * 40 + ", for a test\n# fingerprint\tsize\tname\tbuilds\n"
                     f"{rom_print(row, 'mips', True, str).key}\t{len(code)}\tosCreateThread\t2.0L/libgultra\n")
    monkeypatch.setattr(type(N64), "library_prints", (("libultra", str(table)),))
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    root = tmp_path / "proj"
    root.mkdir()
    (root / "game.z64").write_bytes(b"\0")
    other = code[:8] + struct.pack(">I", 0x24020001) + code[12:]  # the game's own: another instruction
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                         ("demo", "demo", "", "mips", 1, str(root), json.dumps({"kind": "rom", "platform": "n64",
                                                                              "big_endian": True,
                                                                              "rom": {"file": "game.z64"}}))).lastrowid
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,1,'',NULL,'',0,'')", (pid,))
        moved = [[8, 4, 0x80004000], [16, 5, 0x80200000], [20, 6, 0x80200000]]  # (elsewhere in this game)
        for name, addr, raw, rel in (("func_80001000", 0x80001000, code, moved),
                                     ("func_80002000", 0x80002000, other, relocs)):
            db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,status,vram,meta,"
                       "attempts,abandons) VALUES(?,?,?,?,?,?,?,?,?,?,0,0)",
                       (pid, name, len(raw), len(raw) // 4, raw, json.dumps(rel), "", "open", addr, "{}"))
            db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                       (pid, name, addr, len(raw), "func"))
    monkeypatch.setattr(RomNetwork, "is_rom", lambda self, proj: True)
    report = net.find_libraries("demo", log=lambda *_: None, fid=False)
    rows = {r["vram"]: r for r in net.store.all("SELECT * FROM functions WHERE project_id=?", pid)}
    assert report["set_aside"] == 1 and report["named"] == 1
    assert rows[0x80001000]["name"] == "osCreateThread" and rows[0x80001000]["status"] == "asm"
    assert json.loads(rows[0x80001000]["meta"])["set_aside"].startswith("library code: osCreateThread of libultra")
    assert rows[0x80002000]["status"] == "open"


@pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None, reason="needs gcc-2.7.2-kmc")
def test_an_objects_fingerprint_is_the_same_function_s_in_a_rom():
    """The tables are made from objects (object_prints); a game's functions are printed from the ROM (rom_print):
    the same code must give the same fingerprint wherever it's linked."""
    from elftools.elf.elffile import ELFFile

    from decompnet.compiler import compile_source
    from decompnet.project import compiler_config
    from decompnet.rom import match

    source = "extern int counter;\nextern void tick(int);\nint step(int x) { tick(x); return counter + x; }\n"
    result = compile_source(compiler_config(Path("."), {"compiler": {"toolchain": "gcc-2.7.2-kmc"}}), "", source)
    assert result.ok, result.log
    want = object_prints(result.obj)["step"]
    elf = ELFFile(BytesIO(result.obj))
    fn = next(s for s in elf.get_section_by_name(".symtab").iter_symbols() if s.name == "step")
    text = bytearray(elf.get_section_by_name(".text").data()[fn["st_value"]:fn["st_value"] + fn["st_size"]])
    raw = match.raw_relocs(elf, elf.get_section_index(".text"), fn["st_value"], fn["st_size"], bytes(text))
    relocs = []
    for r in raw:  # linked somewhere in a game
        dest = 0x80123450 if r["type"] == match.R_MIPS_26 else 0x80345678
        at = r["off"]
        text[at:at + 4] = match._patch(int.from_bytes(text[at:at + 4], "big"), r["type"], dest).to_bytes(4, "big")
        relocs.append([at, r["type"], dest])
    assert relocs
    got = rom_print({"target": bytes(text), "relocs": json.dumps(relocs)}, "mips", True, str)
    assert (got.key, got.size) == (want.key, want.size)
