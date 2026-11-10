"""Linux (32-bit x86) programs: what the console recognises, its STABS reader and its judge's placement rule. A
real game's run (Slackware 8.0's GCC 2.95.3 reproducing its functions byte for byte) needs the game, so the end to end
check is the demo program built with the same toolchain (projects/demo-linux, and tests/test_consoles.py)."""

import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from decompnet import consoles
from decompnet.arch import x86_link
from decompnet.consoles.linux import debuginfo


def _elf_head(machine: int, kind: int = 2, klass: int = 1) -> bytes:
    head = bytearray(64)
    head[:4], head[4], head[5] = b"\x7fELF", klass, 1
    struct.pack_into("<HH", head, 16, kind, machine)
    return bytes(head)


def test_a_32_bit_x86_executable_is_a_linux_program_and_nothing_else_is():
    linux = consoles.get("linux")
    assert linux.sniff(_elf_head(3), b"")
    assert not linux.sniff(_elf_head(8), b"")  # (a MIPS ELF: the PS2's)
    assert not linux.sniff(_elf_head(3, kind=1), b"")  # (an object, not a program)
    assert not linux.sniff(_elf_head(62, klass=2), b"")  # (64-bit)
    assert not linux.sniff(b"MZ" + bytes(62), b"")  # (a Windows program)


def _stab(strx: int, code: int, value: int, desc: int = 0) -> bytes:
    return struct.pack("<IBBhI", strx, code, 0, desc, value)


def test_stabs_are_read_a_compile_unit_at_a_time_with_continued_strings_joined():
    """Each unit's strings start where the last ended (its N_UNDF entry says how many); GCC continues a long
    string in the next entry, the first ending in a backslash."""
    first = b"\0a.c\0f:F(0,1)\0int:t(0,1)=r(0,1);\\\0-2147483648;2147483647;\0"
    second = b"\0b.c\0g:F(0,1)\0"
    stab = (_stab(0, 0, len(first)) + _stab(1, 0x64, 0) + _stab(5, 0x24, 0x8048100)
            + _stab(14, 0x80, 0) + _stab(34, 0x80, 0)
            + _stab(0, 0, len(second)) + _stab(1, 0x64, 0) + _stab(5, 0x24, 0x8048200))
    units = debuginfo.entries(stab, first + second)
    assert [name for name, _ in units] == ["a.c", "b.c"]
    assert units[0][1] == [(0x24, "f:F(0,1)", 0x8048100, 0), (0x80, "int:t(0,1)=r(0,1);-2147483648;2147483647;", 0, 0)]
    assert units[1][1] == [(0x24, "g:F(0,1)", 0x8048200, 0)]
    assert debuginfo.x86_register(6) == "esi" and debuginfo.x86_register(12) == "st(0)"


def test_a_function_is_compiled_at_its_address_modulo_16():
    """GCC 2.95 pads a loop's start only when that costs at most 7 bytes, from the start of the object: on a 2001
    Linux game, the same C placed at offset 0 instead of 4 got a 3-byte lea for padding the game hasn't."""
    assert x86_link.prelude(0x8068F64) == '__asm__(".text\\n\\t.space 4\\n");\n'
    assert x86_link.prelude(0x8064D60) == ""
    assert consoles.get("linux").compile_prelude(0x8068F64) == x86_link.prelude(0x8068F64)


def test_a_header_written_once_is_put_back_in_each_unit_with_its_types_numbered_program_wide():
    """GCC on Linux numbers a type by (file, index), the file counted in its unit; the linker keeps a header's entries
    in the first unit that included it (N_BINCL ... N_EINCL) and leaves later units an N_EXCL. On a 2001 game 141,455
    of 376,351 type references found no definition in their unit, and the types header didn't compile."""
    strings = b"\0a.c\0h.h\0T:t(1,1)=s4x:(0,1),0,32;;\0b.c\0g.h\0v:G(2,1)\0w:G(0,1)\0"
    at = {name: strings.index(name.encode() + b"\0") for name in ("a.c", "h.h", "b.c", "g.h", "v:G(2,1)", "w:G(0,1)")}
    at["T"] = strings.index(b"T:t(")
    stab = (_stab(0, 0, len(strings))
            + _stab(at["a.c"], 0x64, 0) + _stab(at["h.h"], 0x82, 77) + _stab(at["T"], 0x80, 0) + _stab(0, 0xA2, 0)
            + _stab(at["b.c"], 0x64, 0) + _stab(at["g.h"], 0x82, 5) + _stab(0, 0xA2, 0)  # (g.h: file 1 in b.c)
            + _stab(at["h.h"], 0xC2, 77) + _stab(at["v:G(2,1)"], 0x20, 0) + _stab(at["w:G(0,1)"], 0x20, 0))
    (_, a), (_, b) = debuginfo.entries(stab, strings)
    defined = next(t for _, t, *_ in a if t.startswith("T:t"))
    number = defined[defined.index("(") + 1:defined.index(",")]
    assert defined.startswith(f"T:t({number},1)=s4x:(0,1)")  # (built-in types keep file 0)
    assert any(t == defined for _, t, *_ in b)  # h.h's types are back in b.c ...
    # ... and b.c's file 2 (after its own g.h) is h.h there, by the same number
    assert number != "2" and (0x20, f"v:G({number},1)", 0, 0) in b and (0x20, "w:G(0,1)", 0, 0) in b


def test_a_typedefs_anonymous_struct_numbered_apart_is_written_with_its_body():
    """GCC 2.95 for i386 writes `typedef struct { ... } Foo;` as Foo:t(1,1)=(1,2)=s...: the struct isn't one of its
    file's named types, and the header declared it without its body (64 fields of a 2001 Linux game incomplete)."""
    from decompnet.consoles.ps2 import cheader, stabs

    source = stabs.read_file("a.c", [(0x80, "int:t(0,1)=r(0,1);-2147483648;2147483647;", 0),
                                     (0x80, "Foo:t(1,1)=(1,2)=s4x:(0,1),0,32;;", 0),
                                     (0x80, "Bar:T(1,3)=s4f:(1,1),0,32;;", 0)])
    text = cheader.Header([source]).text()
    assert "struct Foo {" in text and "x; /* 0x0 */" in text and "Foo f; /* 0x0 */" in text



def test_a_functions_line_table_and_where_its_variables_live_reach_its_brief():
    """A 2000s Linux game's last function took 273 agent compiles: its brief named four locals and no line table, so
    nobody saw that its STABS put one channel's unpacking per source line, the values in registers with no local
    (an inner block's, dropped from the debug information by scheduling). The table's lines, each with its code's
    addresses, the line each local is declared on, and a parameter kept in a register (an r entry after its p one)."""
    from decompnet.consoles.ps2 import debuginfo as described
    from decompnet.consoles.ps2 import stabs

    source = stabs.read_file("ps_argb.c", [
        (0x80, "int:t(0,1)=r(0,1);-2147483648;2147483647;", 0, 0),
        (0x24, "lerp:F(0,1)", 0x8099000, 21), (0xA0, "a:p(0,1)", 8, 21), (0xA0, "b:p(0,1)", 12, 21),
        (0x44, "", 9, 21), (0x44, "", 0xC, 25), (0x44, "", 0x15, 26), (0x44, "", 0x1C, 25), (0x44, "", 0x20, 28),
        (0x40, "b:r(0,1)", 3, 21), (0x80, "f:(0,1)", 0xFFFFFFF4, 22),
        (0xC0, "", 0, 0), (0xE0, "", 0x30, 0), (0x24, "", 0x30, 0)], debuginfo.x86_register)
    function = source.functions[0]
    assert [p.where for p in function.params] == ["the stack, frame offset +0x8", "ebx"]
    assert [(v.name, v.where, v.line) for v in function.locals] == [("f", "the stack, frame offset -0xc", 22)]
    table = described._line_table(function)
    assert table["lines"] == [[21, [[0x8099009, 0x809900C]]], [25, [[0x809900C, 0x8099015], [0x809901C, 0x8099020]]],
                              [26, [[0x8099015, 0x809901C]]], [28, [[0x8099020, 0x8099030]]]]
    brief = "\n".join(described.brief_lines({"source": "ps_argb.c", "prototype": "int lerp(int a, int b)",
                                              "locals": ["int f (declared on line 22)"]} | table))
    assert "25: 0809900C-08099015, 0809901C-08099020" in brief and "inner block" in brief


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    """Demo Quest built -g with the pinned GCC 2.95.3 (projects/demo-linux), imported."""
    import json
    import subprocess
    import sys

    from .test_consoles import ROOT, _missing

    console = consoles.get("linux")
    if (missing := _missing(console)):
        pytest.skip(f"{console.name}'s demo needs {', '.join(missing)}")
    folder = ROOT / "projects" / console.demo
    if not (folder / "build" / "demo.json").exists():
        subprocess.run([sys.executable, str(folder / "build.py")], check=True)
    built = json.loads((folder / "build" / "demo.json").read_text())
    return folder / "build" / built["game"], tmp_path_factory


def _imported(demo, name):
    from decompnet.app.engine import RomNetwork

    program, factory = demo
    work = factory.mktemp(name)
    net = RomNetwork(work / "app.db", work)
    return net, net.import_rom(program, confirmed=True, log=lambda *_: None)


def test_the_demos_briefs_have_its_line_tables_and_an_older_import_gets_them_at_start(demo):
    """Demo Quest built -g: a function's brief says which source line each instruction came from. A project imported
    before the line tables were read gets them when the app starts (Linux.add_line_tables), once."""
    net, slug = _imported(demo, "lines")
    pid = net.project_row(slug)["id"]
    row = net.store.one("SELECT * FROM functions WHERE project_id=? AND name='entity_update_physics'", pid)
    assert json.loads(row["meta"])["debug"]["lines"]
    assert any(line.startswith("source lines, each with the addresses of its code")
               for line in net._debug_brief(row, net.project_row(slug)))
    with net.store.tx() as db:  # as an older import left it
        for r in db.execute("SELECT id, meta FROM functions WHERE project_id=? AND meta LIKE '%\"lines\"%'", (pid,)):
            meta = json.loads(r["meta"])
            meta["debug"].pop("lines")
            db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), r["id"]))
    net._update_cfg(slug, lambda c: c.pop("debug_lines", None))
    said = []
    consoles.get("linux").add_line_tables(net, slug, log=said.append)
    row = net.store.one("SELECT meta FROM functions WHERE project_id=? AND name='entity_update_physics'", pid)
    assert json.loads(row["meta"])["debug"]["lines"] and said and "line table" in said[0]
    consoles.get("linux").add_line_tables(net, slug, log=said.append)
    assert len(said) == 1  # (once)


def test_a_brief_and_a_polishing_job_give_the_callees_prototypes_from_the_debug_information(demo):
    """The shared header has the game's types, not its functions: agents declared each callee themselves, as
    returning int, and a struct pointer became an int read at offsets (a 2000s Linux game's `*(unsigned int *)(tex +
    0x2c)` for `Tex->flags`, through polishing too). A brief lists what each callee is, as the debug information
    declares it; the polishing job shows the function's debug information and those too."""
    net, slug = _imported(demo, "callees")
    proj = net.project_row(slug)
    x = net.xrefs(proj)
    rows = net.store.all("SELECT * FROM functions WHERE project_id=? AND meta LIKE '%\"prototype\"%'", proj["id"])
    by_vram = {r["vram"]: r for r in rows}
    fn = next(r for r in rows if any(c in by_vram for c in x["calls"].get(r["vram"], ())))
    callee = by_vram[next(c for c in sorted(x["calls"][fn["vram"]]) if c in by_vram)]
    prototype = json.loads(callee["meta"])["debug"]["prototype"]
    brief = net._callee_brief(fn, proj)
    assert f"{prototype};" in brief and "not through an int and an offset" in brief[-1]
    with net.store.tx() as db:  # (the one matched function left to polish)
        db.execute("UPDATE functions SET readable=1 WHERE project_id=?", (proj["id"],))
        db.execute("UPDATE functions SET status='matched', readable=0, matched_source=? WHERE id=?",
                   (f"int {fn['name']}(void) {{ return 0; }}", fn["id"]))
    agent, _ = net.local_agent("polisher")
    job = net.readability.claim(agent, slug)
    assert f"MAKE READABLE: {fn['name']}" in job and prototype in job and "their fields by name" in job
    # what polishing made readable before it showed them, still reading through offsets: polished again, once
    with net.store.tx() as db:
        db.execute("DELETE FROM claims")
        db.execute("UPDATE functions SET readable=1, matched_source=? WHERE id=?",
                   ("int f(int tex) { return *(unsigned int *)(tex + 0x2c); }", fn["id"]))
    net._update_cfg(slug, lambda c: c.pop("untyped_reading", None))
    assert net.readability.reopen_untyped(slug, log=lambda *_: None) == 1
    assert net.store.one("SELECT readable FROM functions WHERE id=?", fn["id"])["readable"] == 0
    with net.store.tx() as db:
        db.execute("UPDATE functions SET readable=1 WHERE id=?", (fn["id"],))
    assert net.readability.reopen_untyped(slug, log=lambda *_: None) == 0


def test_polishing_names_the_offset_reads_the_header_has_fields_for_and_asks_once(demo):
    """A 2000s Linux game's helper polished every other field into its name and left `*(char ***)((char *)pModel +
    0x40)` for pModel->Geometries, twice. The job lists what each such read is, the first rewrite that keeps one is
    sent back with them, and what was polished so is polished again at start."""
    from decompnet import cfields

    net, slug = _imported(demo, "named")
    proj = net.project_row(slug)
    fn = net.store.one("SELECT * FROM functions WHERE project_id=? ORDER BY vram LIMIT 1", proj["id"])
    header = net._context(proj["id"], fn["unit"])["header"]
    parsed = cfields.Header(header)
    tag, field = next((name, f) for name in parsed.bodies if parsed.struct(name)
                      for f in parsed.struct(name).fields if f.offset and f.count == 1 and parsed.struct(f.type) is None)
    source = (f"int {fn['name']}(struct {tag} *p) {{ return *(int *)((char *)p + 0x{field.offset:x}); }}")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET readable=1 WHERE project_id=?", (proj["id"],))
        db.execute("UPDATE functions SET status='matched', readable=0, matched_source=? WHERE id=?", (source, fn["id"]))
    agent, _ = net.local_agent("polisher")
    job = net.readability.claim(agent, slug)
    assert f"is p->{field.name} ({field.type})" in job
    again = source.replace("int p", "int q") if "int p" in source else source.replace("*p)", "*q)").replace("p +", "q +")
    said = net.readability.submit(agent, slug, fn["name"], again)
    assert said.startswith("✋") and f"q->{field.name}" in said
    assert "✋" not in net.readability.submit(agent, slug, fn["name"], again)  # (the second time it's judged)
    with net.store.tx() as db:
        db.execute("DELETE FROM claims")
        db.execute("UPDATE functions SET readable=1, matched_source=? WHERE id=?", (source, fn["id"]))
    net._update_cfg(slug, lambda c: c.update(untyped_reading=1))  # (polished again for the debug types already)
    assert net.readability.reopen_untyped(slug, log=lambda *_: None) == 1
    assert net.store.one("SELECT readable FROM functions WHERE id=?", fn["id"])["readable"] == 0


def test_without_debug_information_briefs_show_what_calls_return_and_polishing_again_is_asked_for(demo):
    """A game with no debug information: what a function's calls return is the type its code shows across the game
    (structs.recover: one type per function's results), in the brief and the polishing job. Polishing again what
    was made readable through offsets is a guess's worth only when the user asks (the Polish launcher's button)."""
    from decompnet import structs
    from decompnet.app.engine import layouts

    net, slug = _imported(demo, "guesses")
    proj = net.project_row(slug)
    with net.store.tx() as db:  # (as a stripped program's import: no debug information)
        for r in db.execute("SELECT id, meta FROM functions WHERE project_id=?", (proj["id"],)).fetchall():
            meta = json.loads(r["meta"] or "{}")
            meta.pop("debug", None)
            db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), r["id"]))
    found = net.structs(proj)
    rows = net.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"])
    keys = lambda fn: [(structs.ARGUMENT, fn["vram"], n) for n in layouts.BRIEF_ARGUMENTS] + [(structs.RETURN, fn["vram"])]
    fn = next(fn for fn in rows if any(t is not None and len(found.layout(t).functions) >= 2
                                       for t in [found.type_of(k) for k in keys(fn)]
                                       + [t for _, t in found.results_in(fn["vram"])]))
    assert net._struct_brief(fn, proj)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET readable=1 WHERE project_id=?", (proj["id"],))
        db.execute("UPDATE functions SET status='matched', matched_source=? WHERE id=?",
                   ("int f(int p) { return *(int *)(p + 0x18); }", fn["id"]))
    assert net.readability.reopen_untyped(slug, log=lambda *_: None) == 0  # (at start: debug information's only)
    assert net.readability.reopen_untyped(slug, log=lambda *_: None, guesses=True, dry=True) == 1
    assert net.store.one("SELECT readable FROM functions WHERE id=?", fn["id"])["readable"] == 1
    assert net.readability.reopen_untyped(slug, log=lambda *_: None, guesses=True) == 1
    assert net.store.one("SELECT readable FROM functions WHERE id=?", fn["id"])["readable"] == 0


def test_the_demos_struct_comes_from_its_debug_information_and_names_are_c_identifiers(demo):
    """Demo Quest built -g: guess_struct answers with the STABS prototype's type, field for field, and GCC's static
    locals (`mark.21`) get C names an agent can write and a save can store."""
    net, slug = _imported(demo, "structs")
    text = net.guess_struct(slug, "entity_update_physics", "arg0")
    assert "`void entity_update_physics(Entity *e)`" in text and "int hp; /* 0x18 */" in text
    pid = net.project_row(slug)["id"]
    names = [r["name"] for r in net.store.all("SELECT name FROM functions WHERE project_id=?", pid)]
    assert names and all(re.fullmatch(r"[A-Za-z_]\w*", n) for n in names)


def test_a_function_is_split_at_an_instruction_and_cut_where_agents_say_it_ends_and_a_save_keeps_it(demo, tmp_path):
    """split_function and report_boundary on a Linux program (x86: a cut falls on an instruction's start), and the
    layout they leave comes back from a save."""
    from decompnet.app import saves
    from decompnet.consoles.linux import split
    from decompnet.network import NetworkError

    net, slug = _imported(demo, "cuts")
    agent, _ = net.local_agent("claude-opus-5.5-1")
    fn = net._function("game_tick", slug)
    starts = split.boundaries(fn["target"], fn["vram"])
    at = fn["vram"] + starts[len(starts) // 2]
    with pytest.raises(NetworkError, match="start of an instruction"):
        net.split_function(agent, slug, "game_tick", f"0x{at + 1:08X}")
    assert net.split_function(agent, slug, "game_tick", f"0x{at:08X}").startswith("✅ split")
    head, tail = net._function("game_tick", slug), net._function(f"func_{at:08X}", slug)
    assert head["target"] + tail["target"] == fn["target"] and tail["vram"] == at
    assert f"/* {at:08X} */" in tail["asm"] and f"/* {at:08X} */" not in head["asm"]

    other = net._function("entity_update_physics", slug)
    cut = other["vram"] + split.boundaries(other["target"], other["vram"])[-2]
    assert net.request_boundary(agent, slug, "entity_update_physics", f"0x{cut:08X}", "the rest is padding").startswith(
        "Reported")
    [rid] = [r["id"] for r in net.cfg(net._project(slug))["boundaries"]]
    net.resolve_boundary(slug, rid, True)
    assert net._function(f"pad_{cut:08X}", slug)["status"] == "asm"
    assert net._function("entity_update_physics", slug)["size"] == cut - other["vram"]

    saves.save(net, slug, tmp_path / "save")
    from decompnet.app.engine import RomNetwork

    (tmp_path / "two").mkdir()
    fresh = RomNetwork(tmp_path / "two" / "app.db", tmp_path / "two")
    out = saves.restore(fresh, str(tmp_path / "save"), demo[0], log=lambda *_: None)
    assert fresh._function(f"func_{at:08X}", out["slug"])["target"] == tail["target"]
    assert fresh._function("entity_update_physics", out["slug"])["size"] == cut - other["vram"]


def test_a_function_the_symbols_miss_is_found_to_its_return_or_to_the_next_one():
    """function_at: up to the return no jump of its own lands past (a branch over a ret in its middle runs on),
    and a function that ends in a call to exit runs to the next one, its padding left out."""
    from decompnet.consoles.linux import split

    body = bytes.fromhex("5589e57403c9c3" "90c9c3")  # push ebp; mov ebp,esp; je +3; leave; ret; nop; leave; ret
    noreturn = bytes.fromhex("5589e56aff" "e8fcffffff") + bytes.fromhex("8d7600")  # ...; call exit; lea esi,[esi]
    assert split.extent(body, 0x100) == len(body)
    program = _program(body + bytes(6) + noreturn, 0x08048100)
    assert split.function_at(program, 0x08048100, 0x08048200, "f").size == len(body)
    found = split.function_at(program, 0x08048110, 0x08048110 + len(noreturn), "g")
    assert found.size == len(noreturn) - 3
    assert split.padding(bytes.fromhex("8db42600000000"), 0) and not split.padding(bytes.fromhex("5589e5"), 0)


def _program(code: bytes, vram: int) -> bytes:
    """A minimal i386 executable: its header, one executable PT_LOAD holding `code` at `vram`."""
    phoff, at = 52, 52 + 32
    head = (b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, vram, phoff, 0, 0, 52, 32, 1,
                                                                 40, 0, 0))
    phdr = struct.pack("<IIIIIIII", 1, at, vram, vram, len(code), len(code), 5, 0x1000)
    return head + phdr + code


GAME_DEFINES = "#define GRAVITY 2\n#define MAX_FALL_SPEED 24\n#define FLOOR_Y 448\n#define ENTITY_FLAG_GROUNDED 0x2\n"


def _match(net, slug, name: str) -> dict:
    from decompnet.forks import csource

    from .test_consoles import DEMO_GAME

    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.claim(agent, slug, name)
    return net.attempt(agent, name, GAME_DEFINES + csource.get(DEMO_GAME.read_text(), name), slug)


def test_a_switchs_jump_table_matches_and_the_export_rebuilds_it_where_the_program_keeps_it(demo, monkeypatch):
    """A switch's jump table is the function's own .rodata, its words relocations into the function's code: the
    judge places them at the function's address (they were compared unrelocated: 99.9%, never a match), and the
    exported tree's build links the table where the program has it and rebuilds the program byte for byte. (Its
    functions one file each: the export writes no assembly here, so the file isn't whole with the 3 matched.)"""
    import subprocess
    import sys

    from decompnet.consoles.linux import export as linux_export

    monkeypatch.setattr(linux_export, "assembly_source", lambda *a: None)

    net, slug = _imported(demo, "export")
    assert _match(net, slug, "entity_default_hp")["matched"]
    assert _match(net, slug, "clamp_s32")["matched"]
    assert _match(net, slug, "abs_s32")["matched"]  # (straight-line code: the same bytes anywhere)
    res = net.export_rom(slug, log=lambda *_: None)
    assert res["identical"] and res["matched"] == 3, res["log"]
    out = Path(res["path"])
    assert "(3 of" in res["log"] and (out / "build" / "program").read_bytes() == demo[0].read_bytes()
    assert ".own0" in (out / "build" / "obj" / "entity_default_hp.ld").read_text()
    # the shared header without the app's note to its helpers, and once (not again as a file's with nothing more)
    headers = {p.name: p.read_text() for p in (out / "include").glob("*.h")}
    assert "edit_context" not in headers["common.h"]
    assert sum(text == headers["common.h"] for text in headers.values()) == 1, sorted(headers)

    # code before a function in its C (the file's other functions) can leave it at another offset modulo 16 in its
    # object than in the game: the judge relocates its bytes where they are, and so does the build (a loop's
    # .p2align 4 makes the object's .text 16-aligned, ld rounded it up, and a Linux game's export put a function 12
    # bytes off)
    [src] = (out / "src").glob("*/abs_s32.c")
    original = src.read_text()
    lines = original.splitlines(keepends=True)
    at = next(i for i, line in enumerate(lines) if "abs_s32" in line and "(" in line)
    src.write_text("".join(lines[:at]) + ('int sum_before(int *p, int n) { int s = 0; while (n--) s += *p++; return s; }\n'
                                       'int one_before(void) { return 1; }\n') + "".join(lines[at:]))
    ok = subprocess.run([sys.executable, "build.py", "check", "abs_s32"], cwd=out, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    src.write_text(original)

    # a function written in the tree is checked against the original; a wrong one is refused
    [src] = (out / "src").glob("*/clamp_s32.c")
    src.write_text(src.read_text().replace("return v;", "return v + 1;"))
    bad = subprocess.run([sys.executable, "build.py", "check", "clamp_s32"], cwd=out, capture_output=True, text=True)
    assert bad.returncode != 0 and "differs from the original" in bad.stderr


def test_a_global_matched_c_reads_by_its_address_is_named_and_still_matches(demo):
    """C that matched writing a global as its address (`*(u32 *)0x80...`) is given the global's name, judged, and
    kept: the export's tree then names what it reads, and can be relinked. Each C is tried once."""
    from decompnet import addresses
    from decompnet.forks import csource

    from .test_consoles import DEMO_GAME

    net, slug = _imported(demo, "addresses")
    proj = net.project_row(slug)
    at = net.symbols(proj["id"]).resolve("g_rng_state")
    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.claim(agent, slug, "rng_next")
    source = GAME_DEFINES + csource.get(DEMO_GAME.read_text(), "rng_next").replace("g_rng_state", f"*(u32 *)0x{at:x}")
    assert net.attempt(agent, "rng_next", source, slug)["matched"]
    assert net.readability.name_addresses(slug, log=lambda *_: None) == 1
    fn = net._function("rng_next", slug)
    assert addresses.numbers(fn["matched_source"]) == 0 and "g_rng_state" in fn["matched_source"]
    header = net._context(proj["id"], fn["unit"])["header"]
    assert net.readability._still_matches(proj, fn, header, fn["matched_source"])
    assert net.readability.name_addresses(slug, log=lambda *_: None) == 0


def test_a_matched_function_the_export_finds_broken_goes_back_to_the_agents(demo):
    """Matched C that no longer compiles (a header edit since, a rename that missed it) was kept as "matched" and
    written into every export as the program's bytes, with no way to send it back: the export opens it again, its C
    the next agent's start."""
    from decompnet.forks import csource

    from .test_consoles import DEMO_GAME

    net, slug = _imported(demo, "broken")
    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.claim(agent, slug, "rng_next")
    assert net.attempt(agent, "rng_next", GAME_DEFINES + csource.get(DEMO_GAME.read_text(), "rng_next"), slug)["matched"]
    fn = net._function("rng_next", slug)
    with net.store.tx() as db:  # (what a rename that missed it leaves)
        db.execute("UPDATE functions SET matched_source=? WHERE id=?",
                   (fn["matched_source"].replace("g_rng_state", "g_rng_gone"), fn["id"]))
    res = net.export_rom(slug, log=lambda *_: None)
    assert ("rng_next", "doesn't compile any more") in res["fallback"]
    again = net._function("rng_next", slug)
    assert again["status"] == "open" and "g_rng_gone" in again["best_source"]


def test_rom_modes_tidy_moves_what_matched_functions_declare_alike_into_the_header_and_they_still_match(demo):
    """The declarations each matched function made for itself go into the shared header once (tidy.py), every
    function judged again with it."""
    from decompnet.forks import csource

    from .test_consoles import DEMO_GAME

    net, slug = _imported(demo, "tidy")
    agent, _ = net.local_agent("claude-opus-5.5-1")
    for name in ("rng_next", "abs_s32"):
        net.claim(agent, slug, name)
        source = "extern int tidy_helper(int);\n" + GAME_DEFINES + csource.get(DEMO_GAME.read_text(), name)
        assert net.attempt(agent, name, source, slug)["matched"]
    res = net.readability.tidy_declarations(slug, log=lambda *_: None)
    assert res["moved"] >= 1
    proj = net.project_row(slug)
    assert "int tidy_helper(int);" in net._context(proj["id"])["header"]
    for name in ("rng_next", "abs_s32"):
        fn = net._function(name, slug)
        assert "tidy_helper" not in fn["matched_source"]
        assert net.readability._still_matches(proj, fn, net._context(proj["id"])["header"], fn["matched_source"])


def test_a_rename_judged_while_a_polish_saves_keeps_the_polish_and_its_function_is_repaired(demo):
    """A helper sent rename_symbol and make_readable together: the rename judged the C it had read, the polish was
    saved meanwhile, and the rename then wrote its old copy, renamed (or the polish wrote the old name over it): a
    Linux game's function defined its old name under its new one. The rename now renames the C as it is, a polish
    judged before a rename is sent again, and a function left so is renamed in its C at start."""
    from decompnet.forks import csource
    from decompnet.network import write_renamed

    from .test_consoles import DEMO_GAME

    net, slug = _imported(demo, "renamerace")
    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.claim(agent, slug, "rng_next")
    source = GAME_DEFINES + csource.get(DEMO_GAME.read_text(), "rng_next")
    assert net.attempt(agent, "rng_next", source, slug)["matched"]
    fn = net._function("rng_next", slug)
    polished = "/* the game's random numbers */\n" + fn["matched_source"]
    with net.store.tx() as db:
        db.execute("UPDATE functions SET matched_source=? WHERE id=?", (polished, fn["id"]))
        write_renamed(db, {fn["id"]: fn["matched_source"].replace("rng_next", "rng")}, {fn["id"]: fn["matched_source"]},
                      lambda text: text.replace("rng_next", "rng"))
    assert net.store.one("SELECT matched_source FROM functions WHERE id=?", fn["id"])["matched_source"] == \
        polished.replace("rng_next", "rng")

    # a polish judged before a rename committed isn't saved
    proj = net.project_row(slug)
    since = net.store.one("SELECT MAX(id) AS id FROM events WHERE project_id=?", proj["id"])["id"]
    with net.store.tx() as db:
        net._event(db, proj["id"], None, "rename", "abs_s32 → absolute")
    said = net.readability._readable(proj, fn, agent, "/* x */\n" + source, since)
    assert said.startswith("✋") and "/* x */" not in net._function("rng_next", slug)["matched_source"]

    # one left defining its old name: renamed in its C at start, as it still matches
    with net.store.tx() as db:
        db.execute("UPDATE functions SET matched_source=? WHERE id=?", (source, fn["id"]))
        db.execute("UPDATE functions SET name='rng_two' WHERE id=?", (fn["id"],))
        db.execute("UPDATE symbols SET name='rng_two' WHERE project_id=? AND name='rng_next'", (proj["id"],))
        net._event(db, proj["id"], None, "rename", "rng_next → rng_two")
    net._syms.pop(proj["id"], None)
    assert net.readability.repair_renamed(slug, log=lambda *_: None) == ["rng_two"]
    assert "rng_two(" in net._function("rng_two", slug)["matched_source"]


def test_a_function_built_with_fpic_gets_fpic_and_is_open_again_if_it_was_set_aside(demo):
    import json

    from decompnet import consoles

    net, slug = _imported(demo, "pic")
    proj = net.project_row(slug)
    fn = net._function("abs_s32", slug)
    pic = bytes.fromhex("5589e553e8000000005b81c300000000") + bytes(fn["target"])[16:]
    with net.store.tx() as db:
        db.execute("UPDATE functions SET target=?, status='asm', meta=? WHERE id=?",
                   (pic, json.dumps({"not_c": {"a": {}}, "asm_code": "PIC"}), fn["id"]))
    assert consoles.get("linux").add_pic(net, slug, log=lambda *_: None) == 1
    ranges = net.cfg(net.project_row(slug))["compiler_ranges"]
    assert ranges[0]["start"] == fn["vram"] and "-fPIC" in ranges[0]["flags"]
    again = net._function("abs_s32", slug)
    assert again["status"] == "open" and "not_c" not in json.loads(again["meta"])
    assert consoles.get("linux").add_pic(net, slug, log=lambda *_: None) == 0  # (once)
    assert "got" in net.cfg(net.project_row(slug))  # (the program's GOT, recorded at import)
    del proj


RELINK_ASM = """\
.text
.globl twice
.type twice,@function
twice:
    movl 4(%esp), %eax
    addl %eax, %eax
    ret
.size twice,.-twice
.globl answer
answer:
    movl $30, %eax
    ret
"""  # (answer: hand-written, no .type or .size, as a .s file's labels are: no function lists it)
RELINK_FUNCTIONS = {
    "length": "int length(const char *s) { int n = 0; while (s[n]) n++; return n; }\n",
    "say": "static int calls;\nvoid say(const char *s) { calls++; write(1, s, length(s)); }\n",
    "name_of": 'const char *name_of(int k) { switch (k) { case 0: return "zero\\n"; case 1: return "one\\n"; '
               'case 2: return "two\\n"; case 3: return "three\\n"; case 4: return "four\\n"; default: '
               'return "many\\n"; } }\n',
    "greet": "void greet(void) { say(greeting); }\n",  # (the header declares greeting)
    "count": "static int calls;\nint count(void) { return calls; }\n",
    "setup": "static int ready;\nvoid setup(void) __attribute__((constructor));\nvoid setup(void) { ready = twice(2); }\n",
    "bye": 'void bye(void) { write(1, "bye\\n", 4); }\n',
    "main": "static int ready;\nextern void (*table[])(void);\nextern int (*asked)(void);\nextern void *stdout;\n"
            "int main(void) { int i; atexit(bye); for (i = 0; i < 2; i++) table[i](); "
            "for (i = 0; i < 6; i++) say(name_of(i)); return count() + ready + asked() + (stdout ? 0 : 100); }\n",
}
RELINK_DECLARATIONS = ("int write(int, const void *, unsigned int);\nint twice(int);\nint length(const char *);\n"
                       "void say(const char *);\nconst char *name_of(int);\nvoid greet(void);\nint count(void);\n"
                       "int atexit(void (*)(void));\nvoid bye(void);\n")
RELINK_DATA = ('const char *greeting = "hello\\n";\n'  # (a pointer in .data to a string in .rodata)
               "void (*table[])(void) = { greet, greet };\n"  # (pointers in .data to functions)
               "extern int answer(void);\nint (*asked)(void) = answer;\n")  # (and to hand-written code)


@pytest.mark.parametrize("partial", ["", "in file", "bytes"], ids=["whole", "asm-in-file", "bytes"])
def test_the_export_relinks_a_new_program_from_the_c_and_a_function_and_the_data_may_move(tmp_path, partial,
                                                                                           monkeypatch):
    """The export's build links a new program from the C (build.py relink): its functions laid out anew, its data
    written as data/program.s with each pointer named (to functions, to its strings), each function's statics the
    program's own (two functions share one), a switch's jump table its own, its constructor list carried over (a C
    constructor, as a C++ program's globals are made), what isn't C assembled from asm/. It runs as the original
    does; with a function changed to do more (longer than it was), and with the data moved too (relink --move).
    Whole (every function matched): the hand-written code is assembly source, the data C, and the tree builds
    without the program; so it does with count not C yet, as assembly in its file. Where count's assembly can't
    be written ("bytes"), its file stays one file per function, count your copy's bytes (asm/) and the data
    data/program.s."""
    import json
    import subprocess
    import sys

    from decompnet import toolchains
    from decompnet.app.engine import RomNetwork
    from decompnet.compiler import compile_source, run_in
    from decompnet.project import compiler_config

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None or toolchains.installed("runtime-i386") is None:
        pytest.skip(f"needs {gcc} and its runtime")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    runtime = Path(toolchains.ensure("runtime-i386", log=lambda *_: None))
    begin = next(iter(sorted(tc.glob("gcc/usr/lib/**/crtbegin.o"))), None)
    if not (tc / "crt" / "crt1.o").exists() or begin is None:
        pytest.skip(f"{gcc} has no C runtime objects (an install before they were part of it)")
    build = tmp_path / "build"
    build.mkdir()
    cfg = compiler_config(build, {"compiler": {"toolchain": gcc, "flags": ["-O2", "-g"]}})
    program_c = ("static int calls, ready;\n" + RELINK_DECLARATIONS + "extern void (*table[])(void);\n"
                 + "extern int (*asked)(void);\nextern void *stdout;\n"
                 + "".join(v.replace("static int calls;\n", "").replace("static int ready;\n", "")
                           .replace("extern const char *greeting;\n", "").replace("extern void (*table[])(void);\n", "")
                           .replace("extern int (*asked)(void);\n", "").replace("extern void *stdout;\n", "")
                           for v in RELINK_FUNCTIONS.values()) + RELINK_DATA)
    res = compile_source(cfg, "", "extern const char *greeting;\n" + program_c)
    assert res.ok, res.log
    (build / "prog.o").write_bytes(res.obj)
    (build / "twice.s").write_text(RELINK_ASM)
    tool = f'LD_LIBRARY_PATH="{tc}/binutils/usr/lib${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}" "{tc}/binutils/usr/bin/'
    crt = tc / "crt"
    linked = run_in(cfg, build, ["/bin/sh", "-c", f'{tool}as" -o twice.o twice.s && {tool}ld" -m elf_i386 '
                                 f'-dynamic-linker /lib/ld-linux.so.2 -o relinkdemo {crt}/crt1.o {crt}/crti.o {begin} '
                                 f'prog.o twice.o {crt}/libc_nonshared.a {runtime}/libc.so.6 '
                                 f'{begin.with_name("crtend.o")} {crt}/crtn.o'])  # (atexit: libc_nonshared.a's, -fPIC)
    assert linked.returncode == 0, linked.stderr
    program = build / "relinkdemo"
    program.chmod(0o755)

    def run(path: Path) -> subprocess.CompletedProcess:
        return subprocess.run([str(runtime / "ld-linux.so.2"), "--library-path", str(runtime), str(path)],
                              capture_output=True, timeout=30)
    original = run(program)
    assert original.stdout == b"hello\nhello\nzero\none\ntwo\nthree\nfour\nmany\nbye\n" and original.returncode == 42

    work = tmp_path / "home"
    work.mkdir()
    net = RomNetwork(work / "app.db", work)
    slug = net.import_rom(program, confirmed=True, log=lambda *_: None)
    agent, _ = net.local_agent("claude-opus-5.5-1")
    for name, source in RELINK_FUNCTIONS.items():
        if partial and name == "count":
            continue
        net.claim(agent, slug, name)
        result = net.attempt(agent, name, RELINK_DECLARATIONS + source, slug)
        assert result["matched"], (name, result["text"])
    if not partial:  # glibc's atexit as an agent matched it: __dso_handle not said weak, which the program left undefined
        net.claim(agent, slug, "atexit")
        result = net.attempt(agent, "atexit", "extern void *__dso_handle;\nextern int __cxa_atexit(void (*)(), void *, "
                             "void *);\nint atexit(void (*func)()) { return __cxa_atexit(func, 0, &__dso_handle ? "
                             "__dso_handle : 0); }\n", slug)
        assert result["matched"], result["text"]
    if partial == "bytes":
        from decompnet.consoles.linux import export as linux_export

        written = linux_export.assembly_source
        monkeypatch.setattr(linux_export, "assembly_source", lambda name, *a: None if name == "count" else written(name, *a))
    res = net.export_rom(slug, log=lambda *_: None)
    assert res["identical"] and res["relinked"], res["log"]
    out = Path(res["path"])
    relinked = out / "build" / "relinkdemo"
    assert (run(relinked).stdout, run(relinked).returncode) == (original.stdout, original.returncode)
    if partial == "in file":
        [program_file] = (out / "src").glob("*.c")
        assert "count isn't C yet" in program_file.read_text() and json.loads((out / "build.json").read_text())["standalone"]
        assert res["units"] == 1 and res["data"] == 1 and res["matched"] == 7
        return
    if partial:
        _partial_tree(out, res, run, original, tc, tmp_path)
        return
    # its source file is one C file again: the functions in their order, the static two share once, each function
    # declared as defined in the file's header, its constructor still one; built whole, it's the original's code
    assert res["units"] == 1, res["unit_fallback"]
    [program_file] = (out / "src").glob("*.c")
    whole = program_file.read_text()
    assert whole.count("static int calls;") == 1 and whole.index("int length(") < whole.index("int main(")
    assert "__attribute__((constructor))" in whole and [p.name for p in (out / "src").glob("*/*.c")] == ["atexit.c"]
    # (its header, what the rest of the program reads of it, as common.h declared it; no copy of common.h left)
    assert "void say(const char *);" in (out / "include" / f"{program_file.stem}.h").read_text()
    assert sorted(p.name for p in (out / "include").iterdir()) == ["common.h", f"{program_file.stem}.h"]
    # the hand-written code as assembly source a person reads, checked to assemble to the program's bytes
    assert "addl %eax, %eax" in (out / "src" / "asm" / "twice.s").read_text() and (out / "src" / "asm" / "answer.s").exists()
    assert not (out / "asm").exists() and (out / "Makefile").exists()
    assert not (out / "build" / "relink" / "atexit.o").exists()  # (libc_nonshared.a's: never its bytes)
    assert not (out / "src" / "asm" / "atexit.s").exists() and not (out / "src" / "asm" / "_start.s").exists()
    built = (out / "build" / "relinkdemo").read_bytes()
    assert b"stdout" in built  # (copied, as the original's: an import, not a global of its own)
    assert "tools/*/" in (out / ".gitignore").read_text()  # (the compiler make downloads stays out of git)
    # its data is C too: each global with its type and the program's value, a pointer by what it points at (a
    # string, functions, hand-written code); nothing is your copy's any more
    assert res["data"] == 1, res["data_fallback"]
    assert 'char *greeting = "hello\\n";' in whole and "greet, " in whole and "answer;" in whole
    assert "__asm__(\"asked\")" not in whole  # (main's `int (*asked)(void)` is the definition's type: no alias)
    assert json.loads((out / "build.json").read_text())["standalone"] and not (out / "data").exists()

    # the same C built by the system's GCC (`make port`, against the program's own C library headers), linked the
    # same way: a newer GCC's merged strings and .init_array (the constructor) as the 2001 linker and runtime take
    # them, and what it calls that the program never imported in the port's own stubs
    import shutil as _shutil

    probe = tmp_path / "m32.c"
    probe.write_text("#include <stdio.h>\nint main(void) { puts(\"x\"); return 0; }\n")
    gcc = _shutil.which("gcc")
    m32 = gcc and subprocess.run([gcc, "-m32", "-nostdinc", "-isystem", subprocess.run(
        [gcc, "-print-file-name=include"], capture_output=True, text=True).stdout.strip(), f"-I{tc}/include", "-c",
        str(probe), "-o", str(tmp_path / "m32.o")], capture_output=True).returncode == 0
    if m32:
        port = subprocess.run(["make", "-s", f"TC={tc}", f"PY={sys.executable}", "port"], cwd=out, capture_output=True,
                              text=True)
        assert port.returncode == 0, port.stdout + port.stderr
        ported = run(out / "build" / "port" / "relinkdemo")
        assert (ported.stdout, ported.returncode) == (original.stdout, original.returncode)

    # the data moves too: its pointers follow it, and so do the statics the C reads as the program's
    moved = subprocess.run([sys.executable, "build.py", "relink", "--move"], cwd=out, capture_output=True, text=True)
    assert moved.returncode == 0, moved.stderr
    assert (run(relinked).stdout, run(relinked).returncode) == (original.stdout, original.returncode)

    # a fresh checkout, without your copy of the program and without the compiler yet: one `make` downloads it
    # (here the download is a copy of decompdecomp's), writes the rules (they depend on its libc_nonshared.a) and
    # builds the program from the tree alone. A real clone of the tree as committed, so what .gitignore keeps out
    # is missing there too (src/asm/ was, under an unanchored `asm/`)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"]
    subprocess.run(git + ["init", "-q"], cwd=out, check=True)
    subprocess.run(git + ["add", "-A"], cwd=out, check=True)
    subprocess.run(git + ["commit", "-qm", "tree"], cwd=out, check=True)
    tracked = subprocess.run(["git", "ls-files"], cwd=out, capture_output=True, text=True).stdout.split()
    assert "src/asm/twice.s" in tracked and not any(t.startswith(("baserom", "build/")) for t in tracked)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(out), str(clone)], check=True)
    fresh = tmp_path / "fresh-tc"
    (clone / "tools" / "toolchain.sh").write_text(f'#!/bin/sh\nmkdir -p "$1" && cp -a {tc}/. "$1"/\n')
    first = subprocess.run(["make", "-s", f"TC={fresh}", f"PY={sys.executable}", "match"], cwd=clone,
                           capture_output=True, text=True)
    assert first.returncode == 0, first.stdout + first.stderr
    assert "from this tree alone" in first.stdout and (fresh / "crt" / "crt1.o").exists()
    cloned = clone / relinked.relative_to(out)
    assert (run(cloned).stdout, run(cloned).returncode) == (original.stdout, original.returncode)
    # and `make`, the plain build: the system's gcc and libraries, nothing of decompdecomp's (where it links 32-bit)
    makefile = (clone / "Makefile").read_text()
    assert "all: build/plain/$(PROGRAM)" in makefile and "-DNON_MATCHING" in makefile
    linkable = gcc and subprocess.run([gcc, "-m32", str(probe), "-o", str(tmp_path / "m32")],
                                      capture_output=True).returncode == 0
    if linkable:
        plain = subprocess.run(["make", "-s"], cwd=clone, capture_output=True, text=True)
        assert plain.returncode == 0, plain.stdout + plain.stderr
        if Path("/lib/ld-linux.so.2").exists():
            ran = subprocess.run([str(clone / "build" / "plain" / "relinkdemo")], capture_output=True, timeout=30)
            assert (ran.stdout, ran.returncode) == (original.stdout, original.returncode)

    # C that writes an address in the old code as a number is refused, with the name to write
    greet_c = program_file
    kept = greet_c.read_text()
    greet_at = next(f["vram"] for f in json.loads((out / "build.json").read_text())["functions"] if f["name"] == "greet")
    greet_c.write_text(kept + f"void *where(void) {{ return (void *)0x{greet_at:x}; }}\n")
    refused = subprocess.run([sys.executable, "build.py", "relink"], cwd=out, capture_output=True, text=True)
    assert refused.returncode != 0 and "that's greet" in refused.stderr + refused.stdout
    greet_c.write_text(kept)

    # C that writes a variable's address as a number (as matched C does where no name matches): the relinked program
    # has the variable elsewhere, and the number follows it there (count() returns calls, which the exit code adds)
    calls_at = next(a for unit in json.loads((out / "build.json").read_text())["units"]
                    for n, a, _, _ in unit["data"]["variables"] if n == "calls")
    program_file.write_text(kept.replace("int count(void) { return calls; }",
                                         f"int count(void) {{ return *(int *)0x{calls_at:x}; }}"))
    numbered = subprocess.run([sys.executable, "build.py", "relink"], cwd=out, capture_output=True, text=True)
    assert numbered.returncode == 0 and "follow their variables" in numbered.stdout, numbered.stdout + numbered.stderr
    assert (run(relinked).stdout, run(relinked).returncode) == (original.stdout, original.returncode)
    if m32:  # (the port's copy writes it by name: a newer GCC folds numbers and drops statics only they read)
        port = subprocess.run(["make", "-s", f"TC={tc}", f"PY={sys.executable}", "port"], cwd=out, capture_output=True,
                              text=True)
        assert port.returncode == 0, port.stdout + port.stderr
        copy = next((out / "build" / "port").glob("*.o.c")).parent / f"{'file-' if not partial else ''}{program_file.stem}.o.c"
        assert f"0x{calls_at:x}" not in copy.read_text() and "calls" in copy.read_text().split("int count(void)")[1]
        ported = run(out / "build" / "port" / "relinkdemo")
        assert (ported.stdout, ported.returncode) == (original.stdout, original.returncode)
    program_file.write_text(kept)

    # a mod: say() does more, and is longer than the original's
    say = program_file
    say.write_text(say.read_text().replace("write(1, s, length(s));", 'write(1, "> ", 2); write(1, s, length(s));'))
    again = subprocess.run([sys.executable, "build.py", "relink", "--move"], cwd=out, capture_output=True, text=True)
    assert again.returncode == 0, again.stderr
    modded = run(relinked)
    assert modded.stdout.startswith(b"> hello\n> hello\n> zero\n") and modded.returncode == 42


def _partial_tree(out: Path, res: dict, run, original, tc: Path, tmp_path: Path) -> None:
    """The export with count not C yet: its file one file per function, count your copy's bytes in asm/, the data
    data/program.s (every global labelled, a pointer by name); a fresh checkout makes them again from baserom."""
    import shutil
    import subprocess
    import sys

    assert res["units"] == 0 and not json.loads((out / "build.json").read_text())["standalone"]
    assert list((out / "src").glob("*/greet.c")) and (out / "asm" / "count.s").exists()
    data = (out / "data" / "program.s").read_text()
    assert "greeting:" in data and ".long greet" in data and ".long __orig_rodata+" in data
    assert ".section .ctors" not in data  # (setup's C makes its own entry: not twice)
    relinked = out / "build" / "relinkdemo"
    moved = subprocess.run([sys.executable, "build.py", "relink", "--move"], cwd=out, capture_output=True, text=True)
    assert moved.returncode == 0, moved.stderr
    assert (run(relinked).stdout, run(relinked).returncode) == (original.stdout, original.returncode)
    for gone in ("build", "asm", "data"):
        shutil.rmtree(out / gone)
    fresh = tmp_path / "fresh-tc"
    (out / "tools" / "toolchain.sh").write_text(f'#!/bin/sh\nmkdir -p "$1" && cp -a {tc}/. "$1"/\n')
    first = subprocess.run(["make", "-s", f"TC={fresh}", f"PY={sys.executable}"], cwd=out, capture_output=True, text=True)
    assert first.returncode == 0, first.stdout + first.stderr
    assert (out / "asm" / "count.s").exists() and (out / "data" / "program.s").exists()
    assert (run(relinked).stdout, run(relinked).returncode) == (original.stdout, original.returncode)


def test_ghidras_draft_is_made_c_that_compiles_after_the_programs_header():
    """Ghidra's types where the program's header doesn't have them, its names for addresses as the project's, a part
    of a variable read through a pointer of its size; a draft that reads a register no C names is none."""
    from decompnet.consoles.linux import drafts

    draft = ("/* WARNING: x */\nundefined4 f(undefined2 param_1)\n\n{\n  uint uVar1;\n  if (g_player._32_2_ < 1) {\n"
             "    DAT_0804a010 = FUN_08048a20(param_1);\n  }\n  return uVar1;\n}\n")
    made = drafts.compilable(draft, "f", "typedef unsigned int uint;\n")
    assert "typedef unsigned short undefined2;" in made and "typedef unsigned int uint;" not in made
    assert "(*(undefined2 *)((char *)&g_player + 32))" in made
    assert "D_0804A010 = func_08048A20(param_1);" in made
    assert "extern undefined4 D_0804A010;" in made and "int func_08048A20();" in made
    assert "undefined4 f(undefined2 param_1)\n{" in made
    assert drafts.compilable(draft.replace("param_1);", "in_EAX);"), "f", "") is None
    assert drafts.compilable(draft.replace("g_player", "in_count"), "f", "") is not None  # (a variable named in_...)

    # a file's static the header doesn't declare (only a struct's field of that name) is declared by its size
    static = "int g(void)\n\n{\n  return (*(undefined4 *)((char *)&timer + 8)) + _DAT_080a9ee8 + (int)lv;\n}\n"
    made = drafts.compilable(static, "g", "struct clock {\n    int timer;\n};\n", {"timer": 1932, "lv": 8})
    assert "extern undefined1 timer[1932];" in made and "extern undefined8 lv;" in made
    assert "D_080A9EE8" in made and "_DAT_" not in made
    assert "extern" not in drafts.compilable(static, "g", "extern int timer[483];\nextern long long lv;\n"
                                             "extern int D_080A9EE8;\n", {"timer": 1932, "lv": 8})


def test_autopilot_matches_functions_from_ghidras_drafts(demo):
    """m2c reads no x86: a Linux program's drafts are Ghidra's, of the whole program at once, and autopilot judges
    them made into C that compiles (on the demo: 25 of its 96 functions)."""
    from decompnet.forks import ghidra

    if not ghidra.available():
        pytest.skip("needs Ghidra")
    import time

    net, slug = _imported(demo, "drafts")
    proj = net._project(slug)
    assert net.can_draft(proj)
    for fid in net.stale_drafts(proj):
        net._seed_for(net.store.one("SELECT * FROM functions WHERE id=?", fid), proj, wait=True)
    # the app's own way in (Autopilot on the project page, and after an import): it ran only the twins before, as if
    # no drafts existed ("m2c can't read this project's code")
    state = net.start_autopilot(slug)
    deadline = time.time() + 600
    while state["state"] == "running" and time.time() < deadline:
        time.sleep(0.5)
    assert not state["no_drafts"], state["no_drafts"]
    assert state["matched"] - state["twins"] >= 20, state
    brief = net.claim(net.local_agent("claude-opus-5.5-1")[0], slug, "entity_update_physics")
    assert "### Machine draft (Ghidra)" in brief or "### Best attempt so far" in brief
    fn = net._function("entity_update_physics", slug)
    assert fn["seed"].startswith("/* machine-generated by Ghidra")


def test_read_data_shows_doubles_where_the_bytes_are_doubles():
    """A Linux game's constants are doubles (`fld qword`): read_data showed them only as floats (100.0 read as 0 and
    3.39), and a helper stopped to decode them with a command its CLI ended the session for. Doubles are shown where
    the bytes make no sense as floats, and not for a run of real floats."""
    from decompnet import arch

    doubles = struct.pack("<3d", 100.0, 1 / 6, 6.0)
    assert "as f64 (double), each 8 bytes: 100, 0.166667, 6" in arch.float_lines(doubles, False)
    assert arch.float_lines(struct.pack("<4f", 1, 2, 3, 4), False) == ["as f32: 1, 2, 3, 4"]
    assert "as f64 (double), each 8 bytes: 0.1" in arch.float_lines(struct.pack(">d", 0.1), True)  # (a round one, -2.5, is two floats too)


def test_the_c_may_include_glibcs_headers_and_their_inline_asm(demo, tmp_path):
    """A Linux game's port I/O (`out dx, al`) was <sys/io.h>'s outb(): agents found every C rejected ("system
    includes are not allowed") and set the function aside. The pinned GCC's own glibc headers build it."""
    from decompnet.compiler import compile_source
    from decompnet.project import compiler_config

    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": "gcc-2.95.3-linux", "flags": ["-O2"]}})
    res = compile_source(cfg, "", "#include <sys/io.h>\nvoid put(unsigned char v, int port) { outb(v, port); }\n")
    assert res.ok, res.log
    from io import BytesIO

    from elftools.elf.elffile import ELFFile

    assert b"\xee" in ELFFile(BytesIO(res.obj)).get_section_by_name(".text").data()  # out dx, al
    assert "inline assembly" in compile_source(cfg, "", 'void f(void) { __asm__("rdtsc"); }\n').log


def test_an_applied_range_judges_its_open_functions_again(demo):
    """On a Linux game two functions whose C matched with a suggested range's flags stayed open after the user
    applied it: nothing judged them again. Applying a range judges its open functions' best C."""
    net, slug = _imported(demo, "range")
    fn = net._function("clamp_s32", slug)
    span = [[fn["vram"], fn["vram"] + fn["size"]]]
    tc = net.cfg(net._project(slug))["compiler"]["toolchain"]
    net.set_compiler_ranges(slug, span, tc, ["-O0"])
    assert not _match(net, slug, "clamp_s32")["matched"]  # (its C, judged with the wrong flags)
    net.set_compiler_ranges(slug, span, tc, ["-O2"])
    fn = net._function("clamp_s32", slug)
    assert fn["status"] == "matched" and fn["matched_agent_id"] == net.local_agent("claude-opus-5.5-1")[0].id


def test_a_compiler_change_judges_the_open_functions_attempts_again(demo):
    """A Linux game's flags were wrong for three hours: when they were right again, a function with an attempt that
    matched with them stayed open, its best the attempt closest with the wrong flags, and agents gave up on it."""
    net, slug = _imported(demo, "rejudge")
    tc = net.cfg(net._project(slug))["compiler"]["toolchain"]
    net.set_compiler(slug, tc, ["-O0"])
    assert not _match(net, slug, "clamp_s32")["matched"]  # (the right C, judged with the wrong flags)
    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.attempt(agent, "clamp_s32", "int clamp_s32(int v, int lo, int hi) { return v; }", slug)  # (and a wrong one)
    net.set_compiler(slug, tc, ["-O2"])
    fn = net._function("clamp_s32", slug)
    assert fn["status"] == "matched" and fn["matched_agent_id"] == agent.id


LAYOUT_C = """extern int g(int *);
int f(int x, int *p, int *q) {
  int i;
  if (x) { p[1] = 0; p[2] = 0; }
  else {
    p[8] = x + 0; p[9] = x + 1; p[10] = x + 2; p[11] = x + 3;
    for (i = 0; i < p[0]; i++) p[i] += q[i];
    p[40] = 0; p[41] = 1; p[42] = 2; p[43] = 3; p[44] = 4; p[45] = 5;
    for (i = 0; i < p[3]; i++) q[i] -= p[i];
  }
  return g(p);
}"""


def test_a_jump_its_file_made_long_matches_where_the_code_before_it_grew():
    """A Linux game's 188-instruction function, every instruction right, missed by one jmp: the game's is 5 bytes
    though 2 reach, because gas assembled its whole file, whose earlier jumps grew while it relaxed them and widened
    the loop padding the jmp jumps over on the way. A narrow miss is tried again after code that grows."""
    import json
    from types import SimpleNamespace

    from decompnet.compiler import compile_source
    from decompnet.elfobj import extract_function
    from decompnet.network import Network
    from decompnet.project import compiler_config

    from .test_consoles import _missing

    if (missing := _missing(consoles.get("linux"))):
        pytest.skip(f"needs {', '.join(missing)}")
    config = compiler_config(Path("."), {"compiler": {"toolchain": "gcc-2.95.3-linux", "flags": ["-O2"]}})
    fn = {"name": "f", "vram": 0x8048100}
    proj = {"config": json.dumps({"platform": "linux"})}
    code = lambda prelude: extract_function(compile_source(Network._placed(config, proj, fn, prelude), "",  # noqa: E731
                                                           LAYOUT_C, trusted=True).obj, "f")
    plain = code(None)
    layout, grown = next((lay, c) for lay in x86_link.layouts(fn["vram"]) if (c := code(lay)).code != plain.code)
    assert b"\xe9" in grown.code and b"\xe9" not in plain.code  # (the long jmp)

    def judged(game):
        net = SimpleNamespace(_placed=Network._placed, NEAR_PERCENT=Network.NEAR_PERCENT,
                              _target_obj=lambda fn, proj: game,
                              _evaluate=lambda fn, proj, obj: (c := extract_function(obj, "f"), c.code == game.code, []))
        net._judged_exact = lambda *a, **k: Network._judged_exact(net, *a, **k)
        return Network._compile_placed(net, config, proj, fn, "", LAYOUT_C)

    res = judged(grown)  # (the game's function: the jump long)
    assert extract_function(res.obj, "f").code == grown.code and res.layout == layout
    res = judged(plain)
    assert extract_function(res.obj, "f").code == plain.code and res.layout == ""


# ---------------------------------------------------------------------------------------------- GCC 4.3.2 and DWARF

GCC43 = "gcc-4.3.2-linux"


def test_the_gcc_the_programs_comment_names_builds_it_whoever_built_that_gcc():
    """A program's .comment names its GCC as its distribution built it: Debian's, Ubuntu's or GCC's own release.
    The version picks the compiler (an exact match of the string took only Debian's); one none is falls back."""
    linux = consoles.get("linux")
    for said in ("GCC: (Debian 4.3.2-1.1) 4.3.2", "GCC: (Ubuntu 4.3.2-1ubuntu12) 4.3.2", "GCC: (GNU) 4.3.2"):
        assert linux.default_compiler({"compiler_guess": said}, "") == GCC43
    # Red Hat's build, Fedora 10's: its own (Red Hat patches its GCC its own way)
    for said in ("GCC: (GNU) 4.3.2 20081105 (Red Hat 4.3.2-7)", "GCC: (GNU) 4.3.2 20081105 (Red Hat 4.3.2-8)"):
        assert linux.default_compiler({"compiler_guess": said}, "") == "gcc-4.3.2-redhat-linux"
    assert linux.default_compiler({"compiler_guess": "GCC: (GNU) 2.95.3 20010315 (release)"}, "") == "gcc-2.95.3-linux"
    info = {"compiler_guess": "GCC: (GNU) 3.3.6"}
    assert linux.default_compiler(info, "") == "gcc-2.95.3-linux"
    assert "'GCC: (GNU) 3.3.6'" in info["compiler_why"]  # (the import says it has none of that one)
    assert linux.default_compiler({}, "") == "gcc-2.95.3-linux"
    # egcs 1.1.2, as Slackware 7.0 and Red Hat 6 built it: a 1999 program's sound server was matched with GCC 2.95.3
    # for weeks, its agents taking egcs's `leal 0(,%reg,2)` for "a different 2.95.3 build"
    info = {"compiler_guess": "GCC: (GNU) egcs-2.91.66 19990314/Linux (egcs-1.1.2 release)"}
    assert linux.default_compiler(info, "") == "egcs-1.1.2-linux" and "compiler_why" not in info


def test_egcs_writes_what_gcc_2_95_never_does():
    """egcs 1.1.2's `x * 2` into another register is `leal 0(,%reg,2)` (7 bytes), which GCC 2.95.3 always writes as
    `leal (%reg,%reg)` or `addl`: the instruction an egcs program's functions have, and no C gives 2.95.3."""
    from decompnet import compiler, toolchains
    from decompnet.project import compiler_config

    if toolchains.installed("egcs-1.1.2-linux") is None:
        pytest.skip("needs egcs-1.1.2-linux")
    for toolchain, lea in (("egcs-1.1.2-linux", True), ("gcc-2.95.3-linux", False)):
        if toolchains.installed(toolchain) is None:
            continue
        cfg = compiler_config(Path("."), {"compiler": {"toolchain": toolchain, "flags": ["-O2"], "timeout": 60}})
        res = compiler.compile_source(cfg, "", "int g(int);\nint k(int c)\n{\n    return g(c * 2);\n}\n",
                                      trusted=True)
        assert res.ok, res.log
        assert (b"\x8d\x04\x55\x00\x00\x00\x00" in res.obj) == lea, toolchain  # (leal 0(,%edx,2),%eax)


@pytest.fixture(scope="module")
def demo43(tmp_path_factory):
    """Demo Quest built -g (DWARF) with Debian 5.0's GCC 4.3.2 (projects/demo-linux/build.py gcc-4.3.2-linux)."""
    import json
    import subprocess
    import sys

    from decompnet import toolchains

    from .test_consoles import ROOT, ZLIB

    if toolchains.installed(GCC43) is None or not ZLIB.exists():
        pytest.skip(f"needs {GCC43} and zlib (projects/zlib-n64/prepare.py)")
    folder = ROOT / "projects" / "demo-linux"
    build = folder / f"build-{GCC43}"
    if not (build / "demo.json").exists():
        subprocess.run([sys.executable, str(folder / "build.py"), GCC43], check=True)
    return build / json.loads((build / "demo.json").read_text())["game"], tmp_path_factory


def test_a_programs_dwarf_gives_its_header_prototypes_and_locals(demo43):
    """GCC 4.3 writes DWARF with -g, not STABS: its import read only the symbol table, and agents saw no types. The
    DWARF reader gives the same as STABS do: the structs and enums, each function's prototype (a function GCC also
    inlined has its name and parameters in the abstract entry its copy points to), where its parameters and locals
    live, and the line it starts on."""
    info = debuginfo.read(demo43[0].read_bytes(), set())
    assert not info.unread and "game.c" in info.sources
    assert "struct Entity { /* 0x1C bytes */" in info.header and "s32 hp; /* 0x18 */" in info.header
    assert "ENTITY_DRAGON = 4," in info.header
    by_name = {f["prototype"].split("(")[0].split()[-1].lstrip("*"): f for f in info.functions.values()}
    assert by_name["abs_s32"]["prototype"] == "s32 abs_s32(s32 v)"  # (inlined too: its abstract entry's)
    assert by_name["entity_spawn"]["prototype"] == "Entity *entity_spawn(s16 type, s32 x, s32 y)"
    assert "x in the stack, frame offset +0xc" in by_name["entity_spawn"]["params"]
    assert by_name["checksum_save"]["locals"] == ["u32 sum (ebx)", "s32 i (ecx)"]
    assert by_name["lerp"]["line"] > 0 and by_name["lerp"]["source"] == "game.c"


def test_a_program_gcc_4_3_built_matches_from_its_c_and_rebuilds(demo43):
    """Demo Quest as a program of 2008: the import takes GCC 4.3.2 by the .comment and the header from DWARF, every
    function of the game matches from its own C (the #defines no debug information keeps given, and for the three
    that inline the functions before them in the file, those functions in the C too, as the game's file had them),
    and the rebuildable export makes the program again byte for byte (a C file's other functions and globals are
    linked at the program's addresses, as the judge links them)."""
    from decompnet.app.engine import RomNetwork
    from decompnet.forks import csource

    from .test_consoles import DEMO_GAME

    program, factory = demo43
    work = factory.mktemp("gcc43")
    net = RomNetwork(work / "app.db", work)
    slug = net.import_rom(program, confirmed=True, log=lambda *_: None)
    assert net.cfg(net._project(slug))["compiler"]["toolchain"] == GCC43
    game = DEMO_GAME.read_text()
    defines = "".join(f"{line}\n" for line in (DEMO_GAME.parent / "game.h").read_text().splitlines()
                      if line.startswith("#define"))
    agent, _ = net.local_agent("claude-opus-5.5-1")
    names = ("abs_s32", "rng_next", "lerp", "add_score", "count_alive_entities", "clamp_s32", "player_take_damage",
             "entity_update_physics", "checksum_save", "entity_default_hp", "entity_collides", "entity_spawn",
             "game_tick")
    for name in names:
        src = csource.get(game, name)
        if name in ("entity_collides", "entity_spawn", "game_tick"):  # (GCC 4.3 inlines what the file has before)
            before = game[:game.index(src.strip().splitlines()[0])]
            src = re.sub(r"#include [^\n]*\n", "", before) + src
        net.claim(agent, slug, name)
        out = net.attempt(agent, name, defines + src, slug)
        assert out["matched"], (name, out["text"][:600])
    res = net.export_rom(slug, log=lambda *_: None)
    assert res["identical"] and res["matched"] == len(names), res["log"][-2000:]


REDHAT = "gcc-4.3.2-redhat-linux"
CPP_PROGRAM = """
namespace Engine { class Mesh { public: Mesh(); int count; }; Mesh::Mesh() { count = 0; } }
typedef unsigned char data_t;
union Cell { int i; float f; };
typedef int read_fn(void *, int);
struct Callbacks { read_fn *read; };
class Story {
public:
    Story();
    ~Story();
    int Get() const;
    void Copy(const Story &other, Engine::Mesh *mesh);
    static Story *Make(int seed);
    int value;
    Callbacks cb;
    data_t flags;
};
Story::Story() { value = 7; }
Story::~Story() { value = 0; }
int Story::Get() const { return value; }
void Story::Copy(const Story &other, Engine::Mesh *mesh) { value = other.value + mesh->count; }
Story *Story::Make(int seed) { Story *s = new Story; s->value = seed; return s; }
union data_u { int x; };
"""


def test_a_cpp_programs_dwarf_declares_its_classes_methods_for_cpp_and_still_compiles_as_c(tmp_path):
    """A C++ program of 2008 with DWARF: its header compiled as neither C nor C++ (types declared in namespaces and
    classes, a GCC 4.3 typedef inside a method's declaration, typedefs named like another type's tag), and no
    method could be defined against it. Now every named type is read wherever it's declared, a class's methods are
    declared for C++ only (not C++'s implicit ones, not a namespace's class or a template's: their symbols say what
    the flat header can't), references stay references, and C++ names are qualified. A constructor defined against
    the header gets the program's own symbol."""
    from elftools.elf.elffile import ELFFile

    from decompnet import toolchains
    from decompnet.compiler import compile_source
    from decompnet.consoles.ps2 import cheader, dwarf2
    from decompnet.project import compiler_config

    if toolchains.installed(REDHAT) is None:
        pytest.skip(f"needs {REDHAT}")
    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": REDHAT, "flags": ["-O2", "-g"]}})
    built = compile_source(cfg, "", CPP_PROGRAM.replace("namespace Engine", "class Dummy; namespace Engine"))
    assert built.ok and built.language == "c++", built.log
    sources = dwarf2.read(ELFFile(__import__("io").BytesIO(built.obj)))
    functions = {f.name: f for s in sources for f in s.functions}
    assert {"Story::Story", "Story::Get", "Story::Copy", "Engine::Mesh::Mesh"} <= set(functions)
    assert [p.name for p in functions["Story::Copy"].params] == ["other", "mesh"]  # (not `this`)
    header = cheader.Header(sources).text()
    assert "#ifdef __cplusplus" in header and "    Story();" in header and "    ~Story();" in header
    assert "int Get() const;" in header and "void Copy(const struct Story &, struct Mesh *);" in header
    assert "static struct Story *Make(int);" in header  # (GCC names no parameter of a declaration)
    assert "Mesh();" not in header  # (Engine::Mesh: a method defined from the flat header would miss Engine::)
    assert "read_fn *read;" in header
    # glibc's __io_read_fn, a typedef the header leaves out (reserved): the pointer keeps its parentheses
    from decompnet.consoles.ps2.stabs import Type

    fn = Type(kind="function", target=Type(kind="base", name="int", size=4))
    loose = Type(kind="pointer", target=Type(kind="alias", typedef="__io_read_fn", target=fn), size=4)
    assert cheader.Header([]).declaration(loose, "read") == "int (*read)()"
    for language, source in (("c", "int plain(int x) { return x + 1; }\n"),
                             ("c++", "Story::Story() { value = 7; }\n")):
        res = compile_source(compiler_config(tmp_path, {"compiler": {"toolchain": REDHAT, "flags": ["-O2"]}}),
                             header, source)
        assert res.ok and res.language == language, res.log[-2000:]
    names = {s.name for s in ELFFile(__import__("io").BytesIO(res.obj)).get_section_by_name(".symtab").iter_symbols()}
    assert "_ZN5StoryC1Ev" in names


def test_a_cpp_programs_names_are_written_as_cpp_by_its_own_binutils(tmp_path):
    """A C++ program's function list showed its symbols (_ZN14CRandStoryDataC1Ev): the Linux console names each as
    written, by the c++filt of the project's own binutils."""
    from decompnet import toolchains

    if toolchains.installed(REDHAT) is None:
        pytest.skip(f"needs {REDHAT}")
    names = consoles.get("linux").demangle(["_ZN14CRandStoryDataC1Ev", "_ZNK14CRandStoryData3GetEv", "main"], REDHAT)
    assert names == {"_ZN14CRandStoryDataC1Ev": "CRandStoryData::CRandStoryData()",
                     "_ZNK14CRandStoryData3GetEv": "CRandStoryData::Get() const"}


def test_a_librarys_include_folders_are_where_its_users_include_from(tmp_path):
    """boost's headers are included as <boost/...> from its top folder, Ogre's from OgreMain/include, Lua's from
    src/, TinyXML's from its own top: each library's folders in the project's libs/, relative to the project."""
    from decompnet.app.engine import libraries

    for path in ("libs/boost_1_36_0/boost/shared_ptr.hpp", "libs/ogre/OgreMain/include/Ogre.h",
                 "libs/ogre/OgreMain/src/OgreRoot.cpp", "libs/lua-5.1.4/src/lua.h", "libs/lua-5.1.4/src/lapi.c",
                 "libs/tinyxml/tinyxml.h", "libs/tinyxml/tinyxml.cpp", "libs/ois/includes/OIS.h"):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text("")
    for path in ("libs/boost_1_36_0/libs/thread/src/thread.cpp", "libs/boost_1_36_0/libs/thread/test/t.cpp",
                 "libs/boost_1_36_0/tools/jam/src/jam.c", "libs/ogre/Tools/XMLConverter/include/x.h",
                 "libs/lua-5.1.4/test/life.c"):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text("")
    found = libraries.library_includes(tmp_path)
    assert set(found) >= {"libs/boost_1_36_0", "libs/ogre/OgreMain/include", "libs/lua-5.1.4/src", "libs/tinyxml",
                          "libs/ois/includes"}
    assert "libs/boost_1_36_0/boost" not in found and not any("Tools" in f for f in found)
    # a library's own sources: not its tests', examples' or tools' (boost's 4,698 files are mostly those)
    sources = {str(p.relative_to(tmp_path / "libs")) for lib in libraries.library_folders(tmp_path)
               for p in libraries.library_sources(lib)}
    assert sources == {"boost_1_36_0/libs/thread/src/thread.cpp", "ogre/OgreMain/src/OgreRoot.cpp",
                       "lua-5.1.4/src/lapi.c", "tinyxml/tinyxml.cpp"}


def test_a_librarys_own_source_sets_its_functions_aside_and_its_headers_are_in_every_compile(demo43):
    """Demo Quest of 2008 has zlib built in: with zlib's own source in libs/, every zlib function its files make byte
    for byte with the game's compiler is set aside as library code, naming the file (zlibVersion's string comes out
    beside the file's other strings, so its data isn't the game's: it stays open). zlib's headers are then in every
    compile: C may include them."""
    import shutil

    from decompnet.app.engine import RomNetwork

    from .test_consoles import ROOT

    program, factory = demo43
    work = factory.mktemp("libs")
    net = RomNetwork(work / "app.db", work)
    slug = net.import_rom(program, confirmed=True, log=lambda *_: None)
    lib = Path(net._project(slug)["root"]) / "libs" / "zlib-1.1.4"
    lib.mkdir(parents=True)
    for folder in ("original", "sysinclude"):
        for f in (ROOT / "projects" / "zlib-n64" / folder).glob("*.[ch]"):
            shutil.copy(f, lib / f.name)
    res = net.match_libraries(slug, log=lambda *_: None)
    assert res["found"] >= 56, res
    fn = net._function("scan_tree", slug)
    assert fn["status"] == "asm" and json.loads(fn["meta"])["library"] == "zlib-1.1.4/trees.c"
    assert net._function("game_tick", slug)["status"] == "open"
    (lib / "zdemo.h").write_text("#define ZDEMO_SIGN(v) ((v) < 0 ? -(v) : (v))\n")  # (one the header has no types of)
    net.scan_libraries(slug)
    agent, _ = net.local_agent("claude-opus-5.5-1")
    net.claim(agent, slug, "abs_s32")
    out = net.attempt(agent, "abs_s32", "#include <zdemo.h>\ns32 abs_s32(s32 v) { return ZDEMO_SIGN(v); }\n", slug)
    assert out["matched"], out["text"][:500]
    # a reimport replaces the project's folder: the library sources the user put in it stay
    net.reimport_rom(slug, program, confirmed=True, name=program.name, log=lambda *_: None)
    assert (lib / "zlib.h").is_file() and net.scan_libraries(slug)["libraries"] == ["zlib-1.1.4"]


def test_a_call_to_a_static_helper_of_the_same_object_goes_to_the_games_function_of_that_name(tmp_path):
    """A call to a static function the same object defines carries no relocation: the assembler resolved it by the
    two functions' distance in the object, never theirs in the game, so C with its helper beside it (a library's
    file compiled whole) couldn't match. The judge links it as the linker would: to the game's function of that
    name, and only there."""
    import types

    from decompnet import toolchains
    from decompnet.compiler import compile_source
    from decompnet.elfobj import _function_symbols
    from decompnet.project import compiler_config

    if toolchains.installed(GCC43) is None:
        pytest.skip(f"needs {GCC43}")
    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": GCC43, "flags": ["-O0"]}})
    res = compile_source(cfg, "", "static int helper(int v) { return v * 3; }\nint outer(int v) { return helper(v) + 1; }\n")
    assert res.ok, res.log
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(__import__("io").BytesIO(res.obj))
    shndx, start, size = _function_symbols(elf)["outer"]
    code = bytearray(elf.get_section(shndx).data()[start:start + size])
    at = code.index(0xE8)
    vram, helper = 0x8050000, 0x8061230  # where the game has them
    game = bytearray(code)
    game[at + 1:at + 5] = (helper - (vram + at + 5)).to_bytes(4, "little", signed=True)
    symbols = types.SimpleNamespace(resolve=lambda n: {"helper": helper, "outer": vram}.get(n),
                                    label=lambda a: f"0x{a:08X}")
    linked = x86_link.link(res.obj, "outer", x86_link.X86Target("outer", vram, bytes(game)), symbols, lambda *a: None)
    assert linked.exact, linked.problems
    elsewhere = types.SimpleNamespace(resolve=lambda n: {"helper": helper + 0x40}.get(n), label=lambda a: hex(a))
    wrong = x86_link.link(res.obj, "outer", x86_link.X86Target("outer", vram, bytes(game)), elsewhere, lambda *a: None)
    assert not wrong.exact and any("you call helper" in p for p in wrong.problems)


def test_code_built_with_fpic_matches_through_the_programs_got_and_plt(tmp_path):
    """glibc's atexit, linked into a Linux game from libc_nonshared.a, is -fPIC code: it finds the GOT from its own
    address, reads __dso_handle's address from the GOT entry the program's dynamic relocation names, and calls
    __cxa_atexit through the PLT. The judge read none of those relocations, so five agents agreed no C makes it."""
    import types

    from elftools.elf.elffile import ELFFile

    from decompnet import toolchains
    from decompnet.compiler import compile_source
    from decompnet.elfobj import _function_symbols
    from decompnet.project import compiler_config

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None:
        pytest.skip(f"needs {gcc}")
    cfg = compiler_config(tmp_path, {"compiler": {"toolchain": gcc, "flags": ["-O2", "-fPIC"]}})
    res = compile_source(cfg, "", "extern void *__dso_handle __attribute__ ((__weak__));\n"
                         "extern int __cxa_atexit(void (*)(void *), void *, void *);\n"
                         "int atexit(void (*func)(void)) { return __cxa_atexit((void (*)(void *))func, (void *)0, "
                         "&__dso_handle == (void *)0 ? (void *)0 : __dso_handle); }\n")
    assert res.ok, res.log
    elf = ELFFile(__import__("io").BytesIO(res.obj))
    shndx, start, size = _function_symbols(elf)["atexit"]
    code = elf.get_section(shndx).data()[start:start + size]
    vram, got, slot, stub = 0x809D650, 0x80BEA38, 0x80BEC74, 0x8049E30  # where the program has them
    game = bytearray(code)
    for rsec in elf.iter_sections():
        if getattr(rsec, "iter_relocations", None) and rsec["sh_info"] == shndx:
            for rel in rsec.iter_relocations():
                at, kind = rel["r_offset"] - start, rel["r_info_type"]
                addend = int.from_bytes(code[at:at + 4], "little", signed=True)
                value = {10: got + addend - (vram + at), 3: slot - got + addend,
                         4: stub + addend - (vram + at)}[kind]
                game[at:at + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")
    symbols = types.SimpleNamespace(resolve=lambda n: {"__cxa_atexit": stub, "atexit": vram}.get(n),
                                    label=lambda a: f"0x{a:08X}")
    target = x86_link.X86Target("atexit", vram, bytes(game), got=got, got_slots={slot: "__dso_handle"})
    linked = x86_link.link(res.obj, "atexit", target, symbols, lambda *a: None)
    assert linked.exact, linked.problems
    # another GOT entry (__gmon_start__'s) is refused, and without the program's GOT nothing is guessed
    other = x86_link.X86Target("atexit", vram, bytes(game), got=got, got_slots={slot: "__gmon_start__"})
    assert not x86_link.link(res.obj, "atexit", other, symbols, lambda *a: None).exact
    assert not x86_link.link(res.obj, "atexit", x86_link.X86Target("atexit", vram, bytes(game)), symbols,
                             lambda *a: None).exact


def test_flags_a_debug_build_or_another_machine_used_are_tried():
    """A 2008 program's Lua was built -O0 for the build machine's AMD processor, its TinyXML -O0, its libogg -O2:
    library matching tries each library's possible builds (the game's flags first), and search_flags tries -O0 and
    the build machine's -march for an agent's C."""
    from decompnet.app.engine.compilers import CompilerMixin

    linux = consoles.get("linux")
    variants = linux.library_flags(["-O2"])
    assert variants[0] == ["-O2"] and ["-O0", "-march=amdfam10"] in variants and ["-O0"] in variants
    tried = CompilerMixin.flag_variants(None, "gcc-4.3.2-redhat-linux", ["-O2"], linux.flag_extras)
    assert ["-O0"] in tried and ["-O2", "-march=amdfam10"] in tried


def test_the_exported_build_compares_a_scattered_constant_as_the_judge_does(tmp_path):
    """GCC merges a file's equal strings, so a function's constants can be apart in the program: the build gives
    each word the program's address after comparing the constant, without the zeros the object pads it with (105
    of a Linux game's functions were left as the program's bytes, then two failed the build for padding)."""
    import importlib.util
    import shutil

    from decompnet.consoles import linux

    shutil.copyfile(Path(linux.__file__).with_name("export_build.py"), tmp_path / "build.py")
    (tmp_path / "build.json").write_text(json.dumps({"functions": []}))
    spec = importlib.util.spec_from_file_location("exported_build", tmp_path / "build.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    string = b"    barmd NO tex\n\0" + b"\0" * 14  # (padded to the next string's 32-byte alignment)
    assert build.significant(string, 0x809DB8E, []) == 18
    number = bytes.fromhex("97ff283f00000000")  # (a float, padded to the double after it)
    assert build.significant(number, 0x809E954, []) == 4
    assert build.significant(bytes.fromhex("0000000000000040"), 0x1000, []) == 8  # (a double: all of it)
    assert build.significant(b"ab\0\0\0\0\0\0", 0x1000, [0x1004]) == 4  # (the program's next constant is there)


def test_the_export_card_counts_what_the_export_kept_as_the_programs_bytes_apart_from_new_matches():
    """A Linux game's card said "106 new matches since" of an export made a minute before: those were matched
    functions the export kept as the program's bytes."""
    js = (Path(__file__).parents[1] / "src/decompnet/app/static/js/steering.js").read_text()
    assert "ex.matched + kept < ov.matched" in js and "ov.matched - ex.matched - kept" in js


def test_a_source_files_variables_sit_as_far_apart_as_the_game_has_them(tmp_path):
    """GCC 2.95 aligns an array of 32 bytes or more to 32, the game's compiler didn't: C that reads past one variable
    into the next (a table of ammunition reached through the array before it) read the wrong row in the relink.
    Each variable alone in its section at the game's alignment, the shared .bss laid out as the game's, and the
    linker script putting each as far from the file's first as the game has it (export_relink.py)."""
    import os
    import shutil
    import subprocess
    import sys

    from decompnet import toolchains
    from decompnet.consoles.linux import export_make

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None:
        pytest.skip(f"needs {gcc}")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "t.c").write_text(
        "static int pad[10] = {1};\nstatic int head[9] = {21, 23, 20};\nstatic short table[3][9] = {{5, 6}, {7}};\n"
        "static int count;\nstatic int zbig[16];\n"
        "int f(int i) { return ((short *)((char *)head + 0x24))[i] + count + zbig[i] + pad[i]; }\n")
    # (as the game's compiler laid them out: no gaps)
    variables = [["pad", 0x8049000, 40, ".data"], ["head", 0x8049028, 36, ".data"], ["table", 0x804904C, 54, ".data"],
                 ["count", 0x804A004, 4, ".bss"], ["zbig", 0x804A008, 64, ".bss"]]
    build = {"toolchain": gcc, "functions": [{"name": "f", "vram": 0x8048100, "size": 64, "c": "src/t.c"}],
             "units": [{"name": "t", "c": "src/t.c", "functions": ["f"], "data": {"variables": variables, "defines": []}}],
             "symbols": {}}
    (tree / "build.json").write_text(json.dumps(build))
    (tree / "tools").mkdir()
    (tree / "tools" / "cc.sh").write_text(toolchains.registry()[gcc].cmd[2])
    shutil.copyfile(Path(export_make.__file__).with_name("export_relink.py"), tree / "tools" / "relink.py")
    (tree / "build" / "relink").mkdir(parents=True)
    env = {**os.environ, "TC": str(tc)}
    raw, obj = "build/relink/file-t.o.raw", "build/relink/file-t.o"
    subprocess.run(["sh", "tools/cc.sh", str(tc), "src/t.c", raw, "-O2", "-fdata-sections"], cwd=tree, env=env, check=True)
    subprocess.run([sys.executable, "tools/relink.py", "fixup", raw, obj, "file:t"], cwd=tree, env=env, check=True)
    laid = json.loads(subprocess.run(
        [sys.executable, "-c", "import json, sys; sys.path.insert(0, 'tools'); import relink; "
                               "print(json.dumps(relink.placed_as_game()))"],
        cwd=tree, env=env, capture_output=True, text=True, check=True).stdout)
    (tree / "t.ld").write_text(f"SECTIONS {{\n  . = 0x8048000;\n  .text : {{ *(.text) }}\n"
                               f"  .data : {{\n{laid['.data']}    *(.data) *(.data.*) }}\n"
                               f"  .bss : {{\n{laid['.bss']}    *(.bss) *(COMMON) }}\n"
                               f"  /DISCARD/ : {{ *(.comment) *(.note*) }}\n}}\n")
    ld = tc / "binutils" / "usr" / "bin" / "ld"
    lib = {**env, "LD_LIBRARY_PATH": f"{tc}/binutils/usr/lib:{tc}/lib"}
    subprocess.run([str(ld), "-m", "elf_i386", "-T", "t.ld", "-e", "f", "-o", "t.out", obj], cwd=tree, env=lib, check=True)
    at = {p[2]: int(p[0], 16) for p in (line.split() for line in subprocess.run(
        ["nm", "t.out"], cwd=tree, capture_output=True, text=True).stdout.splitlines()) if len(p) == 3}
    assert (at["head"] - at["pad"], at["table"] - at["head"], at["zbig"] - at["count"]) == (0x28, 0x24, 4)
    assert at["pad"] % 32 == 0  # (where the game has the first, modulo 32)
    # and what the code reads past head is table's first row, as in the game
    out = subprocess.run(["objdump", "-d", "t.out"], cwd=tree, capture_output=True, text=True).stdout
    assert f"{at['head'] + 0x24:x}" in out


def test_the_ports_copy_reads_a_files_own_variable_by_its_name_not_another_object(tmp_path):
    """A function's other name for the file's static (`extern Block *Tmu0__tmuReset __asm__("Tmu0");`) is another
    object to a newer GCC, which may keep the static's value in a register across a write through it: make port's
    copy reads the static itself, as the type the function declared it."""
    import subprocess
    import sys

    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "relink.py").write_bytes(
        (Path(debuginfo.__file__).with_name("export_relink.py")).read_bytes())
    (tmp_path / "build.json").write_text(json.dumps({"functions": [], "units": [], "symbols": {}}))
    code = ("static int table[4];\nint f(void)\n{\n    extern char table__f[] __asm__(\"table\");  /* note */\n"
            "    extern short later__f[2] __asm__(\"later\");\n    return table__f[1] + later__f[0];\n}\n"
            "static short later[2];\n")
    out = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, 'tools'); import relink; "
                          f"print(relink.through_aliases({code!r}), end='')"], cwd=tmp_path, capture_output=True,
                         text=True, check=True).stdout
    assert "    #define table__f (*(char (*)[])&table)  /* note */" in out
    assert 'extern short later__f[2] __asm__("later");' in out  # (declared after: left as it is)


def test_the_exports_c_is_made_plain_only_where_gcc_2_95_still_builds_the_same_code(tmp_path):
    """A plain build has no linker script to give `D_08EC894C` its place (`g_Camera + 12`) nor `inline` helpers one
    definition each: the export writes them as C (export_clean.py), kept only where GCC 2.95 compiles the file to
    the same code, every relocation reaching the same address; a number the C writes for a variable's address is
    its name, or both under NON_MATCHING where GCC 2.95 builds the game's code only from the number."""
    from decompnet import toolchains
    from decompnet.consoles.linux import export_clean, export_make

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None:
        pytest.skip(f"needs {gcc}")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    out = tmp_path / "tree"
    (out / "src").mkdir(parents=True)
    (out / "include").mkdir()
    (out / "tools").mkdir()
    (out / "tools" / "cc.sh").write_text("#!/bin/sh\n" + toolchains.registry()[gcc].cmd[2] + "\n")
    build = {"symbols": {"D_08EC894C": 0x8EC894C}, "toolchain": gcc, "standalone": True,
             "functions": [{"name": "read", "vram": 0x8048000, "c": "src/cam.c"},
                           {"name": "where", "vram": 0x8048020, "c": "src/cam.c"},
                           {"name": "add", "vram": 0x8048040, "c": "src/cam.c"},
                           {"name": "count", "vram": 0x8048060, "c": "src/cam.c"}],
             "units": [{"name": "cam", "c": "src/cam.c", "flags": ["-O2"],
                        "data": {"defines": ["g_Camera"], "variables": [["g_Camera", 0x8EC8940, 64, ".data"],
                                                                        ["count_calls", 0x8EC9000, 4, ".data"]],
                                 "aliases": {"calls_7": ["count_calls", 0]},
                                 "link_aliases": {"D_08EC894C": ["g_Camera", 12]}}}]}
    source = ("struct cam { int a, b, c, d; int rest[12]; };\nstruct cam g_Camera = { 1 };\nextern int D_08EC894C;\n"
              '#include "cam.h"\nstatic int count_calls __attribute__((used)) = 5;\n'
              "inline int twice(int x) { return x + x; }\n"
              "int read(void) { return twice(D_08EC894C); }\n"
              "int *where(void) { return (int *)0x8ec8950; }\n"
              "int add(int a, int b) { return a + b; }\n"
              "int count(void)\n{\n    extern int add__count() __asm__(\"add\");  /* add as this function calls it, undeclared */\n"
              "    return add__count(calls_7, 2);\n}\n"
              '__asm__(".globl calls_7\\n\\t.set calls_7, count_calls");  /* the names the C reads these by */\n')
    (out / "src" / "cam.c").write_text(source)
    (out / "include" / "cam.h").write_text("extern int calls_7;\n")  # (as the program's header declares it)
    (out / "build.json").write_text(__import__("json").dumps(build))
    where = export_clean.addresses(build)  # (every name the first C reads, calls_7 too)
    export_clean.clean(out, build, tc, log=lambda *_: None)
    made = (out / "src" / "cam.c").read_text()
    assert "(*(__typeof__(D_08EC894C) *)((char *)&g_Camera + 12))" in made  # (its place, as C)
    assert "extern int D_08EC894C;" in made  # (what __typeof__ reads)
    assert "static inline int twice" in made
    assert "((int)&g_Camera + 0x10)" in made  # (the number by its name, the code the same)
    assert "return add(count_calls, 2);" in made and "__asm__(\"add\")" not in made  # (called by its own name)
    # one name for the variable: the definition's, where the C's is GCC's number for a function's static
    assert ".set" not in made
    assert not any(export_clean.clean(out, build, tc, log=lambda *_: None).values())  # (done once: nothing left)
    # the check itself: the same place written two ways is the same code; another place isn't
    flags = ["-O2"]
    one = export_clean._compile(out, tc, out / "src" / "cam.c", flags, source)
    assert export_clean.same_code(one, export_clean._compile(out, tc, out / "src" / "cam.c", flags, made), where)
    other = source.replace("return twice(D_08EC894C)", "return twice(*(int *)((char *)&g_Camera + 8))")
    assert not export_clean.same_code(one, export_clean._compile(out, tc, out / "src" / "cam.c", flags, other), where)
    # both forms where only the number matches, as decompilations write them
    both = export_clean._non_matching("int f(void)\n{\n    return *(int *)0x8ec8950;\n}\n",
                                      "int f(void)\n{\n    return *(int *)((int)&g_Camera + 0x10);\n}\n")
    assert both == ("int f(void)\n{\n#ifdef NON_MATCHING\n    return *(int *)((int)&g_Camera + 0x10);\n#else\n"
                    "    return *(int *)0x8ec8950;\n#endif\n}\n")
    assert export_clean._non_matching("#define X \\\n  0x8ec8950\n", "#define X \\\n  ((int)&g_Camera)\n") is None
    # the plain link's libraries are what the program asked the loader for
    assert export_make.libraries({"imports": {"needed": ["libc.so.6", "libm.so.6", "libGL.so.1", "libglut.so.3"]}}) \
        == "-lglut -lGL -lm"
    assert export_make.packages({"imports": {"needed": ["libc.so.6", "libm.so.6", "libGL.so.1", "libglut.so.3"]}}) \
        == "gcc-multilib freeglut3-dev:i386 libgl-dev:i386"


def test_the_exports_common_header_becomes_a_header_per_source_file(tmp_path):
    """common.h declared every file's names, so a file with a static of one had its own copy without it
    (common_<file>.h): the export cuts it into a header per source file of what the others read of it, each file
    including those it uses and declaring itself what no header does (another file's static it reads, a
    declaration two files disagree on), kept where GCC 2.95 still compiles each file to the same code."""
    import json

    from decompnet import toolchains
    from decompnet.consoles.linux import export_clean

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None:
        pytest.skip(f"needs {gcc}")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    out = tmp_path / "tree"
    for d in ("src", "include", "tools"):
        (out / d).mkdir(parents=True)
    (out / "tools" / "cc.sh").write_text("#!/bin/sh\n" + toolchains.registry()[gcc].cmd[2] + "\n")
    common = ("typedef int s32;\nint abs(int);\n/* a.c */\nextern s32 score;\nextern int hidden;\n"
              "/* b.c */\nint helper(int x);\n")
    (out / "include" / "common.h").write_text(common)
    (out / "include" / "common_a.h").write_text(common.replace("extern int hidden;\n", ""))
    (out / "include" / "a.h").write_text("#ifndef FILE_A_H\n#define FILE_A_H\nint a_func(void);\n"
                                         "extern int helper();\n#endif\n")
    (out / "include" / "b.h").write_text("#ifndef FILE_B_H\n#define FILE_B_H\nextern char *a_func();\n#endif\n")
    (out / "src" / "a.c").write_text('#include "common_a.h"\n\n#include "a.h"\n'
                                     "s32 score;\nstatic int hidden = 3;\n"
                                     "int a_func(void) { return helper(hidden) + abs(score); }\n")
    (out / "src" / "b.c").write_text('#include "common.h"\n\n#include "b.h"\n'
                                     "int helper(int x) { return x + score + hidden + (int)a_func(); }\n")
    build = {"symbols": {}, "toolchain": gcc, "standalone": True,
             "functions": [{"name": "a_func", "vram": 0x8048000, "c": "src/a.c"},
                           {"name": "helper", "vram": 0x8048040, "c": "src/b.c"}],
             "units": [{"name": "a", "c": "src/a.c", "flags": ["-O2"]},
                       {"name": "b", "c": "src/b.c", "flags": ["-O2"]}]}
    (out / "build.json").write_text(json.dumps(build))
    before = {n: export_clean._compile(out, tc, out / "src" / n, ["-O2"], (out / "src" / n).read_text())
              for n in ("a.c", "b.c")}
    export_clean.clean(out, build, tc, log=lambda *_: None)

    shared = (out / "include" / "common.h").read_text()
    assert "typedef int s32;" in shared and "int abs(int);" in shared  # (types and the libraries' stay)
    assert "score" not in shared and "helper" not in shared and "hidden" not in shared
    a_h, b_h = (out / "include" / "a.h").read_text(), (out / "include" / "b.h").read_text()
    assert "extern s32 score;" in a_h and "#ifndef FILE_A_H" in a_h
    assert "a_func" not in a_h  # (b.c declares it otherwise: its type isn't settled, each file says its own)
    assert "int helper(int x);" in b_h and "a_func" not in b_h
    assert not (out / "include" / "common_a.h").exists()
    a_c, b_c = (out / "src" / "a.c").read_text(), (out / "src" / "b.c").read_text()
    assert a_c.startswith('#include "common.h"\n#include "a.h"\n#include "b.h"\n')
    assert "extern int helper();" not in a_c and "int a_func(void);" in a_c  # (b.h has helper's prototype)
    assert b_c.startswith('#include "common.h"\n#include "b.h"\n#include "a.h"\n')
    assert "extern int hidden;" in b_c and "extern char *a_func();" in b_c  # (a.c's static, read here)
    for n in ("a.c", "b.c"):  # (the same code)
        made = export_clean._compile(out, tc, out / "src" / n, ["-O2"], (out / "src" / n).read_text())
        assert export_clean.same_code(before[n], made, {})
    assert not any(export_clean.clean(out, build, tc, log=lambda *_: None).values())


def test_the_export_reads_fields_by_name_and_a_read_past_a_table_as_the_table_it_reaches(tmp_path):
    """An offset into a variable is the field the game's own types have there (`g_Cam.pos.y`), kept where GCC 2.95
    builds the same code; a read of rows past a table's end (what ASan finds in a plain build) is the table it lands
    in, under NON_MATCHING (GCC 2.95 writes `ammo - 4` as an offset into the file's data, which no relink places);
    a file's own va_start, which steps from an argument's address, is the compiler's own in a plain build."""
    import json

    from decompnet import toolchains
    from decompnet.consoles.linux import export_clean

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None:
        pytest.skip(f"needs {gcc}")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    out = tmp_path / "tree"
    for d in ("src", "include", "tools"):
        (out / d).mkdir(parents=True)
    (out / "tools" / "cc.sh").write_text("#!/bin/sh\n" + toolchains.registry()[gcc].cmd[2] + "\n")
    (out / "include" / "common.h").write_text(
        "typedef void *va_list;\nstruct _V3 { /* 0xc bytes */\n    float x; /* 0x0 */\n    float y; /* 0x4 */\n"
        "    float z; /* 0x8 */\n};\ntypedef struct _V3 V3;\n"
        "struct _Cam { /* 0x14 bytes */\n    int id; /* 0x0 */\n    V3 pos; /* 0x4 */\n    short flags[2]; /* 0x10 */\n};\n"
        "typedef struct _Cam TCam;\nextern TCam g_Cam;\nextern float D_08000008;\nextern float D_08000200;\n"
        "extern char D_08000210[];\n")
    (out / "src" / "cam.c").write_text(
        '#include "common.h"\n\n'
        "TCam g_Cam;\nstatic short hits[2] = { 1, 2 };\nstatic short ammo[3][2] = { { 3, 4 }, { 5, 6 }, { 7, 8 } };\n"
        "int id(void) { return *(int *)((char *)&g_Cam + 0); }\n"
        "float y(void) { return (*(__typeof__(D_08000008) *)((char *)&g_Cam + 8)); }\n"
        "int bits(void) { return *(int *)((char *)&g_Cam + 12); }\n"
        "short *flags(void) { return (short *)((char *)&g_Cam + 0x10); }\n"
        "short *row(int d) { return (short *)(((int)&hits + 0x0) + d * 4); }\n"
        "short *clipped(int d) { short *c; c = (short *) hits; return c + d * 2; }\n"
        "char D_08000200_data[4] = { 0, 0, -56, 67 };\nchar D_08000210_data[4] = { 104, 105, 0, 0 };\n"
        "float width(void) { return (*(__typeof__(D_08000200) *)&D_08000200_data); }\n"
        "char *hello(void) { return (*(__typeof__(D_08000210) *)&D_08000210_data); }\n"
        "#define va_start(AP, LASTARG) \\\n  (AP = (void *)((char *) &(LASTARG) + 4))\n"
        "#define va_arg(AP, TYPE) (*(TYPE *)((AP = (void *)((char *)(AP) + sizeof(TYPE))) - sizeof(TYPE)))\n"
        "#define va_end(AP)\n"
        "int sum(int n, ...) { va_list ap; int s = 0; va_start(ap, n); while (n--) s += va_arg(ap, int); "
        "va_end(ap); return s; }\n")
    build = {"symbols": {"D_08000008": 0x8000008}, "toolchain": gcc, "standalone": True,
             "functions": [{"name": n, "vram": 0x8048000 + 0x20 * k, "c": "src/cam.c"}
                           for k, n in enumerate(["id", "y", "bits", "flags", "row", "clipped", "width", "hello", "sum"])],
             "units": [{"name": "cam", "c": "src/cam.c", "flags": ["-O2"],
                        "data": {"defines": ["g_Cam"], "variables": [["g_Cam", 0x8000000, 20, ".bss"],
                                                                     ["hits", 0x8000100, 4, ".data"],
                                                                     ["ammo", 0x8000104, 12, ".data"],
                                                                     ["D_08000200_data", 0x8000200, 4, ".rodata"],
                                                                     ["D_08000210_data", 0x8000210, 4, ".rodata"]]}}]}
    (out / "build.json").write_text(json.dumps(build))
    export_clean.clean(out, build, tc, log=lambda *_: None)
    made = (out / "src" / "cam.c").read_text()
    assert "return g_Cam.id;" in made and "return g_Cam.pos.y;" in made  # (the field of the type the C reads)
    assert "return *(int *)&g_Cam.pos.z;" in made  # (another type than the field's: the field, read as the C does)
    assert "return (short *)&g_Cam.flags[0];" in made  # (an address: the field there)
    # (hits + 4d: ammo; as C where the file's own data is laid out as the game's, else under NON_MATCHING)
    assert "short *row(int d) { return ammo[d - 1]; }\n" in made
    assert "return ammo[d - 1]; }" in made.split("short *clipped")[1]  # (through a pointer only ever set to hits)
    assert "#ifdef NON_MATCHING\n#define va_start(AP, LASTARG) __builtin_va_start(AP, LASTARG)" in made
    # (a read-only constant read where the game keeps it: its literal, the compiler's to place, in a plain build)
    assert "#ifdef NON_MATCHING\nfloat width(void) { return 400.0f; }\n#else\n" in made
    assert "#ifdef NON_MATCHING\nchar *hello(void) { return \"hi\"; }\n#else\n" in made
    assert "#ifdef NON_MATCHING\ntypedef __builtin_va_list va_list;\n#else\ntypedef void *va_list;\n#endif\n" \
        in (out / "include" / "common.h").read_text()
    assert not any(export_clean.clean(out, build, tc, log=lambda *_: None).values())



def test_a_table_copied_from_a_literal_the_match_placed_is_the_tables_bytes_in_a_plain_build(tmp_path):
    """`memcpy(v, "", sizeof(v))` matches a game's copy of a local table's initializer where the match placed the
    literal at the table, which a plain build reads past (a 1-byte string): under NON_MATCHING the literal is the
    table's bytes, read from the program at the address the game's code loads there."""
    import json
    import struct
    import subprocess

    from decompnet import toolchains
    from decompnet.consoles.linux import export_clean

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None:
        pytest.skip(f"needs {gcc}")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    out = tmp_path / "tree"
    for d in ("src", "include", "tools"):
        (out / d).mkdir(parents=True)
    (out / "tools" / "cc.sh").write_text("#!/bin/sh\n" + toolchains.registry()[gcc].cmd[2] + "\n")
    (out / "include" / "common.h").write_text("void *memcpy(void *, const void *, unsigned int);\n")
    # the game: its own table (GCC 2.95 copies one this big from .rodata), at an address its code loads
    table = ", ".join(str(k) for k in range(36))
    (tmp_path / "game.c").write_text('#include "common.h"\nvoid tris(unsigned short *out) { unsigned short v[12][3] '
                                     "= { " + table + " }; memcpy(out, v, sizeof(v)); }\n")
    subprocess.run(["sh", str(out / "tools" / "cc.sh"), str(tc), str(tmp_path / "game.c"), str(tmp_path / "game.o"),
                    "-I", str(out / "include"), "-O2"], check=True, capture_output=True)
    subprocess.run([str(tc / "binutils" / "usr" / "bin" / "ld"), "-m", "elf_i386", "-Ttext", "0x8048000", "-e", "tris",
                    "-o", str(out / "baserom"), str(tmp_path / "game.o")], check=True, capture_output=True,
                   env={"LD_LIBRARY_PATH": str(tc / "binutils" / "usr" / "lib")})
    # its decompilation: the literal the match placed at the table
    (out / "src" / "tris.c").write_text('#include "common.h"\nvoid tris(unsigned short *out)\n{\n    unsigned short v[12][3];\n'
                                        '\n    memcpy(v, "", sizeof(v));\n    memcpy(out, v, sizeof(v));\n}\n')
    build = {"symbols": {}, "toolchain": gcc, "standalone": True,
             "functions": [{"name": "tris", "vram": 0x8048000, "c": "src/tris.c", "flags": ["-O2"]}]}
    (out / "build.json").write_text(json.dumps(build))
    rewrite = export_clean.copied_literals(build, out, tc, {"src/tris.c": ["-O2"]})
    made = next(rewrite((out / "src" / "tris.c").read_text(), "src/tris.c"), "")
    body = "".join(f"\\{b:03o}" for b in struct.pack("<36H", *range(36)))
    assert f'#ifdef NON_MATCHING\n    memcpy(v, "{body}", sizeof(v));\n#else\n    memcpy(v, "", sizeof(v));\n#endif\n' in made
    # and as the local array's initializer it was (what the export joins a file with): the same code, the table in
    # the file's own .rodata where the game has it; from a name of the table's address alike
    source = (out / "src" / "tris.c").read_text()
    image = (out / "baserom").read_bytes()
    obj = export_clean._compile(out, tc, out / "src" / "tris.c", ["-O2"], source)
    reads = export_clean.literal_reads(obj, image, {"tris": 0x8048000})
    table = "{ " + ", ".join("{ %d, %d, %d }" % (k, k + 1, k + 2) for k in range(0, 36, 3)) + " }"
    made = export_clean.local_table(source, reads["tris"], image)
    assert made == ('#include "common.h"\nvoid tris(unsigned short *out)\n{\n\n    {\n'
                    f"    unsigned short v[12][3] = {table};\n    memcpy(out, v, sizeof(v));\n    }}\n}}\n")
    made_obj = export_clean._compile(out, tc, out / "src" / "tris.c", ["-O2"], made)
    assert export_clean._resolved(made_obj, {"tris": 0x8048000})[(".text", "tris")][0] == \
        export_clean._resolved(obj, {"tris": 0x8048000})[(".text", "tris")][0]  # (the same instructions)
    [address] = reads["tris"][b""]
    named = source.replace('memcpy(v, "", sizeof(v))', f"memcpy(v, (void *)D_{address:08X}, sizeof(v))")
    assert export_clean.local_table(named, {}, image) == made


def test_a_headers_gnu89_extern_inline_functions_link_in_a_plain_build_at_o0(tmp_path):
    """A header's gnu89 `extern __inline` functions (a game's copy of glibc 2.2's <bits/mathinline.h>: __rint_mode,
    rint) are always inlined in a plain build: gnu89 never emits one out of line, so at -O0, where GCC inlines nothing,
    the plain build didn't link (a tester's `make CFLAGS=-O0`). The matching build reads them as they were."""
    from decompnet.consoles.linux import export_clean

    (tmp_path / "include").mkdir()
    header = tmp_path / "include" / "common.h"
    header.write_text("extern double half(double x);\nextern __inline double half(double x) {\n    return x / 2;\n}\n",
                      encoding="utf-8")
    export_clean._header_inlines(tmp_path)
    text = header.read_text(encoding="utf-8")
    assert "DECOMP_EXTERN_INLINE double half(double x) {" in text and "extern double half(double x);" in text
    export_clean._header_inlines(tmp_path)  # (once: done already)
    assert header.read_text(encoding="utf-8") == text
    matching = subprocess.run(["cpp", "-P", "-Iinclude", "include/common.h"], cwd=tmp_path, capture_output=True,
                              text=True) if shutil.which("cpp") else None
    if matching is not None:
        assert "extern __inline double half" in matching.stdout and "always_inline" not in matching.stdout
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    (tmp_path / "main.c").write_text('#include "common.h"\nint main(void) { return half(4.0) == 2.0 ? 0 : 1; }\n',
                                     encoding="utf-8")
    built = subprocess.run(["gcc", "-O0", "-std=gnu89", "-DNON_MATCHING", "-Iinclude", "main.c", "-o", "main"],
                           cwd=tmp_path, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    assert subprocess.run([str(tmp_path / "main")]).returncode == 0


FLOATS = """typedef struct { float x, y, z, w; } Quat;
static float xx, xy, xz, xw, yx, yy, yz, yw, zx, zy, zz, zw, wx, wy, wz, ww;
void quat_mul(Quat *p, Quat *a, Quat *b)
{
    yz = a->y * b->z; zy = a->z * b->y; wx = a->w * b->x; xw = a->x * b->w;
    zx = a->z * b->x; xz = a->x * b->z; wy = a->w * b->y; yw = a->y * b->w;
    xy = a->x * b->y; yx = a->y * b->x; wz = a->w * b->z; zw = a->z * b->w;
    ww = a->w * b->w; xx = a->x * b->x; yy = a->y * b->y; zz = a->z * b->z;
    p->x = yz - zy + wx + xw;
    p->y = zx - xz + wy + yw;
    p->z = xy - yx + wz + zw;
    p->w = ww - xx - yy - zz;
}
float quat_dot(Quat *a, Quat *b)
{
    return a->x * b->x + a->y * b->y + a->z * b->z + a->w * b->w;
}
void *malloc(unsigned);
double sin(double);
void quat_spin(Quat *q, float t)
{
    float *kept = malloc(4);
    *kept = sin(t = t * q->x) * q->z;
    q->y = *kept;
    q->w = t;
}
void quat_fill(Quat *q);
float quat_filled(float s)
{
    Quat q;
    quat_fill(&q);  /* (another file's: what it leaves in q is the game's only where the check runs the game's) */
    return q.x * s + q.y;
}
void quat_scale(Quat *q)
{
    float m = quat_dot(q, q);
    if (m != 0.0f) {
        m = 1.0f / m;
        q->x *= m;
        q->y *= m;
        q->z *= m;
        q->w *= m * 0.1;
    }
}
"""


def test_the_export_makes_the_plain_builds_floats_the_games_where_the_c_can_say_so(tmp_path):
    """GCC 2.95 kept x87 values exact in its 80-bit registers where a newer GCC rounds them (and the other way), so
    the same C gave an arcade game other floats in its plain build (a quaternion multiply a bit off: frames some
    pixels off). The export compares each float function of the game's code with the plain build's
    (tools/floatcheck.py, `make floatcheck`) and finds the C that says what the game's code did: a product kept exact
    for the reads after it, a float returned with all 80 bits, a local kept exact, a literal read as a double, an
    assignment's exact value passed on (slerp's `sin(t = t * omega)`, which kept a game's frames some pixels off); the
    file then builds with -fexcess-precision=standard (its Makefile rule), or GCC's default where that's closer, the
    C beside the matching C, NON_MATCHING, and the matching build the same. The check links the game's own other
    files, so a call's out-arguments are what the game's function leaves there, not a stub's nothing."""
    from decompnet import toolchains
    from decompnet.consoles.linux import export_clean, export_float, export_make

    gcc = "gcc-2.95.3-linux"
    if toolchains.installed(gcc) is None or not export_float.available():
        pytest.skip(f"needs {gcc}, and the system's gcc (32-bit) and binutils")
    tc = Path(toolchains.ensure(gcc, log=lambda *_: None))
    out = tmp_path / "tree"
    for folder in ("src", "include", "tools"):
        (out / folder).mkdir(parents=True)
    (out / "tools" / "cc.sh").write_text("#!/bin/sh\n" + toolchains.registry()[gcc].cmd[2] + "\n")
    shutil.copyfile(Path(export_float.__file__).with_name("export_floatcheck.py"), out / "tools" / "floatcheck.py")
    (out / "include" / "vec.h").write_text("float quat_dot(void *a, void *b);\n")
    (out / "src" / "vec.c").write_text(FLOATS)
    (out / "src" / "fill.c").write_text("typedef struct { float x, y, z, w; } Quat;\n"
                                        "void quat_fill(Quat *q)\n{\n    q->x = 1.5f;\n    q->y = 0.25f;\n}\n")
    build = {"toolchain": gcc, "program": "vec", "functions": [],
             "units": [{"name": "vec", "c": "src/vec.c", "flags": ["-O2"]},
                       {"name": "fill", "c": "src/fill.c", "flags": ["-O2"]}]}
    (out / "build.json").write_text(json.dumps(build))
    matching = export_clean._compile(out, tc, out / "src" / "vec.c", ["-O2"], FLOATS)
    done = export_float.precision(out, build, tc, log=lambda *_: None)
    res = done["src/vec.c"]
    assert "quat_filled" not in res["untestable"] + res["differ"]  # (quat_fill the game's own, not a stub's 0)
    assert res["start"] > 0 and res["standard"] == 0 and res["mode"] == "standard", res  # (the game's, every call)
    assert build["units"][0]["plain_flags"] == ["-fexcess-precision=standard"]
    made = (out / "src" / "vec.c").read_text()
    assert "#ifdef NON_MATCHING" in made and "long double quat_dot(" in made and "_exact" in made
    # the matching build compiles what it did
    assert export_clean.same_code(matching, export_clean._compile(out, tc, out / "src" / "vec.c", ["-O2"], made), {})
    # and the tree's own check says so, as `make floatcheck` runs it
    said = subprocess.run([sys.executable, "tools/floatcheck.py", "src/vec.c"], cwd=out, capture_output=True,
                          text=True, env={**os.environ, "TC": str(tc), "CFLAGS": " ".join(export_float.DEFAULT)})
    # (quat_spin calls malloc: the check's stubs are never the C library's, whose start-up a stub malloc stopped)
    assert said.returncode == 0 and "5 of 5 functions the game's" in said.stdout, said.stdout + said.stderr
    assert "build/plain/vec.o build/asan/vec.o: CFLAGS += -fexcess-precision=standard" in export_make.precision(build)
    # what it writes: a literal not exact in its type as the double it was; a changed function beside the matching one
    assert export_float.literal_casts('a * 0.1 + b * 0.5f + (1.0 / 180.0); printf("%5.2f", x); /* 0.1 */') == \
        'a * (double)0.1 + b * 0.5f + (double)(1.0 / 180.0); printf("%5.2f", x); /* 0.1 */'
    # a product GCC 2.95 spilled to a float slot mid-expression, rounded there; a float GCC's default precision keeps
    # in a register, rounded by a store (volatile)
    body = "void f(void)\n{\n    float m;\n    x = mag * ct + -sip * st;\n}\n"
    spills = [export_float.spilled(body, at) for at in export_float.products(body)]
    assert "x = (float)(mag * ct) + -sip * st;" in spills[0] and "-(float)(sip * st);" in spills[1]
    assert "volatile float m;" in export_float.volatile_local(body, "m")
    # an assignment whose value an expression takes: the variable rounded, the expression given the exact value
    body = "void f(float t)\n{\n    s = sin(t = t * w) * o;\n}\n"
    (at,) = export_float.inner_assignments(body, {"t"})
    assert "s = sin((t = t_exact = t * w, t_exact)) * o;" in export_float.exact_value(body, at, "t_exact")
    assert export_float.merged("int f(void);\nint f(void)\n{\n    return 1;\n}\n",
                               "long f(void);\nint f(void)\n{\n    return 2;\n}\n", lambda t, n: (
                                   (t.index("int f(void)\n{"), t.index("}\n") + 1) if n == "f" else None)) == \
        ("#ifdef NON_MATCHING\nlong f(void);\n#else\nint f(void);\n#endif\n#ifdef NON_MATCHING\nint f(void)\n{\n"
         "    return 2;\n}\n#else\nint f(void)\n{\n    return 1;\n}\n#endif\n")


def test_header_code_and_middleware_are_set_aside_and_the_games_own_code_stays(demo43, tmp_path):
    """A 2008 C++ program had 54,000 functions, half of them no one's to write: template code of the C++ library's and
    boost's the compiler wrote out in the game's own files (13,286 and 5,925), luabind's and Ogre's, and Scaleform
    GFx's own code (7,629, proprietary: no source anywhere). They're set aside by the namespace their demangled name
    is in (std, and each one a library in libs/ opens first in its headers) and, for the middleware, by its classes'
    names where the program has enough of them and they have no debug information; the game's own code stays, a
    namespace of its own named as boost names a nested one (`debug`) too."""
    import json as json_

    from decompnet.app.engine import RomNetwork
    from decompnet.app.engine.libraries import library_namespaces, outer_name

    program, factory = demo43
    work = factory.mktemp("header")
    net = RomNetwork(work / "app.db", work)
    slug = net.import_rom(program, confirmed=True, log=lambda *_: None)
    proj = net._project(slug)
    root = Path(proj["root"])
    for path, text in (("libs/boost_1_36_0/boost/a.hpp", "namespace boost {\nnamespace debug {\n}\n}\n"),
                       ("libs/boost_1_36_0/boost/b.hpp", "namespace boost {\n}\n"),
                       ("libs/boost_1_36_0/libs/x/example/e.hpp", "namespace example {\n}\n"),
                       ("libs/boost_1_36_0/libs/x/example/f.hpp", "namespace example {\n}\n")):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    assert library_namespaces(root) == {"boost": "boost_1_36_0"}  # (not `debug`, nor its examples' `example`)
    assert outer_name("void boost::function_requires<boost::a<int> >(void)") == "boost"
    assert outer_name("non-virtual thunk to GFxSprite::OnTimer(void*)") == "GFxSprite"
    game = {"debug": {"source": "src/graphics/x.cpp"}}
    rows = [("_ZNSt6vectorIiE4push", "std::vector<int, std::allocator<int> >::push_back(int const&)", game),
            ("_ZN5boost17function_req", "void boost::function_requires<int>(void)", game),
            ("_ZN8graphics4ChangeEv", "graphics::Transition::Change()", game),
            ("_ZN5debug3LogEi", "debug::Log(int)", game),  # (the game's own debug namespace)
            ("_ZN2GT8IteratorEv", "GT::Iterator::next()", game),  # (a game class named G + capital, with debug)
            ("_ZN9GRenderer4DrawEv", "GRenderer::Draw()", {})]
    rows += [(f"_ZN9GFxSprite{i}Ev", f"GFxSprite::f{i}()", {}) for i in range(200)]
    with net.store.tx() as db:
        for k, (name, demangled, meta) in enumerate(rows):
            db.execute("INSERT INTO functions(project_id, name, size, status, vram, meta) VALUES(?,?,?,?,?,?)",
                       (proj["id"], name, 4, "open", 0x9000000 + 16 * k, json_.dumps({**meta, "demangled": demangled})))
    found = net.set_aside_header_code(slug, log=lambda *_: None)
    assert found == {"the C++ library's": 1, "boost_1_36_0": 1, "Scaleform GFx": 201}, found
    status = {r["name"]: r["status"] for r in net.store.all("SELECT name, status FROM functions WHERE project_id=?",
                                                            proj["id"])}
    assert status["_ZN8graphics4ChangeEv"] == status["_ZN5debug3LogEi"] == status["_ZN2GT8IteratorEv"] == "open"
    assert status["_ZN9GRenderer4DrawEv"] == status["_ZNSt6vectorIiE4push"] == "asm"
