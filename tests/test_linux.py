"""Linux (32-bit x86) programs: what the console recognises, its STABS reader and its judge's placement rule. A
real game's run (Slackware 8.0's GCC 2.95.3 reproducing its functions byte for byte) needs the game, so the end to end
check is the demo program built with the same toolchain (projects/demo-linux, and tests/test_consoles.py)."""

import re
import struct
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
    assert units[0][1] == [(0x24, "f:F(0,1)", 0x8048100), (0x80, "int:t(0,1)=r(0,1);-2147483648;2147483647;", 0)]
    assert units[1][1] == [(0x24, "g:F(0,1)", 0x8048200)]
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
    defined = next(t for _, t, _ in a if t.startswith("T:t"))
    number = defined[defined.index("(") + 1:defined.index(",")]
    assert defined.startswith(f"T:t({number},1)=s4x:(0,1)")  # (built-in types keep file 0)
    assert any(t == defined for _, t, _ in b)  # h.h's types are back in b.c ...
    # ... and b.c's file 2 (after its own g.h) is h.h there, by the same number
    assert number != "2" and (0x20, f"v:G({number},1)", 0) in b and (0x20, "w:G(0,1)", 0) in b


def test_a_typedefs_anonymous_struct_numbered_apart_is_written_with_its_body():
    """GCC 2.95 for i386 writes `typedef struct { ... } Foo;` as Foo:t(1,1)=(1,2)=s...: the struct isn't one of its
    file's named types, and the header declared it without its body (64 fields of a 2001 Linux game incomplete)."""
    from decompnet.consoles.ps2 import cheader, stabs

    source = stabs.read_file("a.c", [(0x80, "int:t(0,1)=r(0,1);-2147483648;2147483647;", 0),
                                     (0x80, "Foo:t(1,1)=(1,2)=s4x:(0,1),0,32;;", 0),
                                     (0x80, "Bar:T(1,3)=s4f:(1,1),0,32;;", 0)])
    text = cheader.Header([source]).text()
    assert "struct Foo {" in text and "x; /* 0x0 */" in text and "Foo f; /* 0x0 */" in text



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


def test_a_switchs_jump_table_matches_and_the_export_rebuilds_it_where_the_program_keeps_it(demo):
    """A switch's jump table is the function's own .rodata, its words relocations into the function's code: the
    judge places them at the function's address (they were compared unrelocated: 99.9%, never a match), and the
    exported tree's build links the table where the program has it and rebuilds the program byte for byte."""
    import subprocess
    import sys

    net, slug = _imported(demo, "export")
    assert _match(net, slug, "entity_default_hp")["matched"]
    assert _match(net, slug, "clamp_s32")["matched"]
    res = net.export_rom(slug, log=lambda *_: None)
    assert res["identical"] and res["matched"] == 2, res["log"]
    out = Path(res["path"])
    assert "(2 of" in res["log"] and (out / "build" / "program").read_bytes() == demo[0].read_bytes()
    assert ".own0" in (out / "build" / "obj" / "entity_default_hp.ld").read_text()

    # a function written in the tree is checked against the original; a wrong one is refused
    [src] = (out / "src").glob("*/clamp_s32.c")
    src.write_text(src.read_text().replace("return v;", "return v + 1;"))
    bad = subprocess.run([sys.executable, "build.py", "check", "clamp_s32"], cwd=out, capture_output=True, text=True)
    assert bad.returncode != 0 and "differs from the original" in bad.stderr


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
