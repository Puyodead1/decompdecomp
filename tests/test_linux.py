"""Linux (32-bit x86) programs: what the console recognises, its STABS reader and its judge's placement rule. A
real game's run (Slackware 8.0's GCC 2.95.3 reproducing its functions byte for byte) needs the game, so the end to end
check is the demo program built with the same toolchain (projects/demo-linux, and tests/test_consoles.py)."""

import re
import struct

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


def test_the_demos_struct_comes_from_its_debug_information_and_names_are_c_identifiers(tmp_path):
    """Demo Quest built -g: guess_struct answers with the STABS prototype's type, field for field, and GCC's static
    locals (`mark.21`) get C names an agent can write and a save can store."""
    import json
    import subprocess
    import sys

    from decompnet.app.engine import RomNetwork

    from .test_consoles import ROOT, _missing

    console = consoles.get("linux")
    if (missing := _missing(console)):
        pytest.skip(f"{console.name}'s demo needs {', '.join(missing)}")
    folder = ROOT / "projects" / console.demo
    if not (folder / "build" / "demo.json").exists():
        subprocess.run([sys.executable, str(folder / "build.py")], check=True)
    built = json.loads((folder / "build" / "demo.json").read_text())
    net = RomNetwork(tmp_path / "app.db", tmp_path)
    slug = net.import_rom(folder / "build" / built["game"], confirmed=True, log=lambda *_: None)
    text = net.guess_struct(slug, "entity_update_physics", "arg0")
    assert "`void entity_update_physics(Entity *e)`" in text and "int hp; /* 0x18 */" in text
    pid = net.project_row(slug)["id"]
    names = [r["name"] for r in net.store.all("SELECT name FROM functions WHERE project_id=?", pid)]
    assert names and all(re.fullmatch(r"[A-Za-z_]\w*", n) for n in names)
