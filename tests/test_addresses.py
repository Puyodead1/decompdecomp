"""Addresses matched C writes as numbers, named for what the game holds there (addresses.py)."""

import struct

from decompnet import addresses
from decompnet.rom.symbols import Symbol, SymbolTable

RODATA, DATA, TEXT = 0x8001000, 0x8002000, 0x8003000
HEADER = """typedef float f32;
typedef struct { int a; f32 speed; } Settings;
extern Settings g_settings;
typedef struct { int timer; } Wave;
void tick(void);
"""


def _program() -> addresses.Program:
    memory = {RODATA: b"Hello \"you\"\n\0", RODATA + 0x10: struct.pack("<f", 1.5),
              RODATA + 0x18: struct.pack("<d", 0.1), RODATA + 0x20: struct.pack("<f", 90.0),
              DATA + 0x10: b"buffer text\0"}
    image = bytearray(0x3000)
    for at, data in memory.items():
        image[at - RODATA:at - RODATA + len(data)] = data

    def read(address: int, n: int) -> bytes | None:
        at = address - RODATA
        return bytes(image[at:at + n]) if 0 <= at and at + n <= len(image) else None

    def section(address: int) -> str | None:
        return {RODATA: ".rodata", DATA: ".data", TEXT: ".text"}.get(address & ~0xFFF)
    symbols = SymbolTable([Symbol("g_settings", DATA, 8, "data"), Symbol("buf", DATA + 0x10, 16, "data"),
                           Symbol("timer", DATA + 0x20, 0x800, "bss"), Symbol("tick", TEXT, 16, "func"),
                           Symbol("D_08002900", DATA + 0x900, 4, "data")])
    return addresses.Program(read, section, symbols, HEADER)


SOURCE = """#include "common.h"

void f(Wave *w) {
    printf((char *) 0x8001000);
    x = *((float *) 0x8001010) * *(double *)0x8001018 + *(f32 *)0x8001020;
    y = *(float *)0x8002004;
    z = *(int *)0x8002014;
    w->timer = *(int *)0x8002020;
    cb = (void *)0x8003000;
    s = (char *)0x8002010;
    n = *(int *)0x8001010;
    u = *(int *)0x8002900;
}
"""


def test_each_address_is_named_for_what_the_game_holds_there():
    """A read-only string is its literal, a float or double constant its value, a global (or its field, by the
    header's struct) its name, a function its name; a writable buffer that starts with text is the buffer."""
    found = addresses.proposals(SOURCE, _program())
    out = addresses.apply(SOURCE, found)
    assert 'printf("Hello \\"you\\"\\n");' in out
    assert "x = 1.5f * 0.1 + 90.0f;" in out
    assert "y = g_settings.speed;" in out
    assert "z = *(int *)((char *)&buf + 0x4);" in out and "\nextern char buf[];\n" in out
    # (the header's `timer` is a field of Wave: the global needs declaring)
    assert "w->timer = *(int *)&timer;" in out and "extern char timer[];" in out
    assert "cb = (void *)tick;" in out and "void tick();" not in out  # (the header declares it)
    assert "s = (char *)&buf;" in out
    # what nothing names (an integer constant GCC would make an immediate, a name the tools made up) is the
    # address's generated name, which the judge and the export resolve to it
    assert "n = *(int *)D_08001010;" in out and "u = *(int *)D_08002900;" in out
    assert "extern char D_08001010[];" in out
    assert out.index('#include "common.h"') < out.index("extern char buf[];") < out.index("void f(")
    assert addresses.numbers(out) == 0
    # and a named one that doesn't match (GCC sees the global it already reads) has it to fall back on
    [timer] = [p for p in found if p.text == "*(int *)&timer"]
    assert timer.fallback.text == "*(int *)D_08002020"


def test_literals_are_exact():
    assert addresses.c_float(0.1, True) == "0.1f" and addresses.c_float(90.0, True) == "90.0f"
    assert addresses.c_float(1.1736000235915185, False) == "1.1736000235915185"
    assert struct.pack("<f", float(addresses.c_float(1 / 3, True)[:-1])) == struct.pack("<f", 1 / 3)
    assert addresses.c_float(float("inf"), True) is None
    assert addresses.c_string(b"a\tb\x1b1\\") == '"a\\tb\\0331\\\\"'


def test_the_x86_judge_compares_a_loaded_constant_as_far_as_the_code_loads_it():
    """`flds` loads 4 bytes, `fldl` 8; an address pushed (a string passed) isn't a load: all of its datum counts."""
    from decompnet.arch.x86_link import load_widths

    code = bytes.fromhex("d905c0900a08" "dd05c8900a08" "68d0900a08" "8d05d8900a08")
    assert load_widths(code) == {2: 4, 8: 8}


def test_a_callbacks_address_is_its_functions_name():
    """`(void (*)())0x805bc24` and qsort's `(int (*)(const void *, const void *))0x8080c24` stayed numbers: a
    relinked program jumped into code it doesn't load."""
    source = "void f(void) { cb = (void (*)())0x8003000; qsort(a, n, 4, (int (*)(const void *, const void *))0x8003000); }"
    out = addresses.apply(source, addresses.proposals(source, _program()))
    assert out == "void f(void) { cb = (void (*)())tick; qsort(a, n, 4, (int (*)(const void *, const void *))tick); }"
    assert addresses.numbers(source) == 2 and addresses.numbers(out) == 0
