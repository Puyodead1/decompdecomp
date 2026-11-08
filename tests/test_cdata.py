"""A variable's value written as C from the program's bytes, by its debug information's type (cdata.py)."""

import struct

import pytest

from decompnet import cdata
from decompnet.consoles.ps2.cheader import Header
from decompnet.consoles.ps2.stabs import Field, SourceInfo, Type

INT = Type(kind="base", name="int", size=4)
UINT = Type(kind="base", name="unsigned int", size=4, signed=False)
SHORT = Type(kind="base", name="short int", size=2)
CHAR = Type(kind="base", name="char", size=1)
FLOAT = Type(kind="float", name="float", size=4)
POINT = Type(kind="struct", tag="Point", size=4, fields=[Field("x", SHORT, 0, 16), Field("y", SHORT, 16, 16)])
# a struct with a gap the header pads (a float at 8, after an int), a nested struct, an array and a bitfield
THING = Type(kind="struct", tag="Thing", size=24, fields=[
    Field("id", INT, 0, 32), Field("speed", FLOAT, 64, 32), Field("at", POINT, 96, 32),
    Field("name", Type(kind="array", count=4, target=CHAR, size=4), 128, 32), Field("flags", UINT, 160, 3),
    Field("mode", UINT, 163, 5)])
VALUE = Type(kind="union", tag="Value", size=4, fields=[Field("i", INT, 0, 32), Field("f", FLOAT, 0, 32)])


def _writer(pointer=lambda word, t: None):
    header = Header([SourceInfo("t.c", types=[POINT, THING, VALUE])])
    return header, cdata.Writer(header, pointer)


def test_a_struct_is_written_by_its_members_names_and_zeros_are_left_to_c():
    """Designated, as the header names the members: its padding member stays out, a zero member isn't written, a
    bitfield is its bits, a char array its string."""
    h, w = _writer()
    data = struct.pack("<iI f hh 4s I", 7, 0, 2.5, 3, 0, b"ab", 5 | (2 << 3))
    assert w.value(THING, data, 0) == '{ .id = 7, .speed = 2.5f, .at = { .x = 3 }, .name = "ab", .flags = 5, .mode = 2 }'
    assert w.value(THING, bytes(24), 0) == "{ 0 }"
    # an array: the zeros after its last element are C's
    arr = Type(kind="array", count=4, target=INT, size=16)
    assert w.value(arr, struct.pack("<4i", 1, 0, -2, 0), 0) == "{ 1, 0, -2 }"
    # a union by the first member that holds the value
    assert w.value(VALUE, struct.pack("<f", 1.0), 0) == "{ .i = 1065353216 }"


def test_a_pointer_is_what_it_points_at_or_the_value_stays_the_programs():
    h, w = _writer(lambda word, t: "&g_thing" if word == 0x8049000 else None)
    ptr = Type(kind="pointer", target=THING, size=4)
    assert w.value(ptr, struct.pack("<I", 0x8049000), 0) == "&g_thing"
    assert w.value(ptr, bytes(4), 0) == "0"
    with pytest.raises(cdata.Unwritable):
        w.value(ptr, struct.pack("<I", 0x8050000), 0)
    # data in a struct's padding can't be written: the variable stays the program's
    with pytest.raises(cdata.Unwritable):
        w.value(THING, struct.pack("<iI", 1, 9) + bytes(16), 0)


def test_strings_and_numbers_are_exact():
    assert cdata.string_literal(b'say "hi"\n\x1b1') == '"say \\"hi\\"\\n\\033""1"'
    assert cdata._int(-(1 << 31), 4, True) == "(-2147483647 - 1)" and cdata._int(0xFFFFFFFF, 4, False) == "0xFFFFFFFFU"
    h = Header([SourceInfo("t.c", types=[THING])])
    const = cdata.constant(h, Type(kind="array", count=2, target=Type(kind="pointer", target=CHAR, size=4), size=8))
    assert h.declaration(const, "names") == "char *const names[2]"  # (the array's elements: .rodata)


def test_a_constant_holds_every_string_the_c_reaches_as_an_offset_from_its_name():
    """A file's strings read as `D_0809F05A + 0x87` (one label, each string's offset in the pool): the copy is cut
    at 32 bytes no more, or the strings after it are whatever the new link put there (an assert's fopen failed)."""
    from decompnet.consoles.linux import export_data

    pool = b"GameInit\0gameloop.c\0" + bytes(108) + b"%sstartseg.txt\0rt\0" + bytes(64)
    base = 0x0809F05A

    class Pool:
        def section(self, address):
            return ".rodata" if base <= address < base + len(pool) else None

        def variable_at(self, address):
            return None

        def next_symbol(self, address):
            return base + len(pool)

        def read(self, address, size):
            at = address - base
            return pool[at:at + size] if 0 <= at and at + size <= len(pool) else None

    code = ("#define str_function (D_0809F05A)\n#define str_startseg (D_0809F05A + 0x80)\n"
            "#define str_rt (D_0809F05A + 0x8f)\nvoid f(void) { g(str_function, str_startseg, str_rt); }\n")
    [found] = export_data.constants(Pool(), code, lambda a: None, None)
    assert found.size == 0x8f + 3 and found.text.startswith("char D_0809F05A_data[146] = { 71, 97,")
