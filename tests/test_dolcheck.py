"""Where a built DOL differs from the game's, by symbol: a file that didn't link said only "main.dol: FAILED"."""

import struct

from decompnet.forks import dolcheck

SYMS = {"main": (".text", 0x80003100, 0x20), "table": (".data", 0x80004000, 0x8), "count": (".data", 0x80004008, 0x8)}


def dol(text: bytes, data: bytes, data_at: int = 0x80004000) -> bytes:
    head = bytearray(0x100)
    struct.pack_into(">I", head, 0x00, 0x100)
    struct.pack_into(">I", head, 0x48, 0x80003100)
    struct.pack_into(">I", head, 0x90, len(text))
    struct.pack_into(">I", head, 0x1C, 0x100 + len(text))
    struct.pack_into(">I", head, 0x64, data_at)
    struct.pack_into(">I", head, 0xAC, len(data))
    return bytes(head) + text + data


def test_the_first_bytes_that_differ_are_named_by_their_symbol():
    game = dol(bytes(range(0x20)), bytes(0x10))
    assert dolcheck.differences(game, game, SYMS) == []
    built = dol(bytes(range(0x20)), bytes(0xC) + b"\1" + bytes(3))
    assert dolcheck.differences(built, game, SYMS) == [".data count+0x4 (0x8000400C): 1 byte(s) differ"]


def test_a_section_that_grew_is_said_first():
    game = dol(bytes(range(0x20)), bytes(0x10))
    built = dol(bytes(range(0x20)), bytes(0x18))
    lines = dolcheck.differences(built, game, SYMS)
    assert lines[0].startswith("the section at 0x80004000 is 0x10 bytes in the game, 0x18")
