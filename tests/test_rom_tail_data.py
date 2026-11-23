"""#312: a switch's jump table can be tail data of an overlay, with no symbol of its own. spimdisasm writes `%hi`/`%lo`
only when it has a name for the address, so the function's `lui`/`lw` pair comes out as plain numbers and
target_from_split records no relocation. The judge still places the candidate's own .rodata at the ROM's table
address and compares its bytes there; a raw constant pair, which the candidate has no relocation for, stays as it is
(it isn't a data reference)."""

from pathlib import Path

import pytest

from decompnet import scoring, toolchains
from decompnet.compiler import compile_source
from decompnet.project import compiler_config
from decompnet.rom import match
from decompnet.rom.split import AsmLine, RomFunction
from decompnet.rom.symbols import Symbol, SymbolTable

pytestmark = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None,
                                reason="needs gcc-2.7.2-kmc to assemble the candidate")

VRAM, TABLE_OFFSET, ROM_BASE = 0x80129000, 0x10, 0x1000
TABLE = VRAM + TABLE_OFFSET  # right after the function: tail data of its overlay
TABLE_WORD = 0x12345678
HI, LO = (TABLE + 0x8000) >> 16, TABLE & 0xFFFF

# what IDO writes: the switch's table in the object's own .rodata, reached with a hi/lo pair through $at
CANDIDATE = r"""
asm(".set noreorder\n.set noat\n.text\n.globl pick\n.ent pick\npick:\n"
    "lui $at, %hi(tbl)\nlw $v0, %lo(tbl)($at)\njr $ra\nnop\n.end pick\n"
    ".section .rodata\ntbl:\n.word 0x12345678\n.text\n");
"""
CONSTANT = rf"""
asm(".set noreorder\n.set noat\n.text\n.globl pick\n.ent pick\npick:\n"
    "lui $at, {HI:#x}\nlw $v0, {LO - 0x10000}($at)\njr $ra\nnop\n.end pick\n");
"""


def _assemble(source):
    result = compile_source(compiler_config(Path("."), {"compiler": {"toolchain": "gcc-2.7.2-kmc"}}), "", source,
                            trusted=True)  # (a test's own assembly, not an agent's C)
    assert result.ok, result.log
    return result.obj


def _target():
    """The ROM's function, disassembled with raw immediates: spimdisasm had no symbol for the table."""
    words = [(0x0F << 26) | (1 << 16) | HI,  # lui $at, hi
             (0x23 << 26) | (1 << 21) | (2 << 16) | LO,  # lw $v0, lo($at)
             0x03E00008,  # jr $ra
             0]  # nop
    lines = [AsmLine(ROM_BASE + 4 * i, VRAM + 4 * i, word, ("lui", "lw", "jr", "nop")[i], "")
             for i, word in enumerate(words)]
    return RomFunction("pick", VRAM, ROM_BASE, "ovl", lines, Path("pick.s"))


def _judge(obj, table_word=TABLE_WORD):
    syms = SymbolTable([Symbol("pick", VRAM, 0x10, "func")])
    target = match.target_from_split(_target(), syms.resolve)
    code = b"".join(ln.word.to_bytes(4, "big") for ln in _target().lines)
    rom = bytearray(ROM_BASE + 0x100)
    rom[ROM_BASE:ROM_BASE + len(code)] = code
    rom[ROM_BASE + TABLE_OFFSET:ROM_BASE + TABLE_OFFSET + 4] = table_word.to_bytes(4, "big")

    def read(addr, n):
        if VRAM <= addr and addr + n <= VRAM + len(rom) - ROM_BASE:
            return bytes(rom[ROM_BASE + addr - VRAM:ROM_BASE + addr - VRAM + n])
        return None

    return match.link(obj, "pick", target, syms, read), target


def test_a_table_without_a_symbol_is_placed_at_the_roms_address():
    result, target = _judge(_assemble(CANDIDATE))
    assert target.relocs == []  # nothing annotated: where the bug started
    assert result.exact, result.problems
    assert result.placements[".rodata"][0] == TABLE  # its own table lands on the ROM's


def test_the_tables_bytes_are_still_compared_with_the_rom():
    result, _ = _judge(_assemble(CANDIDATE), table_word=TABLE_WORD ^ 0xFF)
    assert not result.exact
    assert any("differs from the ROM" in p for p in result.problems), result.problems


def test_no_relocation_is_invented_for_a_raw_constant():
    """A `lui`/`lw` pair loading a plain 32-bit constant has no relocation in the object, and the target has no
    annotation either: both stay without one, so the diff of a function that already matches doesn't change."""
    result, target = _judge(_assemble(CONSTANT))
    assert target.relocs == []
    assert result.exact, result.problems
    d = scoring.diff(match.canonical_target(target, SymbolTable([Symbol("pick", VRAM, 0x10, "func")])),
                     result.candidate)
    assert d.score == 0, [(r[1], r[2]) for r in d.rows if r[0]]
