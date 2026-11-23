"""spimdisasm writes the %lo of an address 64 KB or more past its symbol as `%lo(sym + (0x12340 & 0xFFFF))`. The ROM
target missed that relocation, so its diff showed the low half as a number against the candidate's relocation
(and the candidate's own data there had no address). It's read when a %hi before it names the full address and the
instruction's own bits agree; a target imported before shows the pair completed in its diff, never in what's
linked."""

import struct
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.rom import match, split
from decompnet.rom.symbols import Symbol, SymbolTable

BASE = 0x80012000
ADDRESS = BASE + 0x12340
WORDS = (0x3C048002, 0x8C844340)  # lui $a0, 0x8002; lw $a0, 0x4340($a0)


def function(words=WORDS, operand="%lo(table + (0x12340 & 0xFFFF))", between=()):
    lines = [split.AsmLine(0, 0x80001000, words[0], "lui", "$a0, %hi(table + 0x12340)")]
    for word in between:
        lines.append(split.AsmLine(4 * len(lines), 0x80001000 + 4 * len(lines), word, "addiu", "$v0, $zero, 1"))
    lines.append(split.AsmLine(4 * len(lines), 0x80001000 + 4 * len(lines), words[1], "lw", f"$a0, {operand}($a0)"))
    return split.RomFunction("example", 0x80001000, 0, "code", lines, Path("example.s"))


@pytest.mark.parametrize("big", [True, False])
@pytest.mark.parametrize("mask", ["0xFFFF", "0xffff", "65535"])
def test_a_masked_low_takes_the_address_its_high_names(big, mask):
    target = match.target_from_split(function(operand=f"%lo(table + (0x12340 & {mask}))"), {"table": BASE}.get, big)
    assert target.relocs == [(0, 5, ADDRESS), (4, 6, ADDRESS)]
    assert target.code == struct.pack(">II" if big else "<II", *WORDS)


def test_a_masked_low_scheduled_away_from_its_high_is_read_too():
    target = match.target_from_split(function(between=(0x24020001,)), {"table": BASE}.get)
    assert target.relocs == [(0, 5, ADDRESS), (8, 6, ADDRESS)]


@pytest.mark.parametrize("operand", ["%lo(table + (0x12340 & 0xff))", "%lo(table + (0x12340 & 0x1ffff))",
                                     "%lo(table + (index & 0xffff))", "%lo(other + (0x12340 & 0xffff))"])
def test_what_doesnt_prove_the_address_adds_nothing(operand):
    target = match.target_from_split(function(operand=operand), {"table": BASE, "other": BASE + 4}.get)
    assert target.relocs == [(0, 5, ADDRESS)]


def test_a_low_whose_bits_disagree_adds_nothing():
    target = match.target_from_split(function((WORDS[0], 0x8C844344)), {"table": BASE}.get)
    assert target.relocs == [(0, 5, ADDRESS)]


@pytest.mark.parametrize("base,sign,addend,high,low,opcode", [
    (0x80012000, "+", 0x1D340, 0x3C048003, 0x2484F340, "addiu"),
    (0x80048000, "-", 0x12340, 0x3C048003, 0x8C845CC0, "lw"),
])
def test_a_signed_low_and_a_negative_addend(base, sign, addend, high, low, opcode):
    fn = function((high, low), f"%lo(table {sign} (0x{addend:x} & 0xffff))")
    fn.lines[0].operands = f"$a0, %hi(table {sign} 0x{addend:x})"
    fn.lines[1].mnemonic = opcode
    address = base + (addend if sign == "+" else -addend)
    assert match.target_from_split(fn, {"table": base}.get).relocs == [(0, 5, address), (4, 6, address)]


def test_a_plain_addend_and_a_missing_high():
    assert match.target_from_split(function(operand="%lo(table + 0x12340)"), {"table": BASE}.get).relocs == \
        [(0, 5, ADDRESS), (4, 6, ADDRESS)]
    fn = function()
    fn.lines[0].operands = "$a0, 0x8002"
    assert match.target_from_split(fn, {"table": BASE}.get).relocs == []


@pytest.mark.parametrize("big", [True, False])
def test_an_older_targets_diff_shows_the_pair_without_changing_the_target(big):
    code = struct.pack(">II" if big else "<II", *WORDS)
    target = match.RomTarget("example", 0x80001000, code, [(0, 5, ADDRESS)], big)
    symbols = SymbolTable([Symbol("table", BASE, 0x20000)])
    complete = match.RomTarget("example", target.vram, code, [(0, 5, ADDRESS), (4, 6, ADDRESS)], big)
    assert match.canonical_target(target, symbols) == match.canonical_target(complete, symbols)
    assert target.relocs == [(0, 5, ADDRESS)]


@pytest.mark.parametrize("words", [(0x3C048002, 0x8CA44340), (0x3C048003, WORDS[1]), (WORDS[0], 0x10804340)])
def test_an_older_targets_pair_that_doesnt_prove_it_stays(words):
    target = match.RomTarget("example", 0x80001000, struct.pack(">II", *words), [(0, 5, ADDRESS)])
    assert match._display_relocs(target) == target.relocs


def test_an_existing_low_stays_and_a_clobbered_high_isnt_completed():
    target = match.RomTarget("example", 0x80001000, struct.pack(">II", *WORDS), [(0, 5, ADDRESS), (4, 6, ADDRESS + 4)])
    assert match._display_relocs(target) == target.relocs
    for middle in (0, 0x24040000, 0x10800001):
        target = match.RomTarget("example", 0x80001000, struct.pack(">III", WORDS[0], middle, WORDS[1]),
                                 [(0, 5, ADDRESS)])
        assert match._display_relocs(target) == target.relocs


@pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None, reason="needs gcc-2.7.2-kmc")
def test_the_diff_completion_leaves_the_judges_verdict_alone():
    from decompnet.compiler import compile_source
    from decompnet.project import compiler_config

    source = ('asm(".set noreorder\\n.text\\n.globl example\\n.ent example\\nexample:\\n'
              'lui $a0, %hi(table + 0x12340)\\nlw $a0, %lo(table + 0x12340)($a0)\\njr $ra\\nnop\\n.end example\\n");\n')
    obj = compile_source(compiler_config(Path("."), {"compiler": {"toolchain": "gcc-2.7.2-kmc"}}), "", source,
                         trusted=True).obj  # (a test's own assembly)
    symbols = SymbolTable([Symbol("table", BASE, 0x20000)])
    code = struct.pack(">IIII", *WORDS, 0x03E00008, 0)
    for words, expected in [(code, True), (code[:-4] + b"\0\0\0\1", False)]:
        target = match.RomTarget("example", 0x80001000, words, [(0, 5, ADDRESS)])
        before = match.link(obj, "example", target, symbols, lambda *_: None)
        match.canonical_target(target, symbols)
        after = match.link(obj, "example", target, symbols, lambda *_: None)
        assert before.exact is after.exact is expected
        assert target.relocs == [(0, 5, ADDRESS)] and target.code == words
