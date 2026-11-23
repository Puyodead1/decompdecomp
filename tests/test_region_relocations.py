"""#221: a region the candidate defines (a helper the compiler keeps in a section of its own: C++'s inline functions
in .gnu.linkonce.t.*, a function with -ffunction-sections) is compared with the ROM after every relocation in it is
applied: its jal, its %hi/%lo and its $gp-relative loads, not only the pointers of a table. Left alone, a
$gp-relative immediate compared as the assembler's unrelocated 0 and a function right in every byte that matters
stayed one half-word short.

The candidates are assembled by hand (KMC GCC 2.7.2 ignores a function's section attribute), and the ROM each test
judges against is that object linked by the MIPS ABI's rules here, independently of match.py: each section in a
slot of its own, every relocation applied."""

import struct
from io import BytesIO
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from decompnet import toolchains
from decompnet.compiler import compile_source
from decompnet.project import compiler_config
from decompnet.rom import match
from decompnet.rom.symbols import Symbol, SymbolTable

pytestmark = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None, reason="needs gcc-2.7.2-kmc")

BASE, SLOT, GP = 0x80010000, 0x400, 0x80014000
G = GP - 0x100  # the game's own `g`, in its small data

# the function the game names: it calls `helper`, which its candidate keeps in a section of its own
CALLER = ('.text\\n.globl caller\\n.ent caller\\ncaller:\\naddiu $sp, $sp, -24\\nsw $ra, 16($sp)\\njal helper\\n'
          'nop\\nlw $ra, 16($sp)\\njr $ra\\naddiu $sp, $sp, 24\\n.end caller\\n')


def _source(*lines: str) -> str:
    return 'asm(".set noreorder\\n.set noat\\n' + CALLER + "".join(lines) + '");\n'


def _sext(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def _game(src, named=(), gp=GP, rom_patch=None):
    """Assemble `src` for a $gp game (-G8) and link the ROM it stands for. `named`: (name, address, bytes) the game
    has. `rom_patch`: section -> bytes the ROM has there instead. Returns (object, target, symbol table, read)."""
    cfg = compiler_config(Path("."), {"compiler": {"toolchain": "gcc-2.7.2-kmc",
                                                   "flags": ["-G8", "-mips3", "-mgp32", "-mfp32", "-O2"]}})
    result = compile_source(cfg, "", src, trusted=True)  # (a test's own assembly, not an agent's C)
    assert result.ok, result.log
    elf = ELFFile(BytesIO(result.obj))
    symtab = elf.get_section_by_name(".symtab")
    gp0 = struct.unpack_from(">i", elf.get_section_by_name(".reginfo").data(), 20)[0]
    progs = [s.name for s in elf.iter_sections() if s["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS") and s.name]
    at = {name: BASE + SLOT * i for i, name in enumerate(progs)}
    ext = {name: addr for name, addr, _ in named}

    def resolve(sym):
        if sym.name in ext:
            return ext[sym.name]
        sh = sym["st_shndx"]
        return at[elf.get_section(sh).name] + sym["st_value"] if isinstance(sh, int) else None

    def relocs_of(name):  # (offset, type, the address it means) of a section's relocations
        idx = elf.get_section_index(name)
        data = elf.get_section_by_name(name).data()
        rels = sorted((r for s in elf.iter_sections() if isinstance(s, RelocationSection) and s["sh_info"] == idx
                       for r in s.iter_relocations()), key=lambda r: r["r_offset"])

        def half(r):
            return int.from_bytes(data[r["r_offset"]:r["r_offset"] + 4], "big") & 0xFFFF

        out = []
        for i, r in enumerate(rels):
            sym = symtab.get_symbol(r["r_info_sym"])
            base = resolve(sym)
            if base is None:
                continue
            off, kind = r["r_offset"], r["r_info_type"]
            word = int.from_bytes(data[off:off + 4], "big")
            if kind == match.R_MIPS_26:
                base += (word & 0x03FFFFFF) << 2
            elif kind == match.R_MIPS_32:
                base += word
            elif kind == match.R_MIPS_GPREL16:  # S + A + GP0 for a local symbol
                base += _sext(word & 0xFFFF) + (gp0 if sym["st_info"]["bind"] == "STB_LOCAL" else 0)
            elif kind == match.R_MIPS_HI16:
                lo = next(q for q in rels[i + 1:] if q["r_info_type"] == match.R_MIPS_LO16
                          and q["r_info_sym"] == r["r_info_sym"])
                base += (half(r) << 16) + _sext(half(lo))
            elif kind == match.R_MIPS_LO16:
                hi = next(q for q in reversed(rels[:i]) if q["r_info_type"] == match.R_MIPS_HI16
                          and q["r_info_sym"] == r["r_info_sym"])
                base += (half(hi) << 16) + _sext(half(r))
            out.append((off, kind, base & 0xFFFFFFFF))
        return out

    def link(name):
        data = bytearray(elf.get_section_by_name(name).data())
        for off, kind, a in relocs_of(name):
            word = int.from_bytes(data[off:off + 4], "big")
            word = match._patch(word, kind, a, gp)  # (the field encodings: the same in every MIPS linker)
            data[off:off + 4] = word.to_bytes(4, "big")
        return data

    image = {at[n]: link(n) for n in progs if elf.get_section_by_name(n)["sh_type"] != "SHT_NOBITS"}
    for name, patch in (rom_patch or {}).items():
        image[at[name]][:len(patch)] = patch
    for _, addr, raw in named:
        image[addr] = bytearray(raw)

    def read(a, n):
        for b, data in image.items():
            if b <= a and a + n <= b + len(data):
                return bytes(data[a - b:a - b + n])
        return None

    code = bytes(image[at[".text"]][:28])
    target = match.RomTarget("caller", at[".text"], code, [r for r in relocs_of(".text") if r[0] < 28], True, gp)
    syms = SymbolTable([Symbol("caller", at[".text"], 28, "func"),
                        *(Symbol(name, addr, len(raw), "data") for name, addr, raw in named)])
    return result.obj, target, syms, read


def _judge(src, **kw):
    obj, target, syms, read = _game(src, **kw)
    return match.link(obj, "caller", target, syms, read)


def _types(obj, section):
    elf = ELFFile(BytesIO(obj))
    idx = elf.get_section_index(section)
    return {r["r_info_type"] for s in elf.iter_sections() if isinstance(s, RelocationSection) and s["sh_info"] == idx
            for r in s.iter_relocations()}


HELPER = '.section .fclone,\\"ax\\"\\nhelper:\\n'
S = '.section .sdata\\ns:\\n.word 0x11223344\\n'  # the helper's own small datum, reached through $gp


def test_a_gp_relative_load_of_the_games_datum_is_relocated():
    src = _source('.comm g, 4\\n', HELPER, 'lw $2, g\\njr $ra\\nnop\\n')  # (small common: the game's)
    named = [("g", G, (0x12345678).to_bytes(4, "big"))]
    assert match.R_MIPS_GPREL16 in _types(_game(src, named=named)[0], ".fclone")
    result = _judge(src, named=named)
    assert result.exact, result.problems


def test_a_helpers_call_to_its_neighbour_is_relocated():
    src = _source(HELPER, 'addiu $sp, $sp, -24\\nsw $ra, 16($sp)\\njal inner\\nnop\\nlw $ra, 16($sp)\\njr $ra\\n'
                  'addiu $sp, $sp, 24\\ninner:\\njr $ra\\nli $2, 0x42\\n')
    result = _judge(src)
    assert result.exact, result.problems


def test_a_helpers_own_datum_by_gp_is_placed_and_compared():
    src = _source(S, HELPER, 'lw $2, s\\njr $ra\\nnop\\n')
    assert match.R_MIPS_GPREL16 in _types(_game(src)[0], ".fclone")
    assert _judge(src).exact
    wrong = _judge(src, rom_patch={".sdata": bytes.fromhex("11223345")})
    assert not wrong.exact and any("11 22 33 44" in p for p in wrong.problems), wrong.problems


def test_a_gp_relative_load_on_a_game_without_gp_is_refused():
    result = _judge(_source(S, HELPER, 'lw $2, s\\njr $ra\\nnop\\n'), gp=0)
    assert not result.exact
    assert any("compile with -G0" in p for p in result.problems), result.problems


def test_a_helpers_lo_load_reads_only_its_width():
    """A helper loading t[0] of a 12-byte array through %hi/%lo matches though the ROM's unused t[1] and t[2]
    differ: the load's width is what's compared, as for the function's own code."""
    src = _source('.data\\nt:\\n.word 0x11223344, 0x55667788, 0x99AABBCC\\n', HELPER,
                  'lui $3, %hi(t)\\nlw $2, %lo(t)($3)\\njr $ra\\nnop\\n')
    assert {match.R_MIPS_HI16, match.R_MIPS_LO16} <= _types(_game(src)[0], ".fclone")
    result = _judge(src, rom_patch={".data": bytes.fromhex("11223344deadbeef01020304")})
    assert result.exact, result.problems


def test_the_widest_load_of_a_datum_is_compared():
    """A helper reading `s` as a byte and as a word compares all four bytes, not the first load's one."""
    src = _source(S, HELPER, 'lbu $3, s\\nlw $2, s\\njr $ra\\nnop\\n')
    result = _judge(src, rom_patch={".sdata": bytes.fromhex("11FFFFFF")})
    assert not result.exact
    assert any("11 22 33 44" in p for p in result.problems), result.problems


def test_a_helper_in_the_functions_own_text_is_refused():
    """A helper sharing the function's own .text the game doesn't name is refused, never matched unchecked."""
    result = _judge(_source('helper:\\njr $ra\\nli $2, 0x42\\n'))
    assert not result.exact
    assert any("not a known symbol" in p for p in result.problems), result.problems
