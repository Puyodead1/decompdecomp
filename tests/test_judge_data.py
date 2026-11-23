"""The ROM judge compares a candidate's own data (jump tables, strings, constants) with the game's: it reads them
through the image the code's segment loads when no code segment holds their address (a racing game's switches
matched with wrong case labels while the read found nothing there and skipped the check)."""

from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from elftools.elf.elffile import ELFFile

from decompnet import toolchains
from decompnet.app.engine.core import Core
from decompnet.app.engine.judging import JudgeMixin
from decompnet.compiler import compile_source
from decompnet.elfobj import section_target
from decompnet.project import compiler_config
from decompnet.rom import match, split
from decompnet.rom.split import Segment
from decompnet.rom.symbols import Symbol, SymbolTable

CONFIG = {"segments": [
    {"name": "header", "type": "header", "start": 0},
    {"name": "main", "type": "code", "start": 0x1050, "vram": 0x80000450,
     "subsegments": [[0x1050, "c", "main"], {"type": "bss", "vram": 0x80000850}]},
    {"name": "code_80000500", "type": "code", "start": 0x1100, "vram": 0x80000500,
     "subsegments": [[0x1100, "c", "code_80000500"]]},
    {"type": "bin", "start": 0x1200},
    [0x1400]]}


def test_a_code_segment_with_its_bss_loads_its_data_too(tmp_path: Path):
    assert split.load_images(CONFIG) == [(0x1050, 0x80000450, 0x80000850)]
    assert split.load_images({"segments": [{"type": "code", "start": 0, "vram": 0x80000000}]}) == []
    (tmp_path / "game.yaml").write_text(yaml.safe_dump(CONFIG))
    assert split.load_images_of(tmp_path) == [(0x1050, 0x80000450, 0x80000850)]
    assert split.load_images_of(tmp_path / "missing") == []


def _engine(rom, segments, images):
    net = object.__new__(Core)
    net._roms = {1: (bytes(rom), segments)}
    net._images = {1: images}
    return net


def test_the_reader_finds_data_after_the_code_and_nothing_in_bss(tmp_path: Path):
    rom = bytes(range(256)) * 32
    (tmp_path / "game.yaml").write_text(yaml.safe_dump(CONFIG))
    net = object.__new__(Core)
    net._roms = {1: (rom, split.segments_from_config(tmp_path / "game.yaml"))}
    read = net.reader({"id": 1, "root": str(tmp_path)})
    assert read(0x80000600, 4) == rom[0x1200:0x1204]  # after the last code segment, in main's image
    assert read(0x80000460, 4) == rom[0x1060:0x1064]  # code reads as before
    assert read(0x80000900, 4) is None  # BSS: no bytes in the ROM


def test_overlays_at_one_address_read_the_callers_own_image():
    rom = b"\0" * 0x100 + b"AAAA" + b"\0" * 0xFC + b"BBBB"
    images = [(0x0, 0x1000, 0x1200), (0x100, 0x1000, 0x1200)]
    net = _engine(rom, [Segment("a", 0x0, 0x10, 0x1000), Segment("b", 0x100, 0x110, 0x1000)], images)
    caller = {"name": "f", "vram": 0x1000, "size": 4, "rom_offset": 0x100}
    assert net.reader({"id": 1}, caller)(0x1100, 4) == b"BBBB"
    assert net.reader({"id": 1})(0x1100, 4) is None  # no caller to choose an image: unknown, as before


needs_gcc = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None,
                               reason="needs gcc-2.7.2-kmc to compile the candidate")

SOURCE = """
int pick(unsigned int x) {
    switch (x) {
    case 0: return 11;
    case 1: return 22;
    case 2: return 33;
    case 3: return 44;
    case 4: return 55;
    case 5: return 66;
    case 6: return 77;
    case 7: return 88;
    default: return 0;
    }
}
"""
NAME = "pick"
VRAM = 0x80001000
RODATA = 0x200  # the jump table, after the code and past the code segment's end
ROM_AT = 0x1000


def _candidate():
    result = compile_source(compiler_config(Path("."), {"compiler": {"toolchain": "gcc-2.7.2-kmc"}}), "", SOURCE)
    assert result.ok, result.log
    elf = ELFFile(BytesIO(result.obj))
    fn = next(s for s in elf.get_section_by_name(".symtab").iter_symbols() if s.name == NAME)
    shndx = {s.name: i for i, s in enumerate(elf.iter_sections()) if s.name in (".text", ".rodata")}
    vram = {shndx[".text"]: VRAM, shndx[".rodata"]: VRAM + RODATA}
    text = bytearray(elf.get_section_by_name(".text").data()[:fn["st_size"]])
    rodata = bytearray(elf.get_section_by_name(".rodata").data())
    relocs = []
    raw = match.raw_relocs(elf, shndx[".text"], fn["st_value"], fn["st_size"], bytes(text))
    for k, r in enumerate(raw):
        sym = r["symtab"].get_symbol(r["symidx"])
        dest = vram[sym["st_shndx"]] + sym["st_value"] + section_target("mips", raw, k)
        relocs.append((r["off"], r["type"], dest))
        at = r["off"]
        text[at:at + 4] = match._patch(int.from_bytes(text[at:at + 4], "big"), r["type"], dest).to_bytes(4, "big")
    for r in match.raw_relocs(elf, shndx[".rodata"], 0, len(rodata), bytes(rodata)):
        if r["type"] == match.R_MIPS_32:
            sym = r["symtab"].get_symbol(r["symidx"])
            rodata[r["off"]:r["off"] + 4] = (vram[sym["st_shndx"]] + sym["st_value"] + r["value"]).to_bytes(4, "big")
    rom = bytearray(ROM_AT) + bytes(text).ljust(RODATA, b"\0") + bytes(rodata) + bytes(0x100)
    target = match.RomTarget(NAME, VRAM, bytes(text), relocs)
    return result.obj, target, rom, len(text)


def _judge(obj, target, rom, size):
    # the code segment ends with the code; the image (to the BSS) holds the table
    net = _engine(rom, [Segment("main", ROM_AT, ROM_AT + size, VRAM)], [(ROM_AT, VRAM, VRAM + 0x400)])
    net.is_rom = lambda proj: True
    net.console = lambda proj: SimpleNamespace(link_function=match.link)
    net._rom_target = lambda fn: target
    net.symbols = lambda project_id: SymbolTable([Symbol(NAME, VRAM, size, "func")])
    fn = {"name": NAME, "vram": VRAM, "size": size, "rom_offset": ROM_AT}
    return JudgeMixin._evaluate(net, fn, {"id": 1}, obj)


@needs_gcc
def test_the_right_jump_table_matches():
    obj, target, rom, size = _candidate()
    _, exact, problems = _judge(obj, target, rom, size)
    assert exact, problems


@needs_gcc
def test_a_wrong_jump_table_past_the_code_segment_is_rejected():
    obj, target, rom, size = _candidate()
    at = ROM_AT + RODATA + 4  # case 1's label
    rom[at:at + 4] = rom[ROM_AT + RODATA + 8:ROM_AT + RODATA + 12]  # points at case 2's code instead
    _, exact, problems = _judge(obj, target, rom, size)
    assert not exact and any("differs from the ROM" in p for p in problems), problems
