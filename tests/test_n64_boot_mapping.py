"""An N64 game whose boot stub maps its code through the TLB and returns: splat filed the stub and the code after it
as one main segment at the boot address. The code becomes a segment of its own at the address its calls agree on,
and only then: every uncertain or explicit layout stays as it was."""

import struct

import pytest
import yaml

from decompnet.consoles.n64 import code
from decompnet.rom.split import segments_from_config
from tests.test_n64code import _code

MAPPING = 0x801FF400  # where the stub maps the code (address minus ROM offset)


def layout(tmp_path, *, tlb=True, count=16, mapping=MAPPING, boot_padding=0):
    start = 0x1080
    boot = bytes(boot_padding) + struct.pack(">4I", code.TLBWI if tlb else 0, 0, 0x03E00008, 0)
    body = _code(start + len(boot) + mapping, count)
    end = start + len(boot) + len(body)
    later = end + 0x100
    rom = bytes(start) + boot + body + bytes(0x100) + _code(later + mapping, 16)
    cfg = {"options": {"platform": "n64"}, "segments": [
        {"name": "entry", "type": "code", "start": 0x1000, "vram": 0x80000400, "subsegments": [[0x1000, "hasm"]]},
        {"name": "main", "type": "code", "start": start, "vram": start + 0x7FFFF400, "follows_vram": "entry",
         "subsegments": [[start, "c", "main"]]},
        {"type": "bin", "start": end},
        {"name": "later", "type": "code", "start": later, "vram": later + mapping,
         "subsegments": [[later, "c", "later"]]},
        [len(rom)]]}
    path = tmp_path / "game.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    return path, rom, start + len(boot), end


def quiet(_):
    pass


def test_the_code_after_a_tlb_stub_gets_the_address_its_calls_agree_on(tmp_path):
    path, rom, start, end = layout(tmp_path)
    assert code.separate_boot(path, rom, [], log=quiet)
    segments = segments_from_config(path)
    boot = next(s for s in segments if s.name == "main")
    found = next(s for s in segments if s.name.startswith("code_"))
    assert (boot.rom_end, boot.vram) == (start, 0x80000480)
    assert (found.rom_start, found.rom_end, found.vram) == (start, end, start + MAPPING)
    saved = path.read_bytes()
    assert not code.separate_boot(path, rom, [], log=quiet)  # (done once)
    assert path.read_bytes() == saved


@pytest.mark.parametrize("case", ["no_tlb", "few_calls", "right_already", "explicit_data", "no_return", "overlap",
                                  "ambiguous", "earlier_leaf", "earlier_frame", "explicit_bss", "late_return"])
def test_uncertain_or_explicit_layouts_stay(tmp_path, case):
    path, rom, start, end = layout(tmp_path, tlb=case != "no_tlb", count=4 if case == "few_calls" else 16,
                                   mapping=0x7FFFF400 if case == "right_already" else MAPPING,
                                   boot_padding=0x1000 if case == "late_return" else 0)
    cfg = yaml.safe_load(path.read_text())
    if case == "explicit_data":
        cfg["segments"][1]["subsegments"].append([end - 4, "data"])
    if case == "no_return":
        rom = rom[:start - 8] + bytes(4) + rom[start - 4:]
    if case == "earlier_frame":
        rom = rom[:start - 12] + struct.pack(">I", 0x27BDFFE8) + rom[start - 8:]
    if case == "explicit_bss":
        cfg["segments"][1]["bss_size"] = 0x100
    if case == "overlap":
        cfg["segments"][3]["vram"] = start + MAPPING
    if case == "ambiguous":  # the same functions called at a second address known code has too: no one answer
        alias = 0x802FF400
        words = list(struct.unpack(f">{len(rom) // 4}I", rom))
        for offset in range(start, end, 32):
            words[(offset + 12) // 4] = 0x0C000000 | (((offset + alias) >> 2) & 0x03FFFFFF)
        rom = struct.pack(f">{len(words)}I", *words)
        cfg["segments"].insert(-1, {"name": "alias", "type": "code", "start": len(rom) - 4, "vram": len(rom) - 4 + alias,
                                    "subsegments": [[len(rom) - 4, "c", "alias"]]})
    if case == "earlier_leaf":  # something called before the first frame: cutting at the frame would lose it
        words = bytearray(rom)
        struct.pack_into(">I", words, start + 12, 0x0C000000 | (((start - 8 + MAPPING) >> 2) & 0x03FFFFFF))
        rom = bytes(words)
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    before = path.read_bytes()
    assert not code.separate_boot(path, rom, [], log=quiet)
    assert path.read_bytes() == before


def test_finding_segments_separates_it_with_nothing_else_found(tmp_path, monkeypatch):
    path, rom, start, end = layout(tmp_path)
    (tmp_path / "rom.z64").write_bytes(rom)
    monkeypatch.setattr(code, "unpack_code", lambda _: [])
    monkeypatch.setattr(code, "find_segments", lambda *_: [])
    assert code.add_segments(path, tmp_path, "rom.z64", log=quiet) == "rom.z64"
    assert any((s.rom_start, s.rom_end, s.vram) == (start, end, start + MAPPING) for s in segments_from_config(path))


def test_the_address_can_come_from_code_found_later(tmp_path):
    path, rom, start, end = layout(tmp_path)
    cfg = yaml.safe_load(path.read_text())
    later = cfg["segments"][3]
    cfg["segments"][3] = {"type": "bin", "start": later["start"]}
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    assert code.separate_boot(path, rom, [(later["start"], len(rom), later["vram"])], log=quiet)
    assert any((s.rom_start, s.rom_end) == (start, end) for s in segments_from_config(path))
