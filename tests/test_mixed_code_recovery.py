"""Functions splat left as `.word`s after a word that isn't an instruction are found through the calls into them, and
only when what's there is plainly one compiled function: never from an instruction pattern alone, never in
explicit data, and never at the cost of a function found before."""

import struct

import pytest
import yaml

from decompnet.arch.mips_recovery import called_extent
from decompnet.consoles import get
from decompnet.rom import mixed_code

BASE = 0x80001000
# addiu sp, -24; sw ra; li v0, 7; lw ra; jr ra; addiu sp, 24
BODY = [0x27BDFFE8, 0xAFBF0014, 0x24020007, 0x8FBF0014, 0x03E00008, 0x27BD0018]
INVALID = 0x7000003F  # (sdbbp: no instruction the VR4300 has)


def packed(words, big=True):
    return struct.pack(f"{'>' if big else '<'}{len(words)}I", *words)


def quiet(_):
    pass


@pytest.mark.parametrize("big", [True, False])
def test_a_called_function_needs_valid_words_one_frame_and_balanced_returns(big):
    data = packed(BODY, big)
    assert called_extent(data, 0, len(data), BASE, big_endian=big) == len(data)
    for words in (BODY[:-1], BODY[:-1] + [0x27BD0010], BODY[:2] + [INVALID] + BODY[3:],
                  BODY[:2] + [0x27BDFFE8] + BODY[3:],  # a second frame
                  BODY[:2] + [0x40906000] + BODY[3:],  # mtc0: hand-written
                  BODY[:2] + [0x10001000] + BODY[3:],  # a branch out of it
                  BODY[:2] + [0x1000FFFD, 0] + BODY[4:]):  # a branch back to its frame
        data = packed(words, big)
        assert called_extent(data, 0, len(data), BASE, big_endian=big) is None


def asm(path, words, start, *, raw=False, big=True):
    """A file of splat's: a function (glabel) or text left as data (dlabel, .words)."""
    import rabbitizer

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["dlabel dropped" if raw else "glabel caller"]
    for i, w in enumerate(words):
        mnemonic = ".word" if raw else rabbitizer.Instruction(w).getOpcodeName()
        lines.append(f"/* {start + i * 4:X} {BASE + start + i * 4:08X} {w.to_bytes(4, 'big' if big else 'little').hex().upper()} */ {mnemonic} 0")
    path.write_text("\n".join(lines) + "\n")


def project(tmp_path, *, call=True, explicit=False, overlap=False, console_id="n64"):
    console = get(console_id)
    big = console.big_endian
    caller = [0x27BDFFE8, 0xAFBF0014, 0x0C000000 | ((BASE + 0x40) >> 2) & 0x3FFFFFF if call else 0, 0,
              0x8FBF0014, 0x27BD0018, 0x03E00008, 0]
    words = caller + [INVALID] * 8 + BODY + [0] * 10
    rom = packed(words, big)
    (tmp_path / "rom.bin").write_bytes(rom)
    cfg = {"options": {}, "segments": [{"name": "unit", "type": "code", "start": 0, "vram": BASE, "subsegments":
                                        [[0, "c", "unit"]] + ([[32, "data", "data"]] if explicit else [])}, [len(rom)]]}
    if overlap:  # another segment at the called address
        cfg["segments"].insert(-1, {"name": "overlay", "type": "code", "start": len(rom) - 4, "vram": BASE + 0x40,
                                    "subsegments": [[len(rom) - 4, "c", "overlay"]]})
    path = tmp_path / "game.yaml"
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    asm(tmp_path / "asm/nonmatchings/unit/caller.s", caller, 0, big=big)
    asm(tmp_path / "asm/nonmatchings/unit/dropped.s", words[8:], 32, raw=True, big=big)
    return path, console


@pytest.mark.parametrize("console_id", ["n64", "ps", "ps2", "psp"])
def test_only_called_text_no_function_has_gets_file_boundaries(tmp_path, console_id):
    path, console = project(tmp_path, console_id=console_id)
    said = []
    assert mixed_code.refine(path, tmp_path, "rom.bin", console, log=said.append)
    subs = yaml.safe_load(path.read_text())["segments"][0]["subsegments"]
    assert [s[0] for s in subs] == [0, 0x20, 0x40, 0x58]  # the caller kept whole, the called function cut out
    assert subs[0] == [0, "c", "unit"]
    assert said == ["found 1 called function in code splat had left as data"]
    assert not mixed_code.refine(path, tmp_path, "rom.bin", console, log=quiet)  # (nothing new in the same files)


@pytest.mark.parametrize("case", ["no_call", "data", "overlap", "invalid", "handwritten_caller"])
def test_weak_or_ambiguous_evidence_changes_nothing(tmp_path, case):
    path, console = project(tmp_path, call=case != "no_call", explicit=case == "data", overlap=case == "overlap")
    if case == "invalid":
        data = bytearray((tmp_path / "rom.bin").read_bytes())
        data[0x54:0x58] = bytes(4)  # its return's delay slot no longer gives the frame back
        (tmp_path / "rom.bin").write_bytes(data)
    if case == "handwritten_caller":  # (mtc0: its calls aren't a compiler's)
        asm(tmp_path / "asm/nonmatchings/unit/caller.s", [0x40806000, 0x0C000000 | ((BASE + 0x40) >> 2) & 0x3FFFFFF,
                                                          0, 0x03E00008, 0], 0)
    before = path.read_bytes()
    assert not mixed_code.refine(path, tmp_path, "rom.bin", console, log=quiet)
    assert path.read_bytes() == before


def test_a_later_pass_finds_code_in_a_file_an_earlier_one_made(tmp_path):
    import shutil

    path, console = project(tmp_path)
    data = bytearray((tmp_path / "rom.bin").read_bytes())
    data.extend(bytes(0xC0 - len(data)))
    data[0x80:0x98] = packed(BODY)
    (tmp_path / "rom.bin").write_bytes(data)
    cfg = yaml.safe_load(path.read_text())
    cfg["segments"][-1] = [len(data)]
    path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    asm(tmp_path / "asm/nonmatchings/unit/dropped.s", list(struct.unpack(">40I", data[32:])), 32, raw=True)
    visited = set()
    assert mixed_code.refine(path, tmp_path, "rom.bin", console, log=quiet, visited=visited)
    shutil.rmtree(tmp_path / "asm")
    caller = [0x27BDFFE8, 0xAFBF0014, 0x0C000000 | ((BASE + 0x80) >> 2) & 0x3FFFFFF, 0, 0x8FBF0014, 0x27BD0018,
              0x03E00008, 0]
    asm(tmp_path / "asm/nonmatchings/unit/caller.s", caller, 0)
    asm(tmp_path / "asm/nonmatchings/unit_000058/dropped.s", list(struct.unpack(">26I", data[0x58:])), 0x58, raw=True)
    assert mixed_code.refine(path, tmp_path, "rom.bin", console, log=quiet, visited=visited)
    subs = yaml.safe_load(path.read_text())["segments"][0]["subsegments"]
    assert [s[0] for s in subs] == [0, 0x20, 0x40, 0x58, 0x80, 0x98]


def test_past_the_call_limit_nothing_changes_and_it_says_so(tmp_path, monkeypatch):
    path, console = project(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(mixed_code, "CANDIDATES", 0)
    said = []
    assert not mixed_code.refine(path, tmp_path, "rom.bin", console, log=said.append)
    assert path.read_bytes() == before
    assert any("first 0 calls" in s for s in said)


def test_a_segment_with_switch_pieces_keeps_its_files(tmp_path):
    path, console = project(tmp_path)
    piece = tmp_path / "asm/nonmatchings/unit/piece.s"
    asm(piece, [0x03E00008, 0], 0x60)
    piece.write_text(piece.read_text().replace("glabel caller", "jlabel L80001060"))
    before = path.read_bytes()
    assert not mixed_code.refine(path, tmp_path, "rom.bin", console, log=quiet)
    assert path.read_bytes() == before


def test_a_processor_without_a_reader_is_left_alone(tmp_path):
    assert not mixed_code.refine(tmp_path / "missing.yaml", tmp_path, "missing.bin", get("nds"))
    assert mixed_code.run(tmp_path / "missing.yaml", tmp_path, "missing.bin", get("nds")) == ""


@pytest.mark.parametrize("corrupt", [False, True])
def test_the_split_finds_code_after_an_invalid_word_and_undoes_one_that_loses_a_function(tmp_path, monkeypatch,
                                                                                        corrupt):
    from decompnet.rom import split

    image = bytearray(0x2000)
    image[:4] = bytes.fromhex("80371240")
    target = BASE + 0x10
    caller = [0x27BDFFE8, 0xAFBF0014, 0x0C000000 | ((target >> 2) & 0x3FFFFFF), 0, 0x8FBF0014, 0x03E00008,
              0x27BD0018, 0]
    image[0x1080:0x10A0] = packed(caller)
    image[0x1000:0x1040] = packed([0x03E00008, 0x24020003, INVALID, INVALID] + BODY + [INVALID] * 6)
    (tmp_path / "rom.z64").write_bytes(image)
    cfg = {"name": "synthetic mixed text", "options": {
        "basename": "mixed", "target_path": "rom.z64", "base_path": ".", "platform": "n64", "compiler": "KMC",
        "o_as_suffix": True}, "segments": [
        [0, "bin", "header"],
        {"name": "mixed", "type": "code", "start": 0x1000, "vram": BASE, "subsegments": [[0x1000, "c", "mixed"]]},
        [0x1040, "bin", "padding"],
        {"name": "caller", "type": "code", "start": 0x1080, "vram": BASE + 0x80,
         "subsegments": [[0x1080, "c", "caller"]]},
        [0x10A0, "bin", "tail"], [len(image)]]}
    real, passes = split._splat, []

    def splat(args, root, log):
        if args[0] == "create_config":
            (root / "mixed.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))
            return ""
        output = real(args, root, log)
        if corrupt and len(passes) == 1:  # the second split loses the caller
            for path in (root / "asm/nonmatchings").glob("**/*.s"):
                fn = split.parse_function(path, path.parent.name)
                if fn and fn.vram == BASE + 0x80:
                    path.unlink()
        passes.append([p.read_text() for p in (root / "asm/nonmatchings").glob("**/*.s")])
        return output

    monkeypatch.setattr(split, "_splat", splat)
    said = []
    result = split.split_rom(tmp_path, console=get("n64"), log=said.append)
    if corrupt:
        assert len(passes) == 3
        assert not any(f.vram == target for f in result.functions)
        assert any(f.vram == BASE + 0x80 for f in result.functions)
        assert any("kept the first split" in s for s in said)
        return
    assert len(passes) == 2
    assert any("dlabel" in text and "7000003F" in text for text in passes[0])
    assert [line.word for line in next(f for f in result.functions if f.vram == target).lines] == BODY
    assert [line.word for line in next(f for f in result.functions if f.vram == BASE).lines] == [0x03E00008,
                                                                                                0x24020003]
    assert "found 1 called function in code splat had left as data" in said
    assert (tmp_path / "rom.z64").read_bytes() == image
