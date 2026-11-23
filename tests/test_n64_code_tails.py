"""A code segment found in an N64 game ends at its last return, rounded up to 16 bytes. When the search stopped two
quiet blocks into a long function, that rounding caught the function's first instructions and left the rest in a
bin: the segment is completed to the function's own return, and only then."""

import struct

import pytest
import yaml

from decompnet.consoles.n64 import code

RETURN, POP = 0x03E00008, 0x27BD0018  # jr $ra; addiu $sp, $sp, 24
VRAM = 0x80001000


def image(body, before=()):
    """A return, its delay slot, `before`, then a 24-byte frame and `body`."""
    words = [RETURN, 0, *before, 0x27BDFFE8, *body]
    return struct.pack(f">{len(words)}I", *words)


def test_a_frame_in_the_alignment_tail_is_completed_through_a_long_quiet_body():
    rom = image([0] * 1000 + [RETURN, POP])
    assert code.complete_tails(rom, [(0, 12, VRAM)]) == [(0, len(rom), VRAM)]


def test_loads_moved_above_the_frame_are_part_of_it():
    rom = image([0] * 1000 + [RETURN, POP], before=(0x3C02800C, 0x8C427F84))  # lui v0; lw v0
    assert code.complete_tails(rom, [(0, 16, VRAM)]) == [(0, len(rom), VRAM)]


def test_only_a_return_that_pops_this_frame_after_valid_instructions():
    for body in ([RETURN, 0x27BD0010], [0x7000003F, RETURN, POP], [0] * 20):  # another frame size, sdbbp, no return
        assert code.complete_tails(image(body), [(0, 12, VRAM)]) == [(0, 12, VRAM)]


def test_no_branch_out_of_it_and_no_jump_before_its_frame():
    rom = image([0x10000008, 0, RETURN, POP] + [0] * 10)  # b past the return
    assert code.complete_tails(rom, [(0, 12, VRAM)]) == [(0, 12, VRAM)]
    rom = image([0] * 20 + [RETURN, POP], before=(0x0C000400,))  # a jal before the frame: not one function
    assert code.complete_tails(rom, [(0, 16, VRAM)]) == [(0, 16, VRAM)]


def test_never_into_another_segment_nor_its_addresses():
    rom = image([0] * 20 + [RETURN, POP])
    assert code.complete_tails(rom, [(0, 12, VRAM)], [(40, len(rom), 0x90001000)]) == [(0, 12, VRAM)]
    assert code.complete_tails(rom, [(0, 12, VRAM)], [(1000, 1100, VRAM + 0x20)]) == [(0, 12, VRAM)]
    rom = image([0] * (code.TAIL_LIMIT // 4) + [RETURN, POP])
    assert code.complete_tails(rom, [(0, 12, VRAM)]) == [(0, 12, VRAM)]


def test_a_complete_segment_and_one_ending_in_padding_stay():
    rom = image([0] * 20 + [RETURN, POP])
    assert code.complete_tails(rom, [(0, len(rom), VRAM)]) == [(0, len(rom), VRAM)]
    rom = struct.pack(">6I", RETURN, 0, 0, 0, 0x27BDFFE8, 0)
    assert code.complete_tails(rom, [(0, 16, VRAM)]) == [(0, 16, VRAM)]


def test_segments_found_end_to_end_get_no_bin_between_them(tmp_path, monkeypatch):
    cfg = {"name": "synthetic", "options": {}, "segments": [
        {"name": "main", "type": "code", "start": 0, "vram": 0x80000400, "subsegments": [[0, "asm"]]},
        {"type": "bin", "start": 32}, [256]]}
    path = tmp_path / "synthetic.yaml"
    path.write_text(yaml.safe_dump(cfg))
    (tmp_path / "rom.z64").write_bytes(bytes(256))
    monkeypatch.setattr(code, "unpack_code", lambda _: [])
    monkeypatch.setattr(code, "find_segments", lambda *_: [(32, 64, 0x80000420), (64, 128, 0x80000440)])
    code.add_segments(path, tmp_path, "rom.z64", log=lambda _: None)
    starts = [s[0] if isinstance(s, list) else s["start"] for s in yaml.safe_load(path.read_text())["segments"]]
    assert len(starts) == len(set(starts))


# a function alone between two segments, too short a stretch for the search: found when known code calls it
BODY = [0x27BDFFE8, 0xAFBF0014, 0x24020007, 0x8FBF0014, RETURN, POP]
MAPPING = 0x7FFFF000  # address minus ROM offset


def between(callees=(0x1020 + MAPPING,), gap=BODY):
    """Segments at 0x1000 (a function calling `callees`) and after the gap (BODY), the gap between them."""
    caller = [0x27BDFFE8, 0xAFBF0014, *(0x0C000000 | (c >> 2) & 0x3FFFFFF for c in callees), 0, 0x8FBF0014,
              RETURN, POP]
    caller += [0] * (-len(caller) % 4)
    words = [0] * (0x1000 // 4) + caller + gap + BODY
    start = 0x1000 + 4 * len(caller)
    end = start + 4 * len(gap)
    rom = struct.pack(f">{len(words)}I", *words)
    return rom, start, [(0x1000, start, 0x1000 + MAPPING), (end, end + 24, end + MAPPING)]


def test_a_called_function_alone_between_two_segments_is_one_of_its_own():
    rom, start, spans = between()
    assert code.called_gaps(rom, spans) == [(start, start + 24, start + MAPPING)]


@pytest.mark.parametrize("case", ["no_call", "padding_after", "second_frame", "early_return", "two_mappings",
                                  "overlap"])
def test_a_gap_that_isnt_plainly_one_called_function_stays(case):
    gap = {"padding_after": BODY + [0], "second_frame": BODY[:2] + [0x27BDFFE8] + BODY[3:],
           "early_return": BODY[:2] + [RETURN, 0] + BODY[2:]}.get(case, BODY)
    callees = {"no_call": (0x1100 + MAPPING,), "two_mappings": (0x1020 + MAPPING, 0x1020 + MAPPING + 0x1000)}
    rom, start, spans = between(callees.get(case, (0x1020 + MAPPING,)), gap)
    assert start == 0x1020
    if case == "two_mappings":  # another segment's mapping lands the second call on the gap too: no one address
        spans.append((len(rom), len(rom), len(rom) + MAPPING + 0x1000))
    if case == "overlap":  # another segment at the gap's addresses
        spans.append((len(rom), len(rom) + 4, start + 8 + MAPPING))
    assert code.called_gaps(rom, spans) == []
