"""MIPS relocations clear only the field they fill: a whole word cleared lets another instruction there pass."""

from decompnet.arch import mips
from decompnet.elfobj import Reloc, mask_relocs


def test_got_and_call16_clear_only_the_immediate():
    """R_MIPS_GOT16 was listed as 21 (R_MIPS_GOT_OFST): IDO -KPIC code's GOT loads were cleared whole."""
    assert (mips.R_MIPS_GOT16, mips.R_MIPS_CALL16, mips.R_MIPS_GOT_OFST) == (9, 11, 21)
    lw = (0x23 << 26 | 28 << 21 | 2 << 16 | 0x8010).to_bytes(4, "big")  # lw $v0, %got(x)($gp)
    addiu = (0x09 << 26 | 28 << 21 | 2 << 16 | 0x8010).to_bytes(4, "big")
    for kind in (mips.R_MIPS_GOT16, mips.R_MIPS_CALL16, mips.R_MIPS_GOT_DISP, mips.R_MIPS_GOT_PAGE, mips.R_MIPS_GOT_OFST):
        a = mask_relocs(lw, [Reloc(0, kind, "x", 0)], "mips", True)
        b = mask_relocs(addiu, [Reloc(0, kind, "x", 0)], "mips", True)
        assert a == lw[:2] + b"\0\0" and a != b
