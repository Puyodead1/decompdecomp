"""ROM mode's judge for 32-bit x86 programs (a Linux game, consoles/linux/): a compiled function linked at the
function's address in the game and compared with it byte for byte.

What a candidate's object refers to is checked against what the original's bytes refer to there, relocation by
relocation: a call or jump (R_386_PC32) must reach the same function, an address (R_386_32) the same symbol, and
data the candidate brings itself (a string literal, a float constant in .rodata) must be the game's own data where
the original's code points (arm._verify_own, shared). Then the original's bytes stand in for those words, and the
rest must be the same bytes.

The function sits in its object at the offset it has in the game modulo 16 (the console's compile prelude): GCC 2.95
pads a loop's start only when that costs at most 7 bytes, measured from the start of the object, so the same C in
another place makes other padding."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ..rom.link import LinkResult

R_386_32, R_386_PC32 = 1, 2
ALIGN = 16  # the alignment GCC 2.95 gives an object's .text (its loops' .p2align 4)


@dataclass
class X86Target:
    """A function to judge: its bytes and where they are; `relocs` ((offset, kind, address): what its code refers
    to) are for cross references and twins: the judge reads the original's bytes."""
    name: str
    vram: int
    code: bytes
    relocs: list[tuple[int, int, int]] = field(default_factory=list)

    def to_json(self) -> list:
        return [list(r) for r in self.relocs]

    @staticmethod
    def relocs_from_json(value: list) -> list[tuple[int, int, int]]:
        return [tuple(r) for r in value]


def canonical_target(target: X86Target):
    from ..elfobj import FunctionObj

    return FunctionObj(target.name, "x86", False, target.code, [])


def prelude(vram: int) -> str:
    """What a function's C starts with so that it sits at its game offset modulo ALIGN in the object."""
    pad = vram % ALIGN
    return f'__asm__(".text\\n\\t.space {pad}\\n");\n' if pad else ""


def link(obj: bytes, name: str, target: X86Target, symbols, read) -> LinkResult:
    """Link a compiled x86 function at the target's address and compare it with the game, byte for byte."""
    from ..elfobj import FunctionObj, _function_symbols
    from .arm import _defined, _sym_name, _verify_own

    elf = ELFFile(BytesIO(obj))
    found = _function_symbols(elf).get(name)
    if found is None:
        return LinkResult(None, False, [f"the object has no function named `{name}`"])
    shndx, start, size = found
    code = bytearray(elf.get_section(shndx).data()[start:start + size])
    tcode = target.code
    problems: list[str] = []
    own: dict[tuple[int, int], int] = {}

    def problem(text: str) -> None:
        if text not in problems:
            problems.append(text)

    for rsec in elf.iter_sections():
        if not isinstance(rsec, RelocationSection) or rsec["sh_info"] != shndx:
            continue
        symtab = elf.get_section(rsec["sh_link"])
        for rel in rsec.iter_relocations():
            at = rel["r_offset"] - start
            if not 0 <= at < len(code):
                continue
            if at + 4 > len(tcode):
                problem("your function is longer than the original")
                continue
            rtype = rel["r_info_type"]
            sname, sym, is_section = _sym_name(elf, symtab, rel["r_info_sym"])
            addend = int.from_bytes(code[at:at + 4], "little", signed=True)
            original = int.from_bytes(tcode[at:at + 4], "little")
            if rtype == R_386_PC32:
                dest = (target.vram + at + 4 + int.from_bytes(tcode[at:at + 4], "little", signed=True)) & 0xFFFFFFFF
                if _defined(sym) and sym["st_shndx"] == shndx:  # within its own object's code (a static helper)
                    inner = (0 if is_section else sym["st_value"]) + addend + 4 - start
                    base = target.vram + inner
                else:
                    base = symbols.resolve(sname)
                    if base is None:
                        problem(f"`{sname}` is not a known function. Call it by the name the game has (its symbol), "
                                f"or give that address this name first with rename_symbol.")
                        continue
                    base = (base + addend + 4) & 0xFFFFFFFF
                if base != dest:
                    problem(f"you call {sname} where the original calls {symbols.label(dest)}")
                    continue
                code[at:at + 4] = tcode[at:at + 4]
            elif rtype == R_386_32:
                if _defined(sym) and sym["st_shndx"] == shndx:  # a jump table into this function
                    inner = (0 if is_section else sym["st_value"]) + addend - start
                    if (target.vram + inner) & 0xFFFFFFFF != original:
                        problem(f"a pointer to your function +0x{inner:X} where the original points at "
                                f"0x{original:08X}")
                elif not _defined(sym) or (not is_section and symbols.resolve(sname) is not None):
                    base = symbols.resolve(sname)
                    if base is None:
                        problem(f"`{sname}` is not a known symbol. Use the name the game has for it, or give that "
                                f"address this name first with rename_symbol.")
                        continue
                    if (base + addend) & 0xFFFFFFFF != original:
                        problem(f"{sname}{f'+0x{addend:X}' if addend else ''} where the original has 0x{original:08X} "
                                f"({symbols.label(original)})")
                else:  # data this function brings itself (a string, a constant): the original's copy is at `original`
                    key = (sym["st_shndx"], addend + (0 if is_section else sym["st_value"]))
                    if own.setdefault(key, original) != original:
                        problem(f"{elf.get_section(key[0]).name}+0x{key[1]:X} is used for two different addresses in "
                                "the original")
                code[at:at + 4] = tcode[at:at + 4]
            else:
                problem(f"relocation type {rtype} isn't supported yet")

    _verify_own(elf, elf.get_section_by_name(".symtab"), name, shndx, start, target, symbols, read, own, problem)
    placements: dict[str, dict[int, int]] = {}
    for (sec_idx, offset), original in own.items():
        placements.setdefault(elf.get_section(sec_idx).name, {})[offset] = original
    linked = bytes(code)
    exact = not problems and linked == tcode
    # (its references are the game's own addresses now, checked above: the diff shows them as the original's)
    return LinkResult(FunctionObj(name, "x86", False, linked, []), exact, problems, placements)
