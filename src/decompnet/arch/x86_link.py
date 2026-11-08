"""ROM mode's judge for 32-bit x86 programs (a Linux game, consoles/linux/): a compiled function linked at the
function's address in the game and compared with it byte for byte.

What a candidate's object refers to is checked against what the original's bytes refer to there, relocation by
relocation: a call or jump (R_386_PC32) must reach the same function, an address (R_386_32) the same symbol, and
data the candidate brings itself (a string literal, a float constant in .rodata) must be the game's own data where
the original's code points (arm._verify_own, shared). Code built with -fPIC (glibc's own atexit, linked into the
program from libc_nonshared.a) finds the GOT from its own address (R_386_GOTPC: the program's GOT), reads a global's
address from the GOT entry the program's dynamic relocation names (R_386_GOT32) and calls through the PLT
(R_386_PLT32: the import's stub). Then the original's bytes stand in for those words, and the rest must be the same
bytes.

The function sits in its object at the offset it has in the game modulo 16 (the console's compile prelude): GCC 2.95
pads a loop's start only when that costs at most 7 bytes, measured from the start of the object, so the same C in
another place makes other padding."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ..rom.link import LinkResult

R_386_32, R_386_PC32, R_386_GOT32, R_386_PLT32, R_386_GOTPC = 1, 2, 3, 4, 10
ALIGN = 16  # the alignment GCC 2.95 gives an object's .text (its loops' .p2align 4)


@dataclass
class X86Target:
    """A function to judge: its bytes and where they are; `relocs` ((offset, kind, address): what its code refers
    to) are for cross references and twins: the judge reads the original's bytes."""
    name: str
    vram: int
    code: bytes
    relocs: list[tuple[int, int, int]] = field(default_factory=list)
    got: int | None = None  # the program's _GLOBAL_OFFSET_TABLE_, for -fPIC code
    got_slots: dict[int, str] = field(default_factory=dict)  # a GOT entry's address -> the symbol it holds

    def to_json(self) -> list:
        return [list(r) for r in self.relocs]

    @staticmethod
    def relocs_from_json(value: list) -> list[tuple[int, int, int]]:
        return [tuple(r) for r in value]


def canonical_target(target: X86Target):
    from ..elfobj import FunctionObj

    return FunctionObj(target.name, "x86", False, target.code, [])


def prelude(vram: int, grown: int = 0) -> str:
    """What a function's C starts with so that it sits at its game offset modulo ALIGN in the object. `grown`: the
    code before it also grows by that many bytes while gas relaxes it (see layouts)."""
    pad = vram % ALIGN
    if not grown:
        return f'__asm__(".text\\n\\t.space {pad}\\n");\n' if pad else ""
    # a jne over 140 bytes: gas starts it short (2 bytes) and grows it to 6 on its first pass, as an earlier
    # function's jumps did in the game's object file. 146 bytes each in the end, then padding to the function's place.
    n = grown // 4
    jumps = "".join(f"\\tjne .Ldd_grown{i}\\n\\t.space 140\\n.Ldd_grown{i}:\\n" for i in range(n))
    k = (pad - 146 * n) % ALIGN
    return f'__asm__(".text\\n{jumps}' + (f"\\t.space {k}\\n" if k else "") + '");\n'


def layouts(vram: int) -> list[str]:
    """The function placed after code that grows while gas relaxes it. Gas starts every jump short and grows the ones
    that don't reach, a pass at a time, and a jump never shrinks again: a jump in a function that came out long when
    its file was assembled whole (the code before it hadn't grown yet, so the loop padding between the jump and its
    target was wider) is short when the function is assembled alone. A Linux game's 188-instruction function with
    every instruction right missed by one jmp's encoding: after one such jne it's byte for byte the game's."""
    return [prelude(vram, grown) for grown in (4, 8, 12)]


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

    loads = load_widths(bytes(code))
    widths: dict[tuple[int, int], int | None] = {}
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
            if rtype == R_386_GOTPC:  # (the GOT's distance from here: `add $_GLOBAL_OFFSET_TABLE_+3, %ebx`)
                if target.got is None or (target.got + addend - target.vram - at) & 0xFFFFFFFF != original:
                    problem("your code finds the GOT where the original doesn't (code built with -fPIC finds it as "
                            "the original does)")
                    continue
                code[at:at + 4] = tcode[at:at + 4]
            elif rtype == R_386_GOT32:  # (an offset into the GOT: the entry holding the symbol's address)
                slot = None if target.got is None else (target.got + original - addend) & 0xFFFFFFFF
                held = symbols.resolve(sname)
                if slot is None or not (target.got_slots.get(slot) == sname or (
                        held is not None and read(slot, 4) == held.to_bytes(4, "little"))):
                    problem(f"you read {sname}'s address from the GOT where the original reads "
                            f"{target.got_slots.get(slot, 'another entry') if slot is not None else 'it'}")
                    continue
                code[at:at + 4] = tcode[at:at + 4]
            elif rtype in (R_386_PC32, R_386_PLT32):  # (a PLT32 call reaches the import's stub, as a plain one)
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
                    width = loads.get(at)
                    if key not in widths:
                        widths[key] = width
                    elif widths[key] != width:  # (loaded as two widths: the wider; an address taken too: all of it)
                        widths[key] = max(widths[key], width) if widths[key] and width else None
                    if own.setdefault(key, original) != original:
                        problem(f"{elf.get_section(key[0]).name}+0x{key[1]:X} is used for two different addresses in "
                                "the original")
                code[at:at + 4] = tcode[at:at + 4]
            else:
                problem(f"relocation type {rtype} isn't supported yet")

    _local_calls(elf, shndx, start, code, tcode, target, symbols, name, problem)
    _verify_own(elf, elf.get_section_by_name(".symtab"), name, shndx, start, target, symbols, read, own, problem,
                abs32=R_386_32, thumb=False, widths=widths)
    placements: dict[str, dict[int, int]] = {}
    for (sec_idx, offset), original in own.items():
        placements.setdefault(elf.get_section(sec_idx).name, {})[offset] = original
    linked = bytes(code)
    exact = not problems and linked == tcode
    # (its references are the game's own addresses now, checked above: the diff shows them as the original's)
    return LinkResult(FunctionObj(name, "x86", False, linked, []), exact, problems, placements)


CALL_REL32, JMP_REL32 = 0xE8, 0xE9


def load_widths(code: bytes) -> dict[int, int]:
    """The bytes each instruction that reads or writes memory at an absolute address moves, by where that address
    is in the code: `flds 0x80a90c0` loads 4. A datum the code only loads is compared that far, as the MIPS judge
    compares a `lwc1`'s: the original's next constant follows a float where the candidate's object pads it with
    zeros, and a polished `90.0f` for `*(float *)0x80a90c0` was refused for the padding. An address used as a value
    (`push $0x80aa0c0`, `lea`) isn't a load: its whole datum counts."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    out: dict[int, int] = {}
    for ins in md.disasm(code, 0):
        if ins.mnemonic == "lea" or not ins.disp_offset:
            continue
        mem = [op for op in ins.operands if op.type == capstone.x86.X86_OP_MEM]
        if len(mem) == 1 and mem[0].size:
            out[ins.address + ins.disp_offset] = mem[0].size
    return out


def _local_calls(elf, shndx: int, start: int, code: bytearray, tcode: bytes, target: X86Target, symbols, name: str,
                 problem) -> None:
    """A call (or a tail jump) to another function of the same object's code carries no relocation: the assembler
    resolved it by their distance in the object, which isn't theirs in the game. Linked as the linker would have
    placed them, it goes to the game's function of that name: where the original's goes there too, its bytes are
    the original's. (A library's file compiled whole had every call to its static helpers wrong: Lua's f_Ccall.)"""
    import capstone

    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return
    functions = {sym["st_value"]: sym.name for sym in symtab.iter_symbols()
                 if sym["st_shndx"] == shndx and sym["st_info"]["type"] == "STT_FUNC" and sym.name}
    relocated = set()
    for rsec in elf.iter_sections():
        if isinstance(rsec, RelocationSection) and rsec["sh_info"] == shndx:
            relocated.update(rel["r_offset"] - start for rel in rsec.iter_relocations())
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for ins in md.disasm(bytes(code), 0):
        at = ins.address
        if ins.size != 5 or code[at] not in (CALL_REL32, JMP_REL32) or at + 1 in relocated or at + 5 > len(tcode):
            continue
        inner = start + at + 5 + int.from_bytes(code[at + 1:at + 5], "little", signed=True)
        callee = functions.get(inner)
        if callee is None or callee == name:  # (its own code: a loop's jump, or a call of itself, is as it is)
            continue
        base = symbols.resolve(callee)
        dest = (target.vram + at + 5 + int.from_bytes(tcode[at + 1:at + 5], "little", signed=True)) & 0xFFFFFFFF
        if base is None:
            problem(f"`{callee}` is not a known function. Call it by the name the game has (its symbol), or give "
                    f"that address this name first with rename_symbol.")
        elif base != dest:
            problem(f"you call {callee} where the original calls {symbols.label(dest)}")
        else:
            code[at + 1:at + 5] = tcode[at + 1:at + 5]
