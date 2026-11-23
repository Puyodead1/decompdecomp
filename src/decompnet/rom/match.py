"""Matching C against code taken straight from a ROM.

The target is final, linked machine code: every address is already filled in. A candidate is a
freshly compiled object whose references are relocations against names. To compare them fairly we
*link* the candidate at the target's address:

- names (func_80001234, D_80012340, or anything renamed in the symbol table) resolve to addresses;
- jumps inside the function resolve against the function's own address;
- data the candidate defines itself (string literals, float constants, jump tables, statics) is
  placed where the ROM keeps the data this instruction refers to, and its contents are checked
  against the ROM bytes there (relocated words, like jump table entries, included).

A match means the linked candidate is byte-for-byte the code in the ROM. For the diff the agent
reads, both sides are shown with the same names (the symbol table's names for those addresses).
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from io import BytesIO
from typing import Callable

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from .. import scoring
from ..arch import mips
from ..elfobj import MASKS_BY_ARCH, FunctionObj, Reloc, canonical_symbol, section_target, symbol_at, unmangle
from .link import LinkResult, significant  # (re-exported: callers still ask match.LinkResult)
from .split import RomFunction
from .symbols import AUTO_NAME, SymbolTable

R_MIPS_32, R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_GPREL16 = 2, 4, 5, 6, 7
_REF = re.compile(r"%(hi|lo|gp_rel)\(\s*([A-Za-z_.$][\w.$]*)\s*(?:([+-])\s*(0x[0-9A-Fa-f]+|\d+))?\s*\)")
# spimdisasm's `%lo(sym + (0x12340 & 0xFFFF))`: an addend past 64 KB, masked, which alone names several addresses
_MASKED_LO = re.compile(r"%lo\(\s*([A-Za-z_.$][\w.$]*)\s*([+-])\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*&\s*(?:0x[fF]{4}|65535)"
                        r"\s*\)\s*\)")
_KIND = {"hi": 5, "lo": 6, "gp_rel": 7}
_JUMPS = {"jal", "j"}
# Bytes a load or store moves, by opcode (lwl/lwr/swl/swr read parts of words, so they don't say)
_REGION_RELOCS = frozenset({R_MIPS_32, R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16, R_MIPS_GPREL16})  # (verify_data)
SHF_EXECINSTR = 0x4  # an executable section: its loads say how much of a datum they read
_WIDTH = {0x20: 1, 0x24: 1, 0x28: 1, 0x21: 2, 0x25: 2, 0x29: 2, 0x23: 4, 0x27: 4, 0x2B: 4, 0x31: 4, 0x39: 4, 0x32: 4,
          0x3A: 4, 0x35: 8, 0x3D: 8, 0x37: 8, 0x3F: 8, 0x1E: 16, 0x1F: 16, 0x36: 16, 0x3E: 16}

ReadFn = Callable[[int, int], "bytes | None"]

# Names a compiler writes into code the programmer never called by that name: the C library's math and string
# routines it calls for a builtin (sqrtf), libgcc's helpers (__divdi3, __fixunsdfsi), libultra's for IDO's long longs
# (__ll_div, __d_to_ull), and the assembler-level helpers older compilers reference (MULT_HI).
_LIBRARY_CALLS = frozenset("sqrt sqrtf sin sinf cos cosf tan tanf fabs fabsf memcpy memmove memset memcmp strlen "
                           "bcopy bzero bcmp abort".split())
_HELPER = re.compile(r"__(?:[a-z]+(?:[sdtx][if]|[sdx]f)\d?|u?ll_\w+|[dfu]+_to_u?ll|u?ll_to_[df])|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def compiler_library_name(name: str) -> bool:
    """Whether a compiler, not the programmer, wrote this call (a builtin's library routine, a helper)."""
    return not AUTO_NAME.match(name) and (name in _LIBRARY_CALLS or bool(_HELPER.fullmatch(name)))


@dataclass
class RomTarget:
    name: str
    vram: int
    code: bytes
    relocs: list[tuple[int, int, int]]  # (offset in function, reloc type, absolute address)
    big_endian: bool = True
    gp: int = 0  # $gp, for $gp-relative references (PlayStation small data)

    @property
    def order(self) -> str:
        return "big" if self.big_endian else "little"

    def to_json(self) -> list:
        return [list(r) for r in self.relocs]

    @staticmethod
    def relocs_from_json(v: list) -> list[tuple[int, int, int]]:
        return [tuple(r) for r in v]


def encode(rtype: int, residual: int) -> int:
    """The relocation field an assembler writes for `symbol + residual` (REL, MIPS)."""
    if rtype == R_MIPS_26:
        return (residual >> 2) & 0x03FFFFFF
    if rtype == R_MIPS_HI16:
        return ((residual + 0x8000) >> 16) & 0xFFFF
    if rtype == R_MIPS_LO16:
        return residual & 0xFFFF
    return residual & 0xFFFFFFFF


def _patch(word: int, rtype: int, address: int, gp: int = 0) -> int:
    if rtype == R_MIPS_GPREL16:
        return (word & ~0xFFFF) | ((address - gp) & 0xFFFF)
    if rtype == R_MIPS_26:
        return (word & ~0x03FFFFFF) | ((address >> 2) & 0x03FFFFFF)
    if rtype == R_MIPS_HI16:
        return (word & ~0xFFFF) | (((address + 0x8000) >> 16) & 0xFFFF)
    if rtype == R_MIPS_LO16:
        return (word & ~0xFFFF) | (address & 0xFFFF)
    if rtype == R_MIPS_32:
        return address & 0xFFFFFFFF
    raise ValueError(rtype)


# ----------------------------------------------------------------------------------- target

def target_from_split(fn: RomFunction, resolve: Callable[[str], int | None], big_endian: bool = True,
                      gp: int = 0) -> RomTarget:
    """The function's bytes from the ROM plus the address behind every annotated reference."""
    code = b"".join(ln.word.to_bytes(4, "big" if big_endian else "little") for ln in fn.lines)
    relocs: list[tuple[int, int, int]] = []
    for ln in fn.lines:
        off = ln.vram - fn.vram
        m = _REF.search(ln.operands)
        if m:
            kind, sym, sign, num = m.groups()
            base = resolve(sym)
            if base is not None:
                addend = (int(num, 0) if num else 0) * (-1 if sign == "-" else 1)
                relocs.append((off, _KIND[kind], (base + addend) & 0xFFFFFFFF))
            continue
        if m := _MASKED_LO.search(ln.operands):
            # the full address is the one a %hi before it names (`%hi(sym + 0x12340)`), when this instruction's
            # own immediate is that address's low half: otherwise the address stays unknown (no relocation)
            sym, sign, num = m.groups()
            if (base := resolve(sym)) is not None:
                addr = (base + int(num, 0) * (-1 if sign == "-" else 1)) & 0xFFFFFFFF
                if (any(kind == R_MIPS_HI16 and at < off and a == addr for at, kind, a in relocs)
                        and ln.word & 0xFFFF == addr & 0xFFFF):
                    relocs.append((off, R_MIPS_LO16, addr))
            continue
        if ln.mnemonic in _JUMPS:
            op = ln.operands.strip()
            if label := re.fullmatch(r"\.?L([0-9A-Fa-f]{8})", op):  # not a function named L... (`j LoadBTF`)
                addr = int(label[1], 16)
            else:
                addr = resolve(op)
                if addr is None:
                    addr = ((ln.vram + 4) & 0xF0000000) | ((ln.word & 0x03FFFFFF) << 2)
            relocs.append((off, R_MIPS_26, addr))
    return RomTarget(fn.name, fn.vram, code, relocs, big_endian, gp)


def _adjacent_low_address(high: int, low: int) -> int | None:
    """The address a `lui reg, hi` and the load, store or addiu right after it through the same register make."""
    register = (high >> 16) & 31
    if high >> 26 != mips.LUI or not register or (low >> 21) & 31 != register:
        return None
    if low >> 26 != mips.ADDIU and low >> 26 not in _WIDTH:
        return None
    return (((high & 0xFFFF) << 16) + mips.signed_immediate(low)) & 0xFFFFFFFF


def _display_relocs(t: RomTarget) -> list[tuple[int, int, int]]:
    """A target imported before masked %lo annotations were read lacks the %lo of a pair: its diff showed the low
    half as a number against the candidate's relocation. Only for the diff (the linked target stays as stored), and
    only where the raw pair right after the annotated %hi proves the address."""
    result = list(t.relocs)
    taken = {off for off, _, _ in result}
    for off, kind, addr in t.relocs:
        if kind != R_MIPS_HI16 or off % 4 or off + 8 > len(t.code) or off + 4 in taken:
            continue
        high = int.from_bytes(t.code[off:off + 4], t.order)
        low = int.from_bytes(t.code[off + 4:off + 8], t.order)
        if _adjacent_low_address(high, low) == addr:
            result.append((off + 4, R_MIPS_LO16, addr))
    return sorted(result)


def canonical_target(t: RomTarget, symbols: SymbolTable) -> FunctionObj:
    relocs = []
    for off, rtype, addr in _display_relocs(t):
        name, residual = symbols.name_at(addr)
        if t.vram <= addr < t.vram + len(t.code):
            name, residual = t.name, addr - t.vram
        relocs.append(Reloc(off, rtype, name, encode(rtype, residual)))
    return FunctionObj(t.name, "mips", t.big_endian, t.code, relocs)


# -------------------------------------------------------------------------------- candidate

def raw_relocs(elf: ELFFile, shndx: int, start: int, size: int, code: bytes) -> list[dict]:
    order = "little" if elf.little_endian else "big"
    raw = []
    for rsec in elf.iter_sections():
        if not isinstance(rsec, RelocationSection) or rsec["sh_info"] != shndx:
            continue
        symtab = elf.get_section(rsec["sh_link"])
        for rel in rsec.iter_relocations():
            off = rel["r_offset"]
            if not (start <= off < start + size):
                continue
            rtype = rel["r_info_type"]
            if rel.is_RELA():
                value = rel["r_addend"]
            else:
                delta, length, mask = MASKS_BY_ARCH.get(("mips", rtype), (0, 4, 0xFFFFFFFF))
                at = off - start + delta
                value = int.from_bytes(code[at:at + length], order) & mask
            raw.append({"off": off - start, "type": rtype, "symidx": rel["r_info_sym"], "rela": rel.is_RELA(),
                        "value": value, "symtab": symtab})
    raw.sort(key=lambda r: r["off"])
    return raw


class _Linker:
    def __init__(self, obj: bytes, name: str, target: RomTarget, symbols: SymbolTable, read: ReadFn):
        self.elf = ELFFile(BytesIO(obj))
        self.name, self.target, self.symbols, self.read = name, target, symbols, read
        self.symtab = self.elf.get_section_by_name(".symtab")
        self.problems: list[str] = []
        self.library_names: dict[str, int] = {}  # a compiler-written library call -> the address the game's call has
        self.local_map: dict[tuple[int, int], int] = {}  # (section index, offset) -> ROM address
        self.target_at = {off: (rtype, addr) for off, rtype, addr in target.relocs}
        self.data: dict[tuple[int, int], int] = {}  # every datum of its own the candidate uses -> ROM address
        self.widths: dict[tuple[int, int], int | None] = {}  # bytes the code loads from it (None: its address is used)
        self.words: list[int] = []
        self.fn_shndx = None
        # the $gp the assembler assumed (.reginfo's ri_gp_value): a $gp-relative reference to the object's own data
        # holds its offset less this (EE-GCC: -0x4000 for the first small datum)
        reginfo = self.elf.get_section_by_name(".reginfo")
        raw = reginfo.data() if reginfo is not None else b""
        self.gp0 = struct.unpack_from("<i" if self.elf.little_endian else ">i", raw, 20)[0] if len(raw) >= 24 else 0

    def problem(self, text: str) -> None:
        if text not in self.problems:
            self.problems.append(text)

    def function(self) -> tuple[int, int, int] | None:
        """(section index, offset, size) of the submitted function, also for period assemblers' size-0 symbols."""
        from ..elfobj import _function_symbols

        return _function_symbols(self.elf).get(self.name)

    def resolve_name(self, name: str) -> int | None:
        addr = self.symbols.resolve(name)
        if addr is None:
            self.problem(f"`{name}` is not a known symbol. Use the name the assembly shows (like D_80012340 or "
                         f"func_80001234), or give that address this name first with rename_symbol.")
        return addr

    def library_call(self, name: str, r: dict, residual: int) -> int | None:
        """The address a compiler-written library call (`sqrtf`, a libgcc helper) means, from the game's own call.
        The game reaches that routine under its automatic name (func_80055B40), so `sqrtf` is no symbol of the
        table, and the C that calls it can't spell it otherwise (a builtin's own name is how the compiler calls it).
        The target has a `jal` at this very place: its address is what the name means here, and the judge still
        compares the linked bytes. A name the table has, or one two calls place differently, is resolve_name's."""
        if r["type"] != R_MIPS_26 or self.symbols.resolve(name) is not None or not compiler_library_name(name):
            return None
        want = self.target_at.get(r["off"])
        if want is None or want[0] != R_MIPS_26:
            return None
        base = (want[1] - residual) & 0xFFFFFFFF
        known, at = self.symbols.name_at(base)
        if at == 0 and not AUTO_NAME.match(known):  # (the routine has a real name: `sinf` isn't called `sqrtf`)
            return None
        if self.library_names.setdefault(name, base) != base:
            self.problem(f"`{name}` is called at two different ROM addresses (0x{self.library_names[name]:08X} and "
                         f"0x{base:08X}): call them by the names the assembly shows")
            return None
        return base

    def _target_word(self, off: int) -> int | None:
        """The ROM's instruction word at `off` in the function, or None outside it."""
        if off < 0 or off % 4 or off + 4 > len(self.target.code):
            return None
        return int.from_bytes(self.target.code[off:off + 4], self.target.order)

    def _raw_ref(self, raw: list[dict], k: int) -> tuple[int, int] | None:
        """(relocation type, address) of a hi/lo pair the disassembler left as plain numbers (#312). A switch's
        jump table at the end of an overlay has no symbol, so spimdisasm writes its `lui`/`lw` with raw immediates
        and target_from_split records no relocation. The candidate's own relocations say which two instructions
        are the pair, and the ROM's words still hold the address (the hi carrying bit 15's carry, the lo signed).
        Only where the candidate has a pair: most raw `lui`/`addiu` pairs are plain constants, and reading them
        as addresses changed the diffs of functions that already matched."""
        r = raw[k]
        if r["type"] not in (R_MIPS_HI16, R_MIPS_LO16):
            return None
        same = [x for x in raw if x["symidx"] == r["symidx"] and x["symtab"] is r["symtab"]]
        if r["type"] == R_MIPS_HI16:
            mate = next((x for x in same if x["off"] > r["off"] and x["type"] == R_MIPS_LO16), None)
        else:
            mate = next((x for x in reversed(same) if x["off"] < r["off"] and x["type"] == R_MIPS_HI16), None)
        if mate is None:
            return None
        hi_off, lo_off = (r["off"], mate["off"]) if r["type"] == R_MIPS_HI16 else (mate["off"], r["off"])
        if hi_off in self.target_at or lo_off in self.target_at:  # (the ROM's pair is annotated: that address)
            return None
        hi, lo = self._target_word(hi_off), self._target_word(lo_off)
        if hi is None or lo is None or hi >> mips.OPCODE_SHIFT != mips.LUI:
            return None
        return r["type"], (((hi & 0xFFFF) << 16) + mips.signed_immediate(lo)) & 0xFFFFFFFF

    def address(self, raw: list[dict], k: int, fn_shndx: int, fn_start: int) -> int | None:
        r = raw[k]
        if r["type"] == R_MIPS_GPREL16:
            residual = r["value"] - 0x10000 if r["value"] & 0x8000 else r["value"]
        else:
            residual = section_target("mips", raw, k)
        if residual is None:
            self.problem(f"relocation type {r['type']} is not supported here")
            return None
        if r["type"] == R_MIPS_GPREL16 and not self.target.gp:
            self.problem("your code uses $gp-relative data, but this game doesn't: compile with -G0")
            return None
        sym = r["symtab"].get_symbol(r["symidx"])
        shndx = sym["st_shndx"]
        if r["type"] == R_MIPS_GPREL16 and sym["st_info"]["bind"] == "STB_LOCAL":
            residual += self.gp0  # (a C static, or C++'s definitions: global data a C file only declares)
        if shndx in ("SHN_UNDEF", "SHN_COMMON") or shndx in (0xFF03, 0xFF04):  # + MIPS small common / small undefined
            name = canonical_symbol(sym.name, sym["st_info"]["bind"])
            if (base := self.library_call(name, r, residual)) is None:
                base = self.resolve_name(name)
            return None if base is None else (base + residual) & 0xFFFFFFFF
        off = residual if sym["st_info"]["type"] == "STT_SECTION" else sym["st_value"] + residual
        named = symbol_at(self.symtab, shndx, off)
        if shndx == fn_shndx:
            if named and named[0] == self.name:
                return self.target.vram + named[1]
            if named is None:
                self.problem(f"a jump into .text+0x{off:X} that isn't part of {self.name}")
                return None
            base = self.resolve_name(named[0])
            return None if base is None else base + named[1]
        # data this submission defines itself: place it where the ROM keeps the data this instruction uses
        base = self.symbols.resolve(named[0]) if named else None
        if base is not None:
            addr = base + named[1]
            if sym["st_info"]["type"] == "STT_SECTION" or sym["st_info"]["bind"] == "STB_LOCAL":
                self.local_map.setdefault((shndx, off), addr)  # g++'s `.sdata+4`: the export places the section
        else:
            want = self.target_at.get(r["off"])
            if want is None:
                want = self._raw_ref(raw, k)
            if want is None or want[0] != r["type"]:
                label =f"{named[0]}+0x{named[1]:X}" if named else f"{self.elf.get_section(shndx).name}+0x{off:X}"
                self.problem(f"your code refers to {label} where the ROM's code has no address")
                return None
            addr = want[1]
            prev = self.local_map.setdefault((shndx, off), addr)
            if prev != addr:
                self.problem(f"{self.elf.get_section(shndx).name}+0x{off:X} is used for two different ROM addresses")
                return None
        self.data.setdefault((shndx, off), addr)
        if r["type"] != R_MIPS_HI16:  # the instruction that uses the address says how much of the data it reads
            width = _WIDTH.get(self.words[r["off"] // 4] >> 26) if r["off"] // 4 < len(self.words) else None
            prev_width = self.widths.get((shndx, off), 0)
            self.widths[(shndx, off)] = None if width is None or prev_width is None else max(prev_width, width)
        return addr

    # ------------------------------------------------------------------ the candidate's own data

    def _region_value(self, raw: list[dict], k: int) -> int | None:
        """The offset into its symbol a relocation inside a region the candidate defines points at."""
        r = raw[k]
        if r["type"] != R_MIPS_GPREL16:
            return section_target("mips", raw, k)
        value = r["value"] - 0x10000 if r["value"] & 0x8000 else r["value"]  # (section_target has no $gp-relative)
        if r["symtab"].get_symbol(r["symidx"])["st_info"]["bind"] == "STB_LOCAL":
            value += self.gp0
        return value

    @staticmethod
    def _unpaired(raw: list[dict], r: dict) -> bool:
        """A REL %hi with no %lo of its symbol after it in the region (or a %lo with no %hi before it): the address
        the pair makes can't be known."""
        if r["type"] not in (R_MIPS_HI16, R_MIPS_LO16) or r["rela"]:
            return False
        mate, after = (R_MIPS_LO16, True) if r["type"] == R_MIPS_HI16 else (R_MIPS_HI16, False)
        return not any(q["symidx"] == r["symidx"] and q["symtab"] is r["symtab"] and q["type"] == mate
                       and (q["off"] > r["off"] if after else q["off"] < r["off"]) for q in raw)

    def extent(self, shndx: int, off: int) -> int:
        """Length of the datum at `off`: up to the next symbol or the next place this candidate uses (period
        assemblers don't record sizes; string literals have no symbol at all)."""
        sec = self.elf.get_section(shndx)
        size = sec["sh_size"]
        sym = next((s for s in self.symtab.iter_symbols() if s["st_shndx"] == shndx and s["st_value"] == off
                    and s["st_size"] and s["st_info"]["type"] == "STT_OBJECT"), None)
        if sym is not None:
            return max(0, min(sym["st_size"], size - off))
        bounds = {s["st_value"] for s in self.symtab.iter_symbols() if s["st_shndx"] == shndx
                  and s["st_info"]["type"] not in ("STT_SECTION", "STT_FILE")} | {o for (i, o) in self.data if i == shndx}
        return next((b for b in sorted(bounds) if b > off), size) - off

    def _pointee(self, s, value: int) -> tuple[int | None, tuple[int, int] | None]:
        """(address, own datum) a word of the candidate's data points at: (address, None) for a named thing,
        (None, (section, offset)) for more of the candidate's own data, (None, None) when it can't be placed."""
        if s["st_shndx"] in ("SHN_UNDEF", "SHN_COMMON") or s["st_shndx"] in (0xFF03, 0xFF04):
            base = self.resolve_name(canonical_symbol(s.name, s["st_info"]["bind"]))
            return (None if base is None else base + value), None
        in_sec = value if s["st_info"]["type"] == "STT_SECTION" else s["st_value"] + value
        hit = symbol_at(self.symtab, s["st_shndx"], in_sec)
        if hit and hit[0] == self.name:
            return self.target.vram + hit[1], None
        base = self.symbols.resolve(hit[0]) if hit else None
        if base is not None:
            return base + hit[1], None
        if s["st_shndx"] == self.fn_shndx:
            return None, None
        return None, (s["st_shndx"], in_sec)

    def place_pointees(self) -> None:
        """Data the candidate's own data points at goes where the ROM's words point: a table's strings, a jump
        table's cases, and what a static helper the candidate keeps in a section of its own calls or loads (its jal,
        %hi/%lo and $gp-relative references, #221), read from the ROM's linked words. A helper sharing the
        function's own .text isn't one: address() refuses a jump there, never matching its body unchecked."""
        todo = list(self.data)
        while todo:
            shndx, off = todo.pop()
            sec = self.elf.get_section(shndx)
            if sec["sh_type"] == "SHT_NOBITS":
                continue
            addr = self.data[(shndx, off)]
            data = sec.data()[off:off + self.extent(shndx, off)]
            raw = raw_relocs(self.elf, shndx, off, len(data), data)
            # the ROM's words at the same places, read one by one (a region's trailing alignment needn't be there)
            rom = [self.read(addr + r["off"], 4) for r in raw]
            linked = [{**r, "rela": False, "value": int.from_bytes(w or bytes(4), self.target.order)
                       & (0xFFFF if r["type"] in (R_MIPS_HI16, R_MIPS_LO16) else 0xFFFFFFFF)}
                      for r, w in zip(raw, rom)]
            for k, r in enumerate(raw):
                rtype = r["type"]
                if rtype not in _REGION_RELOCS or rom[k] is None or self._unpaired(raw, r):
                    continue
                if rtype == R_MIPS_GPREL16 and not self.target.gp:
                    continue  # (verify_data says to compile with -G0)
                if rtype in (R_MIPS_HI16, R_MIPS_LO16) and any(
                        rom[j] is None for j, q in enumerate(raw) if q["symidx"] == r["symidx"]
                        and q["symtab"] is r["symtab"] and q["type"] in (R_MIPS_HI16, R_MIPS_LO16)):
                    continue
                if (value := self._region_value(raw, k)) is None:
                    continue
                _, own = self._pointee(r["symtab"].get_symbol(r["symidx"]), value)
                if own is None:
                    continue
                word = linked[k]["value"]
                if rtype == R_MIPS_GPREL16:  # the ROM's immediate is the address less $gp
                    dest = mips.signed_immediate(word) + self.target.gp
                elif rtype == R_MIPS_26:  # the ROM's jump index, in the instruction's 256 MB region
                    dest = ((addr + r["off"] + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
                else:
                    dest = section_target("mips", linked, k)
                dest &= 0xFFFFFFFF
                # how much of the datum is read, as address() says for the function's own code: a $gp-relative or
                # %lo load in a helper's code reads its width (the %lo after a %hi says it); a pointer, a jal or a
                # %lo kept in data uses the whole datum
                if rtype == R_MIPS_GPREL16 or (rtype == R_MIPS_LO16 and sec["sh_flags"] & SHF_EXECINSTR):
                    w = _WIDTH.get(int.from_bytes(data[r["off"]:r["off"] + 4], self.target.order) >> 26)
                    prev = self.widths.get(own, 0)
                    self.widths[own] = None if w is None or prev is None else max(prev, w)
                elif rtype != R_MIPS_HI16:
                    self.widths[own] = None
                if own in self.data:
                    if self.data[own] != dest:
                        self.problem(f"{sec.name}+0x{off + r['off']:X} points to two different ROM addresses")
                    continue
                self.local_map[own] = self.data[own] = dest
                todo.append(own)

    def significant(self, mine: bytes, addr: int, width: int | None) -> int:
        starts = [*self.data.values(), *(a for _, a in self.target_at.values())]
        return significant(mine, addr, width, lambda lo: min(
            [a for a in (self.symbols.next_after(lo - 1), *starts) if a is not None and a >= lo], default=None))

    def verify_data(self, shndx: int, off: int, addr: int) -> None:
        """Data the candidate defines must be identical to the ROM data it stands for."""
        sec = self.elf.get_section(shndx)
        if sec["sh_type"] == "SHT_NOBITS":
            return
        length = self.extent(shndx, off)
        if length <= 0:
            return
        mine = bytearray(sec.data()[off:off + length])
        width = self.widths.get((shndx, off))
        raw = raw_relocs(self.elf, shndx, off, length, bytes(mine))
        for k, r in enumerate(raw):
            # every relocation in a region the candidate defines is applied before the bytes are compared: a table's
            # pointers, and a static helper's calls, %hi/%lo and $gp-relative loads (#221), whose fields would
            # otherwise compare as the assembler's unrelocated 0 with a match lost on one half-word
            at, rtype = r["off"], r["type"]
            if rtype not in _REGION_RELOCS or not 0 <= at <= length - 4:
                continue
            if self._unpaired(raw, r):
                self.problem(f"a %hi or %lo inside your data at {sec.name}+0x{off + at:X} has no other half")
                return
            if rtype == R_MIPS_GPREL16 and not self.target.gp:
                self.problem("your code uses $gp-relative data, but this game doesn't: compile with -G0")
                return
            if rtype == R_MIPS_32 and width and at >= width:
                # A table of pointers read through an index (GCC's switch: `addu $at, $at, $v0; lw $at,
                # %lo(jtbl)($at)`): the load's width is one entry, but every entry is the candidate's.
                width = None
            value = self._region_value(raw, k)
            dest, own = (None, None) if value is None else self._pointee(r["symtab"].get_symbol(r["symidx"]), value)
            if own is not None:
                dest = self.local_map.get(own)
            if dest is None:
                self.problem(f"can't place a pointer inside your data at {sec.name}+0x{off + at:X}")
                return
            word = int.from_bytes(mine[at:at + 4], self.target.order)
            mine[at:at + 4] = _patch(word, rtype, dest & 0xFFFFFFFF, self.target.gp).to_bytes(4, self.target.order)
        n = self.significant(bytes(mine), addr, width)
        rom = self.read(addr, n)
        if rom is None:
            return  # the ROM has no bytes there (e.g. .bss in the ROM): nothing to compare
        if bytes(mine[:n]) != rom:
            where = self.symbols.label(addr)
            self.problem(f"your data for {where} differs from the ROM: yours {bytes(mine[:min(n, 24)]).hex(' ')}"
                         f"{'…' if n > 24 else ''}, ROM {rom[:24].hex(' ')}{'…' if n > 24 else ''}")

    def run(self) -> LinkResult:
        fsym = self.function()
        if fsym is None:
            return LinkResult(None, False, [f"the object has no function named `{self.name}`"])
        shndx, start, size = fsym
        self.fn_shndx = shndx
        code = self.elf.get_section(shndx).data()[start:start + size]
        raw = raw_relocs(self.elf, shndx, start, size, code)
        if self.elf.little_endian == self.target.big_endian:
            return LinkResult(None, False, ["the compiler produced code in the wrong byte order for this game"])
        fmt = (">" if self.target.big_endian else "<") + f"{len(code) // 4}I"
        words = list(struct.unpack(fmt, code[:len(code) // 4 * 4]))
        self.words = list(words)
        relocs: list[Reloc] = []
        for k, r in enumerate(raw):
            addr = self.address(raw, k, shndx, start)
            if addr is None:
                sym = r["symtab"].get_symbol(r["symidx"])
                relocs.append(Reloc(r["off"], r["type"], f"?{sym.name or 'local'}", 0))
                continue
            i = r["off"] // 4
            if i < len(words):
                words[i] = _patch(words[i], r["type"], addr, self.target.gp)
            name, residual = self.symbols.name_at(addr)
            if self.target.vram <= addr < self.target.vram + len(self.target.code):
                name, residual = self.name, addr - self.target.vram
            relocs.append(Reloc(r["off"], r["type"], name, encode(r["type"], residual)))
        # every place is known before any datum is measured: a datum runs to the next one, whatever the code's order
        self.place_pointees()
        for (dshndx, off), addr in sorted(self.data.items()):
            self.verify_data(dshndx, off, addr)
        linked = struct.pack(fmt[0] + f"{len(words)}I", *words)
        exact = not self.problems and linked == self.target.code
        placements: dict[str, dict[int, int]] = {}
        for (dshndx, off), addr in self.local_map.items():
            placements.setdefault(self.elf.get_section(dshndx).name, {})[off] = addr
        return LinkResult(FunctionObj(self.name, "mips", self.target.big_endian, code, relocs), exact, self.problems,
                          placements, dict(self.library_names))


def link(obj: bytes, name: str, target: RomTarget, symbols: SymbolTable, read: ReadFn) -> LinkResult:
    """Link a compiled candidate at the target's address and compare it with the ROM."""
    obj = unmangle(obj, lambda n: n in symbols.by_name or bool(AUTO_NAME.match(n)))  # C++ names: the game's
    return _Linker(obj, name, target, symbols, read).run()


def diff(target: FunctionObj, result: LinkResult) -> scoring.DiffResult:
    """Score with the usual instruction diff, but decide the match by the linked bytes."""
    d = scoring.diff(target, result.candidate)
    if result.exact:
        return scoring.DiffResult(0, d.max_score, d.rows, True)
    return scoring.DiffResult(max(1, d.score), d.max_score, d.rows, False)
