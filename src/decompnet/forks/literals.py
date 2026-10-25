"""The constants a matched function loads, compared with the original's.

objdiff's progress rules (functionRelocDiffs: none) ignore what a relocation points at, so the compiler's @91 can
stand for the original's lbl_802C2BD0: names and places in a partly decompiled file differ, values don't. But the
same rule would count a function that loads 1.2 where the original loads 1.1 as matched. Where both objects hold
the data an instruction loads (a float in .sdata2, a double in .rodata, a string), the values are compared here.
Data outside an object (an extern) can't be checked, and isn't.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from ..elfobj import _function_symbols, section_target
from ..rom.match import raw_relocs

# Bytes a load or store moves, by mnemonic (PowerPC, MIPS). Anything else (an address computed with addi or lui)
# is only compared when both sides point at a C string.
_WIDTH = {
    **{m: 8 for m in ("lfd", "lfdu", "lfdx", "lfdux", "stfd", "stfdu", "ldc1", "sdc1", "ld", "sd", "ldl", "ldr")},
    **{m: 4 for m in ("lfs", "lfsu", "lfsx", "stfs", "stfsu", "lwz", "lwzu", "lwzx", "stw", "stwu", "lwc1", "swc1",
                      "lw", "lwu", "sw", "l.s", "s.s")},
    **{m: 2 for m in ("lhz", "lhzu", "lha", "lhau", "sth", "sthu", "lh", "lhu", "sh")},
    **{m: 1 for m in ("lbz", "lbzu", "stb", "stbu", "lb", "lbu", "sb")},
}
_ADDRESS = {"addi", "addic", "addiu", "daddiu", "ori", "la", "li"}


@dataclass
class Mismatch:
    offset: int  # in the function
    mnemonic: str
    original: str  # the original's label
    theirs: bytes
    yours: bytes
    big_endian: bool = True

    def describe(self) -> str:
        return (f"+0x{self.offset:X} {self.mnemonic}: the original's {self.original} holds "
                f"{_show(self.theirs, self.big_endian)}, yours {_show(self.yours, self.big_endian)}")


def _show(data: bytes, big: bool = True) -> str:
    e = ">" if big else "<"
    if len(data) == 8:
        return f"{struct.unpack(e + 'd', data)[0]!r} (0x{data.hex().upper()})"
    if len(data) == 4:
        return f"{struct.unpack(e + 'f', data)[0]!r} (0x{data.hex().upper()})"
    if data.endswith(b"\0") and all(32 <= c < 127 or c in (9, 10, 13) for c in data[:-1]):
        return '"' + data[:-1].decode().replace("\n", "\\n") + '"'
    return "0x" + data.hex().upper()


class _Object:
    def __init__(self, path: Path):
        self.elf = ELFFile(BytesIO(path.read_bytes()))
        self.big = not self.elf.little_endian
        self.machine = self.elf["e_machine"]

    def refs(self, name: str) -> tuple[int, dict[int, tuple[str, bytes | None, int]]] | None:
        """(function size, {instruction offset: (label, the referenced section's bytes or None, offset in it)})."""
        found = _function_symbols(self.elf).get(name)
        if found is None:
            return None
        shndx, start, size = found
        code = self.elf.get_section(shndx).data()[start:start + size]
        raw = raw_relocs(self.elf, shndx, start, size, code)
        out: dict[int, tuple[str, bytes | None, int]] = {}
        for k, r in enumerate(raw):
            residual = r["value"] if r["rela"] else section_target("mips", raw, k)
            if residual is None:
                continue
            sym = r["symtab"].get_symbol(r["symidx"])
            target = sym["st_shndx"]
            if not isinstance(target, int) or target == 0:
                out[r["off"] & ~3] = (sym.name, None, 0)  # outside this object
                continue
            sec = self.elf.get_section(target)
            section_sym = sym["st_info"]["type"] == "STT_SECTION"
            data = None if sec["sh_type"] == "SHT_NOBITS" or sec["sh_flags"] & 0x4 else sec.data()
            label = sec.name if section_sym else sym.name
            out[r["off"] & ~3] = (label, data, residual + (0 if section_sym else sym["st_value"]))
        return size, out


_BY_ADDRESS = re.compile(r"^(?:func|data|D|lbl)_(?:[A-Za-z0-9]+_)?[0-9A-Fa-f]{8}$")  # func_10A693A0, D_GZ1A_10B01854


@dataclass
class NameMismatch:
    """A reference to another symbol than the original's (ARM: a word of the pool, a call): objdiff's rules accept
    it, but the link puts another address there."""
    offset: int
    original: str
    yours: str

    def describe(self) -> str:
        return f"+0x{self.offset:X}: the original refers to {self.original} here, yours to {self.yours}"


def _named_refs(obj: _Object, name: str) -> dict[int, str] | None:
    """{offset in the function: the symbol its relocation names}, for references to named symbols (not a section's,
    not a name a compiler makes up)."""
    from .objdiff import _GENERATED

    found = _function_symbols(obj.elf).get(name)
    if found is None:
        return None
    shndx, start, size = found
    out: dict[int, str] = {}
    for sec in obj.elf.iter_sections():
        if sec["sh_type"] not in ("SHT_REL", "SHT_RELA") or sec["sh_info"] != shndx:
            continue
        symtab = obj.elf.get_section(sec["sh_link"])
        for r in sec.iter_relocations():
            off = r["r_offset"] - start
            if not 0 <= off < size:
                continue
            sym = symtab.get_symbol(r["r_info_sym"])
            if sym.name and sym["st_info"]["type"] != "STT_SECTION" and not _GENERATED.match(sym.name):
                out[off] = sym.name
    return out


def _arm_names(left: _Object, right: _Object, symbol: str) -> list[NameMismatch]:
    """ARM (V.Flash, where both objects name what they refer to the same way): the words and calls whose relocation
    names another symbol than the original's. A function whose pool held D_10B0184C where the original's held
    D_10B01854 (two stores in the other order) read 100% and broke the game's rebuild."""
    a, b = _named_refs(left, symbol), _named_refs(right, symbol)
    if a is None or b is None:
        return []
    # (one by its address, the other by its real name, can be the same thing: the library's memset where the
    # original names func_10A693A0; only two of a kind tell)
    return [NameMismatch(at, name, b[at]) for at, name in sorted(a.items())
            if at in b and b[at] != name and bool(_BY_ADDRESS.match(name)) == bool(_BY_ADDRESS.match(b[at]))]


def _string(data: bytes, at: int) -> bytes | None:
    end = data.find(b"\0", at, at + 512)
    if end < 0:
        return None
    s = data[at:end + 1]
    return s if all(32 <= c < 127 or c in (9, 10, 13) for c in s[:-1]) else None


def mismatches(target: Path, base: Path, symbol: str, insns: list[tuple[int, str]]) -> list:
    """Loaded constants that differ, for a function whose instructions match (`insns`: the original's (offset in
    the function, mnemonic), in order); on ARM, references to other symbols than the original's (NameMismatch)."""
    try:
        left, right = _Object(target), _Object(base)
    except (OSError, ValueError, ELFError):  # COFF objects (PC, Xbox): no verdict
        return []
    if left.machine != right.machine or left.machine not in ("EM_PPC", "EM_MIPS", "EM_ARM"):
        return []
    if left.machine == "EM_ARM":
        try:
            return _arm_names(left, right, symbol)
        except Exception:  # an unusual object: no verdict rather than a wrong one
            return []
    try:
        a, b = left.refs(symbol), right.refs(symbol)
    except Exception:  # an unusual object: no verdict rather than a wrong one
        return []
    if a is None or b is None:
        return []
    out = []
    for at, mnemonic in insns:
        ra, rb = a[1].get(at), b[1].get(at)
        if not ra or not rb or ra[1] is None or rb[1] is None:
            continue
        (label, da, oa), (_, db, ob) = ra, rb
        width = _WIDTH.get(mnemonic)
        if width:
            theirs, yours = da[oa:oa + width], db[ob:ob + width]
            if len(theirs) != width or len(yours) != width:
                continue
        elif mnemonic in _ADDRESS:
            theirs, yours = _string(da, oa), _string(db, ob)
            if theirs is None or yours is None:
                continue
        else:
            continue
        if theirs != yours:
            out.append(Mismatch(at, mnemonic, label, theirs, yours, left.big))
    return out
