"""Whether two builds of a unit are the same object: what a machine pass over the source (pruning declarations or
pragmas, making a constant a literal, reordering definitions) must leave as it was. objdiff, as decompdecomp runs it,
can't tell: it scores each function's instructions, and a constant read through another symbol, a function the
original lacks, functions in another order or a reference to the wrong symbol all keep every score.

The fingerprint is the object's sections without `.comment` (the compiler's stamp), each relocation (where, its
kind, what it points at, its addend) and the defined symbols in their order. Names the compiler makes up (MWCC's
`@1234`, GCC's `.L12`) are compared by the order they first appear in, so a pass that changes how many it made
before them isn't a difference unless what they stand for is.

ELF only: a COFF object (PC, Xbox) gives no fingerprint, and callers take that as no verdict."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

SKIP = {".comment", ".note.GNU-stack", ".mwcats", ".mdebug", ".pdr", ".gnu.attributes", ".reginfo", ".MIPS.abiflags"}
_MADE_UP = re.compile(r"^(@\d+|\.L\w+|\$L\w+|L\$\w+|\.\.\.\w+\.\d+)$")


@dataclass(frozen=True)
class Fingerprint:
    sections: tuple  # (name, type, size, align, sha1 of the bytes)
    relocations: tuple  # (section, offset, type, target, addend)
    symbols: tuple  # (name, section, value, size, bind, type), in address order

    def differences(self, other: Fingerprint, most: int = 6) -> list[str]:
        """What differs, in words: one line each, at most `most`."""
        out: list[str] = []
        mine, theirs = {s[0]: s for s in self.sections}, {s[0]: s for s in other.sections}
        for name in sorted(set(mine) | set(theirs)):
            a, b = mine.get(name), theirs.get(name)
            if a is None or b is None:
                out.append(f"section {name} is only in the {'first' if b is None else 'second'} object")
            elif a[2] != b[2]:
                out.append(f"section {name} is 0x{a[2]:X} bytes, then 0x{b[2]:X}")
            elif a != b:
                out.append(f"section {name}'s bytes differ")
        if self.relocations != other.relocations:
            moved = [r for r in self.relocations if r not in set(other.relocations)]
            r = moved[0] if moved else other.relocations[len(self.relocations):][:1][0]
            out.append(f"{len(self.relocations)} relocations, then {len(other.relocations)}; one that differs: "
                       f"{r[0]}+0x{r[1]:X} to {r[3]}")
        if [s[0] for s in self.symbols] != [s[0] for s in other.symbols]:
            a, b = [s[0] for s in self.symbols], [s[0] for s in other.symbols]
            i = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y), min(len(a), len(b)))
            out.append(f"the symbols differ from the {i + 1}. on: {', '.join(a[i:i + 3]) or 'none'} then "
                       f"{', '.join(b[i:i + 3]) or 'none'}")
        elif self.symbols != other.symbols:
            diff = next(s for s, t in zip(self.symbols, other.symbols, strict=True) if s != t)
            out.append(f"symbol {diff[0]} moved or changed size")
        return out[:most]


def _names(symtab: SymbolTableSection | None, elf: ELFFile) -> list[str]:
    """Each symbol's name for comparing: a made-up one as its order of appearance, a section symbol as its section."""
    if symtab is None:
        return []
    out, made = [], {}
    for sym in symtab.iter_symbols():
        name = sym.name
        if sym["st_info"]["type"] == "STT_SECTION" or (not name and isinstance(sym["st_shndx"], int)):
            try:
                name = "section " + elf.get_section(sym["st_shndx"]).name
            except (IndexError, TypeError, ELFError):
                name = "section ?"
        elif _MADE_UP.match(name):
            name = made.setdefault(name, f"<made-up {len(made)}>")
        out.append(name)
    return out


def fingerprint(path: Path) -> Fingerprint | None:
    """The object's fingerprint, or None when it isn't an ELF object (or can't be read)."""
    try:
        data = Path(path).read_bytes()
        elf = ELFFile(BytesIO(data))
        symtab = next((s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)), None)
        names = _names(symtab, elf)
        sections, relocations = [], []
        for sec in elf.iter_sections():
            kind = sec["sh_type"]
            if isinstance(sec, RelocationSection):
                target = elf.get_section(sec["sh_info"]).name
                if target in SKIP:
                    continue
                for rel in sec.iter_relocations():
                    i = rel["r_info_sym"]
                    relocations.append((target, rel["r_offset"], rel["r_info_type"],
                                        names[i] if i < len(names) else f"#{i}",
                                        rel["r_addend"] if rel.is_RELA() else None))
            elif kind in ("SHT_PROGBITS", "SHT_NOBITS", "SHT_INIT_ARRAY", "SHT_FINI_ARRAY") and sec.name not in SKIP:
                digest = "" if kind == "SHT_NOBITS" else hashlib.sha1(sec.data()).hexdigest()
                sections.append((sec.name, kind, sec["sh_size"], sec["sh_addralign"], digest))
        symbols = []
        if symtab is not None:
            for i, sym in enumerate(symtab.iter_symbols()):
                shndx = sym["st_shndx"]
                kind = sym["st_info"]["type"]
                if not isinstance(shndx, int) or kind in ("STT_FILE", "STT_SECTION") or not sym.name:
                    continue
                symbols.append((names[i], elf.get_section(shndx).name, sym["st_value"], sym["st_size"],
                                sym["st_info"]["bind"], kind))
            symbols.sort(key=lambda s: (s[1], s[2]))
        return Fingerprint(tuple(sections), tuple(relocations), tuple(symbols))
    except (OSError, ELFError, ValueError, IndexError, AttributeError, KeyError):
        return None


def same(a: Path, b: Path) -> bool | None:
    """Whether two objects are the same (None: no verdict, one isn't an ELF object)."""
    fa, fb = fingerprint(a), fingerprint(b)
    if fa is None or fb is None:
        return None
    return fa == fb
