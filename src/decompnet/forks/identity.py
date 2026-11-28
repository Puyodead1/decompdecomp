"""Whether two builds of a unit are the same object: what a machine pass over the source (pruning declarations or
pragmas, making a constant a literal, reordering definitions) must leave as it was. objdiff, as decompdecomp runs it,
can't tell: it scores each function's instructions, and a constant read through another symbol, a function the
original lacks, functions in another order or a reference to the wrong symbol all keep every score.

The fingerprint is the object's sections without `.comment` (the compiler's stamp), each relocation (where, its
kind, what it points at, its addend) and the defined symbols in their order. Names the compiler makes up (MWCC's
`@1234`, GCC's `.L12`) are compared by the order they first appear in, so a pass that changes how many it made
before them isn't a difference unless what they stand for is.

A pass meant to change the object's data (an extern of the file's own constant made a literal, a static renamed) is
judged by code_differences instead: the code byte for byte, each relocation where it was and pointing at the same
name or the same bytes; its caller sees that the data got no further from the original's.

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


_EXEC, _ALLOC = 0x4, 0x2


class _Object:
    """An object read for code_differences: its sections, its symbols, where each defined one is."""

    def __init__(self, path: Path):
        self.elf = ELFFile(BytesIO(Path(path).read_bytes()))
        self.secs = list(self.elf.iter_sections())
        self.symtab = next((s for s in self.secs if isinstance(s, SymbolTableSection)), None)
        self.defined: dict[str, object] = {}
        self.spans: dict[int, list[tuple[int, int]]] = {}  # section index: (start, size) of its symbols
        for sym in self.symtab.iter_symbols() if self.symtab is not None else ():
            shndx = sym["st_shndx"]
            if not isinstance(shndx, int) or not shndx or sym["st_info"]["type"] in ("STT_SECTION", "STT_FILE"):
                continue
            if sym.name:
                self.defined.setdefault(sym.name, sym)
            if sym["st_size"]:
                self.spans.setdefault(shndx, []).append((sym["st_value"], sym["st_size"]))

    def code(self) -> dict[str, tuple[int, bytes]]:
        return {s.name: (i, s.data()) for i, s in enumerate(self.secs)
                if s["sh_type"] == "SHT_PROGBITS" and s["sh_flags"] & _EXEC and s.name not in SKIP}

    def place(self, shndx: int, at: int, size: int) -> tuple:
        """What sits at a place in this object: code by where it is (the code is compared byte for byte already),
        data by its bytes, .bss by its size."""
        sec = self.secs[shndx]
        if sec["sh_flags"] & _EXEC:
            return ("code", sec.name, at)
        if not size:  # (a section symbol, or a label without a size: the symbol around the place)
            size = next((start + n - at for start, n in self.spans.get(shndx, ()) if start <= at < start + n), 0)
        if sec["sh_type"] == "SHT_NOBITS":
            return ("bss", size)
        if not size:  # (still none: a pooled constant GCC names by its section; what's there up to the next symbol)
            ends = [start for start, _ in self.spans.get(shndx, ()) if start > at]
            return ("bytes?", sec.data()[at:min(ends, default=sec["sh_size"])])
        return ("bytes", sec.data()[at:at + size])

    def target(self, sym, addend: int, others: tuple[_Object, ...]) -> tuple:
        """What a relocation points at: (its name when that's one other files link by, what's there)."""
        name = sym.name if sym.name and not _MADE_UP.match(sym.name) else None
        shndx = sym["st_shndx"]
        if isinstance(shndx, int) and 0 < shndx < len(self.secs):
            local = sym["st_info"]["bind"] == "STB_LOCAL"
            size = sym["st_size"] - addend if sym["st_size"] > addend else 0
            return (None if local else name), self.place(shndx, sym["st_value"] + addend, size)
        for other in others:  # (declared here, defined there: the original's object holds what it is)
            if name and (found := other.defined.get(name)) is not None:
                size = found["st_size"] - addend if found["st_size"] > addend else 0
                return name, other.place(found["st_shndx"], found["st_value"] + addend, size)
        return name, ("name", sym.name, addend)

    def relocations(self, others: tuple[_Object, ...]) -> dict[str, list[tuple[int, int, tuple]]]:
        """Each code section's relocations: (offset, type, what they point at), in order."""
        out: dict[str, list] = {}
        for rs in self.secs:
            if not isinstance(rs, RelocationSection):
                continue
            into = self.secs[rs["sh_info"]]
            if not (into["sh_flags"] & _EXEC) or into.name in SKIP:
                continue
            symtab = self.elf.get_section(rs["sh_link"])
            for r in rs.iter_relocations():
                addend = r["r_addend"] if r.is_RELA() else 0
                out.setdefault(into.name, []).append(
                    (r["r_offset"], r["r_info_type"], self.target(symtab.get_symbol(r["r_info_sym"]), addend, others)))
        return {k: sorted(v, key=lambda r: (r[0], r[1])) for k, v in out.items()}


def _alike(a: tuple, b: tuple) -> bool:
    """Two relocation targets are the same thing: the same name other files link by (two such names that differ
    never are), or the same bytes there when one has no such name (a constant the file's own literal now holds,
    where an extern of the original's label held it before; a static function renamed)."""
    if a[0] is not None and b[0] is not None:
        return a[0] == b[0]
    x, y = a[1], b[1]
    if {x[0], y[0]} <= {"bytes", "bytes?"} and "bytes?" in (x[0], y[0]):
        # one's size isn't known (a pooled constant named by its section): the other's bytes start it, or for two
        # such, what both hold up to the shorter
        if x[0] == y[0]:
            n = min(len(x[1]), len(y[1]))
            return n > 0 and x[1][:n] == y[1][:n]
        sized, unsized = (x[1], y[1]) if x[0] == "bytes" else (y[1], x[1])
        return bool(sized) and unsized.startswith(sized)
    return x == y


def code_differences(a: Path, b: Path, also: tuple[Path, ...] = ()) -> list[str] | None:
    """What differs between two builds of a unit's code, judged as a pass that moves constants or renames statics
    must be (#ADDON 1-5): every code section's bytes the same, every relocation at the same place and of the same
    kind, and each pointing at the same thing (by a name other files link by, or by the bytes there). Names a
    relocation points at that neither object defines are looked up in `also` (the original's object). None: no
    verdict, an object isn't ELF. The data is the caller's to judge (datadiff: it mustn't get further from the
    original's)."""
    try:
        others = tuple(_Object(p) for p in also if p is not None and Path(p).exists())
        oa, ob = _Object(a), _Object(b)
        out: list[str] = []
        ca, cb = oa.code(), ob.code()
        for name in sorted(set(ca) | set(cb)):
            if name not in ca or name not in cb:
                out.append(f"code section {name} is only in the {'first' if name in ca else 'second'} object")
            elif ca[name][1] != cb[name][1]:
                x, y = ca[name][1], cb[name][1]
                at = next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
                out.append(f"{name}'s code differs from 0x{at:X} on" + (f" (0x{len(x):X} bytes, then 0x{len(y):X})"
                                                                         if len(x) != len(y) else ""))
        ra, rb = oa.relocations(others + (ob,)), ob.relocations(others + (oa,))
        for name in sorted(set(ra) | set(rb)):
            x, y = ra.get(name, []), rb.get(name, [])
            if [(r[0], r[1]) for r in x] != [(r[0], r[1]) for r in y]:
                out.append(f"{name}: {len(x)} relocations, then {len(y)}, or at other places")
                continue
            for (at, _, p), (_, _, q) in zip(x, y, strict=True):
                if not _alike(p, q):
                    out.append(f"{name}+0x{at:X} points at {_said(p)}, then at {_said(q)}")
                    break
        return out
    except (OSError, ELFError, ValueError, IndexError, AttributeError, KeyError):
        return None


def _said(target: tuple) -> str:
    name, (kind, *rest) = target
    if kind in ("bytes", "bytes?"):
        return f"{name or 'a constant'} ({rest[0][:8].hex(' ') or 'nothing'})"
    if kind == "code":
        return f"{name or 'code'} ({rest[0]}+0x{rest[1]:X})"
    if kind == "bss":
        return f"{name or 'a variable'} ({rest[0]} bytes of .bss)"
    return f"{rest[0]}" + (f"+0x{rest[1]:X}" if rest[1] else "")
