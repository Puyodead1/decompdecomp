#!/usr/bin/env python3
"""Rebuild the game's programs (FA and its modules, as VFF files) from what src/ compiles to, in place: every
function at its address in your copy, linked by name.

    python tools/rebuild.py VERSION [--check] [--all]

A function whose compiled code is the original's but for its relocations (a match) is taken from the compiled
object, its calls, branches and addresses resolved by the names it uses (the game's names by address, the real
names of config/VERSION/names.json, the libraries'); the rest of the program is your copy's bytes. --check compares
the result with your copy, program by program: a matched function that names the wrong function or data rebuilds
otherwise, which objdiff (which compares instructions, not where their relocations point) can't see.

--all takes every function src/ compiles, matched or not (a mod): its code must fit where the original's was, and
what the compiled objects add (strings, tables, variables) goes in a region of its own after the program's.

The VFF files go to build/VERSION/rebuilt/ (FA.VFF, <module>.VFF; BOOT.BIN when the project has the loader's part
of your copy's, orig/VERSION/BOOT.HEAD). Standard library only. Made by decompdecomp.
"""

import json
import re
import struct
import sys
from pathlib import Path

from names import real_names  # (tools/names.py, beside this file)

R_ARM_PC24, R_ARM_ABS32 = 1, 2
SHT_SYMTAB, SHT_REL, SHT_NOBITS = 2, 9, 8
SHF_ALLOC, SHF_EXECINSTR = 2, 4
STT_SECTION = 3
REGIONS_AT, REGION_BYTES, REGION_COUNT_AT = 0x30, 16, 0x2C
EXTRA_ALIGN = 0x1000
ADDRESS = re.compile(r"(?:func|D)_(?:[A-Za-z0-9]+_)?([0-9A-Fa-f]{8})")
ROOT = Path(__file__).resolve().parent.parent


class LinkError(Exception):
    pass


def elf_segments(data: bytes) -> list[tuple[int, int, int, int]]:
    """(address, file offset, bytes in the file, bytes in memory) of each of a program's segments."""
    count = struct.unpack_from("<H", data, 44)[0]
    return [(vaddr, off, filesz, memsz) for _, off, vaddr, _, filesz, memsz, _, _ in
            (struct.unpack_from("<8I", data, 52 + 32 * i) for i in range(count))]


class Object:
    """A compiled ELF object: its sections, symbols and relocations."""

    def __init__(self, data: bytes):
        self.data = data
        shoff, = struct.unpack_from("<I", data, 32)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 46)
        self.sections = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]
        self.names = [self._string(shstrndx, s[0]) for s in self.sections]
        symtab = next(i for i, s in enumerate(self.sections) if s[1] == SHT_SYMTAB)
        strtab = self.sections[symtab][6]
        at, size = self.sections[symtab][4], self.sections[symtab][5]
        self.symbols = []  # (name, value, size, type, section)
        for a in range(at, at + size, 16):
            name, value, sym_size, info, _, shndx = struct.unpack_from("<IIIBBH", data, a)
            self.symbols.append((self._string(strtab, name), value, sym_size, info & 0xF, shndx))
        self.relocs: dict[int, list[tuple[int, int, int]]] = {}  # section -> [(offset, type, symbol)]
        for s in self.sections:
            if s[1] == SHT_REL:
                self.relocs[s[7]] = [(off, info & 0xFF, info >> 8) for off, info in
                                     (struct.unpack_from("<II", data, a) for a in range(s[4], s[4] + s[5], 8))]

    def _string(self, table: int, at: int) -> str:
        start = self.sections[table][4] + at
        return self.data[start:self.data.index(b"\0", start)].decode("latin-1")

    def section_bytes(self, i: int) -> bytes:
        s = self.sections[i]
        return bytes(s[5]) if s[1] == SHT_NOBITS else self.data[s[4]:s[4] + s[5]]

    def defined_in(self, shndx: int) -> str | None:
        """The function a section of code is (-ffunction-sections: one each)."""
        return next((s for s, value, _, stype, sec in self.symbols if sec == shndx and value == 0 and stype == 2), None)

    def function(self, name: str):
        """(section, its bytes) of a function defined at the start of a section of its own, or None."""
        for sym, value, _, _, shndx in self.symbols:
            if sym == name and 0 < shndx < len(self.sections) and value == 0 and self.names[shndx].startswith(".text"):
                return shndx, self.section_bytes(shndx)
        return None


def _masked(code: bytes, relocs) -> bytearray:
    out = bytearray(code)
    for off, kind, _ in relocs:
        word = struct.unpack_from("<I", out, off)[0]
        struct.pack_into("<I", out, off, word & (0xFF000000 if kind == R_ARM_PC24 else 0))
    return out


def _sign24(imm: int) -> int:
    return (imm - (1 << 24) if imm & 0x800000 else imm) << 2


class Program:
    """One program of the game, rebuilt in its copy's bytes."""

    def __init__(self, name: str, elf: bytes):
        self.name = name
        self.segments = elf_segments(elf)
        self.loads = [(a, bytearray(elf[off:off + size])) for a, off, size, _ in self.segments if size]
        self.bss = next(((a, m) for a, _, size, m in self.segments if not size), (0, 0))
        self.extra = bytearray()  # what the compiled objects add (--all), in a region of its own
        top = max([a + len(d) for a, d in self.loads] + [self.bss[0] + self.bss[1]])
        self.extra_at = (top + EXTRA_ALIGN - 1) & ~(EXTRA_ALIGN - 1)

    def read(self, addr: int, n: int) -> bytes:
        for a, d in self.loads:
            if a <= addr and addr + n <= a + len(d):
                return bytes(d[addr - a:addr - a + n])
        raise LinkError(f"{self.name} has no bytes at 0x{addr:08X}")

    def write(self, addr: int, data: bytes) -> None:
        for a, d in self.loads:
            if a <= addr and addr + len(data) <= a + len(d):
                d[addr - a:addr - a + len(data)] = data
                return
        raise LinkError(f"{self.name} has no bytes at 0x{addr:08X}")

    def add(self, data: bytes, align: int) -> int:
        """A place for compiled data in the program's own new region (--all): its address."""
        self.extra += bytes(-len(self.extra) % max(align, 4))
        at = self.extra_at + len(self.extra)
        self.extra += data
        return at

    def vff(self) -> bytes:
        """The program as a VFF file: its regions' bytes one after the other, the first starting with the header (a
        new region, when there's one, listed in it)."""
        regions = [bytearray(d) for _, d in self.loads]
        if self.extra:
            head = regions[0]
            count = struct.unpack_from("<I", head, REGION_COUNT_AT)[0]
            slot = REGIONS_AT + REGION_BYTES * count
            if any(head[slot:slot + REGION_BYTES]):
                raise LinkError(f"{self.name}'s header has no room to list another region")
            struct.pack_into("<4I", head, slot, self.extra_at, len(self.extra), 0, 0)
            struct.pack_into("<I", head, REGION_COUNT_AT, count + 1)
            regions.append(self.extra)
        return b"".join(bytes(r) for r in regions)


def rebuild(version: str, every: bool = False, unknown: set[str] | None = None
            ) -> tuple[dict[str, bytes], dict[str, bytes], list[str]]:
    """({program: rebuilt VFF}, {program: your copy's VFF}, what was taken from src/). `unknown` gets the names
    matched code uses that the game hasn't got (where the original's call or address goes is taken instead)."""
    unknown = set() if unknown is None else unknown
    config = ROOT / "config" / version / "functions.json"
    info = json.loads(config.read_text(encoding="utf-8"))
    real = real_names(info, config)
    by_real = {v: k for k, v in real.items()}
    objdiff = json.loads((ROOT / "objdiff.json").read_text(encoding="utf-8"))
    bases = {u["name"]: ROOT / u["base_path"] for u in objdiff["units"] if u.get("base_path")}
    programs = {p: Program(p, (ROOT / w["elf"]).read_bytes()) for p, w in info["programs"].items()}
    originals = {p: prog.vff() for p, prog in programs.items()}
    where: dict[str, int] = {}  # every function's names, by both names, -> address
    for u, fns in info["units"].items():
        for f in fns:
            where[f["name"]] = f["addr"]
            if f["name"] in real:
                where[real[f["name"]]] = f["addr"]

    def address(name: str, program: str) -> int:
        if name in where:
            return where[name]
        name = by_real.get(name, name)
        if (m := ADDRESS.fullmatch(name)):
            return int(m.group(1), 16)
        raise LinkError(f"{program}: nothing of the game is called {name}")
    taken = []
    for unit, fns in info["units"].items():
        program = programs.get(unit.split("/", 1)[0])
        base = bases.get(unit)
        if program is None or base is None or not base.exists():
            continue
        obj = Object(base.read_bytes())
        sections = {}  # a section of the object -> the address it's linked at
        found = []
        for f in fns:
            name = real.get(f["name"], f["name"])
            hit = obj.function(name)
            if hit is None:
                continue
            shndx, code = hit
            relocs = obj.relocs.get(shndx, [])
            original = program.read(f["addr"], f["size"])
            matched = len(code) == f["size"] and _masked(code, relocs) == _masked(original, relocs)
            if not matched and not every:
                continue
            if len(code) > f["size"]:
                raise LinkError(f"{name} is {len(code)} bytes in src/, its place in {program.name} {f['size']}")
            sections[shndx] = f["addr"]
            found.append((f, name, shndx, code, relocs, original, matched))
        for f, name, shndx, code, relocs, original, matched in found:
            out = bytearray(code)
            for off, kind, sym in relocs:
                sname, value, _, stype, sec = obj.symbols[sym]
                word = struct.unpack_from("<I", out, off)[0]
                if stype == STT_SECTION and sec not in sections and (static := obj.defined_in(sec)) in where:
                    target = where[static]  # (a static function of this file, not taken from it: the original's)
                elif stype == STT_SECTION or (sec and sname not in where and not ADDRESS.fullmatch(by_real.get(sname, sname))):
                    if sec in sections:  # (a function of this file: its own labels, a static function)
                        target = sections[sec] + value
                    elif matched:  # (its own data, a static function the game hasn't got: where the original's are)
                        if not (obj.sections[sec][2] & SHF_ALLOC and not obj.sections[sec][2] & SHF_EXECINSTR):
                            unknown.add(obj.defined_in(sec) or obj.names[sec])
                        struct.pack_into("<I", out, off, struct.unpack_from("<I", original, off)[0])
                        continue
                    elif every and obj.sections[sec][2] & SHF_ALLOC and not obj.sections[sec][2] & SHF_EXECINSTR:
                        sections[sec] = program.add(obj.section_bytes(sec), obj.sections[sec][8])
                        target = sections[sec] + value
                    else:
                        raise LinkError(f"{name} refers to {obj.names[sec] or sname}, which has no place in the game")
                else:
                    try:
                        target = address(sname, program.name)
                    except LinkError:
                        if not matched:
                            raise
                        # (a name the game hasn't got yet, a library's memset: where the original's goes)
                        unknown.add(sname)
                        struct.pack_into("<I", out, off, struct.unpack_from("<I", original, off)[0])
                        continue
                at = f["addr"] + off
                if kind == R_ARM_PC24:
                    field = ((target + _sign24(word & 0xFFFFFF) - at) >> 2) & 0xFFFFFF
                    struct.pack_into("<I", out, off, (word & 0xFF000000) | field)
                elif kind == R_ARM_ABS32:
                    struct.pack_into("<I", out, off, (target + word) & 0xFFFFFFFF)
            program.write(f["addr"], bytes(out) + bytes(f["size"] - len(out)))
            taken.append(name)
    return {p: prog.vff() for p, prog in programs.items()}, originals, taken


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    version = args[0]
    unknown: set[str] = set()
    try:
        rebuilt, originals, taken = rebuild(version, every="--all" in sys.argv, unknown=unknown)
    except LinkError as e:
        sys.exit(f"the rebuild failed: {e}")
    if unknown:
        print(f"names matched code uses that the game hasn't got (worth naming its functions so): {', '.join(sorted(unknown))}")
    out = ROOT / "build" / version / "rebuilt"
    out.mkdir(parents=True, exist_ok=True)
    for program, data in rebuilt.items():
        (out / f"{program}.VFF").write_bytes(data)
    head = ROOT / "orig" / version / "BOOT.HEAD"
    if head.exists():
        boot = bytearray(head.read_bytes() + rebuilt["FA"])
        struct.pack_into("<I", boot, 4, len(boot))
        (out / "BOOT.BIN").write_bytes(bytes(boot))
    print(f"{len(taken)} functions from src/, the rest from your copy: build/{version}/rebuilt/")
    if "--check" in sys.argv:
        differ = [p for p in rebuilt if rebuilt[p] != originals[p]]
        for p in differ:
            a, b = rebuilt[p], originals[p]
            at = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
            print(f"{p} differs from your copy, first at byte 0x{at:X} of its VFF")
        print("identical: every program rebuilds byte for byte" if not differ else
              f"not identical: {', '.join(differ)}")
        sys.exit(1 if differ else 0)


if __name__ == "__main__":
    main()
