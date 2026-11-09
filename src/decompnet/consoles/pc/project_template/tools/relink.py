#!/usr/bin/env python3
"""Link the game's program again with Visual C++'s own linker (LINK.EXE), from this project's objects.

    python tools/relink.py config/<version>/functions.json build/<version> --link LINK.EXE [--wrapper WIBO]
    (or: ninja relink)

tools/rebuild.py puts each function back at the game's address in your copy; this links a new program, so code can
change size and the rest moves with it (what a mod or a port needs). What goes in:
- the code: every function of src/ that compiles (build/<version>/src/auto/<unit>.obj), and every other one as
  tools/delink.py cuts it out of your copy, in the game's order;
- the data: every data section of your copy (.rdata, .data, and what is uninitialised as .bss) as one object,
  data.obj, with a symbol for every address the code names (D_00402034) and every word that points at a function, an
  import's slot or into the data written as a relocation to it, so it follows what it points at. Without base
  relocations (a program linked with /FIXED, as most games of the late 1990s), a pointer is a word whose value is a
  function's start or inside the data: a number that happens to be one is taken for one too (the program's data
  says nothing more);
- the imports: their tables stay in the data where your copy has them (their own section, or in .rdata), their RVAs
  relocations, every slot by the name the code reads it by (__imp__CreateFileA), and a thunk (jmp [slot]) for a
  call to the function itself (thunks.obj); the header's import directories are set to them after the link;
- the resources: your copy's, as the resource converter (CVTRES) writes them for the linker: their directory and
  data in .rsrc$01, each data entry's address a relocation (resources.obj).
The program's headers come from the linker, set as your copy's are: its address (/BASE), subsystem, stack and heap,
entry point, and /FIXED when it has no base relocations. Writes build/<version>/relink/<program>.exe, its map
(relink.map) and relink.json (which functions came from C, which moved, what had to be taken on trust); says
whether every function and global came out at the game's address and its code byte for byte the game's. The game's
own DLLs (functions.json's "modules") are not relinked yet. Standard library only. Made by decompdecomp.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

DIR32, DIR32NB, REL32 = 0x06, 0x07, 0x14
FUNCTION = 0x20
EXTERNAL, STATIC, LABEL, WEAK_EXTERNAL = 2, 3, 6, 105
SEARCH_ALIAS = 3  # a weak external's kind: the default symbol stands for it
CNT_CODE, CNT_DATA, CNT_BSS = 0x20, 0x40, 0x80
ALIGN_1, ALIGN_4, ALIGN_16 = 0x00100000, 0x00300000, 0x00500000
COMDAT = 0x1000
READ_WRITE = 0xC0000000
CODE = CNT_CODE | 0x60000000 | ALIGN_16
CODE_EXACT = CNT_CODE | 0x60000000 | ALIGN_1  # (a function of the game's: where the one before it ends, as in the game)
PADDING = b"\x90\xcc\x00"
DATA_SYMBOL = re.compile(r"_D_([0-9A-F]{8})")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# what the C runtime and the linker define as numbers, not places: __except_list is fs:[0], the thread's exception
# handler chain (every function with C++ exception handling reads it); __fltused only says the program uses floats
ABSOLUTE = {"__except_list": 0, "__fltused": 0x9875}
# the data directories (the optional header's table) this reads
IMPORTS, RESOURCES, SECURITY, BASE_RELOCATIONS, TLS, LOAD_CONFIG, IAT = 1, 2, 4, 5, 9, 10, 12
SUBSYSTEMS = {1: "NATIVE", 2: "WINDOWS", 3: "CONSOLE"}
SHOWN = 8
RVA = "$rva"  # (a name for an address outside the program, as a relative jump to it names it)


def fail(why: str) -> None:
    sys.exit(f"relink: {why}")


# ------------------------------------------------------------------------------------------------------- the program

class Image:
    """Your copy of the program: its header's settings, sections, imports and base relocations."""

    def __init__(self, exe: bytes):
        self.exe = exe
        pe = struct.unpack_from("<I", exe, 0x3C)[0]
        count, opt_size, self.characteristics = struct.unpack_from("<H12xHH", exe, pe + 6)
        opt = pe + 24
        self.entry, = struct.unpack_from("<I", exe, opt + 16)
        self.base, self.section_alignment, self.file_alignment = struct.unpack_from("<III", exe, opt + 28)
        self.subsystem_version = struct.unpack_from("<HH", exe, opt + 48)
        self.subsystem, = struct.unpack_from("<H", exe, opt + 68)
        self.stack = struct.unpack_from("<II", exe, opt + 72)
        self.heap = struct.unpack_from("<II", exe, opt + 80)
        dirs, = struct.unpack_from("<I", exe, opt + 92)
        self.dirs = [struct.unpack_from("<II", exe, opt + 96 + 8 * i) for i in range(dirs)]
        self.sections = []  # {"name", "addr", "vsize", "raw" (its bytes in the file), "flags"}
        for i in range(count):
            name, vsize, va, raw_size, raw_at, _, _, _, _, flags = struct.unpack_from("<8sIIIIIIHHI", exe,
                                                                                        opt + opt_size + 40 * i)
            self.sections.append({"name": name.rstrip(b"\0").decode("latin-1"), "addr": self.base + va,
                                  "vsize": vsize or raw_size, "raw": exe[raw_at:raw_at + min(raw_size, vsize or raw_size)],
                                  "flags": flags})

    def directory(self, index: int) -> tuple[int, int]:
        """A data directory's address (not its RVA) and size; (0, 0) when the program has none."""
        rva, size = self.dirs[index] if index < len(self.dirs) else (0, 0)
        return (self.base + rva if rva else 0), size

    def section_of(self, addr: int) -> dict | None:
        return next((s for s in self.sections if s["addr"] <= addr < s["addr"] + s["vsize"]), None)

    def read(self, addr: int, n: int) -> bytes:
        s = self.section_of(addr)
        if s is None:
            return b""
        at = addr - s["addr"]
        return s["raw"][at:at + n].ljust(min(n, s["vsize"] - at), b"\0")

    def word(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4).ljust(4, b"\0"))[0]

    def string(self, addr: int) -> bytes:
        return self.read(addr, 512).split(b"\0", 1)[0]

    def imports(self) -> list[tuple[str, list[dict]]]:
        """Each DLL the program imports from, with its slots in the order it has them: {"slot" (its address in the
        import address table), "symbol" (__imp__<name>, as the project's analysis names it: tools/rebuild.py),
        "name" (bytes; None: by ordinal), "hint", "ordinal"}."""
        at, _ = self.directory(IMPORTS)
        out = []
        while at and len(d := self.read(at, 20)) == 20 and d != bytes(20):
            lookup, _, _, name_rva, iat = struct.unpack("<IIIII", d)
            dll = self.string(self.base + name_rva).decode("latin-1")
            slots, k = [], 0
            while value := self.word(self.base + (lookup or iat) + 4 * k):
                slot = {"slot": self.base + iat + 4 * k, "name": None, "hint": 0, "ordinal": 0}
                if value & 0x80000000:
                    slot["ordinal"] = value & 0xFFFF
                    plain = f"{Path(dll).stem}_{slot['ordinal']}"
                else:
                    slot["hint"] = struct.unpack("<H", self.read(self.base + value, 2).ljust(2, b"\0"))[0]
                    slot["name"] = self.string(self.base + value + 2)
                    plain = slot["name"].decode("latin-1")
                    if not IDENTIFIER.fullmatch(plain):
                        plain = f"{Path(dll).stem}_{k}"
                slot["symbol"] = f"__imp__{plain}"
                slots.append(slot)
                k += 1
            out.append((dll, slots))
            at += 20
        return out

    def import_layout(self) -> list[dict]:
        """Where each DLL's import tables are, in the descriptors' order: {"dll", "descriptor", "lookup" (0: none),
        "iat", "name" (addresses), "slots" (imports(), each with "entry": its hint and name's address)}."""
        at, _ = self.directory(IMPORTS)
        out = []
        for (dll, slots) in self.imports():
            lookup, _, _, name_rva, iat = struct.unpack("<IIIII", self.read(at, 20))
            table = self.base + (lookup or iat)
            for k, slot in enumerate(slots):
                slot["entry"] = None if slot["name"] is None else self.base + self.word(table + 4 * k)
            out.append({"dll": dll, "descriptor": at, "lookup": self.base + lookup if lookup else 0,
                        "iat": self.base + iat, "name": self.base + name_rva, "slots": slots})
            at += 20
        return out

    def relocated(self) -> set[int] | None:
        """The addresses of every word the base relocations say holds an address; None: the program has none."""
        at, size = self.directory(BASE_RELOCATIONS)
        if not at:
            return None
        out, done = set(), 0
        while done + 8 <= size:
            page, length = struct.unpack("<II", self.read(at + done, 8))
            if length < 8:
                break
            entries = self.read(at + done + 8, length - 8)
            for k in range(0, len(entries) - 1, 2):
                entry = struct.unpack_from("<H", entries, k)[0]
                if entry >> 12 == 3:  # HIGHLOW
                    out.add(self.base + page + (entry & 0xFFF))
            done += length
        return out

    def resources(self) -> tuple[bytes, list[int]] | None:
        """The program's resources as they are in it (their directory, then their data), and where in them each
        data entry's address (an RVA) is; None when it has none."""
        root, _ = self.directory(RESOURCES)
        s = self.section_of(root) if root else None
        if s is None:
            return None
        body = self.read(s["addr"], s["vsize"])
        entries, todo = [], [root - s["addr"]]
        while todo:
            at = todo.pop()
            named, ids = struct.unpack_from("<HH", body, at + 12)
            for k in range(named + ids):
                child, = struct.unpack_from("<I", body, at + 16 + 8 * k + 4)
                if child & 0x80000000:
                    todo.append(child & 0x7FFFFFFF)
                else:
                    entries.append(child)
        start = root - s["addr"]
        if any(not start <= self.base + struct.unpack_from("<I", body, e + start)[0] - s["addr"] < len(body)
               for e in entries):
            fail("a resource's data is outside the resources' section")
        return body[start:], sorted(entries)


# ------------------------------------------------------------------------------------------------------ COFF objects

class Coff:
    """A COFF object being written: sections, their relocations, symbols."""

    def __init__(self):
        self.sections: list[dict] = []
        self.symbols: list[tuple] = []  # (name, value, section, type, class, aux bytes)
        self.index: dict[str, int] = {}  # external symbols by name
        self.position: dict[int, int] = {}  # a symbol's index in the table -> its place in self.symbols
        self.count = 0  # records in the table (auxiliary ones too)

    def section(self, name: str, data: bytes | None, flags: int, size: int = 0,
                comdat: tuple[int, int] | None = None) -> int:
        """A new section (data None: uninitialised, `size` bytes); its number, and a static symbol at its start
        (a COMDAT's (`comdat`: its selection, the section an associative one goes with) is its section symbol)."""
        self.sections.append({"name": name, "data": data, "size": len(data) if data is not None else size,
                              "flags": flags | (COMDAT if comdat else 0), "relocs": [], "comdat": comdat})
        number = len(self.sections)
        self.sections[-1]["symbol"] = self.symbol(name, 0, number, cls=STATIC, aux=bytes(18)) if comdat else \
            self.symbol(f"$S{number}", 0, number, cls=STATIC)
        return number

    def defined(self) -> set[str]:
        """The external names this object defines (an alias with its default too)."""
        return {s[0] for s in self.symbols if s[4] == WEAK_EXTERNAL or s[4] == EXTERNAL and (s[2] != 0 or s[1])}

    def undefined(self) -> set[str]:
        return {s[0] for s in self.symbols if s[4] == EXTERNAL and s[2] == 0 and not s[1]} - self.defined()

    def symbol(self, name: str, value: int, section: int, typ: int = 0, cls: int = EXTERNAL, aux: bytes = b"") -> int:
        if cls == EXTERNAL and name in self.index:
            at = self.index[name]
            if section:  # defined now, after code here referred to it: the same symbol, defined
                k = self.position[at]
                self.symbols[k] = (name, value, section, typ or self.symbols[k][3], cls, aux)
            return at
        at = self.count
        self.symbols.append((name, value, section, typ, cls, aux))
        self.position[at] = len(self.symbols) - 1
        self.count += 1 + len(aux) // 18
        if cls in (EXTERNAL, WEAK_EXTERNAL):
            self.index[name] = at
        return at

    def extern(self, name: str, function: bool = False) -> int:
        """A symbol this object refers to (defined here or elsewhere)."""
        return self.index[name] if name in self.index else self.symbol(name, 0, 0, FUNCTION if function else 0)

    def alias(self, name: str, of: str) -> None:
        """`name` stands for `of` wherever it's defined (a weak external with `of` its default)."""
        if name not in self.index:
            target = self.extern(of)
            self.symbol(name, 0, 0, 0, WEAK_EXTERNAL, struct.pack("<II10x", target, SEARCH_ALIAS))

    def reloc(self, section: int, offset: int, symbol: int, kind: int) -> None:
        self.sections[section - 1]["relocs"].append((offset, symbol, kind))

    def bytes(self) -> bytes:
        strings = bytearray(4)

        def short(name: str) -> bytes:
            raw = name.encode("latin-1")
            if len(raw) <= 8:
                return raw.ljust(8, b"\0")
            field = struct.pack("<II", 0, len(strings))
            strings.extend(raw + b"\0")
            return field
        # the table's order: every section's symbol first, then the rest as they were made (a COMDAT's own symbol,
        # defined after code here referred to it, must still come after its section's: LINK.EXE's LNK1143)
        heads = {self.position[s["symbol"]] for s in self.sections}
        order = sorted(heads) + [k for k in range(len(self.symbols)) if k not in heads]
        index_of = {k: i for i, k in self.position.items()}
        renumber, at = {}, 0
        for k in order:
            renumber[index_of[k]] = at
            at += 1 + len(self.symbols[k][5]) // 18
        at = 20 + 40 * len(self.sections)
        headers, body = bytearray(), bytearray()
        for s in self.sections:
            data, relocs = s["data"], s["relocs"]
            raw_at = at if data else 0
            body += data or b""
            at += len(data or b"")
            reloc_at = at if relocs else 0
            for off, symbol, kind in relocs:
                body += struct.pack("<IIH", off, renumber[symbol], kind)
            at += 10 * len(relocs)
            if len(relocs) > 0xFFFF:
                fail(f"a section of {len(relocs)} relocations (COFF holds 65,535)")
            name = s["name"].encode("latin-1")
            if len(name) > 8:
                name = f"/{len(strings)}".encode()
                strings.extend(s["name"].encode("latin-1") + b"\0")
            headers += struct.pack("<8sIIIIIIHHI", name, 0, 0, s["size"], raw_at, reloc_at, 0, len(relocs), 0,
                                   s["flags"])
            if s["comdat"]:  # (its section symbol's record: length, relocations, line numbers, checksum, with, selection)
                k = self.position[s["symbol"]]
                selection, with_it = s["comdat"]
                self.symbols[k] = self.symbols[k][:5] + (struct.pack("<IHHIHB3x", s["size"], len(relocs), 0, 0, with_it,
                                                                     selection),)
        table = bytearray()
        for k in order:
            name, value, section, typ, cls, aux = self.symbols[k]
            if cls == WEAK_EXTERNAL:  # (its default, by its new number)
                aux = struct.pack("<I", renumber[struct.unpack_from("<I", aux, 0)[0]]) + aux[4:]
            table += struct.pack("<8sIhHBB", short(name), value, section, typ, cls, len(aux) // 18) + aux
        struct.pack_into("<I", strings, 0, len(strings))
        count = len(table) // 18
        return struct.pack("<HHIIIHH", 0x14C, len(self.sections), 0, at, count, 0, 0) + headers + body + table + strings


class Compiled:
    """What a source file compiles to, read whole, its code cut into a piece per function: the link takes the
    functions that come from C and leaves the rest (a function C doesn't have yet, or has as other code, comes from
    your copy), with what those reach of the object (its helpers, constants, exception tables)."""

    DROPPED = (".debug$", ".drectve", ".CRT$")  # (debug information, linker directives; the program's own initialiser
    # lists, in the data, already name the game's initialisers)

    def __init__(self, data: bytes):
        _, count, _, table, nsyms, opt, _ = struct.unpack_from("<HHIIIHH", data, 0)
        strings = table + 18 * nsyms

        def text(at: int) -> str:
            return data[at:data.index(b"\0", at)].decode("latin-1")
        self.sections = []
        for i in range(count):
            raw, _, _, size, at, relocs, _, nrelocs, _, flags = struct.unpack_from("<8sIIIIIIHHI", data, 20 + opt + 40 * i)
            name = raw.rstrip(b"\0").decode("latin-1")
            if name.startswith("/"):
                name = text(strings + int(name[1:]))
            self.sections.append({"name": name, "flags": flags, "size": size, "data": data[at:at + size] if at else None,
                                  "relocs": [struct.unpack_from("<IIH", data, relocs + 10 * r) for r in range(nrelocs)]})
        self.symbols: dict[int, dict] = {}
        k = 0
        while k < nsyms:
            raw, value, section, typ, cls, aux = struct.unpack_from("<8sIhHBB", data, table + 18 * k)
            name = text(strings + struct.unpack_from("<I", raw, 4)[0]) if raw[:4] == b"\0\0\0\0" else \
                raw.rstrip(b"\0").decode("latin-1")
            self.symbols[k] = {"name": name, "value": value, "section": section, "type": typ, "cls": cls,
                               "aux": data[table + 18 * (k + 1):table + 18 * (k + 1 + aux)]}
            k += 1 + aux
        self.defined = {s["name"] for s in self.symbols.values() if s["section"] > 0 and s["cls"] == EXTERNAL}
        # pieces: a code section cut where each function starts (a COMDAT one, /Gy's, is one function already);
        # any other section whole
        self.pieces = []  # {"section", "lo", "hi", "function" (an external function's name, or None)}
        for number, sec in enumerate(self.sections, 1):
            if sec["name"].startswith(self.DROPPED) or sec["flags"] & 0xA00:  # (LNK_INFO, LNK_REMOVE)
                continue
            starts = sorted({0, *(s["value"] for s in self.symbols.values() if s["section"] == number
                                  and s["type"] == FUNCTION)}) if sec["flags"] & CNT_CODE and not sec["flags"] & COMDAT \
                else [0]
            for k, lo in enumerate(starts):
                hi = starts[k + 1] if k + 1 < len(starts) else sec["size"]
                names = [s["name"] for s in self.symbols.values() if s["section"] == number and s["value"] == lo
                         and s["cls"] == EXTERNAL and s["type"] == FUNCTION]
                self.pieces.append({"section": number, "lo": lo, "hi": hi, "function": names[0] if names else None})

    def piece_at(self, section: int, offset: int) -> int | None:
        """The piece a place in a section is in."""
        return next((k for k, p in enumerate(self.pieces) if p["section"] == section and p["lo"] <= offset < p["hi"]
                     or p["section"] == section and offset == p["hi"] == self.sections[section - 1]["size"]), None)

    def target(self, piece: dict, reloc: tuple) -> tuple[dict, int]:
        """The symbol a relocation names and the offset into its section it reaches (its value plus what the code
        holds there: a section's symbol and an offset is how a compiler reaches its own static data)."""
        off, index, kind = reloc
        symbol = self.symbols[index]
        sec = self.sections[piece["section"] - 1]
        inline = struct.unpack_from("<i", sec["data"], off)[0] if sec["data"] and kind in (DIR32, DIR32NB, REL32) else 0
        return symbol, symbol["value"] + (inline if self._is_section(symbol) else 0)

    def _is_section(self, symbol: dict) -> bool:
        return symbol["cls"] == STATIC and symbol["section"] > 0 and symbol["value"] == 0 and \
            symbol["name"] == self.sections[symbol["section"] - 1]["name"] and bool(symbol["aux"])

    def emit(self, obj: Coff, relink: "Relink", functions: list[dict], taken: set[str],
             labels: dict[str, list[tuple[str, int]]]) -> None:
        """A unit's functions into `obj` in the game's order, those in `taken` from this object (with what they
        reach of it), the rest delinked."""
        project = set(relink.by_name)
        exact = {fn["name"]: fn for fn in functions if fn["name"] in relink.games_code}

        def constant(piece: dict, reloc: tuple) -> bool:
            """A relocation of a function whose C is the game's code to something of this object's own (a string,
            a float, a static helper, an exception handler, a vtable), which goes to what the game's code has there:
            the game's copy, so this object's isn't needed."""
            if piece["function"] not in exact or reloc[2] not in (DIR32, REL32):
                return False
            symbol, at = self.target(piece, reloc)
            return symbol["section"] > 0 and not (symbol["cls"] == EXTERNAL and symbol["name"] in project) and \
                not DATA_SYMBOL.fullmatch(symbol["name"]) and self.piece_at(symbol["section"], at) != self.pieces.index(piece)

        # a function's piece: its last, where the object defines it twice (two COMDAT copies of an inline function,
        # which may differ: a game's had one with other registers), as tools/rebuild.py checks it against the game
        first: dict[str, int] = {}
        for k, p in enumerate(self.pieces):
            if p["function"] is not None:
                first[p["function"]] = k

        def follows(piece: dict, reloc: tuple) -> int | None:
            symbol, at = self.target(piece, reloc)
            if symbol["section"] <= 0 or constant(piece, reloc) or DATA_SYMBOL.fullmatch(symbol["name"]) or \
                    (symbol["cls"] == EXTERNAL and symbol["name"] in project and symbol["name"] not in taken):
                return None
            if symbol["cls"] == EXTERNAL and symbol["name"] in first:
                return first[symbol["name"]]
            return self.piece_at(symbol["section"], at)
        def reach(roots: list[int]) -> set[int]:
            kept, todo = set(), list(roots)
            while todo:
                k = todo.pop()
                if k in kept:
                    continue
                kept.add(k)
                p = self.pieces[k]
                todo += [t for r in self.sections[p["section"] - 1]["relocs"] if p["lo"] <= r[0] < p["hi"]
                         and (t := follows(p, r)) is not None]
                if p["function"] in exact:
                    continue  # (what goes with it, its exception tables, is the game's copy's)
                for j, q in enumerate(self.pieces):  # (a COMDAT that goes with this section: its associative ones)
                    if j not in kept and self._associated(q["section"]) == p["section"]:
                        todo.append(j)
            return kept
        kept = reach([k for name, k in first.items() if name in taken])
        for name in taken - set(exact):  # (what other code than the game's needs: a name nothing defines makes
            # the function come from your copy instead, Relink.write)
            relink.needs[name] = {self.symbols[r[1]]["name"] for k in reach([first[name]]) for p in [self.pieces[k]]
                                  for r in self.sections[p["section"] - 1]["relocs"] if p["lo"] <= r[0] < p["hi"]
                                  and self.symbols[r[1]]["cls"] in (EXTERNAL, WEAK_EXTERNAL)}
        # the order: the game's, each piece from C followed by the helpers that follow it in the object
        code = [k for k in sorted(kept) if self.sections[self.pieces[k]["section"] - 1]["flags"] & CNT_CODE]
        after: dict[str | None, list[int]] = {}
        owner = None
        for k in code:
            if self.pieces[k]["function"] in taken:
                owner = self.pieces[k]["function"]
            after.setdefault(owner, []).append(k)
        first = True
        order: list[int | dict] = []
        for fn in functions:
            if fn["name"] in taken:
                order += (after.pop(None, []) if first else []) + after.get(fn["name"], [])
                first = False
            else:
                order.append(fn)
        order += [k for k in sorted(kept) if k not in code]
        # each piece's section number, as the sections are made in this order
        number, numbers = len(obj.sections), {}
        for item in order:
            number += 1
            if isinstance(item, int):
                numbers[item] = number
        mapped: dict[int, int] = {}

        def symbol_of(index: int) -> int:
            if index in mapped:
                return mapped[index]
            s = self.symbols[index]
            if s["section"] > 0:
                k = self.piece_at(s["section"], s["value"])
                if k in kept and not DATA_SYMBOL.fullmatch(s["name"]):
                    lo = self.pieces[k]["lo"]
                    if self._is_section(s):
                        new = obj.sections[numbers[k] - 1]["symbol"]
                    else:
                        new = obj.symbol(s["name"], s["value"] - lo, numbers[k], s["type"], s["cls"])
                elif s["cls"] == EXTERNAL or DATA_SYMBOL.fullmatch(s["name"]):
                    # (from your copy, or the data's: a global the C defines, static or not, is the game's)
                    new = obj.extern(s["name"], s["type"] == FUNCTION)
                else:
                    fail(f"{s['name']}, in code of {self.pieces[k]['function'] if k is not None else '?'} the relink "
                         "leaves out, is what code it takes refers to")
            elif s["cls"] == WEAK_EXTERNAL:
                obj.alias(s["name"], self.symbols[struct.unpack_from("<I", s["aux"], 0)[0]]["name"])
                new = obj.index[s["name"]]
            elif s["section"] < 0 or s["value"]:  # (a number; or a common variable, uninitialised, its size)
                new = obj.symbol(s["name"], s["value"], s["section"], s["type"], s["cls"])
            else:
                new = obj.extern(s["name"], s["type"] == FUNCTION)
            mapped[index] = new
            return new

        for item in order:
            if isinstance(item, dict):
                relink.delinked(obj, item, labels)
                continue
            p = self.pieces[item]
            sec = self.sections[p["section"] - 1]
            fn = exact.get(p["function"])
            body = bytearray(sec["data"][p["lo"]:p["hi"]]) if sec["data"] is not None else None
            if fn is not None:  # the game's code, then the padding the game has after it (int3s where the C's has nops)
                ends = [off - p["lo"] + 4 for off, _, _ in sec["relocs"] if p["lo"] <= off < p["hi"]]
                end = min(fn["size"], max([len(bytes(body[:fn["size"]]).rstrip(PADDING)), *ends]))
                body = body[:end] + relink.image.read(fn["addr"] + end, relink.extent[fn["name"]] - end)
            flags, comdat = (CODE_EXACT, None) if fn is not None else (sec["flags"], None)
            if fn is None and sec["flags"] & COMDAT:
                head = next(s for s in self.symbols.values() if s["section"] == p["section"] and self._is_section(s))
                assoc = self._associated(p["section"])
                with_it = next((numbers[k] for k in kept if self.pieces[k]["section"] == assoc), 0) if assoc else 0
                comdat = (head["aux"][14], with_it)
            made = obj.section(sec["name"], None if body is None else b"", flags,
                               size=p["hi"] - p["lo"] if body is None else 0, comdat=comdat)
            assert made == numbers[item]
            for index, s in self.symbols.items():  # (its symbols first: a COMDAT's own follows its section's)
                if s["section"] == p["section"] and p["lo"] <= s["value"] < p["hi"] and not self._is_section(s):
                    symbol_of(index)
            for label, at in labels.get(p["function"], []) if fn is not None else ():
                obj.symbol(label, at, made)
            for reloc in sec["relocs"]:
                off, index, kind = reloc
                if not p["lo"] <= off < p["hi"]:
                    continue
                if fn is not None and off - p["lo"] + 4 > fn["size"]:
                    continue
                s = self.symbols[index]
                if fn is not None and relink.relocated is not None and kind == DIR32 and \
                        fn["addr"] + off - p["lo"] not in relink.relocated:
                    # (the C names a number as an address, D_0098967F for 9999999: the game has the number)
                    struct.pack_into("<I", body, off - p["lo"], relink.image.word(fn["addr"] + off - p["lo"]))
                    continue
                if constant(p, reloc):
                    place = fn["addr"] + off - p["lo"]
                    word = relink.image.word(place)
                    addr = (word + place + 4) & 0xFFFFFFFF if kind == REL32 else word
                    struct.pack_into("<I", body, off - p["lo"], 0)
                    obj.reloc(made, off - p["lo"], obj.extern(relink.starts.get(addr, f"_D_{addr:08X}"),
                                                              addr in relink.starts), kind)
                    continue
                if self._is_section(s) and self.sections[s["section"] - 1]["flags"] & CNT_CODE and \
                        not self.sections[s["section"] - 1]["flags"] & COMDAT:
                    _, at = self.target(p, reloc)
                    k = self.piece_at(s["section"], at)
                    if k not in kept:
                        fail(f"code {p['function']} keeps refers to code of the same file the relink leaves out")
                    struct.pack_into("<i", body, off - p["lo"], at - self.pieces[k]["lo"])
                    obj.reloc(made, off - p["lo"], obj.sections[numbers[k] - 1]["symbol"], kind)
                    continue
                obj.reloc(made, off - p["lo"], symbol_of(index), kind)
            if body is not None:
                obj.sections[made - 1]["data"] = bytes(body)
                obj.sections[made - 1]["size"] = len(body)

    def _associated(self, section: int) -> int | None:
        """The section an associative COMDAT section goes with (selection 5), else None."""
        if not self.sections[section - 1]["flags"] & COMDAT:
            return None
        head = next((s for s in self.symbols.values() if s["section"] == section and self._is_section(s)), None)
        if head is None or head["aux"][14] != 5:
            return None
        return struct.unpack_from("<H", head["aux"], 12)[0]


# ---------------------------------------------------------------------------------------------------------- the link

class Relink:
    def __init__(self, info: dict, image: Image, root: Path, build: Path, all_c: bool = False, pad: int = 0):
        self.info, self.image, self.root, self.build, self.all_c, self.pad = info, image, root, build, all_c, pad
        self.out = build / "relink"
        # the .exe's units (a DLL's are in its folder), in the order of the game's code
        self.units = sorted((u for u in info["units"] if "/" not in u and info["units"][u]),
                            key=lambda u: min(fn["addr"] for fn in info["units"][u]))
        self.functions = sorted((fn for unit, fns in info["units"].items() if "/" not in unit for fn in fns),
                                key=lambda fn: fn["addr"])
        # what a code section has before its first function, as code of its own that goes before that function: an
        # incrementally linked game's table of jumps (jmp <function>, each a relocation to it), int3s
        self.leads: dict[str, dict] = {}
        for s in image.sections:
            first = next((fn for fn in self.functions if s["addr"] <= fn["addr"] < s["addr"] + s["vsize"]), None)
            if first is not None and first["addr"] > s["addr"]:
                self.leads[first["name"]] = self._lead(s["addr"], first["addr"] - s["addr"])
        self.functions = sorted([*self.functions, *self.leads.values()], key=lambda fn: fn["addr"])
        self.by_name = {fn["name"]: fn for fn in self.functions}
        self.starts = {fn["addr"]: fn["name"] for fn in self.functions}
        self.lows = [fn["addr"] for fn in self.functions]
        # each function up to where the next starts, or its section ends: what aligns the next (int3s, nops) too
        self.extent = {}
        for fn, after in zip(self.functions, [*self.lows[1:], None]):
            s = image.section_of(fn["addr"])
            end = s["addr"] + s["vsize"] if s is not None else fn["addr"] + fn["size"]
            self.extent[fn["name"]] = max(fn["size"], min(end, after or end) - fn["addr"])
        self.code_sections = [s for s in image.sections if any(s["addr"] <= a < s["addr"] + s["vsize"]
                                                                for a in self.lows)]
        self.slots = {slot["slot"]: (dll, slot) for dll, slots in image.imports() for slot in slots}
        self.trusted: list[str] = []  # what the relink took on trust, for the report
        self.relocated = image.relocated()  # (every word the game's base relocations name; None: it has none)
        self.needs: dict[str, set[str]] = {}  # a function from C whose code isn't the game's: the names it needs

    def _lead(self, addr: int, size: int) -> dict:
        """Code before a section's first function, as a function: its jumps (E9 <rel32>) relocations to where they
        go, read until something else than a jump or padding."""
        body, relocs, k = self.image.read(addr, size), [], 0
        while k < size:
            if body[k] == 0xE9 and k + 5 <= size:
                target = (addr + k + 5 + struct.unpack_from("<i", body, k + 1)[0]) & 0xFFFFFFFF
                name = next((fn["name"] for fn in self.functions if fn["addr"] == target), None)
                if name is None:
                    break
                relocs.append([k + 1, REL32, name, 0])
                k += 5
            elif body[k] in PADDING:
                k += 1
            else:
                break
        return {"name": f"$lead_{addr:08X}", "addr": addr, "size": size, "relocs": relocs, "lead": True}

    def function_at(self, addr: int) -> dict | None:
        """The function an address is in."""
        import bisect
        k = bisect.bisect_right(self.lows, addr) - 1
        fn = self.functions[k] if k >= 0 else None
        return fn if fn is not None and fn["addr"] <= addr < fn["addr"] + self.extent[fn["name"]] else None

    # ------------------------------------------------------------------------------------------------------ code
    def code(self) -> None:
        """Read what each unit's C compiles to, and which functions come from it (self.from_c): those it compiles to
        the game's code byte for byte (self.games_code, as tools/rebuild.py tells), or with --all-c every one it
        defines; self.other_c: those whose C is other code than the game's."""
        rebuild = _sibling("rebuild")
        program = rebuild.Program(self.info, self.image.exe)
        sizes = {fn["name"]: fn["size"] for fn in self.functions}
        self.from_c, self.games_code, self.other_c = set(), set(), set()
        self.compiled: dict[str, Compiled] = {}
        for unit in self.units:
            obj = self.root / self.build / "src" / "auto" / f"{unit}.obj"
            if not obj.is_file():
                continue
            data = obj.read_bytes()
            compiled = self.compiled[unit] = Compiled(data)
            mine = {fn["name"] for fn in self.info["units"][unit]} & compiled.defined
            same = set(rebuild.from_c(program, data, sizes)) & mine if mine else set()
            self.games_code |= same
            self.from_c |= mine if self.all_c else same
            self.other_c |= mine - same

    def unit(self, unit: str, labels: dict[str, list[tuple[str, int]]]) -> Coff:
        """A unit's object for the link: its functions in the game's order, each from C (cut out of what its C
        compiles to, with the helpers and constants that code reaches) or delinked from your copy, with the labels
        (D_<address> inside a function) other code and the data name."""
        obj = Coff()
        compiled = self.compiled.get(unit)
        fns = sorted(self.info["units"][unit], key=lambda fn: fn["addr"])
        if self.pad and unit == self.units[0]:  # (--pad: everything after it moves, a mod's longer code would)
            obj.section(".text", b"\xcc" * self.pad, CODE_EXACT)
        if fns and fns[0]["name"] in self.leads:  # (what its code section has before it)
            self.delinked(obj, self.leads[fns[0]["name"]], labels)
        taken = {fn["name"] for fn in fns} & self.from_c
        if compiled is not None and taken:
            compiled.emit(obj, self, fns, taken, labels)
        else:
            for fn in fns:
                self.delinked(obj, fn, labels)
        return obj

    def delinked(self, obj: Coff, fn: dict, labels: dict[str, list[tuple[str, int]]]) -> None:
        """A function as tools/delink.py cuts it out of your copy, with the code labels other code and the data
        point at (D_<address> inside it, public symbols)."""
        code = bytearray(self.image.read(fn["addr"], self.extent[fn["name"]]))
        if len(code) != self.extent[fn["name"]]:
            fail(f"{fn['name']} isn't in {self.info['exe']}")
        number = obj.section(".text", b"", CODE_EXACT)
        obj.symbol(fn["name"], 0, number, FUNCTION)
        for label, at in labels.get(fn["name"], []):
            obj.symbol(label, at, number)
        local: dict[int, int] = {}
        relocs = fn["relocs"]
        if self.relocated is not None:  # (the game's base relocations say which words are addresses: the analysis
            # took a mask, 0x00FFFFFF, for one where the data reaches that far, and missed some jump tables)
            relocs = [r for r in relocs if r[1] != DIR32 or fn["addr"] + r[0] in self.relocated]
            have = {r[0] for r in relocs}
            for place in sorted(self.relocated):
                if fn["addr"] <= place < fn["addr"] + len(code) - 3 and place - fn["addr"] not in have:
                    word = self.image.word(place)
                    if fn["addr"] <= word < fn["addr"] + len(code):
                        relocs.append((place - fn["addr"], DIR32, None, word - fn["addr"]))
                    else:
                        relocs.append((place - fn["addr"], DIR32, self.starts.get(word, f"_D_{word:08X}"), 0))
        for at, kind, name, addend in relocs:
            if name is None:  # a place in this function (its jump table, a case)
                if addend not in local:
                    local[addend] = obj.symbol(f"$L{fn['addr'] + addend:08X}", addend, number, cls=LABEL)
                symbol, inline = local[addend], 0
            else:
                if kind == REL32 and (m := DATA_SYMBOL.fullmatch(name)) and \
                        self.image.section_of(int(m.group(1), 16)) is None:
                    name += RVA  # (a jump outside the program: LINK.EXE takes a number it jumps to as an RVA)
                symbol, inline = obj.extern(name, kind == REL32), addend
            struct.pack_into("<i", code, at, inline)
            obj.reloc(number, at, symbol, kind)
        obj.sections[number - 1]["data"] = bytes(code)
        obj.sections[number - 1]["size"] = len(code)

    def write(self, link: list[str]) -> dict:
        """Write every object, run the linker, and say how the program came out."""
        if self.out.exists():
            shutil.rmtree(self.out)
        (self.out / "objects").mkdir(parents=True)
        self.code()
        self.from_copy: set[str] = set()  # (with --all-c: functions whose C isn't the game's code that other code
        # jumps into the middle of, or the data points into: their places are the game's code's)
        while True:
            # what the code names: the units built once without labels (the data says which it needs)
            defined, wanted = set(), set()
            for unit in self.units:
                obj = self.unit(unit, {})
                defined |= obj.defined()
                wanted |= obj.undefined()
            self.jumped_into = set()
            data, labels = self.data(wanted, defined)
            self.thunks = [(n, s) for n, s in self.thunks if n not in defined]
            imports = self.thunks_object()
            missing = wanted - defined - set(self.names) - set(self.import_names) - set(ABSOLUTE)
            needing = {fn for fn, names in self.needs.items() if names & missing} & self.from_c
            if not self.jumped_into and not needing:
                break
            self.from_c -= self.jumped_into | needing
            self.from_copy |= self.jumped_into | needing
        objects = []
        for unit in self.units:
            path = self.out / "objects" / f"{unit}.obj"
            path.write_bytes(self.unit(unit, labels).bytes())
            objects.append(path)
        undefined = sorted(wanted - defined - set(self.names) - set(self.import_names) - set(ABSOLUTE))
        if undefined:
            fail(f"{len(undefined)} names the code uses that nothing defines: {', '.join(undefined[:SHOWN])}"
                 + ("…" if len(undefined) > SHOWN else ""))
        name = Path(self.info["exe"]).name
        program = self.out / name
        res = self.resources_object()
        entry = self.starts.get(self.image.base + self.image.entry)
        if entry is None:
            fail(f"the program starts at 0x{self.image.base + self.image.entry:08X}, which is no function's start")
        argv = [*link, "/nologo", "/NODEFAULTLIB", "/INCREMENTAL:NO", "/OPT:NOREF", "/MACHINE:IX86",
                f"/BASE:0x{self.image.base:X}", f"/ENTRY:{re.sub(r'^_', '', entry)}",
                f"/SUBSYSTEM:{SUBSYSTEMS.get(self.image.subsystem, 'WINDOWS')},"
                f"{self.image.subsystem_version[0]}.{self.image.subsystem_version[1]:02d}",
                f"/STACK:0x{self.image.stack[0]:X},0x{self.image.stack[1]:X}",
                f"/HEAP:0x{self.image.heap[0]:X},0x{self.image.heap[1]:X}",
                f"/MAP:{self.out / 'relink.map'}", f"/OUT:{program}"]
        argv.append("/FIXED" if self.image.relocated() is None else "/FIXED:NO")  # (6.0's makes .exes /FIXED)
        if self.image.characteristics & 0x20:
            argv.append("/LARGEADDRESSAWARE")
        if self.image.file_alignment < 0x1000:
            argv.append("/OPT:NOWIN98")  # (6.0's linker: 512-byte file alignment; later ones have it as default)
        # the data first: it isn't code, so the linker still puts the code first, and the data stays where the game
        # has it while the compiled objects' own constants (strings, floats) go after it
        argv += [str(data), *map(str, objects), *map(str, imports)]
        if res is not None:
            argv.append(str(res))
        (self.out / "link.txt").write_text(" ".join(argv[len(link):]) + "\n", encoding="utf-8")  # (to run it again)
        said = subprocess.run(argv, capture_output=True, text=True, errors="replace")
        output = (said.stdout + said.stderr).strip()
        if said.returncode != 0 or not program.is_file():
            fail(f"the linker stopped:\n{output}")
        self.header(program)
        return self.report(program, self.from_c, output)

    def resources_object(self) -> Path | None:
        """resources.obj: your copy's resources as the resource converter (CVTRES) writes them for the linker, their
        directory and data in .rsrc$01, each data entry's address a relocation; with the names the code gives places
        in them (self.in_resources)."""
        resources = self.image.resources()
        if resources is None:
            return None
        body, entries = resources
        obj = Coff()
        number = obj.section(".rsrc$01", None, CNT_DATA | 0x40000000 | ALIGN_4)
        body = bytearray(body)
        root = self.image.directory(RESOURCES)[0]
        for at in entries:
            rva, = struct.unpack_from("<I", body, at)
            struct.pack_into("<I", body, at, rva - (root - self.image.base))
            obj.reloc(number, at, obj.sections[number - 1]["symbol"], DIR32NB)
        obj.sections[number - 1].update(data=bytes(body), size=len(body))
        for name, addr in self.in_resources:
            obj.symbol(name, addr - root, number)
        path = self.out / "objects" / "resources.obj"
        path.write_bytes(obj.bytes())
        return path

    def header(self, program: Path) -> None:
        """The import directories in the program's header, where its import tables are now (the linker sets them
        only for tables it makes itself, from import libraries)."""
        placed = self.placed()
        exe = bytearray(program.read_bytes())
        opt = struct.unpack_from("<I", exe, 0x3C)[0] + 24
        for directory, name in ((IMPORTS, "__relink_imports"), (IAT, "__relink_iat")):
            if name in placed:
                struct.pack_into("<II", exe, opt + 96 + 8 * directory, placed[name] - self.image.base,
                                 self.image.dirs[directory][1])
        # what your copy has after its last section (an overlay: data some games keep there), but its signature
        # (a signature is of the program it signed: the relinked one is unsigned)
        image = self.image.exe
        pe = struct.unpack_from("<I", image, 0x3C)[0]
        count, opt_size = struct.unpack_from("<H", image, pe + 6)[0], struct.unpack_from("<H", image, pe + 20)[0]
        ends = [sum(struct.unpack_from("<II", image, pe + 24 + opt_size + 40 * i + 16)) for i in range(count)]
        overlay = bytearray(image[max(ends, default=len(image)):])
        signed_at, signed = self.image.dirs[SECURITY] if SECURITY < len(self.image.dirs) else (0, 0)
        if signed:
            start = signed_at - max(ends)
            del overlay[max(0, start):max(0, start + signed)]
            self.trusted.append("its signature isn't carried over: the relinked program is unsigned")
        program.write_bytes(bytes(exe) + bytes(overlay))

    def placed(self) -> dict[str, int]:
        """Every public symbol's address, from the linker's map."""
        out = {}
        for line in (self.out / "relink.map").read_text(encoding="latin-1").splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{8}", parts[0]) and \
                    re.fullmatch(r"[0-9a-fA-F]{8}", parts[2]):
                out[parts[1]] = int(parts[2], 16)
        return out

    # ------------------------------------------------------------------------------------------------------ data
    def data(self, wanted: set[str], defined: set[str]) -> tuple[Path, dict[str, list[tuple[str, int]]]]:
        """data.obj: every data section of your copy, its globals named and its pointers relocations; and the code
        labels (by function) that the code and data name."""
        image = self.image
        dropped = {RESOURCES: ".rsrc", BASE_RELOCATIONS: ".reloc"}  # (made again: resources.obj, the linker)
        kept = []
        for s in image.sections:
            if s in self.code_sections:
                continue
            what = next((d for d, name in dropped.items() if s["name"] == name and image.directory(d)[0]
                         and s["addr"] <= image.directory(d)[0] < s["addr"] + s["vsize"]), None)
            if what is None and s["name"] in (".rsrc", ".reloc"):
                continue
            if what is None:
                kept.append(s)
        self.trusted, self.in_resources = [], []
        if self.info.get("modules"):
            self.trusted.append(f"only {Path(self.info['exe']).name}: the game's DLLs aren't relinked yet "
                                "(`ninja rebuild` rebuilds them)")
        obj = Coff()
        chunks = []  # (start, end, section number)

        def aligned(addr: int, flags: int) -> int:  # (as far as the game's place for it is: no padding before it)
            return (flags & 0xFF0FFFFF) | (min(5, (addr & -addr).bit_length()) << 20 if addr % 16 else ALIGN_16)
        for s in kept:
            initialised = min(s["vsize"], len(s["raw"]))  # (its part in the file; the rest uninitialised, .bss)
            flags = s["flags"] & 0xFE0000E0
            end = s["addr"] + initialised
            if initialised:
                chunks.append((s["addr"], end, obj.section(s["name"], s["raw"][:initialised].ljust(initialised, b"\0"),
                                                           aligned(s["addr"], flags & ~CNT_BSS))))
            if s["vsize"] > initialised:
                chunks.append((end, s["addr"] + s["vsize"],
                               obj.section(".bss", None, aligned(end, (flags & ~CNT_DATA) | CNT_BSS),
                                           s["vsize"] - initialised)))
        self.names = set()
        labels: dict[str, list[tuple[str, int]]] = {}

        def chunk_of(addr: int, end_too: bool = False):
            return next((c for c in chunks if c[0] <= addr < c[1]), None) or \
                (next((c for c in chunks if addr == c[1]), None) if end_too else None)

        stray = []
        # what the linker sets a directory of the program's header from, by the name it looks for: thread-local
        # storage's, and the load configuration's
        for directory, name in ((TLS, "__tls_used"), (LOAD_CONFIG, "__load_config_used")):
            addr, _ = image.directory(directory)
            if addr and (c := chunk_of(addr)) is not None:
                obj.symbol(name, addr - c[0], c[2])
            elif addr:
                stray.append(f"{name} (0x{addr:08X}, outside the data)")
        by_slot = {slot["slot"]: slot["symbol"] for _, slots in image.imports() for slot in slots}
        rvas = self.import_tables(obj, wanted, chunk_of, stray)
        for name in sorted(wanted - defined):
            if name.endswith(RVA) and DATA_SYMBOL.fullmatch(name[:-len(RVA)]):
                obj.symbol(name, (int(name[3:11], 16) - image.base) & 0xFFFFFFFF, -1)
                self.names.add(name)
                continue
            m = DATA_SYMBOL.fullmatch(name)
            if m is None:
                continue
            addr = int(m.group(1), 16)
            if (c := chunk_of(addr)) is not None:
                obj.symbol(name, addr - c[0], c[2])
            elif addr in self.starts:
                obj.alias(name, self.starts[addr])
            elif addr in by_slot:
                obj.alias(name, by_slot[addr])
            elif (fn := self.function_at(addr)) is not None:
                if fn["name"] in self.from_c and fn["name"] not in self.games_code:
                    self.jumped_into.add(fn["name"])
                labels.setdefault(fn["name"], []).append((name, addr - fn["addr"]))
            elif image.section_of(addr) is None or (s := image.section_of(addr)) in kept:
                obj.symbol(name, addr, -1)  # outside the program (its headers, the system's): a number
            else:
                root, _ = image.directory(RESOURCES)
                section = image.section_of(addr)
                if root and section is image.section_of(root) and addr >= root:  # (resources.obj has it)
                    self.in_resources.append((name, addr))
                else:
                    stray.append(f"{name} (in {section['name']}, which a relink makes again)")
            self.names.add(name)

        # the pointers in the data
        relocated = self.relocated
        if relocated is None:
            self.trusted.append("pointers in the data found by their values (the program has no base relocations)")
        pointers = 0
        for start, end, number in chunks:
            body = obj.sections[number - 1]["data"]
            if body is None:
                continue
            body = bytearray(body)
            places = sorted(a for a in relocated | set(rvas) if start <= a <= end - 4) if relocated is not None else \
                range(start, end - 3, 4)
            for addr in places:
                word = struct.unpack_from("<I", body, addr - start)[0]
                target = None
                if addr in rvas and rvas[addr] < 0:
                    struct.pack_into("<I", body, addr - start, -rvas[addr])
                    continue
                if addr in rvas:  # (an import table's RVA: of a name, a lookup table, an address table)
                    c = chunk_of(rvas[addr])
                    struct.pack_into("<I", body, addr - start, rvas[addr] - c[0])
                    obj.reloc(number, addr - start, obj.sections[c[2] - 1]["symbol"], DIR32NB)
                    continue
                if word in self.starts:
                    target, inline = obj.extern(self.starts[word], True), 0
                elif word in by_slot:
                    target, inline = obj.extern(by_slot[word]), 0
                elif (c := chunk_of(word, end_too=True)) is not None:
                    target, inline = obj.sections[c[2] - 1]["symbol"], word - c[0]
                elif (fn := self.function_at(word)) is not None:
                    if fn["name"] in self.from_c and fn["name"] not in self.games_code:
                        self.jumped_into.add(fn["name"])
                    label = f"_D_{word:08X}"
                    if label not in self.names:
                        labels.setdefault(fn["name"], []).append((label, word - fn["addr"]))
                        self.names.add(label)
                    target, inline = obj.extern(label), 0
                elif relocated is not None:
                    stray.append(f"0x{addr:08X} (points at 0x{word:08X}, in nothing the relink has)")
                if target is not None:
                    struct.pack_into("<I", body, addr - start, inline)
                    obj.reloc(number, addr - start, target, DIR32)
                    pointers += 1
            obj.sections[number - 1]["data"] = bytes(body)
        if stray:
            fail(f"{len(stray)} places the relink can't keep pointing where they do: {', '.join(stray[:SHOWN])}"
                 + ("…" if len(stray) > SHOWN else ""))
        for name, value in ABSOLUTE.items():
            if name in wanted and name not in defined:
                obj.symbol(name, value, -1)
        self.pointers = pointers
        path = self.out / "objects" / "data.obj"
        path.write_bytes(obj.bytes())
        return path, labels

    # --------------------------------------------------------------------------------------------------- imports
    def import_tables(self, obj: Coff, wanted: set[str], chunk_of, stray: list[str]) -> dict[int, int]:
        """The import tables stay in the data, where your copy has them (an import section of their own, or in
        .rdata): each slot of the address tables named as the code reads it (__imp__Sleep, and __imp__Sleep@4 where C
        declares it so), and the start of the descriptors and of the address tables named for the program's header
        (Relink.header). Returns the RVAs in them, by where each is: what each points at (a relocation), or (a
        negative number) the ordinal word it holds."""
        self.import_names, self.thunks = set(), []
        layout = self.image.import_layout()
        variants: dict[str, set[str]] = {}
        for name in wanted:  # (__imp__Sleep@4 for __imp__Sleep; a call to Sleep@4 itself, which needs a thunk)
            plain = re.sub(r"@\d+$", "", name)
            variants.setdefault(plain if name.startswith("__imp_") else "__imp_" + plain, set()).add(name)
        rvas = {}
        for dll in layout:
            fields = ((0, dll["lookup"]), (12, dll["name"]), (16, dll["iat"]))
            rvas.update({dll["descriptor"] + at: target for at, target in fields if target})
            for k, slot in enumerate(dll["slots"]):
                for table in {dll["lookup"], dll["iat"]} - {0}:
                    # (by ordinal: the address table as the lookup table has it, unbound: a number, no RVA)
                    rvas[table + 4 * k] = slot["entry"] if slot["entry"] is not None else -(0x80000000 | slot["ordinal"])
                c = chunk_of(slot["slot"])
                if c is None:
                    stray.append(f"{slot['symbol']} (its slot is outside the data)")
                    continue
                for name in {slot["symbol"], *variants.get(slot["symbol"], ())}:
                    if name.startswith("__imp_"):
                        obj.symbol(name, slot["slot"] - c[0], c[2])
                    else:
                        self.thunks.append((name, slot["symbol"]))
                    self.import_names.add(name)
        if any(dll["descriptor"] and self.image.word(dll["descriptor"] + 4) for dll in layout):
            self.trusted.append("bound imports: their address tables are written unbound, as their lookup tables are")
        for directory, name in ((IMPORTS, "__relink_imports"), (IAT, "__relink_iat")):
            addr, _ = self.image.directory(directory)
            if addr and (c := chunk_of(addr)) is not None:
                obj.symbol(name, addr - c[0], c[2])
        return rvas

    def thunks_object(self) -> list[Path]:
        """A thunk (jmp [slot]) for each call to an import itself (_Sleep@4) that nothing else defines."""
        if not self.thunks:
            return []
        obj = Coff()
        for called, slot in self.thunks:
            thunk = obj.section(".text", b"\xff\x25\0\0\0\0", CODE)
            obj.symbol(called, 0, thunk, FUNCTION)
            obj.reloc(thunk, 2, obj.extern(slot), DIR32)
        path = self.out / "objects" / "thunks.obj"
        path.write_bytes(obj.bytes())
        return [path]

    # ---------------------------------------------------------------------------------------------------- report
    def report(self, program: Path, from_c: set[str], said: str) -> dict:
        """Where everything went (the linker's map), and whether it's the game's layout and code."""
        placed = self.placed()
        moved = [fn["name"] for fn in self.functions if placed.get(fn["name"], fn["addr"]) != fn["addr"]
                 and not fn.get("lead")]
        data_moved = [n for n in self.names if DATA_SYMBOL.fullmatch(n) and n in placed
                      and placed[n] != int(n[3:], 16)]
        new = Image(program.read_bytes())
        same_code = not moved and all(
            new.read(fn["addr"], fn["size"]) == self.image.read(fn["addr"], fn["size"]) for fn in self.functions)
        # each section of your copy against the relinked program's at its address (what the linker writes itself,
        # the base relocations, may encode the same relocations otherwise)
        sections = {s["name"]: new.read(s["addr"], s["vsize"]) == self.image.read(s["addr"], s["vsize"])
                    and any(n["name"] == s["name"] and n["addr"] == s["addr"] for n in new.sections)
                    for s in self.image.sections}
        if self.relocated is not None and not sections.get(".reloc", True) and new.relocated() == self.relocated:
            sections[".reloc"] = True  # (the same relocations, in blocks of its own)
        # moved by --pad alone (no other code): each word the game's base relocations name, at its new place, points
        # at what it did, moved as the section it points into moved: what a moved program needs
        follows = None
        if self.pad and not (from_c - self.games_code) and self.relocated is not None:
            shift = {s["name"]: n["addr"] - s["addr"] for s in self.image.sections for n in new.sections
                     if n["name"] == s["name"]}
            first = self.code_sections[0]["name"]
            shift[first] = shift.get(first, 0) + self.pad  # (the pad is where its code starts: the code moved in it)
            def moved_to(addr: int) -> int | None:
                s = self.image.section_of(addr)
                return None if s is None or s["name"] not in shift else addr + shift[s["name"]]
            wrong = [f"0x{a:08X}" for a in sorted(self.relocated) if (to := moved_to(a)) is not None and
                     moved_to(self.image.word(a)) is not None and new.word(to) != moved_to(self.image.word(a))]
            follows = {"relocated": len(self.relocated), "wrong": wrong[:SHOWN * 4]}
        report = {"program": program.relative_to(self.root).as_posix(), "follows": follows,
                  "functions": sum(1 for fn in self.functions if not fn.get("lead")),
                  "c": sorted(from_c), "moved": moved, "data_moved": sorted(data_moved),
                  "other_c": sorted(self.other_c - from_c - self.from_copy), "from_copy": sorted(self.from_copy),
                  "pointers": self.pointers, "imports": sum(len(s) for _, s in self.image.imports()),
                  "same_layout": not moved and not data_moved, "same_code": same_code,
                  "differ": sorted(n for n, same in sections.items() if not same),
                  "same_sections": all(sections.values()) and len(new.sections) == len(self.image.sections),
                  "trusted": self.trusted, "linker": said}
        (self.out / "relink.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
        return report


def _sibling(name: str):
    """Another of this folder's tools, as a module."""
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(description="Links the game's program again with Visual C++'s linker")
    parser.add_argument("config")
    parser.add_argument("build")
    parser.add_argument("--link", required=True, help="Visual C++'s LINK.EXE")
    parser.add_argument("--wrapper", default="", help="what runs it (wibo, off Windows)")
    parser.add_argument("--all-c", action="store_true",
                        help="every function the C defines, not only those it compiles to the game's code (a mod)")
    parser.add_argument("--pad", type=lambda s: int(s, 0), default=0,
                        help="this many bytes (int3s) before the game's code: everything moves, as with a mod's longer "
                             "code (does the program still work?)")
    args = parser.parse_args()
    root = Path(".")
    info = json.loads((root / args.config).read_text(encoding="utf-8"))
    exe = (root / info["exe"]).read_bytes()
    if hashlib.sha1(exe).hexdigest() != info.get("sha1", hashlib.sha1(exe).hexdigest()):
        fail(f"{info['exe']} isn't the copy this project was made from")
    if exe[0x28:0x2C] == b"XBEH":  # (decompdecomp's consoles/xbox: the XBE inside a Windows program made of it)
        fail("an Xbox game's program is relinked as a Windows one, not an XBE, yet: `ninja rebuild` rebuilds it")
    if not args.link:
        fail("it links with Visual C++ 6.0's linker: install Visual C++ 6.0 in decompdecomp's Setup (Compilers & "
             "tools), then run tools/configure.py again")
    relink = Relink(info, Image(exe), root, Path(args.build), args.all_c, args.pad)
    report = relink.write([*([args.wrapper] if args.wrapper else []), args.link])
    how = "every function and global at the game's address" if report["same_layout"] else \
        f"{len(report['moved'])} functions and {len(report['data_moved'])} globals moved"
    code = ", every section byte for byte your copy's (its header is the linker's)" if report["same_sections"] else \
        ", its code byte for byte the game's" if report["same_code"] else ""
    print(f"{report['program']}: linked by LINK.EXE from {report['functions']:,} functions "
          f"({len(report['c']):,} from C), {report['pointers']:,} pointers in the data, {report['imports']:,} "
          f"imports; {how}{code}")
    if report["follows"] is not None:
        wrong = report["follows"]["wrong"]
        print(f"  of the {report['follows']['relocated']:,} addresses the game's base relocations name, "
              + (f"these don't point where they did: {', '.join(wrong[:SHOWN])}" if wrong else
                 "every one points where it did, moved"))
    if report["from_copy"]:
        print(f"  {len(report['from_copy']):,} functions came from your copy, not their C: their C uses a name nothing "
              "defines, or other code or the data points into their middle, where the C has other code "
              f"({', '.join(report['from_copy'][:SHOWN])}{'…' if len(report['from_copy']) > SHOWN else ''})")
    if report["other_c"]:
        print(f"  {len(report['other_c']):,} functions the C defines compile to other code than the game's and came "
              "from your copy: --all-c takes them from C too (a mod)")
    for what in report["trusted"]:
        print(f"  note: {what}")


if __name__ == "__main__":
    main()
