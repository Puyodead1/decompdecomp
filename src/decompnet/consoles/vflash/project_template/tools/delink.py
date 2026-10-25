#!/usr/bin/env python3
"""Cut the game's functions out of your copy of its programs into one ELF object per source file, as GCC 3.2.3 and
binutils 2.14 write them, for objdiff to compare with what src/ compiles to.

    python tools/delink.py config/<version>/functions.json OUT_DIR

functions.json (written by decompdecomp) says where each function of FA and of each game module is, and where its
code refers to addresses: its calls and branches to other functions, and the addresses in its literal pool, become
relocations, as in a compiled object, so a function matches whatever names your C uses for them. Each function gets
a section of its own (.text.<name>), as GCC's -ffunction-sections makes them, which the build compiles with: a
branch to a label of the function is then against its own section, whatever comes before it in the file. Symbols
given a real name in config/<version>/names.json have it here too (tools/names.py). The words of a literal pool or a
switch's table that hold addresses are marked as data ($d, then $a where code follows, and $a where each starts: ARM's mapping symbols), as
tools/names.py marks what GCC compiles, so objdiff compares them as relocated words, not as instructions. Standard
library only. Made by decompdecomp.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

from names import mapping, real_names  # (tools/names.py, beside this file)

R_ARM_PC24, R_ARM_ABS32 = 1, 2
EF_ARM_SOFT_FLOAT = 0x200  # what binutils 2.14 marks GCC's -msoft-float objects with
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_REL = 1, 2, 3, 9
SHF_ALLOC_EXEC = 6
STT_FUNC, STT_SECTION, STB_GLOBAL = 2, 3, 1


def obj(functions: list[dict], image: bytes, real: dict[str, str] | None = None) -> bytes:
    """An ELF object of these functions (each {"name", "offset" in the image, "size", "relocs"})."""
    real = real or {}
    name = lambda n: real.get(n, n)  # noqa: E731
    count = len(functions)
    marks = [(n, sym, at) for n, fn in enumerate(functions)
             for sym, at in mapping([r[0] for r in fn["relocs"] if r[1] == R_ARM_ABS32], fn["size"])]
    symbols: list[tuple[str, int, int, int]] = []  # globals: (name, size, section index or 0, defined: type)
    index: dict[str, int] = {}
    for n, fn in enumerate(functions):  # (a call to a function of this file names its own symbol, as GCC's does)
        index[fn["name"]] = len(symbols)
        symbols.append((name(fn["name"]), fn["size"], 1 + 2 * n, STT_FUNC))
    sections = []
    for n, fn in enumerate(functions):
        code = bytearray(image[fn["offset"]:fn["offset"] + fn["size"]])
        rels = bytearray()
        for off, kind, sym, value in fn["relocs"]:
            word = struct.unpack_from("<I", code, off)[0]
            word = (word & 0xFF000000) | value if kind == R_ARM_PC24 else value & 0xFFFFFFFF
            struct.pack_into("<I", code, off, word)
            if sym is None:  # against its own section (a label of its own, a switch's table)
                at = 1 + n
            else:
                if sym not in index:
                    index[sym] = len(symbols)
                    symbols.append((name(sym), 0, 0, 0))
                at = 1 + count + len(marks) + index[sym]
            rels += struct.pack("<II", off, (at << 8) | kind)
        sections.append((name(fn["name"]), bytes(code), bytes(rels)))

    strtab = bytearray(b"\0")

    def string(table: bytearray, s: str) -> int:
        at = len(table)
        table.extend(s.encode() + b"\0")
        return at
    symtab = bytearray(16)
    for n in range(count):  # a section symbol for each function's section
        symtab += struct.pack("<IIIBBH", 0, 0, 0, STT_SECTION, 0, 1 + 2 * n)
    for n, sym, at in marks:
        symtab += struct.pack("<IIIBBH", string(strtab, sym), at, 0, 0, 0, 1 + 2 * n)
    for sym, size, shndx, kind in symbols:
        symtab += struct.pack("<IIIBBH", string(strtab, sym), 0, size, (STB_GLOBAL << 4) | kind, 0, shndx)
    shstrtab = bytearray(b"\0")
    parts = []  # (name, type, flags, data, link, info, align, entsize)
    for n, (fname, code, rels) in enumerate(sections):
        parts.append((f".text.{fname}", SHT_PROGBITS, SHF_ALLOC_EXEC, code, 0, 0, 4, 0))
        parts.append((f".rel.text.{fname}", SHT_REL, 0, rels, 2 * count + 1, 1 + 2 * n, 4, 8))
    parts.append((".symtab", SHT_SYMTAB, 0, bytes(symtab), 2 * count + 2, 1 + count + len(marks), 4, 16))
    parts.append((".strtab", SHT_STRTAB, 0, bytes(strtab), 0, 0, 1, 0))
    body, headers, at = bytearray(), [bytes(40)], 52
    for sname, kind, flags, data, link, info, align, entsize in parts:
        headers.append(struct.pack("<10I", string(shstrtab, sname), kind, flags, 0, at, len(data), link, info, align,
                                   entsize))
        body += data
        at += len(data)
    headers.append(struct.pack("<10I", string(shstrtab, ".shstrtab"), SHT_STRTAB, 0, 0, at, len(shstrtab), 0, 0, 1, 0))
    body += shstrtab
    at += len(shstrtab)
    body += bytes(-at % 4)
    at += -at % 4
    head = b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack("<HHIIIIIHHHHHH", 1, 40, 1, 0, 0, at, EF_ARM_SOFT_FLOAT,
                                                          52, 0, 0, 40, len(headers), len(headers) - 1)
    return head + bytes(body) + b"".join(headers)


def main() -> None:
    config, out = Path(sys.argv[1]), Path(sys.argv[2])
    info = json.loads(config.read_text(encoding="utf-8"))
    images = {}
    for program, p in info["programs"].items():
        data = Path(p["elf"]).read_bytes()
        if hashlib.sha1(data).hexdigest() != p["sha1"]:
            sys.exit(f"{p['elf']} isn't what this project was made from: make it again from your copy of the game "
                     "(decompdecomp does when the project opens)")
        images[program] = data
    real = real_names(info, config)
    for unit, functions in info["units"].items():
        data = obj(functions, images[unit.split("/", 1)[0]], real)
        path = out / f"{unit}.o"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != data:  # unchanged objects keep their time: nothing rebuilds
            path.write_bytes(data)


if __name__ == "__main__":
    main()
