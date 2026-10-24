#!/usr/bin/env python3
"""Give what src/ compiles to the original's symbol names, so C++ pairs with the game's functions in objdiff.

    python tools/names.py config/<version>/functions.json OBJECT

The game's functions and data are known by address: FA's func_10A715C4 and D_10B3B8FC, a game module's
func_GZ1A_1047B800 (modules share addresses, so their names say which module). Written in C++, as a free function or
a class's method (`void Town::func_1047B800(int)`), GCC mangles the name (`_ZN4Town13func_1047B800Ei`); this renames
every symbol whose name holds one of these to the name the original's object gives it (`func_1047B800`), in the
object itself, and the section GCC's -ffunction-sections gave it with it. A symbol given a real name in
config/<version>/names.json (`"func_10A715C4": "Resource_Update"`, written by decompdecomp's rename_symbol) is found
by that name too, mangled or not, and tools/delink.py gives the original's objects the same names. Other names are
left as they are. The words GCC put in a function's literal pool or switch table that hold addresses (an R_ARM_ABS32
relocation) are marked as data with ARM's mapping symbols, which binutils 2.14 doesn't write, as tools/delink.py
marks the original's: objdiff compares them as relocated words then. Standard library only. Made by decompdecomp.
"""

import json
import re
import struct
import sys
from pathlib import Path

REF = re.compile(r"(func|D)_(?:([A-Za-z0-9]+)_)?([0-9A-Fa-f]{8})")
# Itanium C++ mangling (GCC 3): _Z then a name, or N<names>E for a qualified one, each <length><identifier>
SOURCE_NAME = re.compile(r"(\d+)([A-Za-z_]\w*)")
SHT_SYMTAB, SHT_REL = 2, 9
R_ARM_ABS32 = 2


def c_name(symbol: str) -> str | None:
    """The function's or variable's own name in a symbol: `Update` in _ZN4Town6UpdateEv, `f` in _Z1fi or in f.
    Constructors, destructors and operators have none."""
    if not symbol.startswith("_Z"):
        return symbol if re.fullmatch(r"[A-Za-z_]\w*", symbol) else None
    rest = symbol[2:]
    nested = rest.startswith("N")
    rest = rest[1:] if nested else rest
    rest = rest.lstrip("rVK")  # (a const method's qualifiers)
    name = None
    while (m := SOURCE_NAME.match(rest)):
        length = int(m.group(1))
        name, rest = rest[len(m.group(1)):len(m.group(1)) + length], rest[len(m.group(1)) + length:]
        if not nested:
            break
    return name


def key(symbol: str) -> str | None:
    """func_<MODULE_>ADDRESS or D_<...> as the game's names spell it (the address in capitals), if the symbol holds one."""
    m = REF.search(symbol)
    if not m:
        return None
    return f"{m.group(1)}_{m.group(2) + '_' if m.group(2) else ''}{m.group(3).upper()}"


def real_names(info: dict, config: Path) -> dict[str, str]:
    """names.json: the game's names by address given a real name (func_10A715C4 -> Resource_Update)."""
    try:
        names = json.loads(config.with_name("names.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return names if isinstance(names, dict) else {}


def wanted(info: dict, config: Path) -> dict[str, str]:
    """Each name by address, and each real name, -> the original's symbol."""
    real = real_names(info, config)
    out = {}
    for functions in info["units"].values():
        for fn in functions:
            out[fn["name"]] = real.get(fn["name"], fn["name"])
            for r in fn["relocs"]:
                if r[2]:
                    out[r[2]] = real.get(r[2], r[2])
    for was, now in real.items():
        out[now] = now
        out.setdefault(was, now)
    return out


def rename(data: bytes, names: dict[str, str]) -> bytes:
    """The object with its symbols renamed, and the sections named after them (the new names go in string tables
    appended to the file)."""
    shoff, = struct.unpack_from("<I", data, 32)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 46)
    headers = [list(struct.unpack_from("<10I", data, shoff + i * shentsize)) for i in range(shnum)]

    def string(table: int, at: int) -> str:
        start = headers[table][4] + at
        return data[start:data.index(b"\0", start)].decode("latin-1")
    out = bytearray(data)
    symtab = next((i for i, h in enumerate(headers) if h[1] == SHT_SYMTAB), None)
    if symtab is None:
        return data
    strtab = headers[symtab][6]
    new_strings = bytearray(data[headers[strtab][4]:headers[strtab][4] + headers[strtab][5]])
    renamed: dict[str, str] = {}
    for at in range(headers[symtab][4], headers[symtab][4] + headers[symtab][5], 16):
        name_at = struct.unpack_from("<I", out, at)[0]
        if not name_at:
            continue
        name = string(strtab, name_at)
        k = key(name)
        # by address; else a real name: the symbol itself (a constructor's, _ZN8ResourceC1Ev, has no name to go by),
        # or the function's name in it
        new = names.get(k) if k else names.get(name) or names.get(c_name(name) or "")
        if new is None and k and k.startswith("D_"):
            new = k  # data the original's code doesn't name: its name by address, unmangled
        if new is not None and new != name:
            struct.pack_into("<I", out, at, len(new_strings))
            new_strings += new.encode() + b"\0"
            renamed[name] = new
    if not renamed:
        return data
    new_sections = bytearray(data[headers[shstrndx][4]:headers[shstrndx][4] + headers[shstrndx][5]])
    for i, h in enumerate(headers):
        sname = string(shstrndx, h[0])
        for prefix in (".text.", ".rel.text."):
            if sname.startswith(prefix) and sname[len(prefix):] in renamed:
                h[0] = len(new_sections)
                new_sections += (prefix + renamed[sname[len(prefix):]]).encode() + b"\0"
    out += bytes(-len(out) % 4)
    headers[strtab][4], headers[strtab][5] = len(out), len(new_strings)
    out += new_strings
    headers[shstrndx][4], headers[shstrndx][5] = len(out), len(new_sections)
    out += new_sections
    for i, h in enumerate(headers):
        struct.pack_into("<10I", out, shoff + i * shentsize, *h)
    return bytes(out)


def mapping(words: list[int], size: int) -> list[tuple[str, int]]:
    """ARM's mapping symbols for a section of code whose words at these offsets are data (as tools/delink.py's)."""
    out, data = [], sorted(set(words))
    for i, off in enumerate(data):
        if i == 0 or data[i - 1] != off - 4:
            out.append(("$d", off))
        if (i + 1 == len(data) or data[i + 1] != off + 4) and off + 4 < size:
            out.append(("$a", off + 4))
    return out


def mark_data(data: bytes) -> bytes:
    """The object with mapping symbols where its code sections hold relocated words (none when it has some)."""
    shoff, = struct.unpack_from("<I", data, 32)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 46)
    headers = [list(struct.unpack_from("<10I", data, shoff + i * shentsize)) for i in range(shnum)]
    symtab = next((i for i, h in enumerate(headers) if h[1] == SHT_SYMTAB), None)
    if symtab is None:
        return data
    strtab, first_global = headers[symtab][6], headers[symtab][7]
    sym_at, sym_size = headers[symtab][4], headers[symtab][5]
    names_at = headers[strtab][4]

    def name(at: int) -> bytes:
        return data[names_at + at:data.index(b"\0", names_at + at)]
    symbols = [data[a:a + 16] for a in range(sym_at, sym_at + sym_size, 16)]
    if any(name(struct.unpack_from("<I", s)[0]) in (b"$a", b"$d") for s in symbols):
        return data
    marks = []  # (section, symbol, offset)
    for h in headers:
        if h[1] != SHT_REL or not h[5]:
            continue
        code = h[7]
        words = [struct.unpack_from("<II", data, a)[0] for a in range(h[4], h[4] + h[5], 8)
                 if struct.unpack_from("<II", data, a)[1] & 0xFF == R_ARM_ABS32]
        if words and headers[code][2] & 4:  # (relocated words in code: SHF_EXECINSTR)
            marks += [(code, sym, at) for sym, at in mapping(words, headers[code][5])]
    if not marks:
        return data
    out = bytearray(data)
    strings = bytearray(data[names_at:names_at + headers[strtab][5]])
    added = []
    for code, sym, at in marks:
        added.append(struct.pack("<IIIBBH", len(strings), at, 0, 0, 0, code))
        strings += sym.encode() + b"\0"
    k = len(added)
    for h in headers:  # the globals move up by k: every relocation naming one names it there
        if h[1] == SHT_REL:
            for a in range(h[4], h[4] + h[5], 8):
                off, info = struct.unpack_from("<II", out, a)
                if info >> 8 >= first_global:
                    struct.pack_into("<II", out, a, off, ((info >> 8) + k) << 8 | (info & 0xFF))
    table = b"".join(symbols[:first_global]) + b"".join(added) + b"".join(symbols[first_global:])
    out += bytes(-len(out) % 4)
    headers[strtab][4], headers[strtab][5] = len(out), len(strings)
    out += strings
    out += bytes(-len(out) % 4)
    headers[symtab][4], headers[symtab][5], headers[symtab][7] = len(out), len(table), first_global + k
    out += table
    for i, h in enumerate(headers):
        struct.pack_into("<10I", out, shoff + i * shentsize, *h)
    return bytes(out)


def main() -> None:
    config, obj = Path(sys.argv[1]), Path(sys.argv[2])
    names = wanted(json.loads(config.read_text(encoding="utf-8")), config)
    data = obj.read_bytes()
    obj.write_bytes(mark_data(rename(data, names)))


if __name__ == "__main__":
    main()
