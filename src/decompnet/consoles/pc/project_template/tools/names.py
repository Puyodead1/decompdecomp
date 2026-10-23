#!/usr/bin/env python3
"""Give what src/ compiles to the original's symbol names, so C++ pairs with the game's functions in objdiff.

    python tools/names.py config/<version>/functions.json OBJECT

The game's functions and data are known by address: func_0041B470, D_0066DDA4. Written in C++, as a free function or
a class's method (`void Town::func_0041B470(int)`), MSVC mangles the name (`?func_0041B470@Town@@QAEXH@Z`); this
renames every symbol whose name holds func_<address> or D_<address> to the name the original's object gives it
(`@func_0041B470@8`, `_D_0066DDA4`), in the object itself. A symbol given a real name in config/<version>/names.json
(`"func_0041B470": "Town_Update"`, written by decompdecomp's rename_symbol) is found by that name too, mangled or
not, and tools/delink.py gives the original's objects the same names. Other C names are left as they are. Standard
library only. Made by decompdecomp.
"""

import json
import re
import struct
import sys
from pathlib import Path

REF = re.compile(rb"(func|D)_([0-9A-Fa-f]{8})")
# The C name in a symbol: _f, _f@8 and @f@8 (C, __stdcall, __fastcall), or ?f@... (C++: a function, a class's
# method, a variable). C++'s special names (??0 constructors, ??_C strings) and the compiler's own ($L, __real@) have
# none.
C_SYMBOL = re.compile(r"[_@]?([A-Za-z_]\w*?)(@\d+)?")
CXX_SYMBOL = re.compile(r"\?([A-Za-z_]\w*)@")
DATA = re.compile(r"_(D_[0-9A-F]{8})")


def c_name(symbol: str) -> str | None:
    m = CXX_SYMBOL.match(symbol) if symbol.startswith("?") else C_SYMBOL.fullmatch(symbol)
    return m.group(1) if m else None


def real_names(info: dict, config: Path) -> dict[str, str]:
    """The original's symbols that names.json gives a real name, with their decoration: _func_0041B470@8 (or the
    name a rename gave it before) -> _Town_Update@8."""
    try:
        names = json.loads(config.with_name("names.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not names:
        return {}
    key = {fn["name"]: f"func_{fn['addr']:08X}" for functions in info["units"].values() for fn in functions}
    out = {}
    for functions in info["units"].values():
        for fn in functions:
            for symbol in (fn["name"], *(r[2] for r in fn["relocs"] if r[2])):
                k = key.get(symbol) or ((m := DATA.fullmatch(symbol)) and m.group(1))
                if k in names and (m := C_SYMBOL.fullmatch(symbol)):
                    out[symbol] = symbol[:m.start(1)] + names[k] + symbol[m.end(1):]
    return out


def wanted(info: dict, config: Path) -> dict[bytes, bytes]:
    """func_XXXXXXXX / D_XXXXXXXX (upper case address), and each real name, -> the original's symbol."""
    real = real_names(info, config)
    out = {}
    for functions in info["units"].values():
        for fn in functions:
            name = real.get(fn["name"], fn["name"])
            out[f"func_{fn['addr']:08X}".encode()] = name.encode()
            if (c := c_name(name)):
                out[c.encode()] = name.encode()
            for _, _, ref, _ in fn["relocs"]:
                if ref and (m := DATA.fullmatch(ref)):
                    out[m.group(1).encode()] = real.get(ref, ref).encode()
                    if ref in real:
                        out[c_name(real[ref]).encode()] = real[ref].encode()
    return out


def rename(data: bytes, names: dict[bytes, bytes]) -> bytes:
    """The COFF object with its symbols renamed (new names go at the end of the string table)."""
    sym_at, count = struct.unpack_from("<II", data, 8)
    strings_at = sym_at + 18 * count
    strings = bytearray(data[strings_at:])
    table = bytearray(data[sym_at:strings_at])
    i = 0
    while i < count:
        at = 18 * i
        raw = table[at:at + 8]
        if raw[:4] == b"\0\0\0\0":
            off = struct.unpack_from("<I", raw, 4)[0]
            name = bytes(strings[off:strings.index(b"\0", off)])
        else:
            name = bytes(raw).rstrip(b"\0")
        m = REF.search(name)
        key = m.group(1) + b"_" + m.group(2).upper() if m else (c_name(name.decode("latin-1")) or "").encode()
        if key and not name.startswith(b"."):
            new = names.get(key)
            if new is None and m and m.group(1) == b"D":
                new = b"_" + key  # data the original's code doesn't name
            if new is not None and new != name:
                if len(new) <= 8:
                    table[at:at + 8] = new.ljust(8, b"\0")
                else:
                    table[at:at + 8] = struct.pack("<II", 0, len(strings))
                    strings += new + b"\0"
        i += 1 + table[at + 17]  # its auxiliary records
    struct.pack_into("<I", strings, 0, len(strings))
    return data[:sym_at] + bytes(table) + bytes(strings)


def main() -> None:
    config, obj = Path(sys.argv[1]), Path(sys.argv[2])
    names = wanted(json.loads(config.read_text(encoding="utf-8")), config)
    data = obj.read_bytes()
    obj.write_bytes(rename(data, names))


if __name__ == "__main__":
    main()
