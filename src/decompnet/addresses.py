"""Addresses matched C writes as numbers, given back what is there: a string, a constant, a global, a function.

A ROM-mode judge links a function at its address in the game, so `printf((char *)0x80aa0c0)` matches as well as
`printf("Hull breach\\n")`: the number is the address the game keeps that string at. Helpers (and the decompilers
they read) wrote about 1,100 of them in a 2000s Linux game's matched C: 580 strings, 380 float and double constants,
globals and their fields, 90 functions. Such C matches where it lies and nowhere else: relinked, ported or changed,
the numbers point at nothing. `proposals` reads what the game holds at each one and says what C would name it;
the caller (Readability.name_addresses) keeps each only where the judge still matches, so nothing is weakened: a
constant GCC folds (1.0 is fld1, not a load) stays as the address it was.

A string is only written as one where the game keeps it read-only (a writable buffer that starts with text is a
buffer), and a constant only as a float or double (an integer becomes an immediate, never a load)."""

from __future__ import annotations

import functools
import math
import re
import struct
from dataclasses import dataclass
from decimal import Decimal
from typing import Callable

from . import cfields

_CAST = r"\(\s*(?P<type>(?:(?:const|volatile|unsigned|signed|struct|union)\s+)*\w+(?:\s+(?:const|int|long|short|char))*)\s*(?P<stars>\*+)\s*\)"
_NUMBER = r"(?P<addr>0x[0-9a-fA-F]{5,8})[uUlL]*"
# `*(float *)0x80a4e44`, `*((double *) 0x80a1f18)`: a read of what is at the address
DEREFS = (re.compile(rf"\*\s*\(\s*{_CAST}\s*{_NUMBER}\s*\)"), re.compile(rf"\*\s*{_CAST}\s*{_NUMBER}(?![\w\[(])"))
# `(char *) 0x80aa0c0`, `(void *)0x8051234`: the address itself
POINTER = re.compile(rf"(?<![\w)\]]){_CAST}\s*{_NUMBER}(?![\w\[(])")
READ_ONLY = (".rodata", ".rdata", ".sdata2", ".sbss2", ".rodata1")  # the sections whose names say they're constants
CODE = (".text", ".init", ".fini", ".plt")
STRING_BYTES = set(range(32, 127)) | {9, 10, 13, 27}
LONGEST = 4096  # a string's bytes read at most
TEXT_POINTERS = {"char", "const char", "signed char", "unsigned char", "u8", "s8", "void", "const void"}
FLOATS = {"float": ("<f", 4, "f"), "f32": ("<f", 4, "f"), "double": ("<d", 8, ""), "f64": ("<d", 8, "")}


@dataclass
class Program:
    """What the game holds: its bytes by address, the section each address is in, its symbols, the header."""
    read: Callable[[int, int], bytes | None]
    section: Callable[[int], str | None]  # the name of the section or segment an address is in
    symbols: object  # rom.symbols.SymbolTable
    header: str
    big_endian: bool = False


@dataclass
class Proposal:
    start: int
    end: int
    text: str  # what replaces source[start:end]
    declare: str | None = None  # a declaration the source needs first
    what: str = ""  # "string", "constant", "global", "function", "generated"
    fallback: Proposal | None = None  # tried when this one doesn't match: the address's generated name


def _string(read, address: int) -> bytes | None:
    data = read(address, 1)
    if data is None:
        return None
    out = bytearray()
    while len(out) < LONGEST:
        byte = read(address + len(out), 1)
        if not byte:
            return None
        if byte == b"\0":
            return bytes(out)
        if byte[0] not in STRING_BYTES:
            return None
        out += byte
    return None


def c_string(data: bytes) -> str:
    """The C literal of a string's bytes (octal escapes: a hex escape would run into a following digit)."""
    out = []
    for b in data:
        c = chr(b)
        out.append({"\\": "\\\\", '"': '\\"', "\n": "\\n", "\t": "\\t", "\r": "\\r"}.get(c)
                   or (c if 32 <= b < 127 else f"\\{b:03o}"))
    return '"' + "".join(out) + '"'


def c_float(value: float, single: bool) -> str | None:
    """The shortest C literal that is exactly `value` as a float (single) or a double, or None (inf, NaN)."""
    if not math.isfinite(value):
        return None
    if not single:
        text = repr(value)
    else:
        packed = struct.pack("<f", value)
        text = next(t for t in (f"{value:.{d}g}" for d in range(1, 18))
                    if struct.pack("<f", float(t)) == packed)
        if "e" in text and 1e-4 <= abs(value) < 1e16:  # (90.0f, not 9e+01f)
            text = format(Decimal(text), "f")
    if "e" not in text and "." not in text and "inf" not in text:
        text += ".0"
    return text + ("f" if single else "")


def _plain(type_: str) -> str:
    return " ".join(cfields.QUALIFIERS.sub(" ", type_).split())


def _global_type(text: str, name: str) -> str | None:
    """The type a global is declared with (`extern TSettings GameSettings;`), or None (an array, a pointer, a
    function, or not declared)."""
    for m in re.finditer(rf"^[ \t]*(?:extern\s+)?([A-Za-z_][\w \t]*?)\s+{re.escape(name)}\s*;", text, re.M):
        type_ = _plain(m.group(1))
        if type_ and type_.split()[-1] not in ("return", "typedef", "goto"):
            return type_
    return None


_header = functools.lru_cache(maxsize=4)(cfields.Header)


@functools.lru_cache(maxsize=8)
def _top_level(text: str) -> str:
    """`text`'s declarations outside braces (no struct fields, no function bodies) and without comments."""
    return cfields._without_braces(cfields._COMMENT.sub(" ", text))


def _declared(text: str, name: str) -> bool:
    """Whether `text` (top-level declarations) declares `name`, a global or a function: a struct's field or a local
    of that name (`p->timer`) doesn't count."""
    n = re.escape(name)
    return re.search(rf"^[ \t]*(?:(?:extern|static|const|volatile|struct|union|enum|unsigned|signed)\s+)*"
                     rf"(?!return\b)[A-Za-z_]\w*[\s*]+(?:\(\s*\*\s*)?{n}\s*(?:\[[^\]]*\]\s*)*[;=,()]", text, re.M) is not None


def _named(symbols, address: int):
    """The game's own symbol at or around `address` and the offset into it: (symbol, offset) or None. Names the
    tools make up (D_8012..., func_...) are left out: they are the number again."""
    from .rom.symbols import AUTO_NAME

    sym = symbols.by_addr.get(address)
    if sym is None:
        name, off = symbols.name_at(address)
        sym = symbols.by_name.get(name)
        if sym is None or not (0 < off < max(sym.size, 1)):
            return None
    else:
        off = 0
    if AUTO_NAME.match(sym.name) or not re.fullmatch(r"[A-Za-z_]\w*", sym.name):
        return None
    return sym, off


def proposals(source: str, program: Program) -> list[Proposal]:
    """What C would name each address `source` writes as a number, one proposal each (not yet judged)."""
    header = _header(program.header)
    top = _top_level(program.header) + "\n" + _top_level(source)
    found: list[Proposal] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    def symbolic(m, deref: bool) -> Proposal | None:
        address = int(m.group("addr"), 16)
        type_, stars = _plain(m.group("type")), m.group("stars")
        section = program.section(address) or ""
        named = _named(program.symbols, address)
        if named is not None and named[0].kind in ("func",):
            sym = named[0]
            if deref or named[1]:
                return None
            declare = None if _declared(top, sym.name) else f"void {sym.name}();"
            return Proposal(m.start(), m.end(), f"({m.group('type')} {stars}){sym.name}", declare, "function")
        if section.startswith(READ_ONLY) and named is None:
            if deref and stars == "*" and type_ in FLOATS:
                fmt, size, single = FLOATS[type_]
                data = program.read(address, size)
                if data is None:
                    return None
                value = struct.unpack((">" if program.big_endian else "<") + fmt[1], data)[0]
                text = c_float(value, bool(single))
                if text is None:
                    return None
                return Proposal(m.start(), m.end(), f"({text})" if text.startswith("-") else text, None, "constant")
            if not deref and stars == "*" and type_ in TEXT_POINTERS:
                data = _string(program.read, address)
                return None if data is None else Proposal(m.start(), m.end(), c_string(data), None, "string")
            return None
        if named is None or section.startswith(CODE):
            return None
        sym, off = named
        declared = _declared(top, sym.name)
        declare = None if declared else f"extern char {sym.name}[];"
        held = _global_type(top, sym.name) if declared else None
        if deref and held is not None:
            field = (("", held) if off == 0 else header.name_read(held, off))
            if field is not None and stars == "*" and (off == 0 or field[0]) and \
                    header.resolve(_plain(field[1])) == header.resolve(type_):
                return Proposal(m.start(), m.end(), sym.name + field[0].replace("->", ".", 1), None, "global")
        where = f"&{sym.name}" if off == 0 else f"((char *)&{sym.name} + 0x{off:x})"
        cast = f"({m.group('type')} {stars})"
        return Proposal(m.start(), m.end(), f"*{cast}{where}" if deref else f"{cast}{where}", declare, "global")

    def generated(m, deref: bool) -> Proposal | None:
        """The address's generated name (D_080A4E44, which the judge and the export resolve to it): where nothing
        else names it (a static, a string read as a word), or where GCC must see another object than the global it
        is (C that reads `vect_ix` and, through the number, the same int again matches only so)."""
        address = int(m.group("addr"), 16)
        section = program.section(address) or ""
        if not section or section.startswith(CODE):
            return None
        name = f"D_{address:08X}"
        cast = f"({m.group('type')} {m.group('stars')})"
        return Proposal(m.start(), m.end(), f"*{cast}{name}" if deref else f"{cast}{name}",
                        None if _declared(top, name) else f"extern char {name}[];", "generated")

    def proposal(m, deref: bool) -> Proposal | None:
        p = symbolic(m, deref)
        fallback = generated(m, deref)
        if p is None:
            return fallback
        p.fallback = fallback
        return p

    for pattern, deref in ((DEREFS[0], True), (DEREFS[1], True), (POINTER, False)):
        for m in pattern.finditer(source):
            if not free(m.start(), m.end()):
                continue
            p = proposal(m, deref)
            if p is not None:
                found.append(p)
                taken.append((m.start(), m.end()))
    return sorted(found, key=lambda p: p.start)


def apply(source: str, chosen: list[Proposal]) -> str:
    """`source` with the chosen proposals in place and the declarations they need before its first line of code."""
    out = source
    for p in sorted(chosen, key=lambda p: p.start, reverse=True):
        out = out[:p.start] + p.text + out[p.end:]
    needed = list(dict.fromkeys(p.declare for p in chosen if p.declare))
    if not needed:
        return out
    # after the #includes, so the header's types are known
    at = max((m.end() for m in re.finditer(r"^[ \t]*#[^\n]*\n", out, re.M)), default=0)
    return out[:at] + "".join(f"{d}\n" for d in needed) + out[at:]


def numbers(source: str) -> int:
    """How many addresses `source` still writes as numbers (cast, then a hexadecimal address)."""
    return len(POINTER.findall(source))
