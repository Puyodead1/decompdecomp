"""Machine passes over a source file that make it read like a decomp's and keep what it builds to (#ADDON 1-5):

- **constants as literals**: `extern f32 lbl_803C8728;` where the original's object of this very file holds the
  value is the file's own pooled constant, and it links only against the original's object. Each use becomes the
  value (`0.5f`), all of a file's at once (MWCC pools literals in the order the code first uses them: half of them
  literals reorders the pool), or, where a literal changes the code (the compiler folds `x * 0.0f`), a local
  variable holding it in each function that uses it, which isn't folded.
  Left alone: a double the compiler makes for converting an integer (0x4330...: it comes from the cast), a label
  whose symbol is bigger than the type (the head of a shared pool, a vector or struct initialiser), one whose
  address is taken or that is written to.
- **unused declarations**: a file-scope `extern` or function prototype the file never uses (copied whole from
  another file's, they held most of a GameCube game's placeholders).

These are text transforms; the engine keeps one only when the unit's object stays as it must
(ForkEngine.same_object: the same object for pruning; the same code, relocations pointing at the same bytes and
the data no further from the original's for literals).
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass
from decimal import Decimal
from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .csource import _blank

WIDTH = {"f32": 4, "float": 4, "f64": 8, "double": 8}
_FLOAT_DECL = re.compile(r"\bextern\s+(?:const\s+)?(f32|f64|float|double)\s+(?:const\s+)?"
                         r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*;")
_EXTERN = re.compile(r"\bextern\s+(?!\")([^;{}]*?);")
_PROTOTYPE = re.compile(r"(?<![\w*])([A-Za-z_][\w \t*]*?[\s*])([A-Za-z_]\w*)\s*\(([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*)\)"
                        r"\s*;")
_INT_TO_FLOAT = (bytes.fromhex("4330000000000000"), bytes.fromhex("4330000080000000"))
_KEYWORDS = {"return", "if", "while", "for", "switch", "sizeof", "do", "else", "case", "goto", "typedef"}


@dataclass
class Decl:
    start: int
    end: int  # after the ';'
    names: list[str]
    kind: str  # the type (literals), "" for pruning


def _ident(name: str) -> re.Pattern:
    return re.compile(rf"(?<![\w.]){re.escape(name)}(?!\w)")


def _uses(blank: str, name: str, decls: list[Decl]) -> list[int]:
    """Where a name is used, outside the declarations of it."""
    inside = [(d.start, d.end) for d in decls if name in d.names]
    return [m.start() for m in _ident(name).finditer(blank) if not any(s <= m.start() < e for s, e in inside)]


def _depths(blank: str) -> list[int]:
    """The brace depth before each character."""
    out, depth = [], 0
    for ch in blank:
        out.append(depth)
        depth += (ch == "{") - (ch == "}")
    return out


def float_externs(text: str) -> list[Decl]:
    """The `extern f32 a, b;` declarations of floats and doubles, wherever they are (a function's own too)."""
    blank = _blank(text)
    return [Decl(m.start(), m.end(), [n.strip() for n in m.group(2).split(",")], m.group(1))
            for m in _FLOAT_DECL.finditer(blank)]


def values(objects: list[Path], names: set[str]) -> dict[str, tuple[bytes, int, bool]]:
    """What each name holds in the original's objects that define it: (bytes up to 8, the symbol's size, whether
    little endian). Only symbols in data the program can't write (it's a constant the file pools)."""
    out: dict[str, tuple[bytes, int, bool]] = {}
    for path in objects:
        try:
            elf = ELFFile(BytesIO(Path(path).read_bytes()))
            secs = list(elf.iter_sections())
            for symtab in (s for s in secs if isinstance(s, SymbolTableSection)):
                for sym in symtab.iter_symbols():
                    shndx = sym["st_shndx"]
                    if sym.name not in names or sym.name in out or not isinstance(shndx, int) or not 0 < shndx < len(secs):
                        continue
                    sec = secs[shndx]
                    if sec["sh_type"] != "SHT_PROGBITS" or sec["sh_flags"] & 0x4:
                        continue
                    at = sym["st_value"]
                    out[sym.name] = (sec.data()[at:at + 8], sym["st_size"], elf.little_endian)
        except (OSError, ELFError, ValueError, IndexError):
            continue
    return out


def literal(data: bytes, width: int, little: bool = False) -> str | None:
    """The shortest C literal for a float (`0.1f`) or double (`0.1`) with exactly these bytes; None for what has
    none (NaN, infinity)."""
    if len(data) < width:
        return None
    end = "<" if little else ">"
    kind = "f" if width == 4 else "d"
    value = struct.unpack(end + kind, data[:width])[0]
    if not math.isfinite(value):
        return None
    if width == 4:
        text = next(t for p in range(1, 10) if struct.pack(">f", float(t := f"{value:.{p}g}")) == struct.pack(">f", value))
    else:
        text = repr(value)
    if "e" in text and -5 <= Decimal(text).adjusted() <= 15:  # (90.0f, not 9e+01f)
        text = format(Decimal(text), "f")
    if not any(c in text for c in ".e"):
        text += ".0"
    elif "e" in text and "." not in text.split("e")[0]:
        text = text.replace("e", ".0e", 1)
    return text + ("f" if width == 4 else "")


def own_constants(text: str, held: dict[str, tuple[bytes, int, bool]]) -> dict[str, str]:
    """The float externs of this file that are its own pooled constants, with their literals: defined in the
    original's object (`held`, from values()), the symbol no bigger than the type, not an integer conversion's double,
    never written to or taken the address of."""
    blank = _blank(text)
    decls = float_externs(text)
    out: dict[str, str] = {}
    for d in decls:
        width = WIDTH[d.kind]
        for name in d.names:
            if name not in held or name in out:
                continue
            data, size, little = held[name]
            if (size and size != width) or (width == 8 and data[:8] in _INT_TO_FLOAT):
                continue
            uses = _uses(blank, name, decls)
            if not uses or any(_written(blank, at, name) for at in uses):
                continue
            if (lit := literal(data, width, little)) is not None:
                out[name] = lit
    return out


def _written(blank: str, at: int, name: str) -> bool:
    before = blank[:at].rstrip()
    after = blank[at + len(name):].lstrip()
    return (before.endswith(("&", "++", "--")) and not before.endswith("&&")) or after.startswith(("++", "--", "[")) \
        or (after.startswith("=") and not after.startswith("==")) or bool(re.match(r"[-+*/%&|^]=|<<=|>>=", after))


def _drop(text: str, decls: list[Decl], gone: set[str]) -> str:
    """The declarations without the names in `gone` (a declaration left with none goes, with its line when nothing
    else is on it; a comment after it stays)."""
    for d in sorted(decls, key=lambda d: -d.start):
        keep = [n for n in d.names if n not in gone]
        if len(keep) == len(d.names):
            continue
        if keep:
            head = text[d.start:d.end]
            names = re.search(r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*;$", _blank(head))
            if names is not None:  # (plain names only: `a[], *b` stay as they are)
                text = text[:d.start] + head[:names.start(1)] + ", ".join(keep) + ";" + text[d.end:]
            continue
        start, end = d.start, d.end
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        line_end = len(text) if line_end < 0 else line_end
        if not text[line_start:start].strip():
            rest = text[end:line_end].strip()
            if not rest:  # (the whole line)
                text = text[:line_start] + text[line_end + 1:]
                continue
            if rest.startswith(("/*", "//")):  # (its comment stays, on the line the declaration was)
                text = text[:line_start] + text[line_start:start] + rest + text[line_end:]
                continue
        text = text[:start] + text[end:].lstrip(" \t")
    return text


def with_literals(text: str, constants: dict[str, str], local: set[str] = frozenset()) -> str:
    """The file with each of `constants` written as its literal, its declarations gone; those in `local` instead a
    local variable holding it, at the top of each function using it (a literal there is folded: `x * 0.0f`)."""
    blank = _blank(text)
    decls = float_externs(text)
    kinds = {n: d.kind for d in decls for n in d.names}
    edits: list[tuple[int, int, str]] = []
    depth = _depths(blank)
    bodies: dict[int, set[str]] = {}
    for name, lit in constants.items():
        for at in _uses(blank, name, decls):
            if name in local:
                if not depth[at]:
                    return text  # (used outside a function: nothing to do here)
                start = _body_start(blank, depth, at)
                bodies.setdefault(start, set()).add(name)
            else:
                sign = lit.startswith("-") and blank[:at].rstrip()[-1:] in ("-", "+")
                edits.append((at, at + len(name), f"({lit})" if sign else lit))
    for start, names in bodies.items():
        nl = text.find("\n", start)
        indent = re.match(r"[ \t]*", text[nl + 1:]).group() if nl >= 0 else "    "
        lines = "".join(f"\n{indent or '    '}{kinds.get(n, 'f32')} {n} = {constants[n]};" for n in sorted(names))
        edits.append((start + 1, start + 1, lines))
    for s, e, new in sorted(edits, key=lambda x: -x[0]):
        text = text[:s] + new + text[e:]
    return _drop(text, float_externs(text), set(constants))


def _body_start(blank: str, depth: list[int], at: int) -> int:
    """The `{` opening the function a position is in."""
    i = at
    while i > 0 and not (blank[i] == "{" and depth[i] == 0):
        i -= 1
    return i


def unused_declarations(text: str) -> list[Decl]:
    """File-scope `extern` declarations and function prototypes whose names the file never uses again."""
    blank = _blank(text)
    depth = _depths(blank)
    decls: list[Decl] = []
    taken: list[tuple[int, int]] = []
    for m in _EXTERN.finditer(blank):
        if depth[m.start()]:
            continue
        body = m.group(1)
        if "(" in body:  # a function: `extern void f(int);` (a pointer to one, `(*f)(int)`, is left alone)
            fn = re.search(r"([A-Za-z_]\w*)\s*\(", body)
            names = [fn.group(1)] if fn and fn.group(1) not in WIDTH and not re.match(
                r"(void|int|char|short|long|unsigned|signed|u8|u16|u32|s8|s16|s32|BOOL)$", fn.group(1)) else []
        else:
            names = [re.sub(r"\[.*$", "", part).strip().split()[-1].lstrip("*")
                     for part in _split_top(body.split("=")[0]) if part.strip()]
            names = [n for n in names if re.fullmatch(r"[A-Za-z_]\w*", n)]
            if "=" in body:  # (a definition, not a declaration)
                continue
        if names:
            decls.append(Decl(m.start(), m.end(), names, ""))
            taken.append((m.start(), m.end()))
    for m in _PROTOTYPE.finditer(blank):
        if depth[m.start()] or any(s <= m.start() < e for s, e in taken):
            continue
        head = m.group(1).split()
        if not head or head[0] in _KEYWORDS or "typedef" in head or m.group(2) in _KEYWORDS:
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", m.group(2)) or re.fullmatch(r"[\s\dxXa-fA-F,+*()<>-]*\d[\s\dxXa-fA-F,]*",
                                                                          m.group(3)):
            continue  # (a macro, `Header ATTRIBUTE_ALIGN(32);`: a definition, not a prototype)
        line_start = blank.rfind("\n", 0, m.start()) + 1
        if blank[line_start:m.start()].strip() or blank[line_start:].lstrip().startswith("#"):
            continue  # (part of something longer, or a macro)
        decls.append(Decl(m.start(), m.end(), [m.group(2)], ""))
    out = []
    for d in decls:
        unused = [n for n in d.names if not _uses(blank, n, decls)]
        if unused:
            out.append(Decl(d.start, d.end, unused, ""))
    return out


def _split_top(text: str) -> list[str]:
    """Split at the commas outside brackets."""
    parts, depth, cur = [], 0, ""
    for ch in text:
        depth += ch in "([{"
        depth -= ch in ")]}"
        if ch == "," and not depth:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return [*parts, cur]


def without_unused(text: str) -> tuple[str, list[str]]:
    """The file without its unused declarations, and their names."""
    found = unused_declarations(text)
    gone = {n for d in found for n in d.names}
    if not gone:
        return text, []
    blank = _blank(text)
    every = [Decl(d.start, d.end, _names_at(blank, d), "") for d in found]
    return _drop(text, every, gone), sorted(gone)


def _names_at(blank: str, d: Decl) -> list[str]:
    """All the names a declaration declares (only some of them may be unused)."""
    body = blank[d.start:d.end]
    m = _EXTERN.match(body)
    if not m or "(" in m.group(1):
        return d.names
    names = [re.sub(r"\[.*$", "", p).strip().split()[-1].lstrip("*") for p in _split_top(m.group(1)) if p.strip()]
    return [n for n in names if re.fullmatch(r"[A-Za-z_]\w*", n)] or d.names
