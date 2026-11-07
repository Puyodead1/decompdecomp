"""The struct fields a C header declares, by offset, and the reads a function's C makes through a byte pointer and an
offset that one of them names: `*(char ***)((char *)pModel + 0x40)` is `pModel->Geometries` when pModel is a
`TModel *` and the header has SModel's Geometries at 0x40. Polishing shows them and asks for the names (readable.py):
on a 2000s Linux game a helper polished a function with every other field by name and that one left as an offset,
twice, though the named read compiles to the same code.

Offsets come from the header's own `/* 0x40 */` comments where it has them (the headers made from debug information,
cheader.py), or else from the fields' sizes, as long as every field before it has a size known here and no
alignment the compilers disagree on (8-byte types: 4 in a struct for GCC on x86, 8 for MSVC). What isn't certain is
left out: a wrong name would cost a helper more than an offset does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

POINTER = 4  # every console's processor here is 32-bit
SIZES = {"char": 1, "signed char": 1, "unsigned char": 1, "u8": 1, "s8": 1, "uchar": 1, "bool": 1, "byte": 1,
         "undefined": 1, "undefined1": 1, "BYTE": 1,
         "short": 2, "unsigned short": 2, "signed short": 2, "short int": 2, "u16": 2, "s16": 2, "ushort": 2,
         "undefined2": 2, "WORD": 2, "wchar_t": 2,
         "int": 4, "unsigned int": 4, "signed int": 4, "unsigned": 4, "signed": 4, "long": 4, "unsigned long": 4,
         "long int": 4, "u32": 4, "s32": 4, "uint": 4, "ulong": 4, "float": 4, "f32": 4, "undefined4": 4,
         "DWORD": 4, "BOOL": 4, "s32_bool": 4}
WIDE = {"double", "f64", "long long", "unsigned long long", "u64", "s64", "long double", "undefined8"}  # align differs
BYTE_POINTERS = {"char", "signed char", "unsigned char", "u8", "s8", "uchar", "byte", "undefined", "BYTE"}
QUALIFIERS = re.compile(r"\b(?:const|volatile|register|static)\b")
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_OFFSET_COMMENT = re.compile(r"/\*\s*(?:offset\s*)?0x([0-9A-Fa-f]+)\b")
_TYPEDEF = re.compile(r"\btypedef\s+([^;{}()]+?)\s*\b(\w+)\s*;")
_TAGGED = re.compile(r"\b(struct|union)\s+(\w+)?\s*\{")
_FIELD = re.compile(r"^(.*?)\b(\w+)\s*((?:\[[^\]]*\])*)$", re.S)
_FUNC_POINTER = re.compile(r"\(\s*\*+\s*(\w+)\s*\)\s*\(")
# `*(T *)((char *)v + 0x40)`: a read through a byte pointer made of a variable, at a constant offset
READ = re.compile(r"\*\s*\(\s*[\w\s]+\*+\s*\)\s*\(\s*\(\s*((?:unsigned\s+|signed\s+)?\w+)\s*\*\s*\)\s*(\w+)\s*\+\s*"
                  r"(0x[0-9a-fA-F]+|\d+)\s*\)")
# `*(T *)(param_2 + 0x1bc)`: a read at an offset from a variable declared as an integer (a machine draft's
# `int param_2`), named when the debug information says what the parameter really is (`TObject *pObj`)
INT_READ = re.compile(r"\*\s*\(\s*[\w\s]+\*+\s*\)\s*\(\s*(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
INTEGERS = r"(?:unsigned\s+int|unsigned\s+long|unsigned|int|long|uint|ulong|u32|s32|undefined4|DWORD)"
SHOWN = 12  # reads listed at most


@dataclass
class Field:
    name: str
    offset: int
    type: str  # the type as declared, without the name ("TLODGeometry *", "ushort")
    count: int = 1  # array elements (1: not an array)
    size: int | None = None  # one element's


@dataclass
class Struct:
    fields: list[Field]
    size: int | None


class Header:
    """A header's structs and unions (by tag and by typedef name) and its plain typedefs."""

    def __init__(self, text: str):
        self.typedefs: dict[str, str] = {}
        self.bodies: dict[str, tuple[str, str]] = {}  # name -> (struct/union, body with comments)
        self.structs: dict[str, Struct | None] = {}
        self._read(text)

    def _read(self, text: str) -> None:
        pos = 0
        while (m := _TAGGED.search(text, pos)) is not None:
            end = _closing(text, m.end() - 1)
            if end is None:
                break
            kind, tag, body = m.group(1), m.group(2), text[m.end():end]
            after = re.match(r"\s*(\w+)?\s*;", text[end + 1:])
            typedef = re.search(r"\btypedef\s*$", text[max(0, m.start() - 16):m.start()])
            for name in [tag, after.group(1) if after and typedef else None]:
                if name and name not in self.bodies:
                    self.bodies[name] = (kind, body)
            pos = end + 1
        plain = _COMMENT.sub(" ", _without_braces(text))
        for m in _TYPEDEF.finditer(plain):
            target = " ".join(QUALIFIERS.sub(" ", m.group(1)).split())
            if target not in ("struct", "union") and m.group(2) != target.split()[-1].rstrip("*"):
                self.typedefs.setdefault(m.group(2), target)

    def resolve(self, name: str) -> str:
        """A type name followed through its typedefs: `TModel` -> `struct SModel`, `ushort` -> `unsigned short`."""
        for _ in range(16):
            name = " ".join(QUALIFIERS.sub(" ", name).split())
            if name in self.typedefs:
                name = self.typedefs[name]
            else:
                break
        return name

    def struct(self, name: str, depth: int = 0) -> Struct | None:
        name = self.resolve(name)
        name = re.sub(r"^(?:struct|union)\s+", "", name)
        if name in self.structs:
            return self.structs[name]
        if name not in self.bodies or depth > 8:
            return None
        self.structs[name] = None  # (a struct that contains itself by value: broken, so none)
        kind, body = self.bodies[name]
        self.structs[name] = self._layout(kind, body, depth)
        return self.structs[name]

    def size(self, type_: str, depth: int = 0) -> tuple[int | None, bool]:
        """A type's size and whether its alignment is certain (8-byte types' isn't)."""
        t = self.resolve(type_)
        if t.endswith("*"):
            return POINTER, True
        if t.startswith("enum "):
            return 4, True
        if t in SIZES:
            return SIZES[t], True
        if t in WIDE:
            return 8, False
        found = self.struct(t, depth + 1)
        if found is None or found.size is None:
            return None, False
        return found.size, all(f.size is not None for f in found.fields)

    def _layout(self, kind: str, body: str, depth: int) -> Struct:
        fields: list[Field] = []
        at: int | None = 0
        biggest = 1
        for decl, said in _declarations(body):
            if ":" in decl:  # a bit-field: offsets after it are the compiler's
                at = None
                continue
            fp = _FUNC_POINTER.search(decl)
            if fp:
                name, type_, dims = fp.group(1), "void *", ""
            else:
                m = _FIELD.match(decl)
                if not m or not m.group(1).strip():
                    at = None
                    continue
                type_, name, dims = " ".join(m.group(1).split()), m.group(2), m.group(3)
            count = 1
            for d in re.findall(r"\[([^\]]*)\]", dims):
                try:
                    count *= int(d.strip(), 0)
                except ValueError:
                    count = 0
            size, certain = self.size(type_, depth)
            if kind == "union":
                offset = 0
            elif said is not None:
                offset = said
            elif at is None or size is None or not certain:
                offset = None
            else:
                align = min(size, 4) if self.resolve(type_) in SIZES or type_.endswith("*") else _align(self, type_)
                offset = -(-at // align) * align if align else None
            if offset is None:
                at = None
                continue
            fields.append(Field(name, offset, type_, count, size))
            biggest = max(biggest, min(size or 1, 4))
            at = offset + size * count if size is not None and count and certain else None
        if kind == "union":
            sizes = [f.size * f.count for f in fields if f.size is not None]
            return Struct(fields, max(sizes) if sizes and len(sizes) == len(fields) else None)
        return Struct(fields, -(-at // biggest) * biggest if at is not None else None)

    def name_read(self, type_: str, offset: int) -> tuple[str, str] | None:
        """The fields `offset` bytes into a `type_` reach, as `->a.b[2]`, and the last one's type; None when the
        header doesn't say for certain."""
        path, t = "", type_
        for _ in range(8):
            found = self.struct(t)
            if found is None:  # (a scalar: the read must start where it does)
                return (path, t) if path and offset == 0 else None
            inside = None
            for f in found.fields:
                if f.size is None:
                    if f.offset == offset:
                        inside = f
                    continue
                if f.offset <= offset < f.offset + f.size * max(f.count, 1):
                    inside = f
                    break
            if inside is None:
                return (path, t) if path and offset == 0 else None
            path += ("->" if not path else ".") + inside.name
            offset -= inside.offset
            if inside.count != 1 and inside.size:
                path += f"[{offset // inside.size}]"
                offset %= inside.size
            t = inside.type
            if offset == 0 and self.struct(t) is None:
                return path, t
        return None


def _align(header: Header, type_: str) -> int | None:
    found = header.struct(type_)
    if found is None:
        return None
    aligns = []
    for f in found.fields:
        t = header.resolve(f.type)
        if t.endswith("*") or t in SIZES or t.startswith("enum "):
            aligns.append(min(f.size or 4, 4))
        else:
            aligns.append(_align(header, f.type))
    return None if None in aligns else max(aligns, default=1)


def _closing(text: str, open_at: int) -> int | None:
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _without_braces(text: str) -> str:
    out, depth = [], 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _declarations(body: str):
    """A struct body's member declarations at its own level, each with the offset its comment says (or None). A
    member that's a struct or union written inline has no size here: it's left out, and the offsets after it too
    unless their comments say."""
    pos, depth, start = 0, 0, 0
    while pos < len(body):
        ch = body[pos]
        if body.startswith("/*", pos):
            end = body.find("*/", pos + 2)
            pos = len(body) if end < 0 else end + 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ";" and depth == 0:
            decl = _COMMENT.sub(" ", body[start:pos])
            after = re.match(r"[ \t]*(/\*[^\n]*?\*/)", body[pos + 1:])
            said = _OFFSET_COMMENT.match(after.group(1)) if after else None
            if "{" in decl:
                yield ":", None  # (an inline struct: unknown, as a bit-field is)
            else:
                decl = " ".join(QUALIFIERS.sub(" ", decl).split())
                if decl:
                    yield decl, int(said.group(1), 16) if said else None
            start = pos + 1
        pos += 1


def _declared_type(source: str, var: str) -> str | None:
    """The type a pointer variable (parameter or local) is declared with in the function's C, without its `*`. A
    cast puts `)` between them (`(char *)pModel`), so `TModel *pModel` followed by `,`, `;`, `)`, `=` or `[` is its
    declaration."""
    for m in re.finditer(r"((?:struct\s+|union\s+)?\w+)\s*\*\s*(?:const\s+)?" + re.escape(var) + r"\s*[,;)=\[]",
                         source):
        if m.group(1) not in ("return", "sizeof", "const"):
            return m.group(1)
    return None


def named_reads(source: str, header_text: str, types: dict[str, str] | None = None) -> list[str]:
    """The reads `source` makes through a byte pointer and an offset that the header names, one line each:
    "`*(char ***)((char *)pModel + 0x40)` is pModel->Geometries (TLODGeometry *)". `types`: what the debug
    information says variables declared as integers are (`{"param_2": "TObject"}`), for reads straight off them."""
    types = types or {}
    reads = [(m, m.group(2), m.group(3)) for m in READ.finditer(source)
             if " ".join(m.group(1).split()) in BYTE_POINTERS]
    reads += [(m, m.group(1), m.group(2)) for m in INT_READ.finditer(source) if m.group(1) in types
              and re.search(rf"\b{INTEGERS}\s+{re.escape(m.group(1))}\s*[,;)=]", source)]
    if not reads or not header_text:
        return []
    header = Header(header_text)
    out, seen = [], set()
    for m, var, offset in sorted(reads, key=lambda r: r[0].start()):
        if m.group(0) in seen:
            continue
        seen.add(m.group(0))
        declared = types.get(var) or _declared_type(source, var)
        if declared is None or header.struct(declared) is None:
            continue
        named = header.name_read(declared, int(offset, 0))
        if named is None:
            continue
        really = f" ({var} is a {declared} *)" if var in types else ""
        out.append(f"- `{' '.join(m.group(0).split())}` is {var}{named[0]} ({named[1]}){really}")
        if len(out) >= SHOWN:
            break
    return out
