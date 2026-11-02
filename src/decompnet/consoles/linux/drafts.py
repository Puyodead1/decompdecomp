"""Linux programs: Ghidra's machine drafts (m2c reads no x86) as C that GCC 2.95 compiles, for autopilot and redraft.

Ghidra decompiles the whole program once (forks/ghidra.decompile_program), and each function's draft is found by its
address. As Ghidra writes them, they don't compile: its types (undefined4, uint, code), its names for what has no
symbol (DAT_0804a010, FUN_08048a20) and a signature of its own reading (`undefined4 f(undefined2 param_1)`). Made
compilable: Ghidra's types are declared only where the program's header doesn't declare them itself (glibc's
sys/types.h has uint, ushort and ulong), a part of a variable it has no field for is read through a pointer of its
size, and the addresses Ghidra names are the project's names for them (D_0804A010, func_08048A20), declared. A draft that reads what no C
names (a register before it's set, the stack above the frame) is none: autopilot doesn't try it."""

from __future__ import annotations

import re

GHIDRA_TYPES = [
    ("undefined", "typedef unsigned char undefined;"),
    ("undefined1", "typedef unsigned char undefined1;"),
    ("undefined2", "typedef unsigned short undefined2;"),
    ("undefined3", "typedef unsigned int undefined3;"),
    ("undefined4", "typedef unsigned int undefined4;"),
    ("undefined8", "typedef unsigned long long undefined8;"),
    ("byte", "typedef unsigned char byte;"),
    ("uchar", "typedef unsigned char uchar;"),
    ("ushort", "typedef unsigned short ushort;"),
    ("word", "typedef unsigned short word;"),
    ("uint", "typedef unsigned int uint;"),
    ("uint3", "typedef unsigned int uint3;"),
    ("ulong", "typedef unsigned long ulong;"),
    ("dword", "typedef unsigned int dword;"),
    ("longlong", "typedef long long longlong;"),
    ("ulonglong", "typedef unsigned long long ulonglong;"),
    ("qword", "typedef unsigned long long qword;"),
    ("float10", "typedef long double float10;"),
    ("longdouble", "typedef long double longdouble;"),
    ("code", "typedef int code();"),
    ("bool", "typedef unsigned char bool;"),
]
MACROS = """#define true 1
#define false 0
#define __cdecl
#define CONCAT11(a, b) ((unsigned short)(((unsigned short)(unsigned char)(a) << 8) | (unsigned char)(b)))
#define CONCAT22(a, b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 16) | (unsigned short)(b)))
#define CONCAT31(a, b) ((unsigned int)(((unsigned int)(a) << 8) | (unsigned char)(b)))
#define CONCAT13(a, b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 24) | ((unsigned int)(b) & 0xffffff)))
#define CONCAT44(a, b) ((unsigned long long)(((unsigned long long)(unsigned int)(a) << 32) | (unsigned int)(b)))
#define SUB41(x, n) ((unsigned char)((unsigned int)(x) >> ((n) * 8)))
#define SUB42(x, n) ((unsigned short)((unsigned int)(x) >> ((n) * 8)))
#define SUB84(x, n) ((unsigned int)((unsigned long long)(x) >> ((n) * 8)))
#define ZEXT14(x) ((unsigned int)(unsigned char)(x))
#define ZEXT24(x) ((unsigned int)(unsigned short)(x))
#define ZEXT48(x) ((unsigned long long)(unsigned int)(x))
#define SEXT14(x) ((int)(signed char)(x))
#define SEXT24(x) ((int)(short)(x))
#define SEXT48(x) ((long long)(int)(x))
"""  # (each a draft uses, unless the header defines it)
# What no C stands for: a register read before it's set, the stack above the frame, partial variables
# (local_4._1_3_), the flag helpers, a function Ghidra couldn't follow
_UNWRITABLE = re.compile(r"\b(unaff_\w+|in_stack_\w+|extraout_\w+|in_[A-Z]\w*|stack0x\w+|in_GS_OFFSET|halt_baddata|"
                         r"CARRY\d|SCARRY\d|SBORROW\d|POPCOUNT|LOCK|UNLOCK|WARNING|swi)\b|\.\_\d+_\d+_")
_PART = re.compile(r"\b([A-Za-z_]\w*)\._(\d+)_([1248])_")
# (`_DAT_080a9ee8`: Ghidra's underscores when a global overlaps smaller ones at its address)
_AUTO = re.compile(r"\b_*(DAT|FUN|PTR_DAT|LAB)_([0-9a-fA-F]{8})\b")
_WIDTH = {1: "undefined1", 2: "undefined2", 4: "undefined4", 8: "undefined8"}


def _head(text: str, name: str):
    return re.search(rf"^(?P<ret>[^\n;{{}}()]*?)\b{re.escape(name)}\s*\((?P<params>[^()]*(?:\([^()]*\)[^()]*)*)\)\s*\{{",
                     text, re.M)


def _split(params: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for c in params:
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        depth += c == "("
        depth -= c == ")"
        cur += c
    if cur.strip():
        out.append(cur.strip())
    return [p for p in out if p != "void"]


def _declares(header: str, name: str) -> bool:
    """Whether the header declares `name` itself (a global, a function, a type, an enumerator), not only a struct's
    field of that name (`timer` in a struct, and a file's static `timer` the header doesn't have)."""
    return re.search(rf"^\S[^\n;]*\b{name}\b", header, re.M) is not None \
        or re.search(rf"\benum\b[^;]*\{{[^}}]*\b{name}\b", header) is not None


def _declares_type(header: str, name: str) -> bool:
    return re.search(rf"\btypedef\b[^;]*\b{name}\s*(\)\s*\([^;]*\))?\s*;", header) is not None \
        or re.search(rf"\b(struct|union|enum)\s+{name}\b", header) is not None


def compilable(draft: str, name: str, header: str, data: dict[str, int] | None = None) -> str | None:
    """Ghidra's draft of `name` as C that compiles after the program's header (`header`: what context.h holds), or
    None when it reads what no C names. Its signature stays Ghidra's: its body reads a struct through a parameter by
    byte offsets (`*(int *)(param_1 + 0x1c)`), which the debug information's `z_streamp strm` would scale by the
    struct's size (on the demo program, 25 of its drafts matched with Ghidra's signatures, 16 with the STABS ones).
    `data`: the program's globals by name, with their sizes, for those its header doesn't declare (a file's statics,
    which GCC 2.95's STABS leave out of the shared header)."""
    text = re.sub(r"/\*.*?\*/", "", draft, flags=re.S)
    # a part of a variable Ghidra has no field for (`g_player._32_2_`: 2 bytes at +32) is that part, read through a
    # pointer of its size
    text = _PART.sub(lambda m: f"(*(undefined{m.group(3)} *)((char *)&{m.group(1)} + {m.group(2)}))", text)
    head = _head(text, name)
    if head is None or _UNWRITABLE.search(text):
        return None
    body = text[head.end():].rstrip()
    if not body.endswith("}"):
        return None
    params = _split(head.group("params"))
    ret = head.group("ret").strip() or "void"
    declared: dict[str, str] = {}
    for m in _AUTO.finditer(body):
        kind, addr = m.group(1), m.group(2).upper()
        if kind == "LAB":
            return None  # a jump Ghidra couldn't make C of
        new = f"func_{addr}" if kind == "FUN" else f"D_{addr}"
        if new == name or re.search(rf"\b{new}\b", header):
            continue
        declared[new] = f"int {new}();" if kind == "FUN" else f"extern undefined4 {new};"
    for other in sorted(set(re.findall(r"(?<![\w.>])([A-Za-z_]\w*)\b(?!\s*\()", body)) & set(data or {})):
        if other != name and other not in declared and not _declares(header, other) and \
                not re.search(rf"^\s*[\w ]+[\s*]{other}\s*(\[[^\]]*\])?;", body, re.M):  # (not a local of its own)
            size = (data or {})[other]
            declared[other] = (f"extern {_WIDTH[size]} {other};" if size in _WIDTH
                               else f"extern undefined1 {other}[{size or 1}];")
    body = _AUTO.sub(lambda m: f"func_{m.group(2).upper()}" if m.group(1) == "FUN"
                     else f"D_{m.group(2).upper()}", body)
    typedefs = [t for n, t in GHIDRA_TYPES if re.search(rf"\b{n}\b", f"{ret} {' '.join(params)} {body}")
                and not _declares_type(header, n)]
    for width in sorted({w for d in declared.values() for w in re.findall(r"\b(undefined\d?)\b", d)}):
        if not _declares_type(header, width):
            typedefs.append(dict(GHIDRA_TYPES)[width])
    lines = list(dict.fromkeys(typedefs)) + list(declared.values())
    used = [line for line in MACROS.splitlines() if line.startswith("#define ")
            and re.search(rf"\b{line.split()[1].split('(')[0]}\b", body)]
    macros = "".join(f"#ifndef {line.split()[1].split('(')[0]}\n{line}\n#endif\n" for line in used)
    return (macros + "".join(f"{line}\n" for line in lines)
            + f"\n{ret} {name}({', '.join(params) or 'void'})\n{{" + body + "\n")
