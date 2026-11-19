"""Which compiler built each part of a Linux program that mixes them, from the program itself. A 2009 arcade game's
.comment holds 237 notes, one per object file in link order: 42 of Red Hat's GCC 4.3.2 (the C runtime's start-up
objects and the game's own code), 165 of GCC 3.4.4 (a prebuilt 3D engine and the static libraries, libjpeg, libpng,
xvid...) and 30 of NASM (xvid's hand-written assembly). Its symbol table names the same object files in the same
order (an STT_FILE symbol each, then that object's local symbols), so the notes pair with the objects; the GCC
4.3.2 was the one that linked it (its crtbegin.o), the program's own compiler, and the engine's code needs 3.4.4.

Where an object's code lies: its local symbols (static functions, _GLOBAL__I_ constructors) say it for objects
that have any, and code between two objects one compiler built is that compiler's. Between the last object one
compiler built and the first another did, the padding between functions says which side a function is on: each
toolchain's assembler pads alignment its own way (Fedora 10's binutils 2.18 with `66 90` and `8d 76 00`, Slackware
10.2's 2.15 with `89 f6`), learnt from the code each side surely built. What neither says is left to the project's
compiler: agents' compiler suggestions and the range check widen a range, never this guess."""

from __future__ import annotations

import bisect
import re
from collections import Counter
from dataclasses import dataclass, field
from io import BytesIO

from elftools.elf.elffile import ELFFile

GCC = re.compile(r"GCC: ")
ASSEMBLY = re.compile(r"\.(asm|s|S|nasm)$")
MIN_MARKS = 2  # a padding pattern says a toolchain once it's seen this often in code that toolchain surely built
LEARNT = 20  # paddings seen in code each of two toolchains surely built, before their marks tell them apart
CRT = "crtstuff.c"  # crtbegin.o and crtend.o: the GCC that linked the program


@dataclass
class Obj:
    name: str
    said: str = ""  # its .comment note; "" when no GCC built it (assembly)
    anchors: list[int] = field(default_factory=list)  # its local symbols' addresses in .text

    @property
    def gcc(self) -> str:
        return self.said if GCC.match(self.said) else ""


def _comments(elf) -> list[str]:
    comment = elf.get_section_by_name(".comment")
    return [s.decode("latin-1") for s in comment.data().split(b"\0") if s] if comment is not None else []


def read_objects(elf) -> tuple[list[Obj], str] | None:
    """The program's object files in link order, each with its .comment note and its local symbols in .text, and the
    note of the GCC that linked it; None when the notes and the objects can't be paired for sure (no symbol table,
    or several pairings that disagree). The C runtime's crtbegin.o and crtend.o are left out: their file symbols
    come first, both (ld lists crtend.o's second, not last), and their code is the runtime's, never the program's."""
    table, text = elf.get_section_by_name(".symtab"), elf.get_section_by_name(".text")
    if table is None or text is None:
        return None
    lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
    objs: list[Obj] = []
    for s in table.iter_symbols():
        kind, bind = s["st_info"]["type"], s["st_info"]["bind"]
        if kind == "STT_FILE":
            objs.append(Obj(s.name))
        elif bind != "STB_LOCAL":
            break  # (the locals come first, object by object; then the globals)
        elif objs and kind in ("STT_FUNC", "STT_NOTYPE") and lo <= s["st_value"] < hi:
            objs[-1].anchors.append(s["st_value"])
    crt = sum(o.name == CRT for o in objs)
    objs = [o for o in objs if o.name != CRT]
    said = _comments(elf)
    extra = len(said) - len(objs)
    if not objs or extra < 0:
        return None

    def fits(skip: int) -> bool:  # (every assembler's note on an assembly file, a GCC's on every other)
        return all(bool(ASSEMBLY.search(o.name)) == (not GCC.match(n)) for o, n in zip(objs, said[skip:]))

    # the C runtime's objects, each with its note: glibc's crt1.o and crti.o (no file symbol) and GCC's crtbegin.o
    # first, crtend.o and glibc's crtn.o last; else the one pairing that fits, when the notes say which
    glibc = extra - crt
    skip = min(crt, 1) + min(max(glibc, 0), 2)
    if not (0 <= glibc <= 3 and fits(skip)):
        found = [k for k in range(extra + 1) if fits(k)]
        if not found or any(said[k:k + len(objs)] != said[found[0]:found[0] + len(objs)] for k in found):
            return None
        skip = found[0]
    for o, n in zip(objs, said[skip:]):
        o.said = n
    linker = said[skip - 1] if crt and skip and GCC.match(said[skip - 1]) else ""  # (crtbegin.o's, just before)
    return objs, linker


def program_compiler(objs: list[Obj], linker: str = "") -> str:
    """The GCC that linked the program (its crtbegin.o's), whose code the program's own is; else the one that built
    the most object files."""
    if linker:
        return linker
    built = Counter(o.gcc for o in objs if o.gcc)
    return built.most_common(1)[0][0] if built else ""


def _functions(elf) -> list[tuple[int, int]]:
    text = elf.get_section_by_name(".text")
    lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
    out = {(s["st_value"], s["st_size"]) for s in elf.get_section_by_name(".symtab").iter_symbols()
           if s["st_info"]["type"] == "STT_FUNC" and lo <= s["st_value"] < hi and s["st_size"]}
    return sorted(dict(sorted(out)).items())  # (one per address: the largest size)


def _runs(labels: list[str]) -> list[str]:
    """Consecutive labels, each once ("" left out)."""
    out: list[str] = []
    for label in labels:
        if label and (not out or out[-1] != label):
            out.append(label)
    return out


def object_compilers(data: bytes) -> list[tuple[int, int, str]]:
    """(start, end, compiler note) of each stretch of the program's code one GCC built, for a program whose object
    files more than one GCC built; [] otherwise, or when its objects can't be read for sure."""
    try:
        elf = ELFFile(BytesIO(data))
        objs = (read_objects(elf) or ([], ""))[0]
        if not objs or len({o.gcc for o in objs if o.gcc}) < 2:
            return []
        functions = _functions(elf)
        text = elf.get_section_by_name(".text")
        code, base = text.data(), text["sh_addr"]
    except Exception:  # noqa: BLE001  (a damaged table: no reading, the project's compiler for everything)
        return []
    anchors = sorted((a, i) for i, o in enumerate(objs) for a in o.anchors)
    if any(i2 < i1 for (_, i1), (_, i2) in zip(anchors, anchors[1:])):
        return []  # (objects out of link order: not a layout this reads)
    starts = [f[0] for f in functions]
    label: list[str] = [""] * len(functions)
    for a, i in anchors:  # (the function each local symbol is in is its object's)
        k = bisect.bisect_right(starts, a) - 1
        if k >= 0 and a < starts[k] + functions[k][1] and objs[i].gcc:
            label[k] = objs[i].gcc
    zones = []  # (first function, last function + 1, the two compilers' runs between)
    edges = [(-1, 0), *anchors, (1 << 32, len(objs) - 1)]
    for (a, i), (b, j) in zip(edges, edges[1:]):
        lo_f, hi_f = bisect.bisect_right(starts, a), bisect.bisect_left(starts, b)
        runs = _runs([o.gcc for o in objs[i:j + 1]])
        if len(runs) == 1:
            label[lo_f:hi_f] = [runs[0]] * (hi_f - lo_f)
        elif len(runs) == 2:
            zones.append((lo_f, hi_f, runs))

    def pad(k: int) -> bytes:
        end = functions[k][0] + functions[k][1]
        return code[end - base:starts[k + 1] - base] if k + 1 < len(starts) and starts[k + 1] >= end else b""

    # each toolchain's padding, from the code it surely built (inside one object or between two of its own)
    seen: dict[str, Counter] = {}
    for k in range(len(functions) - 1):
        p = pad(k)
        if label[k] and label[k] == label[k + 1] and len(p) >= 2 and set(p) - {0x90, 0}:
            seen.setdefault(label[k], Counter())[p] += 1
    marks = {p: who for who, c in seen.items() for p, n in c.items()
             if n >= MIN_MARKS and not any(p in other for o, other in seen.items() if o != who)}
    for lo_f, hi_f, (first, second) in zones:
        if sum(seen.get(first, {}).values()) < LEARNT or sum(seen.get(second, {}).values()) < LEARNT:
            continue  # (a toolchain whose padding is unknown: the other's marks could be its too)
        said = [(k, marks[pad(k)]) for k in range(lo_f, hi_f) if not label[k] and pad(k) in marks]
        last_first = max((k for k, who in said if who == first), default=None)
        first_second = min((k for k, who in said if who == second), default=None)
        if last_first is not None and first_second is not None and first_second < last_first:
            continue  # (the padding disagrees: neither side's)
        sure_first = max(k for k in [lo_f - 1, last_first] if k is not None)
        sure_second = min(k for k in [hi_f, first_second] if k is not None)
        for k in range(lo_f, hi_f):
            if not label[k]:
                label[k] = first if k <= sure_first else second if k >= sure_second else ""
    out: list[tuple[int, int, str]] = []
    for k, who in enumerate(label):
        if not who:
            continue
        start, end = functions[k][0], functions[k][0] + functions[k][1]
        if out and k and label[k - 1] == who:  # (over a function nobody's said, a stretch ends)
            out[-1] = (out[-1][0], end, who)
        else:
            out.append((start, end, who))
    return out
