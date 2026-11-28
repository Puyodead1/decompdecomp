"""The files of a game's library code, named as the user's own library archives name them.

A game links its SDK's and its compiler's libraries one object at a time, each object's code in one run: OSAlarm.o of
the SDK's os.a, printf.o of CodeWarrior's MSL. dtk's analysis put a GameCube game's OS, GX, CARD, MSL and TRK code in
a few big files of 10 to 30 objects each, and cut some objects across two of them; a hand-split copy has one file per
object instead, with its real name (dolphin/os/OSAlarm.c, MSL_C/printf.c, TRK_MINNOW_DOLPHIN/nubinit.c).

The user's own copies of the libraries (a console's kits: kits.libraries) say which object a function's code is: its
code, relocations left out, is that object's function's (the library finder's signatures,
app/engine/libraryid.kit_signatures). A run of the game's functions that are one object's, with the functions between
them, is that object's file. Its first and last functions are extended over the object's other functions on either
side when the game has them where the object does (by name or by size): the short ones (a getter, an empty callback)
say too little by their code. An object whose functions are found in two places, or whose code is several objects'
alike, gets no file: the evidence is not one object's.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

LONE = 64  # bytes: a run of one function found by its code is an object's only when it's at least this long
# CodeWarrior's C++ names: __ct__/__dt__, or a name and its class and argument types (__F, __9Class...F)
_CPP = re.compile(r"^(?:__ct__|__dt__|__\w+__)|\w__(?:\d+\w+)?F\w*$")


@dataclass(frozen=True)
class Member:
    """One object of a library archive."""

    library: str  # the archive's name before its first dot, a debug build's D left off: "os", "MSL_C"
    name: str  # the object's, without ".o": "OSAlarm"
    cpp: bool = False  # its functions have C++ names


@dataclass
class Run:
    """A stretch of the game's code that is one member's: from `start` to the start of the function after its last
    one (`last`), `found` of its functions by their code."""

    start: int
    last: int
    member: Member
    found: int


@dataclass
class Function:
    addr: int
    size: int
    name: str
    raw: bytes
    wild: frozenset[int]


def library_name(path: Path) -> str:
    """os.a -> os, osD.a -> os (when os.a is beside it), MSL_C.PPCEABI.bare.H.a -> MSL_C. A G2D.a stays G2D."""
    stem = path.name.split(".", 1)[0]
    if stem.endswith("D") and len(stem) > 1 and any(p.name.split(".", 1)[0] == stem[:-1] for p in _siblings(path.parent)):
        return stem[:-1]
    return stem


@functools.lru_cache(maxsize=512)
def _siblings(folder: Path) -> tuple[Path, ...]:
    try:
        return tuple(p for p in folder.iterdir() if p.suffix.lower() == ".a")
    except OSError:
        return ()


def member_name(unit: str) -> str:
    """An archive member's object name: OSAlarm.o -> OSAlarm. CodeWarrior's own archives name a member by its source
    file's whole path in some versions (C:/.../MSL_Common/Src/printf.c, with backslashes) and by its object's in
    others (printf.o): both are printf, and its code in either is one object's."""
    return re.sub(r"\.(?:o|obj|c|cp|cpp)$", "", re.split(r"[\\/]", unit)[-1], flags=re.I)


@functools.lru_cache(maxsize=1024)
def _contents(path: str, size: int, mtime_ns: int) -> tuple[tuple[str, tuple[tuple[str, int, bytes], ...]], ...]:
    """(member, its functions in the order of its code: (name, size, opcodes: _opcodes)) of each object in an
    archive."""
    from io import BytesIO

    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    from ..app.engine.libraryid import archive_members

    out = []
    try:
        data = Path(path).read_bytes()
    except OSError:
        return ()
    for member, obj in archive_members(data):
        if not obj.startswith(b"\x7fELF"):
            continue
        try:
            elf = ELFFile(BytesIO(obj))
            symtab = elf.get_section_by_name(".symtab")
            text = elf.get_section_by_name(".text")
            if symtab is None or text is None:
                continue
            index = elf.get_section_index(".text")
            funcs = sorted((s["st_value"], s.name, s["st_size"]) for s in symtab.iter_symbols()
                           if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == index and s["st_size"] and s.name)
        except (ELFError, ValueError, KeyError, AttributeError, TypeError):
            continue
        code = text.data()
        out.append((member_name(member), tuple((n, sz, _opcodes(code[at:at + sz])) for at, n, sz in funcs)))
    return tuple(out)


def _opcodes(raw: bytes) -> bytes:
    """Each instruction's primary opcode (its top 6 bits): what two builds of one function share where their
    registers, offsets and relocations differ."""
    return bytes(raw[i] >> 2 for i in range(0, len(raw) - 3, 4))


def _alike(raw: bytes, ops: bytes) -> bool:
    """Whether the game's code `raw` is another build of the function whose opcodes are `ops`: as long, and three
    in four of its instructions of the same kind (a function of the same size beside it is another's: a GameCube
    game's dvd.c reached one function into dvdqueue.c by its size alone)."""
    mine = _opcodes(raw)
    return len(mine) == len(ops) > 0 and 4 * sum(a == b for a, b in zip(mine, ops)) >= 3 * len(ops)


def contents(archives: Iterable[Path]) -> dict[tuple[str, str], list[tuple[tuple[str, int, bytes], ...]]]:
    """(library, member) -> its functions in each copy of it (every version the user has)."""
    out: dict[tuple[str, str], list[tuple[tuple[str, int, bytes], ...]]] = {}
    for path in archives:
        try:
            st = path.stat()
        except OSError:
            continue
        lib = library_name(path)
        for member, funcs in _contents(str(path), st.st_size, st.st_mtime_ns):
            if funcs and funcs not in out.setdefault((lib, member), []):
                out[(lib, member)].append(funcs)
    return out


def game_functions(objects: Iterable[Path]) -> list[Function]:
    """The functions of the original's objects as dtk splits them, at their addresses in the game (dtk's note):
    each one's code and the bytes its relocations fill in. In address order."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    from ..app.engine.libraryid import _wild
    from .pools import _virt

    out: dict[int, Function] = {}
    for path in objects:
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                virt = _virt(elf)
                symtab = elf.get_section_by_name(".symtab")
                if virt is None or symtab is None:
                    continue
                relocs: dict[int, list[tuple[int, int]]] = {}
                for rs in elf.iter_sections():
                    if isinstance(rs, RelocationSection):
                        relocs.setdefault(rs["sh_info"], []).extend(
                            (r["r_offset"], r["r_info_type"]) for r in rs.iter_relocations())
                data: dict[int, bytes] = {}
                for i, s in enumerate(symtab.iter_symbols()):
                    if s["st_info"]["type"] != "STT_FUNC" or not isinstance(s["st_shndx"], int) or not s["st_size"] \
                            or i >= len(virt) or not virt[i]:
                        continue
                    shndx = s["st_shndx"]
                    if shndx not in data:
                        sec = elf.get_section(shndx)
                        data[shndx] = b"" if sec["sh_type"] == "SHT_NOBITS" else sec.data()
                    lo, size = s["st_value"], s["st_size"]
                    mine = [(o - lo, t) for o, t in relocs.get(shndx, []) if lo <= o < lo + size]
                    out[virt[i]] = Function(virt[i], size, s.name, data[shndx][lo:lo + size], _wild(mine, "ppc"))
        except (OSError, ELFError, ValueError, KeyError, AttributeError, TypeError):
            continue
    return [out[a] for a in sorted(out)]


def own_name(name: str) -> str:
    """A game's symbol as its library names it: without dtk's @unit or address suffix."""
    return name.split("@", 1)[0]


def runs(functions: list[Function], archives: list[Path]) -> list[Run]:
    """The runs of `functions` (one stretch of the game's code, in address order) that are one member of the user's
    library archives each, in address order."""
    if not functions or not archives:
        return []
    from .. import libid
    from ..app.engine.libraryid import kit_signatures

    by_name = {p.name: library_name(p) for p in archives}
    by_size: dict[int | None, list] = {}
    for s in kit_signatures(archives):
        by_size.setdefault(s.size, []).append(s)
    labels: list[tuple[str, str] | None] = []
    real: list[str] = []  # (each function's name in its library, where its code says one)
    for f in functions:
        code = libid.Code(f.addr, f.name, f.addr, f.raw, f.wild)
        hits = [s for s in by_size.get(len(f.raw), []) + by_size.get(None, []) if libid.signature_matches(s, code)]
        keys = {(by_name.get(s.library, s.library.split(".", 1)[0]), member_name(s.unit)) for s in hits if s.unit}
        if len(keys) > 1:  # (the same code in several objects: its own name says which, where the game has it)
            keys = {(by_name.get(s.library, s.library.split(".", 1)[0]), member_name(s.unit)) for s in hits
                    if s.unit and s.name == own_name(f.name)}
        labels.append(next(iter(keys)) if len(keys) == 1 else None)
        named = {s.name for s in hits if s.unit and labels[-1] == (by_name.get(s.library, s.library.split(".", 1)[0]),
                                                                    member_name(s.unit))}
        real.append(next(iter(named)) if len(named) == 1 else own_name(f.name))
    table = contents(archives)
    spans: dict[tuple[str, str], list[int]] = {}
    for i, key in enumerate(labels):
        if key is not None:
            spans.setdefault(key, []).append(i)
    out = []
    taken: set[int] = set()
    for key, at in spans.items():
        first, last = at[0], at[-1]
        if any(labels[i] not in (None, key) for i in range(first, last + 1)):
            continue  # (found in two places, another object's code between: not one object's run)
        if len(at) == 1 and functions[first].size < LONE:
            continue  # (one short function's code says too little: MusyX's chorus callback was a game's own)
        copies = table.get(key, [])
        names = {n for c in copies for n, *_ in c}
        first = _extend(functions, labels, real, first, -1, copies)
        last = _extend(functions, labels, real, last, 1, copies)
        if taken.intersection(range(first, last + 1)):
            continue
        taken.update(range(first, last + 1))
        # (most of its functions with C++ names: one C++ inline from a header, sqrtf__Ff, makes no C file C++)
        cpp = 2 * sum(1 for n in names if _CPP.search(n)) > len(names)
        out.append(Run(functions[first].addr, functions[last].addr, Member(key[0], key[1], cpp), len(at)))
    return sorted(out, key=lambda r: r.start)


def _extend(functions: list[Function], labels: list, real: list[str], edge: int, step: int, copies) -> int:
    """How far a member's run reaches beyond its outermost function found by its code (`edge`), one way (`step`):
    over the game's functions no other object's code found, while the member has one more function that way with
    the game's function's name, or another build of its code (_alike). Returns the outermost index."""
    if not copies:
        return edge
    best = edge
    anchor = real[edge]
    for funcs in copies:
        order = [n for n, *_ in funcs]
        sizes = [sz for _, sz, _ in funcs]
        ops = [o for *_, o in funcs]
        if anchor in order:
            k = order.index(anchor)
        else:  # (the game's own name for it isn't the library's: placed by its size, when only one function has it)
            same = [j for j, sz in enumerate(sizes) if sz == functions[edge].size]
            if len(same) != 1:
                continue
            k = same[0]
        i, j = edge, k
        while 0 <= i + step < len(functions) and 0 <= j + step < len(order) and labels[i + step] is None:
            g = functions[i + step]
            if real[i + step] != order[j + step] and not _alike(g.raw, ops[j + step]):
                break
            i, j = i + step, j + step
        best = min(best, i) if step < 0 else max(best, i)
    return best


def pieces(starts: list[int], lo: int, hi: int, found: list[Run], name_of, pools_found, most: int,
           taken: set[str] = frozenset()) -> list[tuple[int, int, str | None]]:
    """The code from lo to hi (functions starting at `starts`, sorted: dtksplits.cut_points) cut into files: each run
    of one library object (`found`: runs()) a file of its own, named name_of(its member) (Console.library_file), and
    the code between cut where the literal pools say the game's files end (pools.cuts; at most `most` functions a
    file). (start, end, name or None) each, in order. A run that doesn't start at a place code may be cut, or whose
    name is another's (`taken`, or an earlier run's), is left to the pools."""
    from . import pools

    places = set(starts) | {lo}
    out: list[tuple[int, int, str | None]] = []
    used = set(taken)
    at = lo

    def between(a: int, b: int) -> None:
        cuts = pools.cuts([s for s in starts if a <= s < b], a, b, pools_found, most)
        out.extend((x, y, None) for x, y in zip(cuts, cuts[1:]))

    for run in found:
        if run.start < at or not lo <= run.start < hi or run.start not in places:
            continue
        name = name_of(run.member)
        if not name or name in used:
            continue
        end = next((s for s in starts if s > run.last), hi)
        if at < run.start:
            between(at, run.start)
        out.append((run.start, end, name))
        used.add(name)
        at = end
    if at < hi:
        between(at, hi)
    return out
