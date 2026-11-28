"""Where a GameCube or Wii game's source files begin and end, read from the compiler's literal pools (#ADDON 6 §7).

MWCC puts each file's float constants, doubles and short strings in a pool of its own (.sdata2; .rodata where small
data is off), one copy of each value per file, in the order the file's code first uses them. So:

- two functions that load the same pooled constant are in one file, and so is every function between them (a file's
  code is one stretch): a GameCube game's radar file used its neighbour's constants, and the two were one file that
  the split had cut in two;
- two copies of one value (each file that converts an int to a float has its own 0x4330000080000000) are two files'
  pools: a file ends after the last function using the first copy and before the first using the second.

Everything is read from the original's objects (the split's objects every unit is compared with), which say where
each symbol was in the game (dtk's VIRT note), whatever the project's splits are now.
"""

from __future__ import annotations

import struct
from bisect import bisect_left, bisect_right
from collections.abc import Iterable
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from decompnet.forks import dtkdata, linklayout

POOLS = (".sdata2", ".rodata")  # where MWCC pools a file's constants (.rodata when -sdata2 0, and in a REL)
CODE = (".text", ".init")
REL24, REL14, SDA21, ADDR16_LO, ADDR16_HA = 10, 11, 109, 4, 6  # how code loads a pooled constant: off r2, or lis/addi (lfs 0@l(rX))
LOADS = (SDA21, ADDR16_LO, ADDR16_HA)
# the D-form loads (lwz, lwzu, lbz, lbzu, lhz, lhzu, lha, lhau, lfs, lfsu, lfd, lfdu): a store, or an addi taking
# the address, is a variable's
_LOAD_OPS = frozenset({32, 33, 34, 35, 40, 41, 42, 43, 48, 49, 50, 51})
LARGEST = 8 # a pooled float or double; a short string in .sdata2 is no bigger
_VIRT = 0x56495254  # dtk's split note: each symbol's address in the game, by symbol index


@dataclass
class Pools:
    """The pooled constants of a game: which functions load each, and its bytes."""

    users: dict[int, set[int]] = field(default_factory=dict)  # constant's address -> addresses of the functions using it
    values: dict[int, bytes] = field(default_factory=dict)  # constant's address -> its bytes
    functions: list[int] = field(default_factory=list)  # every function's address, sorted
    calls: set[tuple[int, int]] = field(default_factory=set)  # (caller, callee) by address

    def uses(self) -> dict[int, set[int]]:
        """function's address -> the constants it loads."""
        if not hasattr(self, "_uses"):
            out: dict[int, set[int]] = {}
            for a, fns in self.users.items():
                for f in fns:
                    out.setdefault(f, set()).add(a)
            self._uses = out
        return self._uses

    def together(self) -> list[tuple[int, int, int]]:
        """(first, last, constant): the functions from first to last are one file's, since both load this constant."""
        return sorted((min(u), max(u), a) for a, u in self.users.items() if len(u) > 1)

    def apart(self) -> list[tuple[int, int, int, int]]:
        """(after, upto, first copy, second copy): a file ends after the function `after` and the next starts by
        `upto`, since the functions up to `after` use one copy of a value and those from `upto` on another. Copies
        whose users interleave say nothing (a constant some other way shared) and are left out."""
        by_value: dict[bytes, list[int]] = {}
        for a, v in self.values.items():
            if a in self.users:
                by_value.setdefault(v, []).append(a)
        out = []
        for copies in by_value.values():
            copies.sort()
            for one, two in zip(copies, copies[1:]):
                if max(self.users[one]) < min(self.users[two]):
                    out.append((max(self.users[one]), min(self.users[two]), one, two))
        return sorted(out)


def _virt(elf: ELFFile) -> list[int] | None:
    sec = elf.get_section_by_name(".note.split")
    if sec is None:
        return None
    data, i = sec.data(), 0
    while i + 12 <= len(data):
        nsz, dsz, kind = struct.unpack(">III", data[i:i + 12])
        i += 12 + ((nsz + 3) & ~3)
        if kind == _VIRT:
            return [v for (v,) in struct.iter_unpack(">I", data[i:i + dsz - dsz % 4])]
        i += (dsz + 3) & ~3
    return None


def read(objects: Iterable[Path], rows: list[tuple[str, str, int, int]]) -> Pools:
    """The pooled constants these objects' code loads (rows: symbols.txt, dtksplits.symbol_rows). A constant is a
    symbol of at most 8 bytes in a pool section that code only loads: one a table points at, or whose address code
    takes (an addi with no load), is a variable."""
    address = dtkdata.resolver(rows)
    small = {a: s for _, sec, a, s in rows if sec in POOLS and 0 < s <= LARGEST}
    users: dict[int, set[int]] = {}
    values: dict[int, bytes] = {}
    not_constants: set[int] = set()
    functions: set[int] = set()
    calls: set[tuple[int, int]] = set()
    for path in objects:
        try:
            elf = ELFFile(BytesIO(Path(path).read_bytes()))
        except Exception:  # (not ELF, or broken: nothing to read)
            continue
        virt = _virt(elf)
        tab = next((s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)), None)
        if virt is None or tab is None:
            continue
        secs = list(elf.iter_sections())
        where: list[int | None] = []
        spans: dict[int, list[tuple[int, int, int]]] = {}  # section index -> (offset, end, game address) of functions
        for i, s in enumerate(tab.iter_symbols()):
            shndx = s["st_shndx"]
            here = virt[i] if i < len(virt) and virt[i] and isinstance(shndx, int) and shndx > 0 else None
            if here is None and shndx == "SHN_UNDEF" and s.name:
                here = address(s.name)
            where.append(here)
            if not isinstance(shndx, int) or shndx <= 0 or here is None:
                continue
            name = secs[shndx].name
            if s["st_info"]["type"] == "STT_FUNC" and name in CODE:
                spans.setdefault(shndx, []).append((s["st_value"], s["st_value"] + max(s["st_size"], 4), here))
                functions.add(here)
            elif name in POOLS and here in small and s["st_info"]["type"] != "STT_SECTION":
                values[here] = secs[shndx].data()[s["st_value"]:s["st_value"] + small[here]]
        relocated: dict[int, set[int]] = {}
        for rs in secs:
            if not isinstance(rs, RelocationSection) or rs["sh_info"] >= len(secs):
                continue
            into = secs[rs["sh_info"]].name
            funcs = _Spans(spans.get(rs["sh_info"], []))
            for r in rs.iter_relocations():
                relocated.setdefault(rs["sh_info"], set()).add(r["r_offset"])
                k = r["r_info_sym"]
                to = where[k] if k < len(where) else None
                if to is not None and r["r_addend"]:
                    to += r["r_addend"]
                if to is None:
                    continue
                if r["r_info_type"] in (REL24, REL14) and into in CODE:
                    if (at := funcs.at(r["r_offset"])) is not None and at != to:
                        calls.add((at, to))
                    continue
                if to not in small:
                    continue
                if into not in CODE or r["r_info_type"] not in LOADS or not _loads(rs, r, elf, secs):
                    not_constants.add(to)
                elif (at := funcs.at(r["r_offset"])) is not None:
                    users.setdefault(to, set()).add(at)
        for index, fns in spans.items():  # (calls the assembler resolved itself, within the object: no relocation)
            if secs[index].name in CODE:
                funcs = _Spans(fns)
                base = {lo: here - lo for lo, _, here in fns}
                for at, to in linklayout.branches(secs[index].data(), relocated.get(index, set())):
                    one, two = funcs.offset(at), funcs.offset(to)
                    if one is not None and two is not None and one != two and to == two:
                        calls.add((one + base[one], two + base[two]))
    for a in not_constants:
        users.pop(a, None)
    return Pools(users, {a: v for a, v in values.items() if a in users}, sorted(functions), calls)


class _Spans:
    """An object's functions in one section: (offset, end, game address), and which one an offset is in."""

    def __init__(self, spans: list[tuple[int, int, int]]):
        self.spans = sorted(spans)
        self.starts = [lo for lo, _, _ in self.spans]

    def _find(self, offset: int) -> tuple[int, int, int] | None:
        j = bisect_right(self.starts, offset) - 1
        return self.spans[j] if j >= 0 and self.spans[j][0] <= offset < self.spans[j][1] else None

    def at(self, offset: int) -> int | None:
        """The game address of the function this offset is in."""
        return f[2] if (f := self._find(offset)) else None

    def offset(self, offset: int) -> int | None:
        """The offset of the function this offset is in."""
        return f[0] if (f := self._find(offset)) else None


def _loads(rs, r, elf: ELFFile, secs) -> bool:
    """Whether this relocation's instruction loads from the constant (lfs, lfd, lwz...), not takes its address: an
    @ha (lis) is half of a load, an @l or @sda21 on an addi is an address."""
    if r["r_info_type"] == ADDR16_HA:
        return True
    code = secs[rs["sh_info"]].data()
    at = r["r_offset"] & ~3
    if at + 4 > len(code):
        return False
    return code[at] >> 2 in _LOAD_OPS


def _between(inside: list[int], after: int, upto: int, banned: set[int], pools: Pools) -> int | None:
    """Where between two files' pools the second file starts: of the starts past `after` up to `upto` no constant
    forbids, those where the first file's constants all lie before the second's (the pools follow the files), and of
    those the one fewest calls among these functions cross (a file's static helpers sit with their callers), the
    latest (a function using no constant is given to the first file: nothing says otherwise)."""
    window = inside[bisect_left(inside, after):bisect_right(inside, upto)]
    places = [a for a in window[1:] if a not in banned]
    if not places:
        return None
    uses = pools.uses()
    ordered = [t for t in places
               if max((c for f in window if f < t for c in uses.get(f, ())), default=-1)
               < min((c for f in window if f >= t for c in uses.get(f, ())), default=1 << 32)]
    places = ordered or places
    lo, hi = window[0], window[-1]
    edges = [(x, y) for x, y in pools.calls if lo <= x <= hi and lo <= y <= hi]
    return min(reversed(places), key=lambda t: sum(1 for x, y in edges if (x < t) != (y < t)))


def cuts(starts: list[int], lo: int, hi: int, pools: Pools | None, most: int) -> list[int]:
    """Where to cut the code from lo to hi (functions starting at `starts`, sorted) into files: [lo, ..., hi].
    A cut is made where the pools say one file ends (one cut serves every copy pair it falls between), never inside
    a stretch one constant's users span; then a stretch of more than `most` functions is cut every `most`, each cut
    moved to the nearest place no pool forbids."""
    inside = [a for a in starts if lo <= a < hi]
    if not inside:
        return [lo, hi]
    banned: set[int] = set()  # function starts a cut can't fall at: inside one constant's users
    if pools:
        for first, last, _ in pools.together():
            banned.update(inside[bisect_right(inside, first):bisect_right(inside, last)])
    made: list[int] = []
    if pools:
        for after, upto, _, _ in sorted(pools.apart(), key=lambda x: x[1]):
            if not (lo <= after and upto < hi) or any(after < c <= upto for c in made):
                continue
            if (at := _between(inside, after, upto, banned, pools)) is not None:
                made.append(at)
    made = sorted(set(made))
    out = [lo]
    for c in [*made, hi]:
        while True:
            i, j = bisect_left(inside, out[-1]), bisect_left(inside, c)
            if j - i <= most:
                break
            want = i + most
            near = sorted(range(i + 1, j), key=lambda k: (abs(k - want), k))
            pick = next((inside[k] for k in near if k <= want and inside[k] not in banned), None)
            if pick is None:
                break  # (one file's constants span it all: one file, however long)
            out.append(pick)
        if c != out[-1]:
            out.append(c)
    return out
