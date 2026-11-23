"""Switch jump tables: which code each entry of a function's tables sends a case to, in the original and in yours.

objdiff compares a function's instructions, and the instructions that load a jump table read the same whatever the
table holds: the table itself is data (MWCC puts it in .data, GCC in .rodata), relocations that point back into the
function. With relocation targets left uncompared (objdiff.REPORT_OPTIONS), a switch whose cases go to the wrong
bodies read 100%: on a GameCube game of 2,082 matched functions, 8 had cases sent elsewhere (cases renumbered by one,
two cases swapped), and nothing caught them until someone read the C. A function's tables are found from its own
code (the address its instructions load, where a relocation back into the function is), so a table is never
mistaken for a pointer to a function's start elsewhere, and tables in a row are told apart.

A split game's original objects don't always hold their tables: dtk puts code no file covers yet in code-only
objects (auto_..._text), which load `jumptable_800D3968` from a data object of its own, whose words name the
function plus an offset. The project's other original objects (`others`) resolve those names. COFF objects (PC,
Xbox) give no verdict, nor does a table nothing resolves, rather than a wrong one."""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ..elfobj import _function_symbols, section_target
from ..rom.match import raw_relocs

# The relocation that stores a 32-bit address in data, per machine.
_ABS32 = {"EM_PPC": 1, "EM_MIPS": 2, "EM_ARM": 2}
_SHF_EXECINSTR = 0x4

# Where a relocation points: ("sec", section index, offset) through a section symbol, or ("sym", name, addend).
Ref = tuple


@dataclass
class TableConflict:
    """A 100% function with a jump table whose entries send cases elsewhere than the original's do."""

    table: int  # which of the function's tables, in the order its code loads them
    at: int  # where the original's code loads it from (offset in the function)
    entries: list[tuple[int, int | None, int | None]]  # (entry, original's target, yours), offsets in the function
    jump_table = True

    def describe(self) -> str:
        def where(off: int | None) -> str:
            return "nothing" if off is None else f"+0x{off:X}"

        shown = ", ".join(f"entry {k} goes to {where(a)} in the original, {where(b)} in yours"
                          for k, a, b in self.entries[:4])
        more = f" (and {len(self.entries) - 4} more)" if len(self.entries) > 4 else ""
        return f"jump table {self.table + 1} (loaded at +0x{self.at:X}): {shown}{more}"


class _Index:
    """One object's symbols and relocations, read once: the addresses stored in its data, and its code's
    references."""

    def __init__(self, data: bytes):
        self.elf = elf = ELFFile(BytesIO(data))
        self.machine = elf["e_machine"]
        self.functions = _function_symbols(elf)
        self.order = "little" if elf.little_endian else "big"
        self.code_secs = {k for k in range(elf.num_sections()) if elf.get_section(k)["sh_flags"] & _SHF_EXECINSTR}
        self.defined: dict[str, tuple[int, int]] = {}  # name -> (section, offset)
        self.data_starts: set[tuple[int, int]] = set()  # where the data's own symbols start (one table each)
        symtab = elf.get_section_by_name(".symtab")
        for s in symtab.iter_symbols() if symtab is not None else ():
            shndx = s["st_shndx"]
            if s.name and isinstance(shndx, int) and shndx and s["st_info"]["type"] not in ("STT_SECTION", "STT_FILE"):
                self.defined.setdefault(s.name, (shndx, s["st_value"]))
                if shndx not in self.code_secs:
                    self.data_starts.add((shndx, s["st_value"]))
        self.by_start: dict[int, list[tuple[int, int, str]]] = {}  # section -> [(start, size, function)], sorted
        for name, (shndx, start, size) in self.functions.items():
            self.by_start.setdefault(shndx, []).append((start, size, name))
        for v in self.by_start.values():
            v.sort()
        self.words: dict[int, dict[int, Ref]] = {}  # data section -> {offset: what the word there points at}
        self.loads: dict[int, list[tuple[int, Ref]]] = {}  # code section -> [(offset, what it refers to)]
        for rsec in elf.iter_sections():
            if not isinstance(rsec, RelocationSection):
                continue
            into = rsec["sh_info"]
            if not into or into >= elf.num_sections():
                continue
            sec = elf.get_section(into)
            if into in self.code_secs:
                self._code(into, sec)
            elif sec["sh_type"] != "SHT_NOBITS":
                self._data(into, sec, rsec)

    def _ref(self, sym, residual: int) -> Ref | None:
        if sym["st_info"]["type"] == "STT_SECTION":
            shndx = sym["st_shndx"]
            return ("sec", shndx, residual) if isinstance(shndx, int) and shndx else None
        return ("sym", sym.name, residual) if sym.name else None

    def _data(self, shndx: int, sec, rsec) -> None:
        kind = _ABS32.get(self.machine)
        symtab = self.elf.get_section(rsec["sh_link"])
        raw = sec.data()
        out = self.words.setdefault(shndx, {})
        for rel in rsec.iter_relocations():
            if rel["r_info_type"] != kind:
                continue
            off = rel["r_offset"]
            addend = rel["r_addend"] if rel.is_RELA() else int.from_bytes(raw[off:off + 4], self.order, signed=True)
            if self.machine == "EM_ARM":
                addend &= ~1
            if ref := self._ref(symtab.get_symbol(rel["r_info_sym"]), addend):
                out[off] = ref

    def _code(self, shndx: int, sec) -> None:
        raw = raw_relocs(self.elf, shndx, 0, sec["sh_size"], sec.data())
        out = self.loads.setdefault(shndx, [])
        for k, r in enumerate(raw):
            if r["rela"]:
                residual = r["value"]
            elif self.machine == "EM_MIPS":
                residual = section_target("mips", raw, k)
            else:
                residual = None  # (ARM keeps its tables in its code, which objdiff compares)
            if residual is not None and (ref := self._ref(r["symtab"].get_symbol(r["symidx"]), residual)):
                out.append((r["off"], ref))

    def place(self, ref: Ref) -> tuple[int, int] | None:
        """(section, offset) in this object, or None when another object defines it."""
        if ref[0] == "sec":
            return ref[1], ref[2]
        hit = self.defined.get(ref[1])
        return (hit[0], hit[1] + ref[2]) if hit else None

    def function_at(self, shndx: int, off: int) -> tuple[str, int] | None:
        fns = self.by_start.get(shndx) or []
        k = bisect.bisect_right(fns, (off, float("inf"), "")) - 1
        if k >= 0 and fns[k][0] <= off < fns[k][0] + fns[k][1]:
            return fns[k][2], off - fns[k][0]
        return None


class _Resolver:
    """Follows a reference into the object that defines it: the object itself, else one of the project's others."""

    def __init__(self, own: _Index, others: list[Path]):
        self.own, self.others, self._names = own, others, None

    def _owner(self, name: str) -> _Index | None:
        if not self.others:  # (yours: what it doesn't define isn't a table of its own)
            return None
        if self._names is None:
            self._names = _names(tuple(self.others))
        path = self._names.get(name)
        return _index(path) if path else None

    def find(self, idx: _Index, ref: Ref) -> tuple[_Index, int, int] | None:
        """(object, section, offset) a reference stands for."""
        if (hit := idx.place(ref)) is not None:
            return idx, hit[0], hit[1]
        owner = self._owner(ref[1]) if ref[0] == "sym" else None
        if owner is None or (hit := owner.place(ref)) is None:
            return None
        return owner, hit[0], hit[1]

    def code(self, idx: _Index, ref: Ref) -> tuple[str, int] | None:
        """(function, offset in it) a reference into code stands for."""
        if ref[0] == "sym" and ref[1] in idx.functions:  # (the function itself, by name, from a data object)
            return ref[1], ref[2]
        if ref[0] == "sym" and ref[1] not in idx.defined:
            if owner := self._owner(ref[1]):
                if ref[1] in owner.functions:
                    return ref[1], ref[2]
                idx = owner
        hit = idx.place(ref)
        if hit is None or hit[0] not in idx.code_secs:
            return None
        return idx.function_at(*hit)


def tables(idx: _Index, name: str, others: list[Path] = ()) -> list[tuple[int, tuple[int, ...]]] | None:
    """(where the code loads it, its entries as offsets in the function) for each of a function's jump tables,
    in the order its code loads them; None when the object doesn't define the function."""
    found = idx.functions.get(name)
    if found is None:
        return None
    shndx, start, size = found
    res = _Resolver(idx, list(others))

    def entry(obj: _Index, sec: int, pos: int) -> int | None:
        ref = obj.words.get(sec, {}).get(pos)
        hit = res.code(obj, ref) if ref else None
        return hit[1] if hit and hit[0] == name and 0 <= hit[1] < size else None

    starts: dict[tuple[int, int, int], tuple[_Index, int]] = {}  # (object, section, offset) -> (object, loaded at)
    for off, ref in idx.loads.get(shndx, []):
        if not start <= off < start + size:
            continue
        hit = res.find(idx, ref)
        if hit is None or hit[1] in hit[0].code_secs:
            continue
        obj, sec, at = hit
        key = (id(obj), sec, at)
        if key not in starts and entry(obj, sec, at) is not None:
            starts[key] = (obj, off - start)
    out = []
    for (_, sec, at), (obj, loaded) in sorted(starts.items(), key=lambda kv: kv[1][1]):
        entries, pos = [], at
        while (e := entry(obj, sec, pos)) is not None:
            entries.append(e)
            pos += 4
            if (id(obj), sec, pos) in starts or (sec, pos) in obj.data_starts:  # the next table starts here
                break
        if len(entries) >= 2:  # (a switch with a table has cases; one word into the function is its vtable's)
            out.append((loaded, tuple(entries)))
    return out


_CACHE: dict[Path, tuple[tuple[int, int], _Index | None]] = {}
_NAMES: dict[tuple, dict[str, Path]] = {}  # objects -> name -> the object defining it


def _index(path: Path) -> _Index | None:
    """An object's index, read again only when the file changed (a game's own objects never do)."""
    try:
        st = path.stat()
    except OSError:
        return None
    key = (st.st_mtime_ns, st.st_size)
    hit = _CACHE.get(path)
    if hit and hit[0] == key:
        return hit[1]
    try:
        made = _Index(path.read_bytes())
    except (OSError, ValueError, ELFError, KeyError, AttributeError):  # COFF (PC, Xbox) or an unusual object
        made = None
    _CACHE[path] = (key, made)
    return made


def _names(paths: tuple[Path, ...]) -> dict[str, Path]:
    """Which of the objects defines each global name, read once per set of objects: the game's own, which don't
    change. (A few sets are kept, and your object never asks: with one kept, the original's lookups and yours
    took turns and rebuilt it for every function, and a pass over a GameCube game's 2,082 matches took 23 seconds
    rather than 2.)"""
    if paths not in _NAMES:
        out: dict[str, Path] = {}
        for p in paths:
            if (idx := _index(Path(p))) is not None:
                for name in idx.defined:
                    out.setdefault(name, Path(p))
        if len(_NAMES) >= 4:  # (a few projects' sets)
            _NAMES.pop(next(iter(_NAMES)))
        _NAMES[paths] = out
    return _NAMES[paths]


def conflicts(target: Path, base: Path, symbol: str, others: list[Path] = ()) -> list[TableConflict]:
    """The function's jump tables that send cases elsewhere than the original's (`target`: the original's object,
    `base`: yours; `others`: the project's other original objects, which may hold the original's tables). Only
    for a function whose instructions match: offsets in it are then the same code."""
    try:
        left, right = _index(Path(target)), _index(Path(base))
        if left is None or right is None or left.machine != right.machine:
            return []
        theirs, yours = tables(left, symbol, others), tables(right, symbol)
    except Exception:  # an unusual object: no verdict rather than a wrong one
        return []
    # Tables are paired by the instruction that loads them; a table nothing resolves leaves the lists unequal,
    # and no verdict.
    if not theirs or yours is None or [at for at, _ in theirs] != [at for at, _ in yours]:
        return []
    out = []
    for k, ((at, a), (_, b)) in enumerate(zip(theirs, yours)):
        if a != b:
            n = max(len(a), len(b))
            a, b = a + (None,) * (n - len(a)), b + (None,) * (n - len(b))
            out.append(TableConflict(k, at, [(i, a[i], b[i]) for i in range(n) if a[i] != b[i]]))
    return out


def subtract(units: list[dict], paths: dict[str, tuple[Path, Path]], others: list[Path]) -> tuple[
        int, int, dict[str, tuple[int, int]]]:
    """Mark a report's 100% functions whose jump tables differ as 99.99 (`paths`: unit name -> (original's object,
    yours); `others`: every original object of the project). Returns the functions and code taken off in all, and
    per unit."""
    fns = code = 0
    per: dict[str, tuple[int, int]] = {}
    for unit in units:
        pair = paths.get(unit.get("name"))
        if pair is None or not pair[0].is_file() or not pair[1].is_file():
            continue
        u_fns = u_code = 0
        for f in unit.get("functions", []):
            if float(f.get("fuzzy_match_percent") or 0) < 100.0 or not f.get("name"):
                continue
            if conflicts(pair[0], pair[1], f["name"], others):
                f["fuzzy_match_percent"] = 99.99
                u_fns, u_code = u_fns + 1, u_code + int(f.get("size") or 0)
        if u_fns:
            per[unit["name"]] = (u_fns, u_code)
            fns, code = fns + u_fns, code + u_code
    return fns, code, per
