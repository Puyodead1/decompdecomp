"""Which data each source file of a dtk-template project owns, when splits.txt gives files only their code.

A game started from scratch has files that cover only .text: everything else (.rodata, .data, .bss, .sdata, ...)
sits in dtk's auto units (auto_06_..._rodata). objdiff then compares 0 bytes of data, so a file whose functions all
match looked finished and was linked, and its C's own constants and globals collided with the auto units' copies
(a GameCube game: 12 tries, every one multiply defined or a checksum off). Its data has to be the
file's before the file can link, and before its data can be compared at all.

The linker lays out each section file by file in link order, so a file's data is one stretch of each section, in the
order of the files' code. Which stretch: the symbols only one file's code uses (anchors). The anchors that agree
with the code's order (the longest run of them; one out of order is a global another file defines) mark where each
file's part starts; between two files, the cut is the first symbol the next file uses and the earlier one doesn't.
The cut snaps to an aligned symbol (dtk refuses a split that starts unaligned). Data no file's code uses stays with
the file before it, as the linker put it. The engine keeps the result only if the game still builds byte for byte.

A symbol is known by its address, not its name: dtk names another file's local symbol name_<address> in the objects
that refer to it, and MWCC's local names (@84, lbl_...) repeat from file to file. Read by name, a GameCube game's OS
strings looked used by no code and stayed with the game file before them (ADDON 5 §1).
"""

from __future__ import annotations

import bisect
import re
from collections import defaultdict
from pathlib import Path

from decompnet.forks.dtksplits import FileSplit

DATA = (".rodata", ".data", ".bss", ".sdata", ".sbss", ".sdata2", ".sbss2")
ALIGN = 4  # (dtk takes a data split that starts 4-aligned: it wants 8, warns, and halves down to 4, split.rs)
_AT = re.compile(r"(.+)_([0-9A-Fa-f]{8})")


def code_refs(obj: Path) -> set[str]:
    """The symbols an object's code refers to (every relocation in its .text: a symbol the object defines too, since
    dtk's split objects define data that only their code uses)."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    out = set()
    with obj.open("rb") as f:
        elf = ELFFile(f)
        tab = elf.get_section_by_name(".symtab")
        if tab is None:
            return out
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection) and sec.name.startswith(".rela.text"):
                for r in sec.iter_relocations():
                    name = tab.get_symbol(r["r_info_sym"]).name
                    if name:
                        out.add(name)
    return out


def _in_order(anchors: list[tuple[int, str]], rank: dict[str, int]) -> list[tuple[int, str]]:
    """The longest run of anchors whose files come in code order (non-decreasing)."""
    seq = [rank[f] for _, f in anchors]
    tails: list[int] = []
    tail_at: list[int] = []
    prev = [-1] * len(seq)
    for k, x in enumerate(seq):
        j = bisect.bisect_right(tails, x)
        if j == len(tails):
            tails.append(x)
            tail_at.append(k)
        else:
            tails[j] = x
            tail_at[j] = k
        prev[k] = tail_at[j - 1] if j else -1
    keep = []
    k = tail_at[-1] if tail_at else -1
    while k >= 0:
        keep.append(anchors[k])
        k = prev[k]
    return keep[::-1]


Row = tuple[str, str, int, int]  # (name, section, address, size): one line of symbols.txt


def _rows(syms) -> list[Row]:
    """symbols.txt as rows: from a {name: (section, address, size)} or from a list of rows (dtksplits.symbol_rows,
    which keeps the local names that repeat)."""
    return [(n, *v) for n, v in syms.items()] if isinstance(syms, dict) else list(syms)


def resolver(rows: list[Row]):
    """name -> address, for a name an object's relocation gives: name_<address> as dtk writes another file's local
    symbol, or a name only one symbol has (a repeated local name says nothing about which one)."""
    by_name: dict[str, list[int]] = defaultdict(list)
    for n, _, a, _ in rows:
        by_name[n].append(a)
    at = {(n, a) for n, _, a, _ in rows}

    def address(ref: str) -> int | None:
        if (m := _AT.fullmatch(ref)) and (m.group(1), int(m.group(2), 16)) in at:
            return int(m.group(2), 16)
        found = by_name.get(ref, ())
        return found[0] if len(set(found)) == 1 else None
    return address


def _fits(fences: list[tuple[int, int]], address: int, rank: int) -> bool:
    """Whether a file of this rank in code order can own data here, between the kept parts around it ((start, rank),
    in address order)."""
    k = bisect.bisect_left(fences, (address, -1))
    return (k == 0 or fences[k - 1][1] <= rank) and (k == len(fences) or rank <= fences[k][1])


def parts(files: list[FileSplit], syms, uses: dict[str, set[str]],
          skip: set[str] = frozenset(), sections=DATA) -> dict[str, dict[str, tuple[int, int]]]:
    """{file: {section: (start, end)}}: the data to give each file that covers code.

    files: splits.txt's files; syms: symbols.txt (name -> (section, address, size), or rows); uses: file -> the
    symbols its code refers to (its original object's relocations); skip: files that get nothing (linked ones: their
    objects are built from their C, which defines its own data)."""
    rows = _rows(syms)
    texts = sorted((f for f in files if ".text" in f.sections), key=lambda f: f.sections[".text"][0])
    rank = {f.name: i for i, f in enumerate(texts)}
    address = resolver(rows)
    used_by: dict[int, set[str]] = defaultdict(set)
    for f in texts:
        for ref in uses.get(f.name, ()):
            if (a := address(ref)) is not None:
                used_by[a].add(f.name)
    out: dict[str, dict[str, tuple[int, int]]] = defaultdict(dict)
    for section in sections:
        owned = [f.sections[section] for f in files if section in f.sections]
        # a file that keeps its part (a linked one) fixes the order around it: before its part, only the files before
        # it in code order; after it, only those after (a GameCube game's vtable before a linked file's .data, used by
        # a later file, made that later file's part start there and end at the linked one's: it lost the rest)
        fences = sorted((f.sections[section][0], rank[f.name]) for f in files if section in f.sections and f.name in rank)
        starts: dict[int, int] = {}
        for _, sec, a, size in rows:
            if sec == section:
                starts[a] = max(starts.get(a, 0), a + max(size, 1))
        items = [(a, end) for a, end in sorted(starts.items()) if not any(lo <= a < hi for lo, hi in owned)]
        users = [used_by[a] for a, _ in items]
        anchors = [(i, next(iter(u))) for i, u in enumerate(users) if len(u) == 1]
        anchors = [(i, f) for i, f in anchors if _fits(fences, items[i][0], rank[f])]
        runs: list[list] = []  # [file, first item, last item]
        for i, f in _in_order(anchors, rank):
            if runs and runs[-1][0] == f:
                runs[-1][2] = i
            else:
                runs.append([f, i, i])
        if runs:  # what comes before the first part is its file's too: no file before it has this section (or what's
            # before is a kept part's): a GameCube game's first .sbss variable, used by no code, stayed in dtk's auto unit
            fence = max([hi for lo, hi in owned if hi <= items[runs[0][1]][0]], default=0)
            runs[0][1] = next(j for j in range(runs[0][1] + 1) if items[j][0] >= fence)
        if runs and items[runs[0][1]][0] % ALIGN:  # the first part starts at an aligned symbol before it, else after
            first, last = runs[0][1], runs[0][2]
            back = [j for j in range(first, -1, -1) if items[j][0] % ALIGN == 0]
            ahead = [j for j in range(first, last + 1) if items[j][0] % ALIGN == 0]
            if back or ahead:
                runs[0][1] = (back or ahead)[0]
            else:
                runs[0][0] = None
        for n, (f, first, last) in enumerate(runs):
            end_i = last
            if n + 1 < len(runs):
                nxt, nfirst = runs[n + 1][0], runs[n + 1][1]
                cut = next((j for j in range(last + 1, nfirst) if nxt in users[j] and f not in users[j]), nfirst)
                # (not before a part kept between the two: what's before it is the earlier file's)
                fence = max([hi for lo, hi in owned if items[last][0] < lo and hi <= items[nfirst][0]], default=0)
                cut = next(j for j in range(cut, nfirst + 1) if items[j][0] >= fence)
                if items[cut][0] % ALIGN:  # the aligned cut nearest the rule's, in the gap
                    gap = [j for j in range(last + 1, nfirst + 1) if items[j][0] % ALIGN == 0 and items[j][0] >= fence]
                    if gap:
                        cut = min(gap, key=lambda j: (abs(j - cut), -j))
                    else:  # (the two can't be told apart: the next file gets no part of this section)
                        runs[n + 1][0] = None
                end_i = cut - 1
                runs[n + 1][1] = cut
            start = items[first][0]
            end = items[end_i + 1][0] if end_i + 1 < len(items) else items[end_i][1]
            # a part ends where a file that keeps its data starts (a linked file's part sits between the two items)
            end = min([lo for lo, _ in owned if start < lo < end] + [end])
            if f is None or f in skip or end <= start or any(lo < end and start < hi for lo, hi in owned):
                continue
            out[f][section] = (start, end)
    return dict(out)


def apply(header: str, files: list[FileSplit], given: dict[str, dict[str, tuple[int, int]]],
          again: bool = False) -> int:
    """Give the files their parts, each file's sections in the Sections: block's order (dtk wants that order); the
    number of files that got any. again: the parts replace the data each of those files had (an empty one: it has
    none now)."""
    order = [line.split()[0] for line in header.splitlines()[1:] if line.strip()]
    n = 0
    for f in files:
        if f.name not in given or not (given[f.name] or again):
            continue
        n += 1
        if again:
            f.sections = {k: v for k, v in f.sections.items() if k not in DATA}
        f.sections.update(given[f.name])
        f.sections = dict(sorted(f.sections.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else len(order)))
    return n


def again(files: list[FileSplit], syms, uses: dict[str, set[str]], fixed: set[str]) -> dict[str, dict]:
    """{file: its data now}: each file's part worked out again, for the files whose part changes. A part given
    before (by an older rule, or before a file was split: the split's new file got none of the data its code uses)
    goes to the file whose code uses it. fixed: files that keep what they have (linked ones, and those a change was
    refused for)."""
    movable = {f.name for f in files if ".text" in f.sections and f.name not in fixed}
    bare = [FileSplit(f.name, {k: v for k, v in f.sections.items() if k not in DATA} if f.name in movable
                      else dict(f.sections)) for f in files]
    given = parts(bare, syms, uses, skip=set(fixed))
    out = {}
    for f in files:
        if f.name in movable:
            now = {k: v for k, v in f.sections.items() if k in DATA}
            if now != given.get(f.name, {}):
                out[f.name] = given.get(f.name, {})
    return out
