"""Which data each source file of a dtk-template project owns, when splits.txt gives files only their code.

A game started from scratch has files that cover only .text: everything else (.rodata, .data, .bss, .sdata, ...)
sits in dtk's auto units (auto_06_..._rodata). objdiff then compares 0 bytes of data, so a file whose functions all
match looked finished and was linked, and its C's own constants and globals collided with the auto units' copies
(a GameCube game with 400 files: 12 tries, every one multiply defined or a checksum off). Its data has to be the
file's before the file can link, and before its data can be compared at all.

The linker lays out each section file by file in link order, so a file's data is one stretch of each section, in the
order of the files' code. Which stretch: the symbols only one file's code uses (anchors). The anchors that agree
with the code's order (the longest run of them; one out of order is a global another file defines) mark where each
file's part starts; between two files, the cut is the first symbol the next file uses and the earlier one doesn't.
The cut snaps to an aligned symbol (dtk refuses a split that starts unaligned). Data no file's code uses stays with
the file before it, as the linker put it. The engine keeps the result only if the game still builds byte for byte.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from pathlib import Path

from decompnet.forks.dtksplits import FileSplit

DATA = (".rodata", ".data", ".bss", ".sdata", ".sbss", ".sdata2", ".sbss2")
ALIGN = 8  # (dtk's alignment for a data split: "Invalid alignment for split" at 0x803C6F04, a .sbss cut 4 bytes off)


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


def parts(files: list[FileSplit], syms: dict[str, tuple[str, int, int]], uses: dict[str, set[str]],
          skip: set[str] = frozenset(), sections=DATA) -> dict[str, dict[str, tuple[int, int]]]:
    """{file: {section: (start, end)}}: the data to give each file that covers code.

    files: splits.txt's files; syms: symbols.txt (name -> (section, address, size)); uses: file -> the symbols its
    code refers to (its original object's relocations); skip: files that get nothing (linked ones: their objects are
    built from their C, which defines its own data)."""
    texts = sorted((f for f in files if ".text" in f.sections), key=lambda f: f.sections[".text"][0])
    rank = {f.name: i for i, f in enumerate(texts)}
    used_by: dict[str, set[str]] = defaultdict(set)
    for f in texts:
        for s in uses.get(f.name, ()):
            used_by[s].add(f.name)
    out: dict[str, dict[str, tuple[int, int]]] = defaultdict(dict)
    for section in sections:
        owned = [f.sections[section] for f in files if section in f.sections]
        items = sorted((a, a + max(size, 1), n) for n, (sec, a, size) in syms.items() if sec == section)
        items = [it for it in items if not any(lo <= it[0] < hi for lo, hi in owned)]
        anchors = [(i, next(iter(used_by[n]))) for i, (_, _, n) in enumerate(items) if len(used_by[n]) == 1]
        runs: list[list] = []  # [file, first item, last item]
        for i, f in _in_order(anchors, rank):
            if runs and runs[-1][0] == f:
                runs[-1][2] = i
            else:
                runs.append([f, i, i])
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
                cut = next((j for j in range(last + 1, nfirst)
                            if nxt in used_by[items[j][2]] and f not in used_by[items[j][2]]), nfirst)
                if items[cut][0] % ALIGN:  # the aligned cut nearest the rule's, in the gap
                    gap = [j for j in range(last + 1, nfirst + 1) if items[j][0] % ALIGN == 0]
                    if gap:
                        cut = min(gap, key=lambda j: (abs(j - cut), -j))
                    else:  # (the two can't be told apart: the next file gets no part of this section)
                        runs[n + 1][0] = None
                end_i = cut - 1
                runs[n + 1][1] = cut
            start = items[first][0]
            end = items[end_i + 1][0] if end_i + 1 < len(items) else items[end_i][1]
            if f is None or f in skip or end <= start or any(lo < end and start < hi for lo, hi in owned):
                continue
            out[f][section] = (start, end)
    return dict(out)


def apply(header: str, files: list[FileSplit], given: dict[str, dict[str, tuple[int, int]]]) -> int:
    """Give the files their parts, each file's sections in the Sections: block's order (dtk wants that order); the
    number of files that got any."""
    order = [line.split()[0] for line in header.splitlines()[1:] if line.strip()]
    n = 0
    for f in files:
        if not given.get(f.name):
            continue
        n += 1
        f.sections.update(given[f.name])
        f.sections = dict(sorted(f.sections.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else len(order)))
    return n
