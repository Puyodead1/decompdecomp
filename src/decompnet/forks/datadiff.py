"""A file's data next to the original's: what still keeps it from being linked once its functions match.

A file links when its whole object is the original's: every function, and every data section (constants the
compiler pools, strings, tables, globals) with the same values in the same order. The compiler emits most of it from
the functions (their literals, in the order the functions use them), so once every function matches, what's left is
the data written by hand: globals and statics in the right section and order, with the original's values.
Both objects are read directly; values are shown decoded (float, double, string) and compared in order. Words a
relocation fills in (pointers) are compared by what they point at being data of the same kind, not by address.
"""

from __future__ import annotations

import difflib
import struct
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

_SKIP = (".comment", ".note", ".debug", ".line", ".mwcats", ".gnu", ".reginfo", ".mdebug", ".pdr", ".MIPS")
PADDING = 32  # zero bytes at a data section's end the linker's alignment may add before the next file's


@dataclass
class Item:
    name: str
    data: bytes | None  # None: .bss (only a size)
    size: int
    pointers: tuple[int, ...] = ()  # offsets of relocated words in it

    def key(self) -> tuple:
        if self.data is None:
            return ("bss", self.size)
        data = bytearray(self.data)
        for at in self.pointers:
            data[at:at + 4] = b"PTR!"
        return (bytes(data),)


@dataclass
class Section:
    name: str
    original: list[Item]
    yours: list[Item] | None  # None: your object has no such section
    rows: list[tuple[str, Item | None, Item | None]] = field(default_factory=list)  # (mark, original, yours)

    @property
    def matches(self) -> bool:
        return self.yours is not None and all(m == " " for m, _, _ in self.rows)


def _items(path: Path) -> dict[str, list[Item]]:
    elf = ELFFile(BytesIO(path.read_bytes()))
    out: dict[str, list[Item]] = {}
    symtab = elf.get_section_by_name(".symtab")
    relocs: dict[int, list[int]] = {}
    for rs in elf.iter_sections():
        if isinstance(rs, RelocationSection):
            relocs.setdefault(rs["sh_info"], []).extend(r["r_offset"] for r in rs.iter_relocations())
    for idx, sec in enumerate(elf.iter_sections()):
        flags = sec["sh_flags"]
        if not sec.name or sec.name.startswith(_SKIP) or not flags & 0x2 or flags & 0x4:  # allocated, not code
            continue
        if sec["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS") or not sec["sh_size"]:
            continue
        nobits = sec["sh_type"] == "SHT_NOBITS"
        data = b"" if nobits else sec.data()
        syms = sorted({s["st_value"]: s for s in (symtab.iter_symbols() if symtab else [])
                       if s["st_shndx"] == idx and s["st_info"]["type"] not in ("STT_SECTION", "STT_FILE")
                       and s.name and not s.name.startswith("$")}.items())
        starts = [v for v, _ in syms]
        if not starts or starts[0] != 0:
            starts = [0, *starts]
            syms = [(0, None), *syms]
        items = []
        for k, (value, s) in enumerate(syms):
            end = starts[k + 1] if k + 1 < len(starts) else sec["sh_size"]
            size = (s["st_size"] if s is not None and s["st_size"] else end - value)
            size = max(0, min(size, sec["sh_size"] - value))
            if not size:
                continue
            name = s.name if s is not None else f"{sec.name}+0x{value:X}"
            ptrs = tuple(r - value for r in relocs.get(idx, []) if value <= r < value + size)
            items.append(Item(name, None if nobits else data[value:value + size], size, ptrs))
            if not nobits and end > value + size and any(data[value + size:end]):  # bytes no symbol covers
                items.append(Item(f"{sec.name}+0x{value + size:X}", data[value + size:end], end - value - size))
        out.setdefault(sec.name, []).extend(items)
    return out


def _padding(item: Item) -> bool:
    """Alignment the original's split names (gap_...) or zero bytes between data: not something to write."""
    return item.data is not None and not any(item.data) and (item.name.startswith("gap_") or "+0x" in item.name)


def _layout(path: Path) -> dict[str, tuple[int, bytes | None, frozenset]]:
    """Each allocated data section of an object: (its size, its bytes (None: .bss), its relocations as (offset, type,
    what they point at)). A pointer into the object itself is its section and offset, whatever symbol it names; one
    to anything else is that thing's name."""
    elf = ELFFile(BytesIO(path.read_bytes()))
    secs = list(elf.iter_sections())
    out: dict[str, list] = {}
    for sec in secs:
        flags = sec["sh_flags"]
        if (not sec.name or sec.name.startswith(_SKIP) or not flags & 0x2 or flags & 0x4
                or sec["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS") or not sec["sh_size"]):
            continue
        out[sec.name] = [sec["sh_size"], None if sec["sh_type"] == "SHT_NOBITS" else sec.data(), set()]
    for rs in secs:
        if not isinstance(rs, RelocationSection) or (into := secs[rs["sh_info"]].name) not in out:
            continue
        symtab = elf.get_section(rs["sh_link"])
        for r in rs.iter_relocations():
            s = symtab.get_symbol(r["r_info_sym"])
            addend = r["r_addend"] if r.is_RELA() else 0
            if isinstance(s["st_shndx"], int) and 0 < s["st_shndx"] < len(secs):
                what = ("here", secs[s["st_shndx"]].name, s["st_value"] + addend)
            else:
                what = ("name", s.name, addend)
            out[into][2].add((r["r_offset"], r["r_info_type"], what))
    return {k: (size, data, frozenset(rel)) for k, (size, data, rel) in out.items()}


def same_layout(target: Path, base: Path | None) -> bool:
    """Whether your object's data is the original's byte for byte, only named or cut differently: each data section
    the same size, with the same bytes and the same pointers. A GameCube game's file whose .bss was one 1,632-byte
    variable in the project's symbols and four in its C, and one whose strings were one 72-byte label in the project
    and five literals in its C, waited as data jobs no C could finish: what links is bytes, and the link decides."""
    if base is None or not base.exists():
        return False
    known = {n for _, _, n in _functions(target)}
    if any(n not in known for _, _, n in _functions(base)):
        return False  # (a function only yours has moves all code after it: 20 files' copy of a static helper)
    theirs, yours = _layout(target), _layout(base)
    if set(theirs) != set(yours):
        return False
    for name, (size, data, rel) in theirs.items():
        mine, mdata, mrel = yours[name]
        # the original's section runs on to where the next file's starts: alignment the linker adds (a GameCube
        # game's strings, 72 bytes in the split and 68 compiled, the last 4 zeros)
        if rel != mrel or not 0 <= size - mine < PADDING:
            return False
        if data is not None and (mdata is None or data[:mine] != mdata or any(data[mine:])):
            return False
    return True


def _functions(path: Path) -> list[tuple[int, int, str]]:
    """(offset, size, name) of each function in an object's code, in order."""
    elf = ELFFile(BytesIO(path.read_bytes()))
    symtab = elf.get_section_by_name(".symtab")
    return sorted((s["st_value"], s["st_size"], s.name) for s in (symtab.iter_symbols() if symtab else [])
                  if s["st_info"]["type"] == "STT_FUNC" and isinstance(s["st_shndx"], int) and s.name)


def _pointer_lines(name: str, rel: frozenset, mrel: frozenset) -> tuple[int, list[str]]:
    """Pointers that point elsewhere in yours: (how many, what to say). Pointers into the object that all moved by
    the same amount say the code or data before them grew or shrank."""
    theirs = {at: what for at, _, what in rel}
    yours = {at: what for at, _, what in mrel}
    moved: dict[tuple[str, int], list[int]] = {}
    other = []
    for at in sorted(set(theirs) | set(yours)):
        a, b = theirs.get(at), yours.get(at)
        if a == b:
            continue
        if a and b and a[0] == b[0] == "here" and a[1] == b[1]:
            moved.setdefault((a[1], b[2] - a[2]), []).append(a[2])
        else:
            other.append(f"{name}+0x{at:X} points at {_what(a)} in the original, {_what(b)} in yours")
    lines = []
    for (sec, by), starts in sorted(moved.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"{name}: {len(starts)} pointer{'s' * (len(starts) != 1)} into {sec} point {abs(by)} bytes "
                     f"{'further' if by > 0 else 'less far'} in yours (the first to {sec}+0x{min(starts):X}): yours has "
                     f"{abs(by)} bytes {'more' if by > 0 else 'fewer'} before there")
    return sum(len(s) for s in moved.values()) + len(other), lines + other[:3]


def _what(what) -> str:
    if what is None:
        return "nothing"
    kind, sym, value = what
    return f"{sym}+0x{value:X}" if kind == "here" else sym + (f"+0x{value:X}" if value else "")


def layout(target: Path, base: Path | None) -> tuple[int, list[str]]:
    """What still differs between your object and the original's once names are set aside (same_layout's terms):
    (about how many bytes, the differences in plain words). A GameCube game's files with every function matched and
    no data left to write by name were nobody's job and never linked: strings 4-aligned in the original and packed in
    yours, tables of function pointers 56 bytes further into yours' code (a function only yours has)."""
    if base is None or not base.exists():
        return 1, ["your object hasn't been built"]
    theirs, yours = _layout(target), _layout(base)
    cost, out = 0, []
    mine_fns, their_fns = _functions(base), _functions(target)
    known = {n for _, _, n in their_fns}
    if extra := [(at, size, n) for at, size, n in mine_fns if n not in known]:
        cost += sum(size for _, size, _ in extra)
        out.append("functions only yours has (they move all code after them): "
                   + ", ".join(f"{n} ({size} bytes at 0x{at:X})" for at, size, n in extra[:5]))
    order = [n for _, _, n in mine_fns if n in known]
    if order != [n for _, _, n in their_fns if n in set(order)]:
        cost += 4
        out.append("your functions are in another order than the original's: " + ", ".join(order[:8]))
    for name in [*theirs, *(n for n in yours if n not in theirs)]:
        if name not in yours or name not in theirs:
            size = (theirs.get(name) or yours[name])[0]
            cost += size
            out.append(f"{name}: the original has {size} bytes of it, yours none" if name in theirs
                       else f"{name}: only yours has it ({size} bytes)")
            continue
        (size, data, rel), (mine, mdata, mrel) = theirs[name], yours[name]
        if size != mine:
            cost += abs(size - mine)
            padded = data is not None and mdata is not None and size > mine and data[:mine] == mdata and not any(data[mine:])
            out.append(f"{name}: {size} bytes in the original, {mine} in yours"
                       + (f" (the original's last {size - mine} are zeros: alignment the link may not add back)" if padded else ""))
        if data is not None and mdata is not None:
            at = next((i for i, (a, b) in enumerate(zip(data, mdata)) if a != b), None)
            if at is not None:
                cost += sum(a != b for a, b in zip(data[at:], mdata[at:]))
                line = (f"{name}+0x{at:X} is the first byte that differs: original {data[at:at + 8].hex(' ')}, "
                        f"yours {mdata[at:at + 8].hex(' ')}")
                zeros = len(data[at:]) - len(data[at:].lstrip(b"\0"))
                if zeros and data[at + zeros:at + zeros + 8] == mdata[at:at + 8]:
                    line += (f": the original has {zeros} zero bytes there before the same bytes as yours (it aligns "
                             "what follows, a string or table: give it the original's alignment or size)")
                out.append(line)
        if rel != mrel:
            n, lines = _pointer_lines(name, rel, mrel)
            cost += 4 * n
            out += lines
    return (max(cost, 1) if out else 0), out


def compare(target: Path, base: Path | None) -> list[Section]:
    """Every data section of the original's object, in order, next to yours."""
    theirs = _items(target)
    mine = _items(base) if base is not None and base.exists() else {}
    out = []
    for name, original in theirs.items():
        yours = mine.get(name)
        a = [i for i in original if not _padding(i)]
        b = [i for i in (yours or []) if not _padding(i)]
        rows: list[tuple[str, Item | None, Item | None]] = []
        sm = difflib.SequenceMatcher(a=[i.key() for i in a], b=[i.key() for i in b], autojunk=False)
        for op, a0, a1, b0, b1 in sm.get_opcodes():
            if op == "equal":
                rows += [(" ", x, y) for x, y in zip(a[a0:a1], b[b0:b1])]
                continue
            for k in range(max(a1 - a0, b1 - b0)):
                x = a[a0 + k] if a0 + k < a1 else None
                y = b[b0 + k] if b0 + k < b1 else None
                rows.append(("|" if x and y else "<" if x else ">", x, y))
        out.append(Section(name, original, yours, rows))
    for name, yours in mine.items():  # sections only yours has
        if name not in theirs and any(not _padding(i) for i in yours):
            rows = [(">", None, y) for y in yours if not _padding(y)]
            out.append(Section(name, [], yours, rows))
    return out


def show(item: Item | None) -> str:
    """One data item as an agent reads it in a data diff: pointers, a float, a string or bytes."""
    if item is None:
        return ""
    if item.data is None:
        return f"{item.name}: {item.size} bytes of zeros (.bss)"
    d = item.data
    if item.pointers and len(d) == 4 * len(item.pointers):
        value = f"{len(item.pointers)} pointer{'s' if len(item.pointers) > 1 else ''}"
    elif len(d) == 4 and not item.pointers:
        f = struct.unpack(">f", d)[0]
        value = f"{f!r}f" if d != b"\0\0\0\0" and 1e-6 < abs(f) < 1e9 else f"0x{d.hex().upper()}"
    elif len(d) == 8 and not item.pointers:
        f = struct.unpack(">d", d)[0]
        value = f"{f!r}" if 1e-9 < abs(f) < 1e15 else f"0x{d.hex().upper()}"
    elif d.rstrip(b"\0") and all(32 <= c < 127 or c in (9, 10, 13) or c >= 0x80 for c in d.rstrip(b"\0")):
        text = d.rstrip(b"\0").decode("latin-1").replace("\n", "\\n")
        value = '"' + (text if len(text) <= 40 else text[:40] + "…") + '"'
    else:
        value = d[:16].hex(" ") + ("…" if len(d) > 16 else "") + (f" ({len(item.pointers)} pointers)" if item.pointers else "")
    return f"{item.name} = {value}" if len(f"{item.name} = {value}") < 60 else f"{item.name[:30]}… = {value}"


def hints(sections: list[Section]) -> list[str]:
    """What the differences usually mean, said plainly."""
    out = []
    where = {i.name.split("$")[0]: s.name for s in sections for i in s.original}
    for sec in sections:
        for i in sec.yours or []:
            orig = where.get(i.name)
            if orig and orig != sec.name:
                fix = "const" if orig.startswith((".rodata", ".sdata2", ".rdata")) else f"not const ({orig})"
                out.append(f"{i.name} is in {sec.name} in yours but {orig} in the original: declare it {fix}")
        theirs = {i.name for i in sec.original}
        for i in sec.original:
            base, _, n = i.name.partition("$")
            if n.isdigit() and base in {y.name for y in sec.yours or []} and base not in theirs:
                out.append(f"the original's {base} is a static variable inside a function ({i.name}): move it into "
                           "the function that uses it")
    return list(dict.fromkeys(out))


def render(sections: list[Section], max_rows: int = 60) -> str:
    """The sections that differ: the original's data next to yours, in order."""
    lines = [f"hint: {h}" for h in hints(sections)]
    for sec in sections:
        if sec.matches:
            continue
        if sec.yours is None:
            lines.append(f"{sec.name}: yours has none of it yet ({len(sec.original)} items in the original)")
        else:
            lines.append(f"{sec.name}: differs (< the original's, missing from yours; > only yours; | different)")
        width = 44
        shown = 0
        for i, (mark, x, y) in enumerate(sec.rows):
            near = any(m != " " for m, _, _ in sec.rows[max(0, i - 1):i + 2])
            if not near:
                continue
            lines.append(f" {mark} {show(x)[:width]:<{width}} | {show(y)}")
            shown += 1
            if shown >= max_rows:
                lines.append("   ...")
                break
    return "\n".join(lines)
