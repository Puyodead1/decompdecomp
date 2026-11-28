"""What a dtk-template project's config must say for a file to link from its C where its assembly linked (#ADDON 5):

- **force_active**: a function nothing refers to stays in the game while its file is assembled from the split, but
  the linker drops it once the file is compiled: mwld strips what nothing references unless config.yml lists it under
  `force_active:` (the linker script's FORCEACTIVE; a `force_active` attribute in symbols.txt never reaches it). A
  GameCube game's debugger file lost two functions nothing calls so, and its game no longer built byte for byte.
  Every function in the game was kept by something, so a function no relocation anywhere points at needs it.
- **alignment**: a split's data section runs to where the next file's starts, alignment padding included. Compiled,
  the file ends where its last variable does, and the next file (still assembled) starts at its own section's
  alignment: dtk's 8 unless a symbol in it asks for more (split.rs). The OS's error file ended 0x10 bytes short of the
  reboot file's 32-byte aligned buffer, and every later .bss symbol moved by -0x10: `align:32` on that symbol in
  symbols.txt is what the original's C said (ATTRIBUTE_ALIGN(32)).

Padding arrays (`gap_...`) written in the C to fill the layout instead are the other way round, and wrong: the tidy
pass removes them (forks/cleanup.py, `without_gaps`). The engine (ForkEngine.link) applies these with the files it
links and keeps them only for the files that then link, the checksum deciding.
"""

from __future__ import annotations

import json
import re
from bisect import bisect_left, bisect_right
from collections.abc import Iterable
from io import BytesIO
from pathlib import Path

import yaml
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

DEFAULT_ALIGN = 8  # dtk's for a data section (default_section_align): what an assembled split starts aligned to
MOST_ALIGN = 64  # the most a variable asks for (ATTRIBUTE_ALIGN(32) for the hardware's buffers; 64 is .bss's own)
DATA = (".rodata", ".data", ".bss", ".sdata", ".sbss", ".sdata2", ".sbss2")
_SYMBOL = re.compile(r"^(\S+)\s*=\s*(\.\w+):0x([0-9A-Fa-f]+);(.*)$")


def _sext(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _branches(code: bytes, relocated: set[int]) -> list[tuple[int, int]]:
    """(where, target) of each PowerPC branch in this code the assembler resolved itself (no relocation): a call to
    a function in the same object has none."""
    out = []
    for at in range(0, len(code) - 3, 4):
        if at in relocated:
            continue
        word = int.from_bytes(code[at:at + 4], "big")
        op = word >> 26
        if op == 18 and not word & 2:  # b, bl
            out.append((at, at + _sext(word & 0x03FFFFFC, 26)))
        elif op == 16 and not word & 2:  # bc, bcl
            out.append((at, at + _sext(word & 0xFFFC, 16)))
    return out


class _Functions:
    """An object's functions in one section, by address: which one a place is in."""

    def __init__(self, spans: list[tuple[int, int, str]]):
        self.spans = sorted(spans)
        self.starts = [lo for lo, _, _ in self.spans]

    def at(self, address: int) -> str | None:
        i = bisect_right(self.starts, address) - 1
        if i < 0:
            return None
        lo, hi, name = self.spans[i]
        return name if lo <= address < hi or lo == address else None


def _refers_to(elf: ELFFile) -> set[str]:
    """What one object refers to (references())."""
    secs = list(elf.iter_sections())
    tab = next((s for s in secs if isinstance(s, SymbolTableSection)), None)
    if tab is None:
        return set()
    spans: dict[int, list[tuple[int, int, str]]] = {}
    for s in tab.iter_symbols():
        if s.name and s["st_info"]["type"] == "STT_FUNC" and isinstance(s["st_shndx"], int):
            spans.setdefault(s["st_shndx"], []).append((s["st_value"], s["st_value"] + s["st_size"], s.name))
    out: set[str] = set()
    relocated: dict[int, set[int]] = {}
    for rs in secs:
        if not isinstance(rs, RelocationSection) or rs["sh_link"] >= len(secs):
            continue
        into = rs["sh_info"]
        for r in rs.iter_relocations():
            relocated.setdefault(into, set()).add(r["r_offset"])
            s = tab.get_symbol(r["r_info_sym"])
            if s.name and not (s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == into
                               and s["st_value"] <= r["r_offset"] < s["st_value"] + s["st_size"]):
                out.add(s.name)
    for index, sec in enumerate(secs):
        if sec["sh_flags"] & 0x4 and sec["sh_type"] == "SHT_PROGBITS" and index in spans:
            funcs = _Functions(spans[index])
            for at, to in _branches(sec.data(), relocated.get(index, set())):
                if (name := funcs.at(to)) and name != funcs.at(at):
                    out.add(name)
    return out


def references(objects: Iterable[Path]) -> set[str]:
    """The names these objects refer to: what relocations point at, from any section (code, a vtable, a constructor
    list), and the functions branches inside one object reach (the assembler leaves those no relocation); except a
    function's own call to itself: that keeps nothing in the game."""
    out: set[str] = set()
    for path in objects:
        try:
            out |= _refers_to(ELFFile(BytesIO(Path(path).read_bytes())))
        except Exception:  # (an object that isn't ELF, or a broken one: it refers to nothing we can tell)
            continue
    return out


def unreferenced(obj: Path, refs: set[str]) -> list[str]:
    """The global functions this object defines that nothing refers to (refs: references() of the whole game). A
    reference to a label inside a function keeps the function: the runtime's register saves are called at
    `_savegpr_14`...`_savegpr_31`, never by their own name."""
    try:
        elf = ELFFile(BytesIO(Path(obj).read_bytes()))
    except Exception:
        return []
    funcs, used = [], []
    for tab in (s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)):
        for s in tab.iter_symbols():
            if not s.name or not isinstance(s["st_shndx"], int) or s["st_shndx"] <= 0:
                continue
            if s.name in refs:
                used.append((s["st_shndx"], s["st_value"]))
            elif (s["st_info"]["type"] == "STT_FUNC" and s["st_info"]["bind"] == "STB_GLOBAL"
                  and not s.name.startswith("gap_")):  # (dtk's label for padding between functions)
                funcs.append((s["st_shndx"], s["st_value"], s["st_value"] + max(s["st_size"], 1), s.name))
    at: dict[int, list[int]] = {}
    for index, address in sorted(used):
        at.setdefault(index, []).append(address)
    return sorted({name for index, lo, hi, name in funcs
                   if (i := bisect_left(at.get(index, []), lo)) >= len(at.get(index, [])) or at[index][i] >= hi})


def linked_objects(build: Path) -> list[Path] | None:
    """Every object dtk links into the game, the program's and each REL's (build/<version>/config.json), auto units
    too; None without it. Only these: an object left in obj/ from before a split refers to things nothing links
    (#ADDON 8)."""
    try:
        cfg = json.loads((build / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    root = build.parent.parent
    out = []
    for part in [cfg, *(cfg.get("modules") or [])]:
        out += [root / u["object"] for u in part.get("units") or [] if u.get("object")]
    return out


def force_active(text: str) -> list[str]:
    """config.yml's force_active: list."""
    try:
        cfg = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return []
    return [str(n) for n in cfg.get("force_active") or []] if isinstance(cfg, dict) else []


def with_force_active(text: str, names: Iterable[str]) -> str:
    """config.yml with these names in its force_active: list too, the rest of it (comments, order) as written."""
    have = force_active(text)
    new = [n for n in dict.fromkeys(names) if n not in have]
    if not new:
        return text
    lines = text.splitlines()
    at = next((i for i, line in enumerate(lines) if re.match(r"force_active\s*:", line)), None)
    if at is None:
        return text.rstrip("\n") + "\nforce_active:\n" + "".join(f"- {n}\n" for n in new)
    end = at + 1
    while end < len(lines) and (lines[end].startswith((" ", "\t", "-")) or not lines[end].strip()):
        end += 1
    while end > at + 1 and not lines[end - 1].strip():
        end -= 1
    item = next((re.match(r"[ \t]*-[ \t]*", line).group() for line in lines[at + 1:end]
                 if re.match(r"[ \t]*-", line)), "- ")  # (the list's own indent)
    block = ["force_active:", *(f"{item}{n}" for n in [*have, *new])]
    return "\n".join([*lines[:at], *block, *lines[end:]]) + "\n"


def _align_up(x: int, a: int) -> int:
    return (x + a - 1) & -a


def _rows(text: str) -> list[tuple[int, str, int, int, int]]:
    """symbols.txt as (line, section, address, size, align: 0 when it says none)."""
    out = []
    for i, line in enumerate(text.splitlines()):
        if m := _SYMBOL.match(line):
            size = re.search(r"\bsize:0x([0-9A-Fa-f]+)", m.group(4))
            align = re.search(r"\balign:(\d+)", m.group(4))
            out.append((i, m.group(2), int(m.group(3), 16), int(size.group(1), 16) if size else 0,
                        int(align.group(1)) if align else 0))
    return out


def split_align(text: str, section: str, start: int, end: int) -> int:
    """The alignment dtk gives an assembled split's section starting at `start` (split.rs): the most any of its
    symbols asks for, at least 8, halved down to 4 while `start` isn't aligned to it."""
    align = max([DEFAULT_ALIGN, *(a for _, sec, at, size, a in _rows(text) if sec == section and start <= at < end
                                  and size and a)])
    while align > 4 and start % align:
        align //= 2
    return align


def needed_align(end: int, start: int, now: int) -> int | None:
    """The alignment a section starting at `start` needs, after a file's that ends at `end`, to stay there: None when
    the one it has (now) keeps it there, or no alignment up to MOST_ALIGN does (the gap isn't padding then)."""
    if end > start or _align_up(end, now) == start:
        return None
    align = now * 2
    while align <= MOST_ALIGN:
        if start % align == 0 and _align_up(end, align) == start:
            return align
        align *= 2
    return None


def with_align(text: str, section: str, address: int, align: int) -> tuple[str, str] | None:
    """symbols.txt with `align:N` on the symbol that starts the section at this address (its name too); None when no
    symbol with a size starts there."""
    lines = text.splitlines(keepends=True)
    for i, sec, at, size, have in _rows(text):
        if sec == section and at == address and size:
            if have >= align:
                return None
            line = lines[i]
            body, nl = line.rstrip("\r\n"), line[len(line.rstrip("\r\n")):]
            body = (re.sub(r"\balign:\d+", f"align:{align}", body) if have
                    else body + (" " if "//" in body else " // ") + f"align:{align}")
            lines[i] = body + nl
            return "".join(lines), _SYMBOL.match(body).group(1)
    return None


def sections(obj: Path) -> dict[str, tuple[int, bytes | None]]:
    """An object's data sections: (size, bytes; None for .bss)."""
    elf = ELFFile(BytesIO(Path(obj).read_bytes()))
    return {s.name: (s["sh_size"], None if s["sh_type"] == "SHT_NOBITS" else s.data()) for s in elf.iter_sections()
            if s.name in DATA and s["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS")}


def short_ends(target: Path, base: Path) -> dict[str, int]:
    """{section: bytes} for each data section the compiled object (base) has shorter than the original's split
    (target) by zeros only at its end: padding the split had and the C doesn't, which the next file's alignment must
    make up for."""
    theirs, yours = sections(target), sections(base)
    out = {}
    for name, (size, data) in theirs.items():
        if name not in yours:
            continue
        mine, _ = yours[name]
        if 0 < size - mine < MOST_ALIGN and (data is None or not any(data[mine:])):
            out[name] = size - mine
    return out
