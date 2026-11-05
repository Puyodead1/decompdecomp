"""What a Linux program's debug information gives its import: GCC 2.95 and egcs write STABS with -g into the
program's own .stab and .stabstr sections (not inside .mdebug, as the PS2's EE-GCC does). The entries are read here,
a compile unit at a time, and handed to the PS2 console's STABS reader (consoles/ps2/stabs.py, debuginfo.py): the
source files (the project's units), each function's prototype, parameters and locals, the globals' types and every
struct, union, enum and typedef, as C for the shared header. GCC 3 and newer (4.3: a program of 2008) write DWARF 2
or later instead (.debug_info), read by consoles/ps2/dwarf2.py into the same shapes."""

from __future__ import annotations

import logging
import re
import struct
from io import BytesIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from ..ps2 import dwarf2, stabs, symtab
from ..ps2.debuginfo import DebugInfo, _describe, _dwarf, _short_names

N_UNDF, N_FUN, N_SO = 0x00, 0x24, 0x64
N_BINCL, N_EINCL, N_EXCL = 0x82, 0xA2, 0xC2  # a header's start and end, and a header written in an earlier unit
ENTRY = 12  # n_strx (4), n_type, n_other, n_desc (2), n_value (4)
_TYPE_NUMBER = re.compile(r"\((\d+),(\d+)\)")
# GCC's numbers for the i386's registers in STABS (its dbx_register_map, with ebp and esp in that order), and the x87
# stack from 12
X86_REGISTERS = ("eax", "ecx", "edx", "ebx", "ebp", "esp", "esi", "edi")


def x86_register(number: int) -> str:
    if 0 <= number < len(X86_REGISTERS):
        return X86_REGISTERS[number]
    if 12 <= number < 20:
        return f"st({number - 12})"
    return f"register {number}"


def entries(stab: bytes, strings: bytes) -> list[tuple[str, list[tuple[int, str, int]]]]:
    """Each compile unit's source file and its STABS entries (code, string, value), GCC's continued strings (a
    trailing backslash) joined. Each unit starts with an N_UNDF entry whose value is the size of its strings.

    A type is numbered (file, index), its file counted in its unit by each N_BINCL and N_EXCL. The linker writes a
    header's entries once (N_BINCL ... N_EINCL, keyed by its name and a checksum that skips those file numbers) and
    puts an N_EXCL in each later unit that included it. As gdb does, a header's types are the header's own: every
    file number is rewritten to one number for that header in the whole program (each unit's own source another),
    and each N_EXCL brings back the header's entries, so the types it defines are there for the unit that refers to
    them by their header."""
    out: list[tuple[str, list[tuple[int, str, int]]]] = []
    ranges: dict[tuple[str, int], list[tuple[int, str, int]]] = {}  # header (name, checksum) -> its entries
    numbers: dict[tuple[str, int], int] = {}  # header, or a unit's own source -> its number in the whole program
    base = next_base = 0
    pending = ""
    unit: list[tuple[int, str, int]] | None = None
    files: list[int] = []  # this unit's file numbers -> program-wide ones
    open_ranges: list[tuple[tuple[str, int], list]] = []

    def number(key: tuple[str, int]) -> int:
        return numbers.setdefault(key, len(numbers) + 1)

    def program_wide(text: str) -> str:
        """(0, n) stays: every unit numbers the built-in types (int, char...) in its own file, in the same order."""
        def one(m):
            n = int(m.group(1))
            return m.group(0) if n == 0 or n >= len(files) else f"({files[n]},{m.group(2)})"
        return _TYPE_NUMBER.sub(one, text)

    def add(entry: tuple[int, str, int]) -> None:
        unit.append(entry)
        for _, kept in open_ranges:  # (an enclosing header's range has its nested headers in it)
            kept.append(entry)

    for k in range(len(stab) // ENTRY):
        strx, code, _, _, value = struct.unpack_from("<IBBhI", stab, k * ENTRY)
        if code == N_UNDF:
            base, next_base = next_base, next_base + value
            continue
        at = base + strx
        text = strings[at:strings.index(b"\0", at)].decode("latin-1") if strx and at < len(strings) else ""
        if code == N_SO and text and not text.endswith("/"):
            unit, open_ranges = [], []
            files = [0]
            out.append((text, unit))
            continue
        if unit is None:
            continue
        text = pending + text
        if text.endswith("\\"):
            pending = text[:-1]
            continue
        pending = ""
        if code in (N_BINCL, N_EXCL):
            files.append(number((text, value)))
        if code == N_EXCL:
            for entry in ranges.get((text, value), ()):  # the header's own entries, already program-wide
                add(entry)
            continue
        entry = (code, program_wide(text), value)
        add(entry)
        if code == N_BINCL:
            open_ranges.append(((text, value), [entry]))
        elif code == N_EINCL and open_ranges:
            key, kept = open_ranges.pop()
            ranges.setdefault(key, kept)
    return out


def read(data: bytes, reserved: set[str] = frozenset()) -> DebugInfo | None:
    """The debug information of a Linux program, or None when it has none."""
    try:
        elf = ELFFile(BytesIO(data))
        info = DebugInfo(named=symtab.read(elf), unread=_dwarf(elf))
        stab, strings = elf.get_section_by_name(".stab"), elf.get_section_by_name(".stabstr")
        units = entries(stab.data(), strings.data()) if stab is not None and strings is not None else []
    except (ELFError, ValueError, KeyError):
        return None
    try:
        if not units and dwarf2.has_dwarf(elf):  # (GCC 3 on: DWARF, no STABS)
            dwarf = dwarf2.read(elf)
            info.unread = []
            if dwarf:
                short = _short_names([source.name for source in dwarf])
                for source in dwarf:
                    source.name = short[source.name]
                    for function in source.functions:
                        info.units.setdefault(function.address, source.name)
                info.sources = sorted({source.name for source in dwarf if source.functions})
                _describe(info, dwarf, reserved, None)
        if units:
            short = _short_names([name for name, _ in units])
            sources = [stabs.read_file(short[name], found, x86_register) for name, found in units]
            for name, found in units:
                for code, text, value in found:
                    if code == N_FUN and text and value:
                        info.units.setdefault(value, short[name])
            info.sources = sorted({short[name] for name, found in units
                                   if any(code == N_FUN and text for code, text, _ in found)})
            _describe(info, sources, reserved, None)
    except Exception:  # a heuristic over the game's own data: never stands between the user and the import
        logging.getLogger("decompdecomp").exception("reading the program's debug information failed")
    if not info.named and not info.sources and not info.unread:
        return None
    return info
