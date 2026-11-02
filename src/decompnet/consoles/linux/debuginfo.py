"""What a Linux program's debug information gives its import: GCC 2.95 and egcs write STABS with -g into the
program's own .stab and .stabstr sections (not inside .mdebug, as the PS2's EE-GCC does). The entries are read here,
a compile unit at a time, and handed to the PS2 console's STABS reader (consoles/ps2/stabs.py, debuginfo.py): the
source files (the project's units), each function's prototype, parameters and locals, the globals' types and every
struct, union, enum and typedef, as C for the shared header."""

from __future__ import annotations

import logging
import struct
from io import BytesIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from ..ps2 import stabs, symtab
from ..ps2.debuginfo import DebugInfo, _describe, _dwarf, _short_names

N_UNDF, N_FUN, N_SO = 0x00, 0x24, 0x64
ENTRY = 12  # n_strx (4), n_type, n_other, n_desc (2), n_value (4)
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
    trailing backslash) joined. Each unit starts with an N_UNDF entry whose value is the size of its strings."""
    out: list[tuple[str, list[tuple[int, str, int]]]] = []
    base = next_base = 0
    pending = ""
    current: list[tuple[int, str, int]] | None = None
    for k in range(len(stab) // ENTRY):
        strx, code, _, _, value = struct.unpack_from("<IBBhI", stab, k * ENTRY)
        if code == N_UNDF:
            base, next_base = next_base, next_base + value
            continue
        at = base + strx
        text = strings[at:strings.index(b"\0", at)].decode("latin-1") if strx and at < len(strings) else ""
        if code == N_SO and text and not text.endswith("/"):
            current = []
            out.append((text, current))
            continue
        if current is None:
            continue
        text = pending + text
        if text.endswith("\\"):
            pending = text[:-1]
            continue
        pending = ""
        current.append((code, text, value))
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
