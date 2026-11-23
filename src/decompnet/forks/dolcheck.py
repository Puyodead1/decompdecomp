"""Where a dtk-template project's built DOL differs from the game's, by symbol.

A file that doesn't link fails the checksum check with one line ("build/<version>/main.dol: FAILED"), which says
nothing an agent can fix. The DOL is a header and up to 18 sections at fixed addresses, so the first bytes that
differ, named by the symbol around them (symbols.txt), say which function or data to look at.
"""

from __future__ import annotations

import struct
from pathlib import Path

import yaml

from decompnet.forks import dtksplits


def sections(dol: bytes) -> list[tuple[int, int, int]]:
    """(file offset, address, size) of each section the header lists (7 text, 11 data), in header order."""
    offs = struct.unpack_from(">18I", dol, 0x00)
    addrs = struct.unpack_from(">18I", dol, 0x48)
    sizes = struct.unpack_from(">18I", dol, 0x90)
    return [(o, a, s) for o, a, s in zip(offs, addrs, sizes) if s]


def _runs(a: bytes, b: bytes, limit: int) -> list[tuple[int, int]]:
    """(start, end) of the first runs of bytes that differ (a gap under 16 bytes joins two runs)."""
    out: list[tuple[int, int]] = []
    i, n = 0, min(len(a), len(b))
    while i < n and len(out) < limit:
        if a[i:i + 4096] == b[i:i + 4096]:  # (a game's DOL is megabytes: skip what's the same a page at a time)
            i += 4096
            continue
        if a[i] == b[i]:
            i += 1
            continue
        j = i
        while j < n and j - i < 0x10000 and (a[j] != b[j] or a[j:j + 16] != b[j:j + 16]):
            j += 1
        out.append((i, j))
        i = j
    return out


def _named(addr: int, syms: list[tuple[int, int, str, str]]) -> str:
    """The symbol around an address, with the offset into it."""
    best = None
    for start, size, name, section in syms:
        if start <= addr < start + max(size, 1):
            best = (start, name, section)
        elif start > addr:
            break
    if best is None:
        return f"0x{addr:08X} (no symbol)"
    start, name, section = best
    return f"{section} {name}" + (f"+0x{addr - start:X}" if addr != start else "") + f" (0x{addr:08X})"


def differences(built: bytes, orig: bytes, symbols: dict[str, tuple[str, int, int]], limit: int = 6) -> list[str]:
    """Lines naming where the built DOL differs from the original: a section of another address or size, then the
    first differing bytes by symbol. [] when the two are the same."""
    syms = sorted((a, size, name, sec) for name, (sec, a, size) in symbols.items())
    mine, theirs = sections(built), sections(orig)
    lines = []
    if len(mine) != len(theirs):
        lines.append(f"the build has {len(mine)} sections, the game {len(theirs)}")
    for (bo, ba, bs), (oo, oa, os_) in zip(mine, theirs):
        if (ba, bs) != (oa, os_):
            lines.append(f"the section at 0x{oa:08X} is 0x{os_:X} bytes in the game, "
                         f"0x{bs:X} at 0x{ba:08X} in the build: what comes after it moved")
        for lo, hi in _runs(built[bo:bo + bs], orig[oo:oo + os_], limit - len(lines)):
            lines.append(f"{_named(oa + lo, syms)}: {hi - lo} byte(s) differ")
        if len(lines) >= limit:
            break
    return lines[:limit]


def report(root: Path, version: str) -> str:
    """differences() for a project's main DOL as text ("" when it can't be read or doesn't differ)."""
    try:
        cfg = yaml.safe_load((root / "config" / version / "config.yml").read_text(encoding="utf-8"))
        orig = root / cfg.get("object_base", "") / cfg["object"]
        built = root / "build" / version / "main.dol"
        mods = dtksplits.modules(root, version)
        lines = differences(built.read_bytes(), orig.read_bytes(), dtksplits.symbols(mods["main"].symbols))
    except (OSError, KeyError, TypeError, ValueError, struct.error, yaml.YAMLError):
        return ""
    return ("Where the built DOL differs from the game's:\n" + "\n".join(f"- {x}" for x in lines)) if lines else ""
