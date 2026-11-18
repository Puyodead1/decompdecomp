"""Nintendo's GameCube and Wii libraries, the user's own copies: the Dolphin SDK's (OS, GX, DVD, PAD, AX, CARD...),
the Revolution SDK's, and the like. Every game links some of them, prebuilt: their functions are Nintendo's, not the
game's, and the library finder (app/engine/libraryid.py, on Check again) matches each of their functions against the
game's and sets aside the ones that are the same, relocated fields aside, saying which library function each is,
so agents work on the game's own code. On a GameCube game of 20,000 functions a 2001 SDK set aside 178 (the game's
own SDK is a later one: what changed between them stays open).

A copy is any folder holding the libraries (`.a` archives of PowerPC ELF objects, as the SDK installs them in
HW2/lib, or RVL/lib): an SDK's folder, or one holding several versions. A debug build (osD.a) is read too: a game
built against it has its code. Only the folder is recorded; the archives are read where the user keeps them.
"""

from __future__ import annotations

import functools
from pathlib import Path

from . import Kit

MAX_DEPTH = 8  # (an SDK's libraries: <copy>/dolphin/HW2/lib/os.a, under a folder of SDKs)


def _ppc_archive(path: Path) -> bool:
    """A System V archive of big-endian PowerPC ELF objects (e_machine 20)."""
    try:
        with path.open("rb") as f:
            head = f.read(65536)
    except OSError:
        return False
    at = head.find(b"\x7fELF\x01\x02\x01")
    return head.startswith(b"!<arch>\n") and at >= 0 and head[at + 18:at + 20] == b"\x00\x14"


@functools.lru_cache(maxsize=16)
def _archives(folder: Path, stamp: int) -> tuple[Path, ...]:
    out = []
    try:
        for p in sorted(folder.rglob("*")):
            if p.suffix.lower() == ".a" and len(p.relative_to(folder).parts) <= MAX_DEPTH and p.is_file() \
                    and _ppc_archive(p):
                out.append(p)
    except OSError:
        pass
    return tuple(out)


@functools.lru_cache(maxsize=16)
def _headers(folder: Path, stamp: int) -> tuple[Path, ...]:
    out = []
    try:
        for p in sorted(folder.rglob("*.h")):
            if len(p.relative_to(folder).parts) <= MAX_DEPTH and p.is_file():
                out.append(p)
    except OSError:
        pass
    return tuple(out)


class Dolphin(Kit):
    id = "dolphin-sdk"
    name = "Nintendo GameCube and Wii libraries (your own copies)"
    platform = "GameCube/Wii"  # (as the CodeWarrior pack says it: Setup groups cards by it, its chip "GameCube, Wii")
    description = ("The libraries GameCube and Wii games link: the Dolphin SDK's (OS, GX, DVD, PAD, AX...) and the "
                   "Revolution SDK's. Their code in a game is found and set aside on Check again, so agents "
                   "work on the game's own. Give the folder of your own copy (the SDK's, or one holding several).")
    files = ("lib",)

    def locate(self, folder: Path) -> Path | None:
        """The folder itself, when a PowerPC library archive is anywhere inside (MAX_DEPTH)."""
        return folder.resolve() if folder.is_dir() and self.libraries(folder) else None

    def libraries(self, folder: Path) -> list[Path]:
        try:
            return list(_archives(folder.resolve(), folder.stat().st_mtime_ns))
        except OSError:
            return []

    # (CodeWarrior for the Gekko, as the SDK's own builds define it: its headers' Gekko code, never the PC
    # emulator's (EMU), SN Systems' compiler's (__SN__) or Windows' (_WIN32))
    defines = ("GEKKO", "HW2", "__MWERKS__", "__PPCGEKKO__")

    def headers(self, folder: Path) -> list[Path]:
        """Every header of the copy (an SDK's include/dolphin/os/OSFastCast.h), as deep as its libraries."""
        try:
            return list(_headers(folder.resolve(), folder.stat().st_mtime_ns))
        except OSError:
            return []

    def verify(self, folder: Path) -> str:
        n = len(self.libraries(folder))
        return f"{n} PowerPC librar{'y' if n == 1 else 'ies'}" if n else ""


DOLPHIN = Dolphin()
