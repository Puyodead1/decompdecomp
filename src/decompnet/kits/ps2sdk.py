"""Sony's PlayStation 2 libraries, the user's own copies: the SDK's (libgraph, libdma, libvu0, libpad, libmc, libcdvd,
libsd...) and the C, math and C++ runtime libraries its EE-GCC came with. Every game links some of them, prebuilt:
their functions are Sony's or the compiler's, not the game's, and the library finder (app/engine/libraryid.py, on
Check again) matches each of their functions against the game's and sets aside the ones that are the same,
relocated fields aside, or (the project's choice) that have one of their names. A North American C++ game of 3,223
functions said which SDK it was built with in its own text ("PsIIlibcdvd 3100": 3.1.0), and agents had been working
on its library code.

A copy is any folder holding the libraries (`.a` archives of little-endian MIPS ELF objects, as the SDK installs
them in sce/ee/lib, and its compiler's in ee/lib and ee/lib/gcc-lib): an SDK's folder, or one holding several
versions. Only the folder is recorded; the archives are read where the user keeps them. The IOP's libraries (the
I/O processor's modules, sce/iop/lib) are another processor's code, never in a game's main program: left out.
"""

from __future__ import annotations

import functools
from pathlib import Path

from . import Kit

MAX_DEPTH = 10  # (an SDK's libraries: <copy>/sce/ee/lib/libgraph.a, its compiler's deeper: ee/lib/gcc-lib/ee/2.96-ee-001003-1)
EM_MIPS = 8


def _ee_archive(path: Path) -> bool:
    """A System V archive of little-endian 32-bit MIPS ELF objects (e_machine 8): the EE's, not the IOP's (whose
    libraries are .ilb or sit under iop/)."""
    if "iop" in (p.lower() for p in path.parts):
        return False
    try:
        with path.open("rb") as f:
            head = f.read(65536)
    except OSError:
        return False
    at = head.find(b"\x7fELF\x01\x01\x01")
    return head.startswith(b"!<arch>\n") and at >= 0 and head[at + 18:at + 20] == EM_MIPS.to_bytes(2, "little")


@functools.lru_cache(maxsize=16)
def _archives(folder: Path, stamp: int) -> tuple[Path, ...]:
    out = []
    try:
        for p in sorted(folder.rglob("*.a")):
            if len(p.relative_to(folder).parts) <= MAX_DEPTH and p.is_file() and _ee_archive(p):
                out.append(p)
    except OSError:
        pass
    return tuple(out)


class Ps2Sdk(Kit):
    id = "ps2-sdk"
    name = "Sony PlayStation 2 libraries (your own copies)"
    platform = "PS2"  # (as the EE-GCC and CodeWarrior packs say it: Setup groups cards by it)
    description = ("The libraries PlayStation 2 games link: the SDK's (libgraph, libdma, libvu0, libpad, libmc, "
                   "libcdvd...) and its compiler's C, math and C++ libraries. Their code in a game is found and set "
                   "aside on Check again, so agents work on the game's own. Give the folder of your own copy (the "
                   "SDK's, or one holding several versions).")
    files = ("lib",)

    def locate(self, folder: Path) -> Path | None:
        """The folder itself, when an EE library archive is anywhere inside (MAX_DEPTH)."""
        return folder.resolve() if folder.is_dir() and self.libraries(folder) else None

    def libraries(self, folder: Path) -> list[Path]:
        try:
            return list(_archives(folder.resolve(), folder.stat().st_mtime_ns))
        except OSError:
            return []

    def verify(self, folder: Path) -> str:
        n = len(self.libraries(folder))
        return f"{n} EE librar{'y' if n == 1 else 'ies'}" if n else ""


PS2SDK = Ps2Sdk()
