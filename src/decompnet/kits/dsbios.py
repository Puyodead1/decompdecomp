"""The Nintendo DS's ARM7 BIOS, the user's own dump: the key ds-decomp decrypts a ROM's secure area with. A copy of a
cartridge keeps the first 2 KB of its ARM9 program encrypted, as the cartridge does; dsd unpacks such a ROM only with
the BIOS (`dsd rom extract --arm7-bios`), and encrypts it again when it rebuilds the ROM (`dsd rom build --arm7-bios`),
so the rebuild can be the user's copy byte for byte. Nintendo's code: nobody may publish it, so the user dumps their
own DS's (GodMode9i on a DSi or 3DS, a BIOS dumper on a flashcart).

A copy is a file, not a folder: the user gives the file or the folder holding it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import Kit, find

SIZE = 0x4000
NAMES = ("bios7.bin", "biosnds7.rom", "bios7.rom", "nds7.bin", "arm7.bin", "biosnds7.bin", "bios_arm7.bin")
MD5 = "df692a80a5b1bc90728bc3dfc76cd948"  # the DS's ARM7 BIOS (Batocera's and emulators' BIOS lists)


class DsBios(Kit):
    id = "nds-bios"
    name = "Nintendo DS ARM7 BIOS (your own dump)"
    platform = "DS"
    description = ("Opens DS games whose copy keeps its secure area encrypted, as the cartridge does. Give your own "
                   "dump of the DS's ARM7 BIOS (16 KB, usually bios7.bin or biosnds7.rom), or the folder holding it.")
    files = ("bios7.bin",)

    def locate(self, folder: Path) -> Path | None:
        """The BIOS file: the one given, or one of NAMES in the folder given; 16 KB (a DSi's 64 KB BIOS isn't it)."""
        try:
            if folder.is_file():
                return folder.resolve() if folder.stat().st_size == SIZE else None
            for name in NAMES:
                if (f := find(folder, name)) is not None and f.stat().st_size == SIZE:
                    return f.resolve()
        except OSError:
            pass
        return None

    def verify(self, folder: Path) -> str:
        try:
            digest = hashlib.md5(folder.read_bytes()).hexdigest()
        except OSError:
            return ""
        return ("verified: the DS's ARM7 BIOS" if digest == MD5 else
                "not the DS ARM7 BIOS decompdecomp knows (a bad dump, or another console's): an encrypted game may "
                "not open with it")


DSBIOS = DsBios()


def bios() -> Path | None:
    """The user's BIOS file, or None: it isn't set up."""
    from . import folder

    return folder(DSBIOS.id)
