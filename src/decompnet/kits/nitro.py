"""Nintendo's DS and DSi libraries, the user's own copies: NitroSDK and TwlSDK (OS_, GX_, FS_, CARD_...), NitroSystem
and TwlSystem (NNS_), NitroWiFi, NitroDWC and TwlDWC, and CodeWarrior's own runtime (MSL). Every DS game links some
of them, prebuilt: their functions are Nintendo's, not the game's, and the DS import finds them by these libraries'
bytes, sets them aside and gives them their names (consoles/nds/sdklib.py), so agents work on the game's own code.

A copy is any folder holding the libraries (`.a` archives of ARM ELF objects, as the SDKs ship them under lib/):
an SDK's folder, the folder above several, a patch's. Several copies can be given; each library function found in
any of them counts. The ARM7's libraries are left out: decompdecomp decompiles the ARM9's code.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import Kit

MAX_DEPTH = 7  # (a library's folder in an SDK: NitroSDK-4_2/NitroSDK/lib/ARM9-TS/Rom)
# (what each SDK's version header is, and which library it versions)
VERSION_HEADERS = (("include/nitro/version.h", "NitroSDK"), ("include/twl/version.h", "TwlSDK"),
                   ("include/nnsys/version.h", "NitroSystem"))


def archives(folder: Path) -> list[Path]:
    """The ARM9 library archives in a copy (`.a`, any case), not the ARM7's."""
    out = []
    try:
        for p in sorted(folder.rglob("*")):
            rel = p.relative_to(folder).parts
            if len(rel) > MAX_DEPTH or p.suffix.lower() != ".a" or any(x.upper().startswith("ARM7") for x in rel):
                continue
            if p.is_file():
                out.append(p)
    except OSError:
        pass
    return out


def _elf_archive(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    return head.startswith(b"!<arch>\n") and b"\x7fELF" in head


class Nitro(Kit):
    id = "nitro"
    name = "Nintendo DS and DSi libraries (your own copies)"
    platform = "DS"
    description = ("The libraries DS and DSi games link: NitroSDK, TwlSDK, NitroSystem, TwlSystem, NitroWiFi, DWC, "
                   "CodeWarrior's runtime. Their code in a game is found, named and set aside, so agents work on the "
                   "game's own. Give the folder of your own copy (an SDK's, or one holding several).")
    files = ("lib",)

    def locate(self, folder: Path) -> Path | None:
        """The folder itself, when it holds an ARM ELF library archive anywhere inside (MAX_DEPTH)."""
        try:
            if folder.is_dir() and any(_elf_archive(a) for a in archives(folder)):
                return folder.resolve()
        except OSError:
            pass
        return None

    def build(self, folder: Path) -> str | None:
        """Which SDKs the copy holds, by their version headers ("NitroSDK 4.2 (20090511)")."""
        found = []
        for rel, what in VERSION_HEADERS:
            for header in sorted(folder.glob(f"**/{rel}"))[:3]:
                try:
                    text = header.read_text(encoding="latin-1")
                except OSError:
                    continue
                major = re.search(r"VERSION_MAJOR\s+(\d+)", text)
                minor = re.search(r"VERSION_MINOR\s+(\d+)", text)
                date = re.search(r"VERSION_DATE\s+(\d+)", text)
                if major and minor:
                    found.append(f"{what} {major.group(1)}.{minor.group(1)}" + (f" ({date.group(1)})" if date else ""))
        return ", ".join(dict.fromkeys(found)) or None

    def verify(self, folder: Path) -> str:
        n = len(archives(folder))
        return f"{n} librar{'y' if n == 1 else 'ies'} of the ARM9" if n else ""


NITRO = Nitro()


def folders() -> list[Path]:
    """The user's copies (none: not set up)."""
    from . import folders as copies

    return copies(NITRO.id)
