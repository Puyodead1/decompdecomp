"""Nintendo's DS and DSi libraries, the user's own copies: NitroSDK and TwlSDK (OS_, GX_, FS_, CARD_...), NitroSystem
and TwlSystem (NNS_), NitroWiFi, NitroDWC and TwlDWC, and CodeWarrior's own runtime (MSL). Every DS game links some
of them, prebuilt: their functions are Nintendo's, not the game's, and the DS import finds them by these libraries'
bytes, sets them aside and gives them their names (consoles/nds/sdklib.py), so agents work on the game's own code.

A copy is any folder holding the libraries (`.a` archives of ARM ELF objects, as the SDKs ship them under lib/):
an SDK's folder, the folder above several, a patch's. Several copies can be given; each library function found in
any of them counts. The ARM7's libraries are left out: decompdecomp decompiles the ARM9's code.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

from . import Kit

MAX_DEPTH = 12  # (a library's folder in an SDK: NitroSDK-4_2/NitroSDK/lib/ARM9-TS/Rom, under a folder of SDKs)
# (the folder of a library's version header, include/<folder>/version.h, and the library it versions)
VERSION_HEADERS = {"nitro": "NitroSDK", "twl": "TwlSDK", "nnsys": "NitroSystem", "nitrowifi": "NitroWiFi",
                   "nitrocrypto": "NitroCrypto"}


def archives(folder: Path) -> list[Path]:
    """The ARM9 library archives in a copy (`.a`, any case), not the ARM7's. Remembered while the folder's own time
    stays (Setup's list asks on every load, and a folder of every SDK is 4 GB)."""
    try:
        stamp = folder.stat().st_mtime_ns
    except OSError:
        return []
    return list(_archives(folder.resolve(), stamp))


@functools.lru_cache(maxsize=16)
def _archives(folder: Path, stamp: int) -> tuple[Path, ...]:
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
    return tuple(out)


def _elf_archive(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    return head.startswith(b"!<arch>\n") and b"\x7fELF" in head


def _version(folder: Path) -> tuple[str, str]:
    """(library, "4.2") from the first version header inside a package, or ("", "")."""
    try:
        headers = sorted(folder.glob("**/include/*/version.h"))
    except OSError:
        return "", ""
    for header in headers:
        what = VERSION_HEADERS.get(header.parent.name.lower())
        try:
            text = header.read_text(encoding="latin-1") if what else ""
        except OSError:
            continue
        major = re.search(r"VERSION_MAJOR\s+(\d+)", text)
        minor = re.search(r"VERSION_MINOR\s+(\d+)", text)
        if major and minor and not (what == "NitroSDK" and int(major.group(1)) >= 5):
            return what, f"{major.group(1)}.{minor.group(1)}"
    return "", ""


@functools.lru_cache(maxsize=16)
def _contents(folder: Path, stamp: int) -> list[dict]:
    """A copy's packages by section: in a folder of folders of packages (NitroSDK/NitroSDK-4_2-20071210/...), each
    first folder a section and each second one a package; a folder of packages, its own name the section; an SDK
    itself, one package."""
    packages: dict[tuple[str, str], int] = {}
    for a in archives(folder):
        rel = a.relative_to(folder).parts[:-1]
        lib_at = next((i for i, p in enumerate(rel) if p.lower() == "lib"), len(rel))
        if lib_at >= 2:
            key = (rel[0], rel[1])
        elif lib_at == 1:
            key = (folder.name, rel[0])
        else:
            key = (folder.name, folder.name)
        packages[key] = packages.get(key, 0) + 1
    sections: dict[str, list[dict]] = {}
    for (section, package), n in sorted(packages.items()):
        where = folder / section / package if section != folder.name or (folder / section).is_dir() else folder
        where = where if where.is_dir() else folder / package if (folder / package).is_dir() else folder
        what, version = _version(where)
        sections.setdefault(section, []).append({"name": package, "version": version, "library": what,
                                                 "libraries": n})
    return [{"name": s, "items": items} for s, items in sections.items()]


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
            if folder.is_dir() and any(_elf_archive(a) for a in archives(folder)[:50]):
                return folder.resolve()
        except OSError:
            pass
        return None

    def build(self, folder: Path) -> str | None:
        """Which SDKs the copy holds, by their version headers: "NitroSDK 4.2", or for a folder of many, each
        library's versions ("NitroSDK 1.0, 2.0, 4.2; TwlSDK 5.1, 5.5")."""
        found: dict[str, set[tuple[int, int]]] = {}
        try:
            headers = sorted(folder.glob("**/include/*/version.h"))
        except OSError:
            return None
        for header in headers:
            what = VERSION_HEADERS.get(header.parent.name.lower())
            try:
                text = header.read_text(encoding="latin-1") if what else ""
            except OSError:
                continue
            major = re.search(r"VERSION_MAJOR\s+(\d+)", text)
            minor = re.search(r"VERSION_MINOR\s+(\d+)", text)
            if major and minor and not (what == "NitroSDK" and int(major.group(1)) >= 5):  # (TwlSDK's own copy)
                found.setdefault(what, set()).add((int(major.group(1)), int(minor.group(1))))
        def versions(v: set[tuple[int, int]]) -> str:
            seen = [f"{a}.{b}" for a, b in sorted(v)]
            return ", ".join(seen) if len(seen) <= 3 else f"{seen[0]}–{seen[-1]} ({len(seen)} versions)"
        return "; ".join(f"{what} {versions(v)}" for what, v in sorted(found.items())) or None

    def contents(self, folder: Path) -> list[dict]:
        """The packages the copy holds, by library: a folder of several (Setup's sections, NitroSDK, TwlSDK, ...)
        lists each package in it with its version and its libraries; a copy that is one SDK is one package."""
        try:
            stamp = folder.stat().st_mtime_ns
        except OSError:
            return []
        return _contents(folder.resolve(), stamp)

    def verify(self, folder: Path) -> str:
        n = len(archives(folder))
        return f"{n} librar{'y' if n == 1 else 'ies'} of the ARM9" if n else ""


NITRO = Nitro()


def folders() -> list[Path]:
    """The user's copies (none: not set up)."""
    from . import folders as copies

    return copies(NITRO.id)
