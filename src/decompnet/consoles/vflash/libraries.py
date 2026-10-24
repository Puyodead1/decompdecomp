"""The libraries V.Flash firmware was built from, unchanged, recognised at import: zlib 1.2.3, Tremor (the Ogg Vorbis
decoder's lowmem branch) and newlib 1.12.0's maths library, compiled with the game's GCC and the flags each was built
with, and every compiled function looked for among the game's functions of the same size, byte for byte but for
what the link decides (relocated words). Each library source file that has some becomes a source file of the
project (src/<program>/lib/<library>/<file>.c) holding the library's own source, with every function of the game
from the first it matched to the last of that file's, and the ones it matched named by their names: they measure
100% from the first build, and agents never spend a compile on them. (On a game's firmware: zlib's 56 of 64, Tremor's
81, the maths library's 12.)"""

from __future__ import annotations

import io
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ... import toolchains
from ...limits import capped

PACK = "vflash-libraries"
COMMON = ["-c", "-ffunction-sections", "-fomit-frame-pointer", "-mno-apcs-frame", "-msoft-float"]
COMPILE_SECONDS = 120
R_ARM_PC24, R_ARM_ABS32 = 1, 2


@dataclass(frozen=True)
class Library:
    name: str  # its folder in the project: src/<program>/lib/<name>/
    folders: tuple[str, ...]  # where its .c files are, in the pack
    headers: tuple[str, ...]  # folders whose .h files its sources include as "x.h": copied next to them
    flags: tuple[str, ...]  # what the game built it with
    skip: tuple[str, ...] = ()  # its files that aren't the library (examples, tests)
    notice: tuple[str, ...] = ()  # its licence files, copied with it


NEWLIB_INCLUDE = "newlib/libc/include"  # the C library's headers the libraries include (<string.h>...)
LIBRARIES = (
    Library("zlib", ("zlib",), ("zlib",), ("-O3", "-mcpu=arm9tdmi"),
            skip=("example.c", "minigzip.c", "gzio.c"), notice=("zlib/README",)),
    Library("tremor", ("tremor",), ("tremor",), ("-O3", "-mcpu=arm9tdmi", "-D_ARM_ASSEM_"),
            skip=("ivorbisfile_example.c",), notice=("tremor/COPYING",)),
    Library("libm", ("newlib/libm/math", "newlib/libm/common"), ("newlib/libm/common",), ("-O1", "-mcpu=arm9tdmi"),
            notice=("newlib/libm/math/../../COPYING.NEWLIB",)),
)
MIN_BYTES = 24  # shorter functions look alike in any program (a getter, `return 0`): not taken as the library's


@dataclass
class Compiled:
    library: Library
    source: Path  # in the pack
    functions: dict[str, tuple[bytes, list[tuple[int, int]]]]  # name -> (code, [(offset, relocation type)]), in
    # the order the file has them (GCC keeps the source's: the order they're linked in)


def available() -> bool:
    return toolchains.installed(PACK) is not None


def _functions(obj: bytes) -> dict[str, tuple[bytes, list[tuple[int, int]]]]:
    """Each function of a GCC object compiled with -ffunction-sections: its section's bytes, and where they're
    relocated."""
    elf = ELFFile(io.BytesIO(obj))
    relocs: dict[int, list[tuple[int, int]]] = {}
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection):
            relocs[sec["sh_info"]] = [(r["r_offset"], r["r_info_type"]) for r in sec.iter_relocations()]
    out = {}
    symbols = [s for s in elf.get_section_by_name(".symtab").iter_symbols()
               if s["st_info"]["type"] == "STT_FUNC" and isinstance(s["st_shndx"], int) and s["st_value"] == 0]
    for sym in sorted(symbols, key=lambda s: s["st_shndx"]):
        sec = elf.get_section(sym["st_shndx"])
        if sec.name.startswith(".text."):
            out[sym.name] = (sec.data(), relocs.get(sym["st_shndx"], []))
    return out


def compile_all(gcc: Path, log=print) -> list[Compiled]:
    """Every library source file compiled as the game's were (one that doesn't build here is left out)."""
    pack = toolchains.path(PACK)
    out = []
    with tempfile.TemporaryDirectory(prefix="decomp-vflash-libs-") as tmp:
        for lib in LIBRARIES:
            includes = [f"-I{pack / h}" for h in lib.headers] + [f"-I{pack / NEWLIB_INCLUDE}"]
            for folder in lib.folders:
                for src in sorted((pack / folder).glob("*.c")):
                    if src.name in lib.skip:
                        continue
                    obj = Path(tmp) / f"{lib.name}-{src.stem}.o"
                    res = subprocess.run(capped([str(gcc / "bin" / "arm-elf-gcc"), *COMMON, *lib.flags, *includes,
                                                 "-o", str(obj), str(src)]), capture_output=True,
                                         timeout=COMPILE_SECONDS)
                    if res.returncode or not obj.exists():
                        continue
                    try:
                        out.append(Compiled(lib, src, _functions(obj.read_bytes())))
                    except (ELFError, ValueError, AttributeError):
                        continue
    log(f"compiled {len(out)} library source files to look for in the game")
    return out


def _same(code: bytes, original: bytes, relocs: list[tuple[int, int]]) -> bool:
    """Whether the compiled function is the original but for what the link decides: a relocated word (an
    address), a branch's target."""
    if len(code) != len(original):
        return False
    a, b = bytearray(code), bytearray(original)
    for off, kind in relocs:
        mask = 0x00FFFFFF if kind == R_ARM_PC24 else 0xFFFFFFFF
        for buf in (a, b):
            word = struct.unpack_from("<I", buf, off)[0]
            struct.pack_into("<I", buf, off, word & ~mask & 0xFFFFFFFF)
    return a == b


def find(compiled: list[Compiled], functions, read) -> dict[int, tuple[Compiled, str]]:
    """The game's functions (`functions`: analysis.Function) that a library's are, by address: (its file, its name).
    `read(addr, n)`: the program's bytes. A library function the game has twice (two modules' copies are other
    programs) is taken where it's found first."""
    by_size: dict[int, list] = {}
    for f in functions:
        by_size.setdefault(f.size, []).append(f)
    out: dict[int, tuple[Compiled, str]] = {}
    for c in compiled:
        for name, (code, relocs) in c.functions.items():
            if len(code) < MIN_BYTES:
                continue
            for f in by_size.get(len(code), []):
                if f.addr not in out and _same(code, read(f.addr, f.size), relocs):
                    out[f.addr] = (c, name)
                    break
    return out


def units(program: str, functions, found: dict[int, tuple[Compiled, str]]):
    """The library source files the game has, as units: ({unit: (Compiled, [its functions])}, the functions left for
    the program's own source files, {address: library name}). A file's unit runs from the first function it matched
    to its last; when the game has as many functions there as the file has from the one to the other, the ones it
    didn't match (a library function the game's makers changed) are named by their place too."""
    by_file: dict[Path, list[int]] = {}
    files: dict[Path, Compiled] = {}
    for addr, (c, _) in found.items():
        by_file.setdefault(c.source, []).append(addr)
        files[c.source] = c
    taken: set[int] = set()
    out, names = {}, {}
    order = sorted(functions, key=lambda f: f.addr)
    for source, addrs in sorted(by_file.items(), key=lambda kv: min(kv[1])):
        lo, hi = min(addrs), max(addrs)
        inside = [f for f in order if lo <= f.addr <= hi and f.addr not in taken]
        if any(f.addr in found and found[f.addr][0].source != source for f in inside):
            inside = [f for f in inside if f.addr in addrs]  # (files interleaved: only its own functions)
        taken.update(f.addr for f in inside)
        c = files[source]
        own = list(c.functions)
        first, last = own.index(found[lo][1]), own.index(found[hi][1])
        if last - first + 1 == len(inside) and all(own[first + i] == found[f.addr][1]
                                                   for i, f in enumerate(inside) if f.addr in found):
            names.update({f.addr: own[first + i] for i, f in enumerate(inside)})
        else:
            names.update({a: found[a][1] for a in addrs})
        out[f"{program}/lib/{c.library.name}/{source.stem}"] = (c, inside)
    return out, [f for f in order if f.addr not in taken], names


def write_sources(root: Path, program: str, used: list[Compiled]) -> dict[str, list[str]]:
    """The library source files a program has, with the headers next to them and the libraries' licences, in
    src/<program>/lib/; the C library's headers in include/newlib/. Returns each source file's flags (flags.json's)."""
    pack = toolchains.path(PACK)
    newlib = root / "include" / "newlib"
    if not newlib.exists():
        shutil.copytree(pack / NEWLIB_INCLUDE, newlib)
    flags = {}
    for c in used:
        folder = root / "src" / program / "lib" / c.library.name
        folder.mkdir(parents=True, exist_ok=True)
        for h in c.library.headers:
            for header in (pack / h).glob("*.h"):
                shutil.copy(header, folder / header.name)
        for notice in c.library.notice:
            if (pack / notice).is_file():
                shutil.copy(pack / notice, folder / Path(notice).name)
        shutil.copy(c.source, folder / c.source.name)
        flags[f"src/{program}/lib/{c.library.name}/{c.source.name}"] = [*c.library.flags, "-Iinclude/newlib"]
    return flags
