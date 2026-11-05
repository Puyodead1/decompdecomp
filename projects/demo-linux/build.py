"""Build Demo Quest for Linux, a 32-bit x86 Linux program made only from code we may share: the same Demo Quest game,
main loop and tiny libc as the N64 demo (CC0, ../demo-rom/src, ../demo-n64/original) and zlib 1.1.4 (Zlib
license, ../zlib-n64), compiled the way Linux games of
2001 were: Slackware 8.0's GCC 2.95.3 at -O2 -g (STABS) and its binutils, linked into an i386 ELF executable that
keeps its symbol table and debug information, as such games shipped.

    uv run python projects/demo-linux/build.py    ->  build/demoquest (+ build/demo.json for tests/test_consoles.py)
    uv run python projects/demo-linux/build.py gcc-4.3.2-linux   ->  build-gcc-4.3.2-linux/demoquest: the same game as
        a program of 2008 (Debian 5.0's GCC 4.3.2 at -O2 -g, DWARF), for tests/test_linux.py

Needs the pinned gcc-2.95.3-linux toolchain and its 32-bit runtime; they install on first use (free software). The
compiler runs in the app's sandbox, with that runtime, as every compile of the app does.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from decompnet import compiler, toolchains
from decompnet.project import compiler_config

HERE = Path(__file__).resolve().parent
BUILD = HERE / "build"
DEMO = HERE.parent / "demo-rom" / "src"
GAME = HERE.parent / "demo-n64" / "original"
ZLIB = HERE.parent / "zlib-n64"
ZLIB_UNITS = ["adler32", "compress", "crc32", "deflate", "inflate", "infblock", "infcodes", "inffast", "inftrees",
              "infutil", "trees", "uncompr", "zutil"]
TOOLCHAIN = "gcc-2.95.3-linux"
PROGRAM = "demoquest"


def run(cfg, argv: list[str], build: Path = BUILD) -> None:
    res = compiler.run_in(cfg, build, argv, timeout=300)
    if res.returncode != 0:
        sys.exit(f"failed: {' '.join(argv)}\n{res.stdout}{res.stderr}")


def write_key(build: Path, program: Path) -> None:
    """build/demo.json: the program this build made and the address of every symbol, for tests/test_consoles.py."""
    from elftools.elf.elffile import ELFFile

    with open(program, "rb") as f:
        symbols = {s.name: s["st_value"] for s in ELFFile(f).get_section_by_name(".symtab").iter_symbols() if s.name}
    (build / "demo.json").write_text(json.dumps({"game": program.name, "symbols": symbols}, indent=1), encoding="utf-8")


def main(toolchain: str = TOOLCHAIN) -> None:
    build = BUILD if toolchain == TOOLCHAIN else HERE / f"build-{toolchain}"
    missing = [str(p) for p in (DEMO / "main.c", DEMO / "libc.c", GAME / "game.c", GAME / "game.h") if not p.exists()]
    if missing:
        sys.exit("missing demo sources: " + ", ".join(missing))
    if build.exists():
        shutil.rmtree(build)
    build.mkdir()
    for src in (DEMO / "main.c", DEMO / "libc.c", GAME / "game.c", GAME / "game.h"):
        shutil.copy(src, build / src.name)
    for folder in (ZLIB / "original", ZLIB / "sysinclude"):  # (zlib's own headers, and the few system ones it takes)
        for src in folder.glob("*.[ch]"):
            if not (build / src.name).exists():
                shutil.copy(src, build / src.name)
    toolchains.ensure("runtime-i386", log=print)
    tc = toolchains.ensure(toolchain, log=print)
    cfg = compiler_config(build, {"compiler": {"toolchain": toolchain, "flags": ["-O2", "-g"]}})
    objs = []
    for stem in ("main", "libc", "game", *ZLIB_UNITS):
        argv = [a.replace("{src}", f"{stem}.c").replace("{obj}", f"{stem}.o").replace("{include}", ".") for a in cfg.cmd]
        run(cfg, argv, build)
        objs.append(f"{stem}.o")
    # no C runtime: the demo's main is its entry, as the N64 and GBA builds' are; the symbol table and STABS stay
    run(cfg, ["/bin/sh", "-c", f'LD_LIBRARY_PATH="{tc}/binutils/usr/lib${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}" exec "{tc}/binutils/usr/bin/ld" '
                               f'-m elf_i386 -e main -o {PROGRAM} {" ".join(objs)}'], build)
    write_key(build, build / PROGRAM)
    print(f"built {build.name}/{PROGRAM} ({(build / PROGRAM).stat().st_size} bytes)")


if __name__ == "__main__":
    main(*sys.argv[1:2])
