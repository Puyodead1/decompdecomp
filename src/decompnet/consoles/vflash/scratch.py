"""Start a V.Flash decompilation from scratch: a project made for the user's own copy of the game (its disc image, or
the disc's files), built with the game's GCC 3.2.3 for ARM and judged by objdiff, worked on like any community
project.

A game is its firmware (FA, resident) and its game modules (overlays that share addresses and call FA by address):
each is a program of the project, with source files of its own (src/FA/, src/<module>/), and a module's names say
which module they're in (func_GZ1A_1047B800). As for PC games, decompdecomp does the delinking itself:

- Ghidra's analysis says where functions start, in every program in one run (forks/ghidra.functions_of);
- analysis.py follows each function's code for its extent (its literal pool and switch tables with it), finds the
  functions nothing calls that Ghidra missed, and turns what the code refers to into relocations;
- the project's tools/delink.py cuts the functions out of the programs into ELF objects at build time, one per
  source file (src/<program>/text_<address>.cpp, about 4 KiB of functions each), and the build compiles src/ with
  GCC 3.2.3 (tools/compile.py), one section per function, as the objects are cut.

The programs the build reads are ELFs made from the game's files (disc.py), in orig/<version>/; the project's
tools/extract.py makes them again from the user's copy of the game (a restored project, a new computer).
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from decompnet.hostenv import NO_WINDOW

from ... import toolchains
from ...forks.project import ForkError, ForkProject
from . import analysis, disc

TOOLCHAIN = "gcc-3.2.3-arm-elf"
TEMPLATE = Path(__file__).with_name("project_template")
UNIT_BYTES = 0x1000
TOOL_SECONDS = 3600  # Ghidra on a whole game, the project's build
ERROR_TAIL = 1500
GCC_FLAGS_AT = re.compile(r"^GCC_FLAGS = (\[[^\]]*\])", re.M)
CXX_FLAGS_AT = re.compile(r"^CXX_FLAGS = (\[[^\]]*\])", re.M)
# read_data
READ_DEFAULT_BYTES, READ_MIN_BYTES, READ_MAX_BYTES = 64, 4, 512
HEX_ROW_BYTES = 16
POINTERS_SHOWN = 24
MIN_STRING_CHARS = 3
PRINTABLE = range(32, 127)
_NAME = re.compile(r"(func|D)_(?:([A-Za-z0-9]+)_)?([0-9A-Fa-f]{8})")


def _load(path: Path) -> disc.Game:
    try:
        return disc.check(disc.load(Path(path)))
    except (disc.DiscError, OSError) as e:
        raise ForkError(str(e)) from e


def version_of(game: disc.Game, path: Path) -> str:
    """The project's version: the disc's volume id when it's a product id with its revision (93160_000), else the
    product from its 0ID_ folder, else the file's name."""
    for v in (game.label, game.product):
        if re.fullmatch(r"\d+_\d+", v or ""):
            return v
    return re.sub(r"[^a-z0-9]+", "", Path(path).stem.lower()) or "game"


def game_info(path: Path) -> dict:
    game = _load(path)
    if game.fa is None:
        raise ForkError("this isn't all of a V.Flash game: " + "; ".join(game.notes) + ". Pick the disc image (.iso, "
                        ".bin or .cue) or the disc's folder")
    title = Path(path).stem if Path(path).name.upper() not in ("BOOT.BIN", "FA.VFF") else Path(path).parent.parent.name
    return {"platform": "vflash", "id": version_of(game, path), "title": title, "region": "", "sha1": game.sha1(),
            "build": game.fa.build, "modules": len(game.modules), "compiler": TOOLCHAIN}


def identity(path: Path) -> str | None:
    """Which game a file is: its FA and modules, whatever form the disc takes (the same game as an ISO, a .bin or
    the disc's files)."""
    path = Path(path)
    try:
        if path.is_dir():
            if not (path / "0SYSTEM").is_dir():
                return None
        else:
            with open(path, "rb") as f:
                head = f.read(0x10000)
            if not disc.is_vflash(head, path) and path.suffix.lower() != ".cue":
                return None
        game = disc.check(disc.load(path))
    except (OSError, ValueError, struct.error):
        return None
    return game.sha1() if game.fa else None


# ---------------------------------------------------------------------------------------------------- analysis


def constructors(img: disc.Image) -> set[int]:
    """The functions the C++ static constructors' table lists (they run before the game starts)."""
    out, at = set(), img.init_start
    while at and at + 4 <= img.init_end:
        word = img.read(at, 4)
        if len(word) < 4:
            break
        value = int.from_bytes(word, "little")
        if value and img.contains(value):
            out.add(value)
        at += 4
    return out


def analyse(game: disc.Game, found: dict[str, list[dict]]) -> dict[str, list[analysis.Function]]:
    """Every program's functions, by program name (FA first: the modules' calls name FA's functions)."""
    out: dict[str, list[analysis.Function]] = {}
    fa = game.fa
    fa_fns = analysis.analyse("FA", fa.regions, {r["entry"] for r in found.get("FA.elf", [])},
                              {fa.entry} | constructors(fa), fa.contains)
    out["FA"] = fa_fns
    fa_names = {f.addr: f.name for f in fa_fns}
    for m in game.modules:
        out[m.name] = analysis.analyse(m.name, m.regions, {r["entry"] for r in found.get(f"{m.name}.elf", [])},
                                       {m.entry} | constructors(m), m.contains, fa_names, fa.contains)
    return out


def units(program: str, functions: list[analysis.Function]) -> dict[str, list[analysis.Function]]:
    """Source files: runs of neighbouring functions of about UNIT_BYTES each, `<program>/text_<address>`."""
    out: dict[str, list[analysis.Function]] = {}
    cur: list[analysis.Function] = []
    for fn in functions:
        if cur and (fn.addr + fn.size - cur[0].addr > UNIT_BYTES or fn.addr != cur[-1].addr + cur[-1].size):
            out[f"{program}/text_{cur[0].addr:08X}"] = cur
            cur = []
        cur.append(fn)
    if cur:
        out[f"{program}/text_{cur[0].addr:08X}"] = cur
    return out


def elf_offsets(img: disc.Image) -> list[tuple[int, int, int]]:
    """(address, size, file offset) of each region's data in img.to_elf(), the same walk it makes."""
    loads = [(a, len(d)) for a, d in img.regions if d]
    at = (52 + 32 * (len(loads) + (1 if img.bss_size else 0)) + disc.ELF_DATA_ALIGN - 1) & ~(disc.ELF_DATA_ALIGN - 1)
    out, body = [], 0
    for addr, size in loads:
        out.append((addr, size, at + body))
        body += size + (-size % 4)
    return out


def file_offset(spans: list[tuple[int, int, int]], addr: int) -> int:
    return next(off + addr - a for a, size, off in spans if a <= addr < a + size)


# ---------------------------------------------------------------------------------------------------- the project


def tool_args() -> list[str]:
    """configure.py arguments pointing at decompdecomp's pinned GCC (free software: installed when it's needed)."""
    if sys.platform == "win32":  # (its compiler is a Linux program: the build would need WSL's paths throughout)
        raise ForkError("V.Flash projects build on Linux for now: GCC 3.2.3 for ARM is a Linux program, and running it "
                        "through WSL is still to do")
    if toolchains.installed(TOOLCHAIN) is None:
        if not toolchains.get(TOOLCHAIN).supported:
            raise ForkError("V.Flash games are built with GCC 3.2.3 for ARM, which decompdecomp runs on 64-bit Linux "
                            "only for now")
        toolchains.ensure(TOOLCHAIN, log=lambda *_: None)
    return ["--gcc", str(toolchains.path(TOOLCHAIN))]


TYPES_H = """/* Basic types for this decompilation (V.Flash: ARM9, GCC 3.2.3, written in C++ or C). Agents add structs,
 * classes and prototypes here or in new headers next to it.
 *
 * The game's functions are named by address: FA's (the firmware, resident) func_<address>, a game module's
 * func_<module>_<address> (modules are loaded one at a time into the same addresses); its data D_<address> and
 * D_<module>_<address>. Write them as free functions or as a class's methods (`void Town::func_GZ1A_1047B800(int)`):
 * the build gives what they compile to the original's names, so C++'s name mangling pairs with the game's code.
 * Data: `extern int D_10B3B8FC;`. No C library comes with the compiler: declare what you use. */
#ifndef COMMON_H
#define COMMON_H

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
typedef float f32;
typedef double f64;
typedef unsigned int size_t;
#ifndef NULL
#define NULL 0
#endif

#endif
"""


def _run(cmd: list[str], root: Path, what: str, log) -> None:
    ok, tail = ForkProject(root).run(cmd, log=log, timeout=TOOL_SECONDS)
    if not ok:
        raise ForkError(f"{what} failed:\n{tail[-ERROR_TAIL:]}")


def _ghidra(game: disc.Game, log) -> dict[str, list[dict]]:
    """Where Ghidra's analysis says functions start, in every program of the game ("FA.elf", "GZ1A.elf")."""
    from ...forks import ghidra

    if not ghidra.available():
        if ghidra.java_home() is not None and toolchains.installed("jdk") is None:
            log("installing a Java development kit for Ghidra (200 MB, once): this computer has none of its own")
            toolchains.ensure("jdk", log=log)
        if toolchains.installed("ghidra") is None:
            log("installing Ghidra (540 MB, once): it finds where the game's functions start")
            toolchains.ensure("ghidra", log=log)
    with tempfile.TemporaryDirectory(prefix="decomp-vflash-") as tmp:
        paths = []
        for img in game.images():
            p = Path(tmp) / f"{img.name}.elf"
            p.write_bytes(img.to_elf())
            paths.append(p)
        return ghidra.functions_of(paths)


def create(root: Path, game_path: Path, *, compiler: str | None = None, log=print) -> dict:
    """Make the project in `root` (which must not exist yet) and build it once. Returns facts about the game."""
    info = game_info(game_path)
    game = _load(game_path)
    version = info["id"]
    for note in game.notes:
        log(f"note: {note}")
    args = tool_args()
    log(f"analysing FA and {len(game.modules)} game modules with Ghidra (finds where functions start; a whole game "
        "takes about ten minutes)")
    found = _ghidra(game, log)
    programs = analyse(game, found)
    log(", ".join(f"{p} {len(fns)}" for p, fns in programs.items()) + " functions")

    shutil.copytree(TEMPLATE, root, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(Path(disc.__file__), root / "tools" / "vflash.py")
    orig = root / "orig" / version
    orig.mkdir(parents=True)
    described, groups = {}, {}
    for img in game.images():
        data = img.to_elf()
        (orig / f"{img.name}.elf").write_bytes(data)
        described[img.name] = {"elf": f"orig/{version}/{img.name}.elf", "sha1": hashlib.sha1(data).hexdigest(),
                               "build": img.build, "source": img.source}
        spans = elf_offsets(img)
        for u, fns in units(img.name, programs[img.name]).items():
            groups[u] = [{"name": f.name, "addr": f.addr, "offset": file_offset(spans, f.addr), "size": f.size,
                          "relocs": [list(r) for r in f.relocs]} for f in fns]
    (root / "include").mkdir()
    (root / "include" / "common.h").write_text(TYPES_H, encoding="utf-8")
    conf = root / "config" / version
    conf.mkdir(parents=True)
    (conf / "functions.json").write_text(json.dumps({"sha1": info["sha1"], "programs": described, "units": groups},
                                                    indent=1), encoding="utf-8")
    for u, fns in groups.items():
        src = root / "src" / f"{u}.cpp"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(f"/* {len(fns)} function{'s' if len(fns) != 1 else ''} of {u.split('/')[0]} from "
                       f"0x{fns[0]['addr']:08X} to 0x{fns[-1]['addr'] + fns[-1]['size']:08X}. */\n#include \"common.h\"\n",
                       encoding="utf-8")
    log(f"{len(groups)} source files for agents to write into")

    for cmd in ([sys.executable, "tools/configure.py", version, *args], ["ninja", "prepare"]):
        _run(cmd, root, "the first build", log)
    if not (root / "objdiff.json").exists():
        raise ForkError("the first build finished without writing objdiff.json")

    (root / ".decomp.wtf.json").write_text(json.dumps({
        "created": "from scratch", "platform": "vflash", "version": version, "compiler": TOOLCHAIN,
        "game": {"what": "your copy of the game (its disc image: .iso, or .bin with its .cue; or the disc's files)",
                 "path": f"orig/{version}/", "sha1": None},
        "setup": [["python", "tools/extract.py", version], ["python", "tools/configure.py", version, *args],
                  ["ninja", "prepare"]],
    }, indent=2), encoding="utf-8")
    (root / ".gitignore").write_text("# made from your copy of the game, or by the build\norig/\nbuild/\nbuild.ninja\n"
                                     ".ninja_*\nobjdiff.json\n__pycache__/\n.decomp-wtf/\n", encoding="utf-8")
    (root / "README.md").write_text(f"""# {info['title']} decompilation

Started from scratch with [decompdecomp](https://github.com/n-delic/decompdecomp): the functions of the game's
firmware (FA) and of its game modules are cut out of your copy of the game and compared with what `src/` compiles
to, function by function, with objdiff.

1. Put your own copy of the game in `orig/{version}/` (its disc image, or the disc's files; never commit it), then
   `python tools/extract.py {version}`.
2. `python tools/configure.py {version} --gcc <GCC 3.2.3 for ARM's folder>`, then `ninja`.
3. Decompiled code goes in `src/` (`src/FA/` for the firmware, `src/<module>/` for each game module); `objdiff.json`
   shows each function's progress in [objdiff](https://github.com/encounter/objdiff).

Compiler: GCC 3.2.3 for ARM (arm-elf) with binutils 2.14; `GCC_FLAGS` in tools/configure.py are what most of the
game was built with, and `config/{version}/flags.json` holds the flags of files built otherwise (the maths library
with `-O1`). `config/{version}/functions.json` holds what the analysis found: every function's address, size, symbol
and relocations.
""", encoding="utf-8")
    if shutil.which("git"):
        for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "-c", "user.name=decompdecomp", "-c", "user.email=noreply@decompdecomp.invalid", "commit",
                     "-q", "-m", f"Start the {info['title']} decompilation (decompdecomp, Ghidra)"]):
            subprocess.run(cmd, cwd=root, capture_output=True, creationflags=NO_WINDOW)
    return {"platform": "vflash", "id": version, "title": info["title"], "compiler": TOOLCHAIN, "sources": len(groups),
            "sha1": info["sha1"]}


# ---------------------------------------------------------------------------------------------------- flags, file by file


def _settings(fp) -> tuple[list[str], list[str], str] | None:
    """(GCC_FLAGS, CXX_FLAGS, the text) of the project's tools/configure.py; None when it isn't ours."""
    try:
        text = (Path(fp.root) / "tools" / "configure.py").read_text(encoding="utf-8")
        flags, cxx = GCC_FLAGS_AT.search(text), CXX_FLAGS_AT.search(text)
        return (list(ast.literal_eval(flags.group(1))), list(ast.literal_eval(cxx.group(1))), text) \
            if flags and cxx else None
    except (OSError, ValueError, SyntaxError):
        return None


def _flags_file(fp) -> Path:
    return Path(fp.root) / "config" / str((fp.manifest or {}).get("version")) / "flags.json"


def _file_extras(fp) -> dict[str, list[str]]:
    try:
        data = json.loads(_flags_file(fp).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def file_flags(fp, source: str) -> tuple[str, list[str]] | None:
    """(the compiler, the flags `source` builds with: GCC_FLAGS, CXX_FLAGS for C++, and its own)."""
    settings = _settings(fp)
    if settings is None:
        return None
    flags, cxx, _ = settings
    own = cxx if Path(source).suffix.lower() in (".cpp", ".cc", ".cxx") else []
    return TOOLCHAIN, [*flags, *own, *_file_extras(fp).get(Path(source).as_posix(), [])]


def build_file_with(fp, unit, text: str, flags: list[str], log=print) -> tuple[Path | None, str]:
    """`text` built as `unit`'s source with `flags`, by the project's own command for its files (build.ninja's cc
    rule), into build/flagsearch/: the project's source and objects stay as they are."""
    try:
        ninja = re.sub(r"\$\n\s+", "", (Path(fp.root) / "build.ninja").read_text(encoding="utf-8"))
    except OSError:
        return None, "build.ninja is missing: build the project once first"
    rule = re.search(r"^rule cc\n  command = (.*)$", ninja, re.M)
    if not rule or "$cflags" not in rule.group(1):
        return None, "this project's build.ninja has no cc rule decompdecomp knows"
    work = Path(fp.root) / "build" / "flagsearch"
    work.mkdir(parents=True, exist_ok=True)
    src = work / (unit.name.replace("/", "_") + Path(unit.source or "x.cpp").suffix)
    out = src.with_suffix(".o")
    src.write_text(text, encoding="utf-8")
    out.unlink(missing_ok=True)
    rel = lambda p: p.relative_to(fp.root).as_posix()  # noqa: E731
    cmd = (rule.group(1).replace("$cflags", shlex.join(flags)).replace("$out", shlex.quote(rel(out)))
           .replace("$in", shlex.quote(rel(src))))
    ok, output = ForkProject(Path(fp.root)).run(["/bin/sh", "-c", cmd], log=lambda *_: None, timeout=300)
    return (out if ok and out.exists() else None), output


def set_file_flags(fp, source: str, flags: list[str]) -> str:
    """Build `source` with `flags` (all of them, as file_flags gives them) from now on: what GCC_FLAGS and CXX_FLAGS
    don't have goes in flags.json. Returns flags.json's path in the project."""
    settings = _settings(fp)
    if settings is None:
        raise ForkError("this project's tools/configure.py isn't one decompdecomp made: change its flags there")
    base, cxx, _ = settings
    data = _file_extras(fp)
    have = [*base, *(cxx if Path(source).suffix.lower() in (".cpp", ".cc", ".cxx") else [])]
    extra = [f for f in flags if f not in have]
    key = Path(source).as_posix()
    if extra:
        data[key] = extra
    else:
        data.pop(key, None)
    path = _flags_file(fp)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path.relative_to(fp.root).as_posix()


# ---------------------------------------------------------------------------------------------------- names and data


def real_names(root: Path, version: str) -> dict[str, str]:
    """config/<version>/names.json: the game's symbols given a real name, by their name by address."""
    try:
        names = json.loads((root / "config" / version / "names.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return names if isinstance(names, dict) else {}


_INFO: dict[str, tuple[int, dict]] = {}  # functions.json by path: (its time, its contents)


def _info(root: Path, version: str) -> dict:
    """config/<version>/functions.json, read again only when it changed (a whole game's is tens of MB, and every
    draft and read_data asks)."""
    path = root / "config" / version / "functions.json"
    when = path.stat().st_mtime_ns
    have = _INFO.get(str(path))
    if have is None or have[0] != when:
        if len(_INFO) > 8:
            _INFO.clear()
        have = _INFO[str(path)] = (when, json.loads(path.read_text(encoding="utf-8")))
    return have[1]


def rename(root: Path, version: str, old: str, new: str) -> dict[Path, str]:
    """rename_symbol on a V.Flash project: names.json gives the function or data `old` (its name by address, or the
    real name it has) the real name `new`. Returns names.json, with what it held before."""
    if _NAME.search(new):
        raise ForkError(f"{new} holds an address (func_/D_ and 8 digits): tools/names.py would pair it by that "
                        "address, with whatever's there: pick a name without one")
    if not re.fullmatch(r"[A-Za-z_]\w*", new):
        raise ForkError(f"{new} isn't a C name")
    info = _info(root, version)
    names = real_names(root, version)
    key: dict[str, str] = {}  # every symbol of the game -> its name by address
    for fns in info["units"].values():
        for f in fns:
            key[f["name"]] = f["name"]
            for r in f["relocs"]:
                if r[2]:
                    key[r[2]] = r[2]
    for was, real in names.items():
        key[real] = was
    if _NAME.fullmatch(old) and old.startswith("D_"):  # data only the source names
        key.setdefault(old, old)
    at = key.get(old)
    if at is None:
        raise ForkError(f"{old} isn't one of the game's functions or data")
    if at in names and old != names[at]:
        raise ForkError(f"{old} is called {names[at]} now: rename {names[at]}")
    if new in key:
        raise ForkError(f"{new} is a symbol of the game already")
    path = root / "config" / version / "names.json"
    before = path.read_text(encoding="utf-8") if path.exists() else "{}\n"
    names[at] = new
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(dict(sorted(names.items())), indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return {path: before}


def address_of(root: Path, version: str, name: str) -> tuple[str, int] | None:
    """(program, address) of a function or data named by address (func_10A715C4, D_GZ1A_10614000) or by a real
    name."""
    for was, real in real_names(root, version).items():
        if real == name:
            name = was
            break
    m = _NAME.fullmatch(name.strip())
    return (m.group(2) or "FA", int(m.group(3), 16)) if m else None


def function_asm(root: Path, unit: str, symbol: str) -> str | None:
    """A function's assembly, as m2c reads it (asm.py), from the program the project cut it from."""
    from . import asm

    try:
        manifest = json.loads((root / ".decomp.wtf.json").read_text(encoding="utf-8"))
        info = _info(root, str(manifest.get("version")))
        fn = next((f for f in info["units"].get(unit, []) if f["name"] == symbol), None)
        if fn is None:
            return None
        with open(root / info["programs"][unit.split("/", 1)[0]]["elf"], "rb") as f:
            f.seek(fn["offset"])
            code = f.read(fn["size"])
    except (OSError, ValueError, KeyError):
        return None
    return asm.function_asm(symbol, code, fn["addr"], fn["relocs"])


_IMAGES: dict[tuple[str, int], tuple[list[tuple[int, int, int]], bytes, int, int]] = {}


def _program(root: Path, info: dict, program: str):
    """(regions as (address, size, offset), the ELF's bytes, BSS start, BSS size) of a program of the project."""
    p = info["programs"][program]
    path = root / p["elf"]
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _IMAGES:
        if len(_IMAGES) > 32:
            _IMAGES.clear()
        data = path.read_bytes()
        count = struct.unpack_from("<H", data, 44)[0]
        spans, bss = [], (0, 0)
        for i in range(count):
            _, off, addr, _, filesz, memsz, _, _ = struct.unpack_from("<8I", data, 52 + 32 * i)
            if filesz:
                spans.append((addr, filesz, off))
            else:
                bss = (addr, memsz)
        _IMAGES[key] = (spans, data, *bss)
    return _IMAGES[key]


def _read(root: Path, info: dict, program: str, addr: int, n: int) -> tuple[bytes, str] | None:
    """(bytes at an address of a program, what part of it they're in), or None when it has no such address."""
    spans, data, bss, bss_size = _program(root, info, program)
    for a, size, off in spans:
        if a <= addr < a + size:
            return data[off + addr - a:off + min(addr - a + n, size)], f"{program} 0x{a:08X}+0x{addr - a:X}"
    if bss <= addr < bss + bss_size:
        return b"", f"{program}'s BSS"
    return None


def read_data(root: Path, manifest: dict, name: str, length: int = READ_DEFAULT_BYTES) -> str:
    """What read_data shows on a V.Flash project: the bytes at a D_<address> (FA's) or D_<module>_<address> in the
    user's copy, the addresses its words point to, and a string when it reads as one."""
    version = str(manifest.get("version"))
    where = address_of(root, version, name)
    if where is None and (m := re.fullmatch(r"(?:0x)?([0-9A-Fa-f]{6,8})", name.strip())):
        where = ("FA", int(m.group(1), 16))
    if where is None:
        raise ForkError(f"`{name}` isn't data by address or by a real name: V.Flash data is named D_<address> "
                        "(FA's) or D_<module>_<address> until it's renamed")
    program, addr = where
    info = _info(root, version)
    if program not in info["programs"]:
        raise ForkError(f"{program} isn't a program of this game: FA or one of its modules ({', '.join(info['programs'])})")
    n = max(READ_MIN_BYTES, min(int(length or READ_DEFAULT_BYTES), READ_MAX_BYTES))
    found = _read(root, info, program, addr, n)
    if found is None and program != "FA":
        program, found = "FA", _read(root, info, "FA", addr, n)
    if found is None:
        raise ForkError(f"0x{addr:08X} isn't in {program}'s data")
    data, part = found
    out = [f"{name} ({part}, {n} bytes)"]
    if not data:
        return out[0] + ": uninitialized data (BSS), zeros at start-up."
    for i in range(0, len(data), HEX_ROW_BYTES):
        chunk = data[i:i + HEX_ROW_BYTES]
        out.append(f"  +0x{i:03X}: {chunk.hex(' '):<47}  {''.join(chr(c) if c in PRINTABLE else '.' for c in chunk)}")
    words = [w for (w,) in struct.iter_unpack("<I", data[:len(data) // 4 * 4])]
    ptrs = [(4 * i, w) for i, w in enumerate(words) if _read(root, info, program, w, 1) is not None
            or (program != "FA" and _read(root, info, "FA", w, 1) is not None)]
    if ptrs:
        out.append("pointers in it: " + ", ".join(f"+0x{at:X} -> 0x{w:08X}" for at, w in ptrs[:POINTERS_SHOWN]))
    text = data.split(b"\0", 1)[0]
    if len(text) >= MIN_STRING_CHARS and all(c in PRINTABLE or c in b"\t\n" for c in text):
        out.append(f"as a string: {json.dumps(text.decode('latin-1'))}")
    return "\n".join(out)


def data_bytes(root: Path, manifest: dict, addr: int, length: int) -> bytes | None:
    """The bytes at an address of FA (the modules share theirs: which one a diff is about isn't known here)."""
    try:
        info = _info(root, str(manifest.get("version")))
        found = _read(root, info, "FA", addr, length)
    except (OSError, ValueError, KeyError):
        return None
    return found[0] if found and len(found[0]) == length else None


ASM_CHECK = 1  # set_aside's version, in each function it checked: a better check (a bigger number) looks again


def set_aside(net, proj, fp, version: str, reason) -> int:
    """The project's open functions whose original code `reason` says no compiler makes (Console.asm_reason) get
    status 'asm', with that reason. Each is checked once (its meta says so). How many."""
    try:
        info = _info(Path(fp.root), version)
    except (OSError, ValueError):
        return 0
    where = {f["name"]: (u.split("/", 1)[0], f["offset"], f["size"]) for u, fns in info["units"].items() for f in fns}
    images: dict[str, bytes] = {}
    n, checked = 0, []
    for r in net.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND status='open'", proj["id"]):
        meta = json.loads(r["meta"] or "{}")
        if meta.get("asm_check") == ASM_CHECK:
            continue
        at = where.get(meta.get("symbol") or r["name"])
        if at is None:
            continue
        program, off, size = at
        if program not in images:
            try:
                images[program] = (Path(fp.root) / info["programs"][program]["elf"]).read_bytes()
            except (OSError, KeyError):
                continue
        meta["asm_check"] = ASM_CHECK
        if (why := reason(images[program][off:off + size])):
            net.forks.mark_asm({**dict(r), "meta": json.dumps(meta)}, reason=why)
            n += 1
        else:
            checked.append((json.dumps(meta), r["id"]))
    if checked:
        with net.store.tx() as db:
            db.executemany("UPDATE functions SET meta=? WHERE id=?", checked)
    return n
