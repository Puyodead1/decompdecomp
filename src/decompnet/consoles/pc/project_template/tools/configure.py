#!/usr/bin/env python3
"""Write build.ninja and objdiff.json for this PC (Windows) decompilation, then run `ninja`.

    python tools/configure.py VERSION --msvc DIR [--msvc DIR ...] [--wibo PATH] [--own VERSION=RUNNER,CL,INCLUDE]

The build cuts every function out of your copy of the game (orig/, see config/VERSION/functions.json) into objects,
one per source file (tools/delink.py), and compiles src/ with the game's Visual C++ (run through wibo on Linux and
macOS, Visual C++ 2015 and newer through wine, which wibo can't run them on: the build finds wine and its prefix in
$DECOMPNET_WINE and $DECOMPNET_WINE_PREFIX, and the packs wine runs in $DECOMPNET_WINE_PACKS, which decompdecomp
sets): each file with its own version when config/VERSION/file_compilers.json names one, and with the more flags
config/VERSION/file_flags.json gives it (/Oy-: the frame pointer kept). objdiff.json (for objdiff and decompdecomp)
compares every source file's functions with the original's. `ninja rebuild` puts the whole program back together from
them (tools/rebuild.py) and checks it against your copy; `ninja relink` links it again with Visual C++ 6.0's linker
(tools/relink.py: code can change size and the rest moves with it; run it yourself for its options, --all-c and
--pad). Without your copy of the game, a project with its program as source (source/, what decompdecomp's Export
writes: its code as assembly, its data as C) makes it from that first (tools/assemble.py, with Visual C++ 6.0's MASM
and compiler), `ninja reccmp` links it with a PDB for reccmp (github.com/isledecomp/reccmp: reccmp-project.yml, which
Export writes), and `ninja relink-source` links the program from that source alone with the same linker (what you
edited may change size: the rest moves with it); with source/, `ninja relink` takes what isn't from C from it, not
from your copy. A game built with link-time code generation (LTCG = True:
units with a driver in harness/) builds those units through tools/ltcg.py, whose linker runs through wine. Made by
decompdecomp.
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import ninja_syntax

# Settings (decompdecomp wrote these for this game; change them if the game was built differently)
MSVC_VERSION = "6.0"  # every file's, unless config/<version>/file_compilers.json names another for it
CL_FLAGS = ["/nologo", "/c", "/O2", "/W3", "/GX"]  # /GX: C++ exceptions, as games of the time were built
# Link-time code generation (games built with /GL and /LTCG, many Xbox games): a unit whose driver in harness/ defines
# HarnessEntry compiles with CL_FLAGS plus /GL and links in harness mode (tools/ltcg.py, run through wine); the rest
# compile with CL_FLAGS alone.
LTCG = False

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
parser = argparse.ArgumentParser(description="Writes build.ninja and objdiff.json")
parser.add_argument("version", help="game version (a directory in config/)")
parser.add_argument("--msvc", required=True, action="append",
                    help="Visual C++ directory (holds 6.0/Bin/CL.EXE, 10.0SP1/Bin/cl.exe, ...); several: the first "
                         "with MSVC_VERSION")
parser.add_argument("--wibo", default="", help="runs the Windows compilers on Linux and macOS")
parser.add_argument("--own", default=[], action="append",
                    help="a compiler of the user's own (a kit: decompdecomp's kits/): VERSION=RUNNER,CL[,INCLUDE...], "
                         "RUNNER wibo, wine or none")
args = parser.parse_args()
WINE_FROM = 14  # without $DECOMPNET_WINE_PACKS: the first Visual C++ wibo can't run (2015 and newer), which wine runs
# the --msvc folders whose compilers run through wine, not wibo (decompdecomp sets it from its toolchains' `wine`, as
# it sets $DECOMPNET_WINE: an environment variable, not an argument, so no configure.py is given one it doesn't know)
WINE_PACKS = "DECOMPNET_WINE_PACKS"
INCLUDES = "includes.txt"  # in a version's folder: more header folders, relative to it (decompdecomp's toolchains.py)

VERSION = args.version
# the user's own compilers by version: [runner, compiler, header folders...] (decompdecomp names those its kits have;
# a version no --own names is in the --msvc folders)
OWN = {own.split("=", 1)[0]: own.split("=", 1)[1].split(",") for own in args.own}
CONFIG = Path("config") / VERSION / "functions.json"
FILE_COMPILERS = CONFIG.parent / "file_compilers.json"  # {"src/auto/text_00401000.cpp": "7.1"}: files built with another
FILE_FLAGS = CONFIG.parent / "file_flags.json"  # {"src/auto/text_00401000.cpp": ["/Oy-"]}: files built with more flags
BUILD = Path("build") / VERSION
# the header folders of the libraries the game uses, from their own source in libs/ (decompdecomp writes it: one folder
# a line, relative to the project): searched after Visual C++'s own, so `#include <GL/glut.h>` finds GLUT's
LIBRARY_INCLUDES = CONFIG.parent / "library_includes.txt"
LIBRARIES = [line.strip() for line in (LIBRARY_INCLUDES.read_text(encoding="utf-8").splitlines()
                                       if LIBRARY_INCLUDES.exists() else []) if line.strip() and Path(line.strip()).is_dir()]


def q(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv) if sys.platform == "win32" else shlex.join(argv)


# the Python the build's steps run with: on Windows python.exe, not the console-less pythonw.exe (under it, every
# compiler and linker a step starts opens a console window of its own)
_W = Path(sys.executable)
PYTHON = str(_W.with_name("python.exe")) if _W.name.lower() == "pythonw.exe" and _W.with_name("python.exe").is_file() \
    else sys.executable
PY = q([PYTHON]).replace("$", "$$")


def msvc(version: str) -> tuple[str, list[str]]:
    """A Visual C++ version's compiler and its header folders, from the first --msvc folder that has it: its own
    Include, then the ones its includes.txt names (a Windows SDK installed beside the pack), searched in that order."""
    if version in OWN:  # (a compiler of the user's own: an early Xbox game's, its XDK's)
        return OWN[version][1], [*OWN[version][2:], *LIBRARIES]
    homes = [Path(d) / version for d in args.msvc]
    home, cl = next(((h, p) for h in homes for p in (h / "Bin" / "CL.EXE", h / "Bin" / "cl.exe") if p.exists()),
                    (None, None))
    if cl is None:
        sys.exit(f"configure: Visual C++ {version} isn't in {' or '.join(args.msvc)} (file_compilers.json or "
                 "MSVC_VERSION)")
    more = home / INCLUDES
    lines = more.read_text(encoding="utf-8").splitlines() if more.exists() else []
    extra = [os.path.normpath(home / line.strip()) for line in lines if line.strip()]
    if missing := [d for d in extra if not Path(d).is_dir()]:
        sys.exit(f"configure: Visual C++ {version}'s headers aren't where {more} says ({missing[0]}): install it again "
                 "in decompdecomp's Compilers & tools")
    return str(cl), [str(home / "Include"), *extra, *LIBRARIES]


def pack_of(version: str) -> Path | None:
    """The --msvc folder a Visual C++ version comes from: the first that has it."""
    return next((Path(d) for d in args.msvc for p in (Path(d) / version / "Bin" / "CL.EXE",
                                                      Path(d) / version / "Bin" / "cl.exe") if p.exists()), None)


def runner(version: str) -> list[str]:
    """What runs a Visual C++ version's compiler here: nothing on Windows, else wibo, or wine for a pack decompdecomp
    says wine runs ($DECOMPNET_WINE_PACKS, folders separated by os.pathsep; without it, the versions from WINE_FROM
    on)."""
    if sys.platform == "win32":
        return []
    if version in OWN:
        runner = OWN[version][0]
        return [] if runner == "none" else ["--wine"] if runner == "wine" else ["--wrapper", args.wibo] if args.wibo else []
    wine_packs = {os.path.normcase(os.path.abspath(d)) for d in os.environ.get(WINE_PACKS, "").split(os.pathsep) if d}
    folder = pack_of(version)
    by_wine = os.path.normcase(os.path.abspath(folder)) in wine_packs if wine_packs and folder is not None else \
        int(version.split(".")[0]) >= WINE_FROM
    if not by_wine:
        return ["--wrapper", args.wibo] if args.wibo else []
    # wine itself is found when the file builds (compile.py: $DECOMPNET_WINE, $DECOMPNET_WINE_PREFIX): build.ninja
    # stays right whether or not wine was there when it was written
    return ["--wine"]


def linker() -> list[str]:
    """tools/relink.py's arguments for the linker it links with: Visual C++ 6.0's LINK.EXE, from the first --msvc folder
    that has it, and what runs it (wibo, off Windows). 6.0's for every game: it links later compilers' objects too,
    and wibo runs 2005's and later linkers only up to their first lstrcmpiW."""
    link = next((p for d in args.msvc for p in (Path(d) / "6.0" / "Bin" / "LINK.EXE",) if p.exists()), None)
    if link is None:
        return ["--link", ""]  # (relink.py says what to install)
    return ["--link", str(link), *(["--wrapper", args.wibo] if args.wibo and sys.platform != "win32" else [])]


def assembler() -> list[str]:
    """tools/assemble.py's arguments for the assembler it makes the program from its source with: Visual C++ 6.0's
    MASM (ml.exe 6.15, in the 6.0 service packs' folders), and what runs it."""
    ml = next((p for d in args.msvc for p in sorted(Path(d).glob("6.0SP*/Bin/ml.exe"), reverse=True)), None)
    if ml is None:
        sys.exit("configure: the program's source is assembled with Visual C++ 6.0's MASM (6.0SP*/Bin/ml.exe): "
                 "install Visual C++ 6.0 in decompdecomp's Setup")
    return ["--ml", str(ml), *(["--wrapper", args.wibo] if args.wibo and sys.platform != "win32" else [])]


def file_compilers() -> dict[str, str]:
    return json.loads(FILE_COMPILERS.read_text(encoding="utf-8")) if FILE_COMPILERS.exists() else {}


def file_flags() -> dict[str, list[str]]:
    return json.loads(FILE_FLAGS.read_text(encoding="utf-8")) if FILE_FLAGS.exists() else {}


def files(top: str, suffixes: tuple[str, ...]) -> list[Path]:
    return sorted(p for p in Path(top).rglob("*") if p.suffix.lower() in suffixes)


def folders(*tops: str) -> list[str]:
    """These folders and every folder in them. build.ninja depends on them, not on every file: a folder changes when
    a file is added to it or removed, which is when build.ninja must change, and not when one is edited (on a big
    game, writing build.ninja again took half a minute, before every compile)."""
    return sorted(p.as_posix() for t in tops if Path(t).is_dir() for p in [Path(t), *Path(t).rglob("*")] if p.is_dir())


def write(path: str, text: str) -> None:
    """Whole or not at all: ninja deletes a build.ninja it was interrupted writing, and a half-written one can't be
    read."""
    tmp = Path(path + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def source_of(unit: str) -> str:
    """A unit's source file: C++ (.cpp), or C (.c) in projects made before decompdecomp wrote C++."""
    cpp = Path("src") / "auto" / f"{unit}.cpp"
    return cpp.as_posix() if cpp.exists() or not cpp.with_suffix(".c").exists() else cpp.with_suffix(".c").as_posix()


def main() -> None:
    info = json.loads(CONFIG.read_text(encoding="utf-8"))
    units = info["units"]
    headers = [p.as_posix() for p in files("include", (".h", ".hpp"))]
    # written aside and put in place whole: a configure that stops half way (a driver it can't read) leaves the last
    # build.ninja, so ninja runs this again and shows why
    with open("build.ninja.tmp", "w", encoding="utf-8") as f:
        n = ninja_syntax.Writer(f)
        n.rule("delink", f"{PY} tools/delink.py {CONFIG.as_posix()} {(BUILD / 'target').as_posix()}", restat=True)
        compiler = [PYTHON, "tools/compile.py", "--config", CONFIG.as_posix()]
        # The runner invokes the compiler and names.py separately: cmd /c misparsed quoted compiler paths.
        # $runner: what runs the file's compiler (wibo, wine or nothing: runner())
        n.rule("cl", q(compiler).replace("$", "$$") + " $runner --compiler $cl $includes --output $out "
               "--source $in -- " + q(CL_FLAGS).replace("$", "$$") + " $cflags")
        n.rule("configure", f"{PY} tools/configure.py " + q(sys.argv[1:]).replace("$", "$$"), generator=True)

        exe = Path(info["exe"]).as_posix()
        # each program of the game's and its source's folder: the .exe's source/, a DLL's source/<its folder>/
        sourced = [(Path(p).as_posix(), Path("source") / m) for m, p in
                   [("", info["exe"]), *((m["name"], m["exe"]) for m in info.get("modules", []))]]
        missing = [(p, s) for p, s in sourced if not Path(p).exists() and (s / "program.json").exists()]
        if missing:
            # no copy of the game here, its program as source (decompdecomp's Export): the program from that
            n.rule("assemble", f"{PY} tools/assemble.py $in $objects " + q(assembler()).replace("$", "$$"))
            # (once: it's your copy from then on, the assembly you edit afterwards doesn't make it again; ninja relink
            # takes those edits)
            for program, folder in missing:
                n.build(program, "assemble", [(folder / "program.json").as_posix()],
                        variables={"objects": (BUILD / folder).as_posix()})
        targets = [(BUILD / "target" / f"{u}.obj").as_posix() for u in units]
        n.build(targets, "delink", [CONFIG.as_posix(), "tools/delink.py"], implicit=[exe])
        objs, debug_objs = [], []
        versions, more = file_compilers(), file_flags()
        harness, harness_files = set(), []
        if LTCG:  # ---- harness mode (tools/ltcg.py, tools/dll2coff.py)
            import ltcg

            def compiler_of(source: str):
                cl, includes = msvc(versions.get(source, MSVC_VERSION))
                return cl, includes, [*CL_FLAGS, *more.get(source, [])]

            harness, harness_files = ltcg.write_rules(
                n, units=list(units), source_of=source_of, build=BUILD, config=CONFIG, compiler_of=compiler_of, py=PY,
                wibo=args.wibo, headers=headers)
            objs += [(BUILD / Path(s).with_suffix(".obj")).as_posix() for s in sorted(harness)]
        # ---- end of harness mode
        for src in files("src", (".c", ".cpp")):
            if src.as_posix() in harness:
                continue
            obj = (BUILD / src.with_suffix(".obj")).as_posix()
            src_posix = src.as_posix()
            version = versions.get(src_posix, MSVC_VERSION)
            cl, includes = msvc(version)
            n.build(obj, "cl", src_posix, implicit=[*headers, CONFIG.as_posix(), "tools/compile.py", "tools/names.py"],
                    variables={"cl": q([cl]).replace("$", "$$"),
                               "includes": q([a for d in includes for a in ("--include", d)]).replace("$", "$$"),
                               "runner": q(runner(version)).replace("$", "$$"),
                               "cflags": q(more.get(src_posix, [])).replace("$", "$$")})
            objs.append(obj)
            # the same with CodeView (/Z7) for `ninja reccmp`: its PDB's lines are how reccmp finds a function of the C
            debug_objs.append((BUILD / "reccmp-src" / src.with_suffix(".obj")).as_posix())
            n.build(debug_objs[-1], "cl", src_posix,
                    implicit=[*headers, CONFIG.as_posix(), "tools/compile.py", "tools/names.py"],
                    variables={"cl": q([cl]).replace("$", "$$"),
                               "includes": q([a for d in includes for a in ("--include", d)]).replace("$", "$$"),
                               "runner": q(runner(version)).replace("$", "$$"),
                               "cflags": q([*more.get(src_posix, []), "/Z7"]).replace("$", "$$")})
        n.build("all_source", "phony", objs)
        n.build("prepare", "phony", [*targets, *objs])
        # the whole program, from what src/ compiles to and the delinked functions (not the default: a build for
        # objdiff needs only the objects)
        # (each program where rebuild.py writes it: the game's DLLs too, functions.json's "modules")
        exes = [Path(info["exe"]).as_posix(), *(Path(m["exe"]).as_posix() for m in info.get("modules", []))]
        programs = [(BUILD / (Path(exe).relative_to("orig") if Path(exe).parts[0] == "orig" else Path(exe).name)).as_posix()
                    for exe in exes]
        n.rule("rebuild", f"{PY} tools/rebuild.py {CONFIG.as_posix()} {BUILD.as_posix()}")
        n.build(programs, "rebuild", [*targets, *objs],
                implicit=[CONFIG.as_posix(), *exes, "tools/rebuild.py", "tools/delink.py"])
        n.build("rebuild", "phony", programs)
        # the program linked again by Visual C++'s own linker from the same objects (tools/relink.py): code can grow
        # and the rest moves with it (not the default either)
        relinked = (BUILD / "relink" / Path(info["exe"]).name).as_posix()
        # (with the program as source, source/: what isn't from C comes from it, the assembly you edited, not your copy)
        source = Path("source/program.json").exists()
        asm = sorted(p.as_posix() for pattern in ("*.asm", "*.c", "*.h") for p in Path("source").rglob(pattern)) \
            if source else []  # (its assembly, and its data as C)
        n.rule("relink", f"{PY} tools/relink.py {CONFIG.as_posix()} {BUILD.as_posix()} "
               + q([*linker(), *(["--asm", "source", *assembler()] if source else [])]).replace("$", "$$"))
        n.build([relinked, *((BUILD / "relink" / Path(m["exe"]).name).as_posix() for m in info.get("modules", []))],
                "relink", [*targets, *objs], implicit=[CONFIG.as_posix(), *exes, "tools/relink.py", "tools/rebuild.py",
                                                       "tools/delink.py", *asm,
                                                       *(["tools/assemble.py"] if source else [])])
        n.build("relink", "phony", [relinked])
        # the same with a PDB, into build/<version>/reccmp/: what reccmp compares with your copy (reccmp-build.yml,
        # which Export writes with reccmp-project.yml); /DEBUG adds a debug directory, so not `ninja relink`'s
        compared = (BUILD / "reccmp" / Path(info["exe"]).name).as_posix()
        n.rule("reccmp", f"{PY} tools/relink.py {CONFIG.as_posix()} {BUILD.as_posix()} --pdb "
               + q([*linker(), *(["--asm", "source", *assembler()] if source else [])]).replace("$", "$$"))
        n.build([compared, *((BUILD / "reccmp" / Path(m["exe"]).name).as_posix() for m in info.get("modules", []))],
                "reccmp", [*targets, *objs, *debug_objs], implicit=[CONFIG.as_posix(), *exes, "tools/relink.py", "tools/rebuild.py",
                                                       "tools/delink.py", *asm,
                                                       *(["tools/assemble.py"] if source else [])])
        n.build("reccmp", "phony", [compared])
        if source:
            # the program linked by the same linker from its source alone (tools/assemble.py --link), no C: assembly
            # you edited may make a function longer or shorter, and the rest moves with it
            n.rule("relink_source", f"{PY} tools/assemble.py $in $objects --out $out "
                   + q([*assembler(), *linker()]).replace("$", "$$"))
            made = []
            for program, folder in sourced:  # (each DLL's too, where Export wrote its source)
                if (folder / "program.json").exists():
                    made.append((BUILD / "relink-source" / Path(program).name).as_posix())
                    n.build(made[-1], "relink_source", [(folder / "program.json").as_posix()],
                            implicit=[*asm, "tools/assemble.py", "tools/relink.py", "tools/delink.py"],
                            variables={"objects": (BUILD / folder).as_posix()})
            n.build("relink-source", "phony", made)
        # the source folders, not each file: on a game of 9,608 files every edit rewrote build.ninja (20-37 s)
        n.build("build.ninja", "configure", ["tools/configure.py", CONFIG.as_posix(), *folders("src", "include"),
                                             *[p.as_posix() for p in (FILE_COMPILERS, FILE_FLAGS, LIBRARY_INCLUDES)
                                               if p.exists()],
                                             *harness_files])
        n.default(["prepare"])

    objdiff = {
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "custom_make": "ninja", "custom_args": [], "build_target": False, "build_base": True,
        "watch_patterns": ["*.c", "*.cpp", "*.h", "*.hpp"],
        "units": [{"name": u, "target_path": (BUILD / "target" / f"{u}.obj").as_posix(),
                   "base_path": (BUILD / "src" / "auto" / f"{u}.obj").as_posix(),
                   "metadata": {"source_path": source_of(u), "complete": False}} for u in units],
    }
    write("objdiff.json", json.dumps(objdiff, indent=2))
    os.replace("build.ninja.tmp", "build.ninja")  # last: the moment it changes, ninja takes this run as done


if __name__ == "__main__":
    main()
