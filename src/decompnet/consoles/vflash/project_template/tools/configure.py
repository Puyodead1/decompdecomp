#!/usr/bin/env python3
"""Write build.ninja and objdiff.json for this V.Flash decompilation, then run `ninja`.

    python tools/configure.py VERSION --gcc DIR

The build cuts every function of the game's firmware (FA) and game modules out of your copy of them (orig/, see
config/VERSION/functions.json) into objects, one per source file (tools/delink.py), and compiles src/ with the
game's GCC 3.2.3 for ARM. objdiff.json (for objdiff and decompdecomp) compares every source file's functions with the
original's. Made by decompdecomp.
"""

import argparse
import io
import json
import os
import shlex
import sys
from pathlib import Path

import ninja_syntax

# Settings (decompdecomp wrote these from what the game's code is known to be built with; flags for one file go in
# config/VERSION/flags.json, after these: GCC takes the last of a kind)
GCC_FLAGS = ["-O3", "-mcpu=arm9tdmi", "-fomit-frame-pointer", "-mno-apcs-frame", "-msoft-float"]
# C++ (.cpp): the game's has no run-time type information; -fpermissive takes C's ways (arithmetic on a void *, a
# void * to another pointer) as warnings, which machine drafts are full of, and makes the same code either way
CXX_FLAGS = ["-fno-rtti", "-fpermissive"]

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
parser = argparse.ArgumentParser(description="Writes build.ninja and objdiff.json")
parser.add_argument("version", help="game version (a directory in config/)")
parser.add_argument("--gcc", required=True, help="GCC 3.2.3 for ARM's folder (holds bin/arm-elf-gcc)")
args = parser.parse_args()

VERSION = args.version
CONFIG = Path("config") / VERSION / "functions.json"
FLAGS = Path("config") / VERSION / "flags.json"  # {"src/..": [flags]}
BUILD = Path("build") / VERSION
PY = shlex.quote(sys.executable).replace("$", "$$")
CXX = (".cpp", ".cc", ".cxx")


def files(top: str, suffixes: tuple[str, ...]) -> list[Path]:
    return sorted(p for p in Path(top).rglob("*") if p.suffix.lower() in suffixes)


def folders(*tops: str) -> list[str]:
    """These folders and every folder in them: build.ninja depends on them, not on every file (a folder changes when
    a file is added or removed, which is when build.ninja must change)."""
    return sorted(str(p) for t in tops if Path(t).is_dir() for p in [Path(t), *Path(t).rglob("*")] if p.is_dir())


def write(path: str, text: str) -> None:
    """Whole or not at all: ninja can't read a half-written build.ninja."""
    tmp = Path(path + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def source_of(unit: str) -> str:
    """A unit's source file: C++ (.cpp) unless it was made C (.c)."""
    cpp = Path("src") / f"{unit}.cpp"
    return cpp.as_posix() if cpp.exists() or not cpp.with_suffix(".c").exists() else cpp.with_suffix(".c").as_posix()


def main() -> None:
    units = json.loads(CONFIG.read_text(encoding="utf-8"))["units"]
    file_flags = json.loads(FLAGS.read_text(encoding="utf-8")) if FLAGS.exists() else {}
    headers = [str(p) for p in files("include", (".h", ".hpp"))]
    f = io.StringIO()
    n = ninja_syntax.Writer(f)
    n.rule("delink", f"{PY} tools/delink.py {CONFIG} {BUILD / 'target'}", restat=True)
    compile_ = [sys.executable, "tools/compile.py", "--gcc", args.gcc, "--config", str(CONFIG)]
    n.rule("cc", shlex.join(compile_).replace("$", "$$") + " --output $out --source $in -- $cflags")
    n.rule("configure", f"{PY} tools/configure.py " + shlex.join(sys.argv[1:]).replace("$", "$$"), generator=True)
    # `ninja rebuild`: the game's programs rebuilt in place from what's matched, and compared with your copy
    n.rule("rebuild", f"{PY} tools/rebuild.py {VERSION} --check")

    targets = [str(BUILD / "target" / f"{u}.o") for u in units]
    # names.json (real names, rename_symbol's) cuts the original's objects again; a source file compiles again when
    # it changes, and a rename changes every file that uses the name, so compiles don't wait on it
    names = CONFIG.with_name("names.json")
    n.build(targets, "delink", [str(CONFIG), "tools/delink.py", "tools/names.py", *([str(names)] if names.exists() else [])])
    objs = []
    for src in files("src", (".c", *CXX)):
        obj = BUILD / src.with_suffix(".o")
        flags = [*GCC_FLAGS, *(CXX_FLAGS if src.suffix.lower() in CXX else []), *file_flags.get(src.as_posix(), [])]
        n.build(str(obj), "cc", str(src), implicit=[*headers, str(CONFIG), "tools/compile.py", "tools/names.py"],
                variables={"cflags": shlex.join(flags)})
        objs.append(str(obj))
    n.build("all_source", "phony", objs)
    n.build("prepare", "phony", [*targets, *objs])
    n.build("build.ninja", "configure", ["tools/configure.py", str(CONFIG), *folders("src", "include"), str(CONFIG.parent),
                                         *([str(FLAGS)] if FLAGS.exists() else [])])
    n.build("rebuild", "rebuild", implicit=["prepare", "tools/rebuild.py"])
    n.default(["prepare"])

    objdiff = {
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "custom_make": "ninja", "custom_args": [], "build_target": False, "build_base": True,
        "watch_patterns": ["*.c", "*.cpp", "*.h", "*.hpp"],
        # each function's section on its own: combined, objdiff left the mapping symbols ($d: a literal pool's
        # relocated words) where they were in their own sections, and read every function after the first as code
        # from the wrong place (40% for functions identical byte for byte)
        "options": {"combineTextSections": False},
        "units": [{"name": u, "target_path": str(BUILD / "target" / f"{u}.o"),
                   "base_path": str(BUILD / Path(source_of(u)).with_suffix(".o")),
                   "metadata": {"source_path": source_of(u), "complete": False}} for u in units],
    }
    write("objdiff.json", json.dumps(objdiff, indent=2))
    write("build.ninja", f.getvalue())  # last: the moment it changes, ninja takes this run as done


if __name__ == "__main__":
    main()
