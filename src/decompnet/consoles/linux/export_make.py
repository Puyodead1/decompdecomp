"""A Linux export's own build: a Makefile, the compiler's command as decompdecomp runs it (tools/cc.sh), the script
that downloads that compiler from the archives decompdecomp pins (tools/toolchain.sh) and tools/relink.py (Python's
standard library only). Building the program needs neither decompdecomp nor its sandbox: make and python3."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

MAKEFILE = """\\
# Builds {program} from this tree's C.
#   make              build/plain/{program}: the C as plain source, compiled by the system's gcc (CC, CFLAGS) with
#                     NON_MATCHING defined and linked against the system's libraries (LDLIBS){plain_note}
#   make asan         build/asan/{program}: the same, with AddressSanitizer (reads past a variable, reported and
#                     carried on from: ASAN_OPTIONS=halt_on_error=0)
#   make match        build/{program}: the program linked anew from the C with the compiler it was built with, its
#                     code GCC 2.95's, byte for byte the original's (`python build.py` checks it); the first time,
#                     the compiler is downloaded into tools/ (`make toolchain`)
#   make move         the same, its data laid out after the code too
#   make toolchain    the compiler into tools/ (pinned downloads, each checked against its SHA-256)
#   make port         build/port/{program}: the C built by the system's GCC (PORT_CC, PORT_FLAGS: no matching
#                     there) against the program's own C library headers from the toolchain, linked as `make match`
#                     links it, its variables where the program has them
# The matching builds need make, python3, curl or wget, tar and ar; `python build.py` (with decompdecomp installed)
# checks that the C still rebuilds your copy byte for byte.
PROGRAM := {program}
TOOLCHAIN := {toolchain}
TC ?= tools/$(TOOLCHAIN)
PY ?= python3
export TC
MATCH_CC := sh tools/cc.sh $(abspath $(TC))
AS := $(abspath $(TC))/binutils/usr/bin/as
LD := $(abspath $(TC))/binutils/usr/bin/ld
export LD_LIBRARY_PATH := $(abspath $(TC))/binutils/usr/lib:$(abspath $(TC))/lib
PRELUDE := {prelude}
HEADERS := $(wildcard include/*.h)
TOOLCHAIN_READY := $(TC)/crt/crt1.o
STUBS := build/relink/stubs
PORT_CC ?= gcc -m32
PORT_FLAGS ?= -O2 -std=gnu89 -fno-pie -fno-pic -fno-stack-protector -fcf-protection=none -fcommon \\
  -fno-strict-aliasing -fdata-sections -fno-toplevel-reorder -Wall -nostdinc -isystem $(shell $(PORT_CC) -print-file-name=include) -I$(abspath $(TC))/include
PORT_STUBS := build/port/stubs

# the plain build: every source file, compiled and linked as any C program is
CC ?= gcc
CFLAGS ?= -O2
PLAIN_FLAGS := -m32 -std=gnu89 -fno-pie -fcommon -fno-strict-aliasing -DNON_MATCHING
LDLIBS ?= {ldlibs}
SOURCES := {sources}
ASSEMBLY := {assembly}
PLAIN_OBJS := $(patsubst src/%.c,build/plain/%.o,$(SOURCES)) $(patsubst src/%.s,build/plain/%.o,$(ASSEMBLY))
ASAN_OBJS := $(patsubst build/plain/%,build/asan/%,$(PLAIN_OBJS))
ASAN_FLAGS := -g -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer

all: {default}

build/plain/$(PROGRAM): $(PLAIN_OBJS)
\t$(CC) -m32 -no-pie $(LDFLAGS) -o $@ $(PLAIN_OBJS) $(LDLIBS)
build/plain/%.o: src/%.c $(HEADERS)
\t@mkdir -p $(dir $@)
\t$(CC) $(PLAIN_FLAGS) $(CFLAGS) -Iinclude -iquote $(dir $<) -c $< -o $@
build/plain/%.o: src/%.s
\t@mkdir -p $(dir $@)
\t$(CC) -m32 -c $< -o $@

asan: build/asan/$(PROGRAM)
build/asan/$(PROGRAM): $(ASAN_OBJS)
\t$(CC) -m32 -no-pie $(ASAN_FLAGS) $(LDFLAGS) -o $@ $(ASAN_OBJS) $(LDLIBS)
build/asan/%.o: src/%.c $(HEADERS)
\t@mkdir -p $(dir $@)
\t$(CC) $(PLAIN_FLAGS) $(CFLAGS) $(ASAN_FLAGS) -Iinclude -iquote $(dir $<) -c $< -o $@
build/asan/%.o: src/%.s
\t@mkdir -p $(dir $@)
\t$(CC) -m32 -c $< -o $@

match: build/$(PROGRAM)

toolchain: $(TOOLCHAIN_READY)
$(TOOLCHAIN_READY):
\tsh tools/toolchain.sh $(TC)

build/relink build/port:
\tmkdir -p $@

# (after the toolchain: which functions its libc_nonshared.a brings decides the rules; written whole or not at all,
# an empty one left by a failure was never made again)
build/rules.mk: build.json tools/relink.py $(wildcard src/*.c src/*/*.c) $(wildcard asm/*.s) | build/relink $(TOOLCHAIN_READY)
\t$(PY) tools/relink.py rules > $@.tmp
\tmv $@.tmp $@
-include build/rules.mk

data/program.s: | $(OBJS) $(TOOLCHAIN_READY)
\t$(PY) tools/relink.py data $@

build/relink/data.o: data/program.s | $(TOOLCHAIN_READY)
\t$(AS) -o $@ data/program.s

$(STUBS)/stubs.txt: build.json $(OBJS) | build/relink $(TOOLCHAIN_READY)
\t$(PY) tools/relink.py stubs $(STUBS)
\twhile read lib stem; do \\
\t  $(MATCH_CC) $(STUBS)/$$stem.c $(STUBS)/$$stem.o -fPIC -O0 -fno-builtin || exit 1; \\
\t  map=; [ -s $(STUBS)/$$stem.map ] && map="--version-script $(STUBS)/$$stem.map"; \\
\t  $(LD) -m elf_i386 -shared -soname $$lib $$map -o $(STUBS)/$$lib $(STUBS)/$$stem.o || exit 1; \\
\tdone < $(STUBS)/stubs.txt

build/$(PROGRAM): $(OBJS) {data_o}$(STUBS)/stubs.txt
\t$(PY) tools/relink.py link $@

move: $(OBJS) {data_o}$(STUBS)/stubs.txt
\t$(PY) tools/relink.py link build/$(PROGRAM) move

# the port's own stubs: a newer GCC calls what the program never imported (puts for printf, sincos)
$(PORT_STUBS)/stubs.txt: build.json $(PORT_OBJS) | build/port $(TOOLCHAIN_READY)
\tOBJDIR=build/port $(PY) tools/relink.py stubs $(PORT_STUBS)
\twhile read lib stem; do \\
\t  $(MATCH_CC) $(PORT_STUBS)/$$stem.c $(PORT_STUBS)/$$stem.o -fPIC -O0 -fno-builtin || exit 1; \\
\t  map=; [ -s $(PORT_STUBS)/$$stem.map ] && map="--version-script $(PORT_STUBS)/$$stem.map"; \\
\t  $(LD) -m elf_i386 -shared -soname $$lib $$map -o $(PORT_STUBS)/$$lib $(PORT_STUBS)/$$stem.o || exit 1; \\
\tdone < $(PORT_STUBS)/stubs.txt

port: build/port/$(PROGRAM)
build/port/$(PROGRAM): $(PORT_OBJS) {data_o}$(PORT_STUBS)/stubs.txt
\tOBJDIR=build/port $(PY) tools/relink.py link $@

clean:
\trm -r -f build/relink build/port build/rules.mk build/rules.mk.tmp build/$(PROGRAM)

.PHONY: all asan match toolchain move port clean
.DELETE_ON_ERROR:
"""

TOOLCHAIN_SH = """\
#!/bin/sh
# Downloads the compiler this program was built with into $1 (default tools/{toolchain}): the archives decompdecomp
# pins, each checked against its SHA-256 before it's unpacked. Where the system has no 32-bit loader, a 32-bit C
# runtime comes too, and the compiler's programs start through it.
set -e
DEST=${{1:-tools/{toolchain}}}
DL=tools/.downloads
mkdir -p "$DL" "$DEST"
fetch() {{
  if [ ! -f "$DL/$3" ]; then
    curl -fL -o "$DL/$3.part" "$1" 2>/dev/null || wget -O "$DL/$3.part" "$1"
    mv "$DL/$3.part" "$DL/$3"
  fi
  echo "$2  $DL/$3" | sha256sum -c - >/dev/null || {{ echo "$3: its SHA-256 isn't the pinned one" >&2; exit 1; }}
}}
unpack() {{  # archive, the folder in it (or .), where it goes in $DEST
  tmp=$(mktemp -d)
  here=$(pwd)
  case "$1" in
    *.deb) (cd "$tmp" && ar x "$here/$DL/$1" && tar -xf data.tar.* && rm -f data.tar.* control.tar.* debian-binary) ;;
    *.rpm) (cd "$tmp" && rpm2cpio "$here/$DL/$1" | cpio -idm --quiet) ;;
    *) tar -xf "$DL/$1" -C "$tmp" ;;
  esac
  mkdir -p "$DEST/$3"
  cp -a "$tmp/$2/." "$DEST/$3/"
  [ -n "$tmp" ] && [ -d "$tmp" ] && rm -r -- "$tmp"
}}
{parts}
if [ ! -e /lib/ld-linux.so.2 ]; then
{runtime}
  python3 tools/relink.py wrap "$DEST" "$DEST/runtime"
fi
echo "$DEST: ready"
"""


def write(out: Path, build: dict) -> None:
    from ... import toolchains

    tid = build.get("toolchain") or "gcc-2.95.3-linux"
    tc = toolchains.registry()[tid]
    tools = out / "tools"
    tools.mkdir(exist_ok=True)
    shutil.copyfile(Path(__file__).with_name("export_relink.py"), tools / "relink.py")
    if not (tc.cmd and tc.cmd[:2] == ["/bin/sh", "-c"]):
        return  # (a compiler run otherwise: build.py's relink only)
    (tools / "cc.sh").write_text("#!/bin/sh\n# compile one C file as decompdecomp does: cc.sh TOOLCHAIN SOURCE OBJECT "
                                 f"FLAGS...\n{tc.cmd[2]}\n", encoding="utf-8")
    prelude = ""
    if tc.prelude:
        (tools / "prelude.h").write_text(tc.prelude, encoding="utf-8")
        prelude = "-include tools/prelude.h"

    def lines(parts, base: str = "") -> list[str]:
        out_lines = []
        for part in parts:
            name = part.get("file") or part["url"].rsplit("/", 1)[-1].split("?")[0]
            into = f"{base}{part.get('into', '')}" or "."
            out_lines += [f"fetch '{part['url']}' {part['sha256']} '{name}'",
                          f"unpack '{name}' '{part.get('subdir') or '.'}' '{into}'"]
        return out_lines
    linux = [p for p in tc.parts_for("linux-x86_64") if not p.get("build") and not p.get("binary")]
    runtime = toolchains.registry().get("runtime-i386")
    # (Debian's 32-bit C runtime: a .deb, which ar and tar unpack; the other is zstd)
    portable = [p for p in (runtime.parts if runtime else []) if "wsl-x86_64" in (p.get("platforms") or [])]
    runtime_lines = [f"  {line}".replace("'runtime/'", "'runtime'") for line in lines(
        [{**p, "into": ""} for p in portable], "runtime/")]
    (tools / "toolchain.sh").write_text(TOOLCHAIN_SH.format(toolchain=tid, parts="\n".join(lines(linux)),
                                                            runtime="\n".join(runtime_lines) or "  :"),
                                        encoding="utf-8")
    # (a tree whose code and data are all source links no data of your copy's: data/program.s isn't made)
    data_o = "" if build.get("standalone") else "build/relink/data.o "
    sources = list(dict.fromkeys([u["c"] for u in build.get("units") or [] if u.get("c")]
                                 + [f["c"] for f in build["functions"] if f.get("c")]
                                 + [d["c"] for d in build.get("data_files") or [] if d.get("c")]))
    assembly = list(dict.fromkeys(f["s"] for f in build["functions"] if (f.get("s") or "").startswith("src/")))
    standalone = bool(build.get("standalone"))
    (out / "Makefile").write_text(MAKEFILE.format(
        program=build["program"], toolchain=tid, prelude=prelude, data_o=data_o, ldlibs=libraries(build),
        sources=" \\\n  ".join(sources), assembly=" \\\n  ".join(assembly),
        default="build/plain/$(PROGRAM)" if standalone else "build/$(PROGRAM)",
        plain_note="" if standalone else (
            "\n#                     (not yet the default: what isn't source yet is your copy's, which only the matching "
            "build\n#                     links; `make` builds build/{0} as `make match` does)".format(build["program"]))),
        encoding="utf-8")


def libraries(build: dict) -> str:
    """The plain link's libraries: what the program asked the loader for (libGL.so.1 is -lGL), the C library being
    the compiler's own."""
    needed = (build.get("imports") or {}).get("needed") or []
    out = []
    for lib in needed:
        m = re.fullmatch(r"lib(.+?)\.so(?:\.[\d.]+)?", lib)
        if m and m.group(1) != "c":
            out.append(f"-l{m.group(1)}")
    return " ".join(reversed(out))  # (a library before what it uses: GLUT before GL, as a person writes it)
