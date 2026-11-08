"""A Linux export's own build: a Makefile, the compiler's command as decompdecomp runs it (tools/cc.sh), the script
that downloads that compiler from the archives decompdecomp pins (tools/toolchain.sh) and tools/relink.py (Python's
standard library only). Building the program needs neither decompdecomp nor its sandbox: make and python3."""

from __future__ import annotations

import shutil
from pathlib import Path

MAKEFILE = """\
# Builds build/{program}: the program linked anew from this tree's C, with the compiler it was built with.
#   make              the program (the first time, the compiler is downloaded into tools/: `make toolchain`)
#   make move         the same, its data laid out after the code too
#   make toolchain    the compiler into tools/ (pinned downloads, each checked against its SHA-256)
# Needs make, python3, curl or wget, tar and ar. `python build.py` (with decompdecomp installed) checks that the C
# still rebuilds your copy byte for byte; building doesn't need it.
PROGRAM := {program}
TOOLCHAIN := {toolchain}
TC ?= tools/$(TOOLCHAIN)
PY ?= python3
export TC
CC := sh tools/cc.sh $(abspath $(TC))
AS := $(abspath $(TC))/binutils/usr/bin/as
LD := $(abspath $(TC))/binutils/usr/bin/ld
export LD_LIBRARY_PATH := $(abspath $(TC))/binutils/usr/lib:$(abspath $(TC))/lib
PRELUDE := {prelude}
HEADERS := $(wildcard include/*.h)
TOOLCHAIN_READY := $(TC)/crt/crt1.o
STUBS := build/relink/stubs

all: build/$(PROGRAM)

toolchain: $(TOOLCHAIN_READY)
$(TOOLCHAIN_READY):
\tsh tools/toolchain.sh $(TC)

build/relink:
\tmkdir -p $@

build/rules.mk: build.json tools/relink.py $(wildcard src/*/*.c) $(wildcard asm/*.s) | build/relink
\t$(PY) tools/relink.py rules > $@
-include build/rules.mk

data/program.s: | $(OBJS)
\t$(PY) tools/relink.py data $@

build/relink/data.o: data/program.s | $(TOOLCHAIN_READY)
\t$(AS) -o $@ data/program.s

$(STUBS)/stubs.txt: build.json | build/relink $(TOOLCHAIN_READY)
\t$(PY) tools/relink.py stubs $(STUBS)
\twhile read lib stem; do \\
\t  $(CC) $(STUBS)/$$stem.c $(STUBS)/$$stem.o -fPIC -O0 || exit 1; \\
\t  map=; [ -s $(STUBS)/$$stem.map ] && map="--version-script $(STUBS)/$$stem.map"; \\
\t  $(LD) -m elf_i386 -shared -soname $$lib $$map -o $(STUBS)/$$lib $(STUBS)/$$stem.o || exit 1; \\
\tdone < $(STUBS)/stubs.txt

build/$(PROGRAM): $(OBJS) build/relink/data.o $(STUBS)/stubs.txt
\t$(PY) tools/relink.py link $@

move: $(OBJS) build/relink/data.o $(STUBS)/stubs.txt
\t$(PY) tools/relink.py link build/$(PROGRAM) move

clean:
\trm -r -f build/relink build/rules.mk build/$(PROGRAM)

.PHONY: all toolchain move clean
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
    (out / "Makefile").write_text(MAKEFILE.format(program=build["program"], toolchain=tid, prelude=prelude),
                                  encoding="utf-8")
