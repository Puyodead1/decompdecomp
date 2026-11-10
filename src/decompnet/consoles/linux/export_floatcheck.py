#!/usr/bin/env python3
"""Whether the plain build computes what the game's code does with floats, bit for bit: Python's standard library,
the system's gcc (as `make` runs it, 32-bit), its binutils (objdump, objcopy, ld) and the matching compiler (tools/).

    python3 tools/floatcheck.py [-n N] [--cflags "..."] src/FILE.c ...   (or: make floatcheck)

GCC 2.95 computed with the x87's 80-bit registers, rounding a float only where it stored one; a newer GCC keeps
other values in registers, rounds others, and reads a constant at another width, so the same C can give other
floats in a plain build (a quaternion a bit off, a frame a few pixels off). For each function of a source file whose
game's code uses the x87 and whose arguments it can make (numbers, pointers), this calls the matching build's
function (the game's code, compiled by tools/cc.sh) and the plain build's (the system's gcc with NON_MATCHING and
the Makefile's CFLAGS, against the program's own C library headers, as `make port` compiles) with the same random
arguments, each in a child process of its own, and compares what they return (all 80 bits) and the memory their
pointer arguments reach. The program's other functions are stubs that return 0, its variables memory whose every
word is an address in that memory and a float between 1 and 1.25 (a field read either way leads somewhere), and
the pointer arguments' memory random floats, or, where a function crashes on those, the same addresses. A function
that crashes or loops even so is "untestable". Prints each function that differs, and exits 1 if one does or a file
couldn't be checked.

Written by decompdecomp (https://github.com/n-delic/decompdecomp) with the export; build.json says what's where.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUTS = 200  # random calls of each function, per build
SECONDS = 10  # what one function's calls may take, per build, before it counts as untestable (one that loops)
SCALAR = {"float": "f", "double": "d", "long double": "x", "int": "i", "unsigned int": "i", "unsigned": "i",
          "short": "h", "unsigned short": "h", "char": "c", "unsigned char": "c", "signed char": "c", "long": "i",
          "unsigned long": "i", "void": "v"}
C_TYPE = {"f": "float", "d": "double", "x": "long double", "i": "int", "h": "short", "c": "char", "p": "void *"}
RETURNED = {"f": "long double", "d": "long double", "x": "long double", "i": "int", "h": "int", "c": "int", "v": "void",
            "p": "void *"}
# (a float function's result as the x87 returns it, st(0): all of it, not what a float keeps)
DEFINITION = re.compile(r"^([A-Za-z_][\w \t\*]*?)\b([A-Za-z_]\w*)\s*\(([^()]*)\)\s*\{", re.M)
LIBRARY = re.compile(r"^(sin|cos|tan|atan2?|acos|asin|sqrt|sqrtl|pow|exp|log|log10|floor|ceil|fabs|fmod|sinf|cosf|"
                     r"sqrtf|printf|sprintf|fprintf|puts|putchar|memcpy|memset|memcmp|memmove|strlen|strcpy|strcmp|"
                     r"strncpy|strncmp|strcat|rand|srand|abs|labs|__divdi3|__udivdi3|__moddi3|__umoddi3|stderr|"
                     r"stdout|_IO_\w+)$")

HARNESS = r"""
int printf(const char *, ...); void *malloc(unsigned); int atoi(const char *); void *memcpy(void *, const void *, unsigned);
int memcmp(const void *, const void *, unsigned); int fork(void); int pipe(int *); int read(int, void *, unsigned);
int write(int, const void *, unsigned); int close(int); int waitpid(int, int *, int); unsigned alarm(unsigned);
void _exit(int); void *mmap(void *, unsigned, int, int, int, long); int kill(int, int); int time(int *);
struct pollfd { int fd; short events, revents; }; int poll(struct pollfd *, unsigned long, int);
#define BUF 4096
#define NP 6
#define POOL 0x3F800000u
#define POOL_SIZE 0x100000u
static unsigned rs;
static unsigned rnd(void) { rs = rs * 1103515245u + 12345u; return rs >> 8; }
static float rf(void) { unsigned r = rnd(); float u = (r & 0xFFFF) / 65536.0f; switch (r >> 16 & 3) {
  case 0: return u * 2 - 1; case 1: return (u * 2 - 1) * 100; case 2: return (u * 2 - 1) * 360; default: return u; } }
static char (*bufs)[BUF];
extern void stub_fill(unsigned (*)(void));
static unsigned word(void) { return POOL + (rnd() %% (POOL_SIZE / 4)) * 4; }
double sqrt(double);
static void put_float(int at, float f) { memcpy((char *)bufs + 4 * at, &f, 4); }
static float get_float(int at) { float f; memcpy(&f, (char *)bufs + 4 * at, 4); return f; }
/* mode 0: the pointer arguments' memory floats, of four kinds in turn so that a function's branches run: mixed
   magnitudes (-360 to 360), unit groups of four (a rotation, a direction), the other arguments' memory as the first's
   or a hair from it (a nearly equal pair: slerp's other branch), and values near 0; 1, where those crash: pointers
   there too */
static void fill(int mode, int it) {
  unsigned *w = (unsigned *)POOL, j, k, words = NP * BUF / 4, per = BUF / 4;
  for (j = 0; j < POOL_SIZE / 4; j++) w[j] = word();
  if (!mode) {
    int shape = it %% 4;
    for (j = 0; j < words; j += 4) {
      float v[4]; double m = 0;
      for (k = 0; k < 4; k++) { v[k] = shape == 3 ? rf() * 0.001f : shape ? (rnd() & 0xFFFF) / 32768.0f - 1 : rf(); m += v[k] * v[k]; }
      for (k = 0; k < 4; k++) put_float(j + k, shape == 1 || shape == 2 ? (m > 0 ? v[k] / sqrt(m) : 1) : v[k]);
    }
    if (shape == 2)  /* (the others the first's: exactly every other time, else a hair off) */
      for (k = 1; k < NP; k++) for (j = 0; j < per; j++)
        put_float(k * per + j, get_float(j) * (it & 4 ? 1 : 1 + ((int)(rnd() %% 201) - 100) * 1e-6f));
  }
  stub_fill(word);
}
static void put(int fd, const void *p, int n) { while (n > 0) { int w = write(fd, p, n); if (w <= 0) _exit(3); p = (const char *)p + w; n -= w; } }
%(decls)s
static void side(int fn, int alt, int n, int fd, int mode)
{
  int it;
  rs = 1234567 + fn;
  close(1); close(2);  /* (what the function prints: not the report) */
  for (it = 0; it < n; it++) {
    long double r = 0; int ri = 0;
    fill(mode, it);
    switch (fn * 2 + alt) {
%(cases)s
    }
    put(fd, &r, 10); put(fd, &ri, 4); put(fd, bufs, NP * BUF);
  }
  _exit(0);
}
static int run(int fn, int alt, int n, char *out, int size, int mode)
{
  int p[2], st, got = 0, pid;
  pipe(p);
  if ((pid = fork()) == 0) { close(p[0]); alarm(%(seconds)d); side(fn, alt, n, p[1], mode); }
  close(p[1]);
  {
    /* (the deadline the parent keeps: a function that sets the game's own timers takes the child's alarm) */
    int deadline = time(0) + %(seconds)d + 2;
    while (got < size) {
      struct pollfd w; int r;
      w.fd = p[0]; w.events = 1; w.revents = 0;
      if (time(0) >= deadline || poll(&w, 1, 1000) < 0) break;
      if (!w.revents) continue;
      r = read(p[0], out + got, size - got);
      if (r <= 0) break;
      got += r;
    }
  }
  kill(pid, 9);
  close(p[0]); waitpid(pid, &st, 0);
  if (got == size) st = 0;
  return got == size && (st & 0x7f) == 0 && (st >> 8 & 0xff) == 0;
}
int main(int argc, char **argv)
{
  int n = argc > 1 ? atoi(argv[1]) : 200, fn, rec = 14 + NP * BUF;
  char *a = malloc(n * rec), *b = malloc(n * rec);
  if (mmap((void *)POOL, POOL_SIZE, 3, 0x32, -1, 0) != (void *)POOL) { printf("no memory at 0x3F800000\n"); return 2; }
  bufs = (char (*)[BUF])(POOL + POOL_SIZE / 2);
  for (fn = 0; fn < %(count)d; fn++) {
    int ok, it, bad = 0;
    if (argc > 2 && atoi(argv[2]) != fn) continue;
    ok = run(fn, 0, n, a, n * rec, 0) && run(fn, 1, n, b, n * rec, 0);
    if (!ok) ok = run(fn, 0, n, a, n * rec, 1) && run(fn, 1, n, b, n * rec, 1);
    if (!ok) { printf("%%s untestable\n", names[fn]); continue; }
    for (it = 0; it < n; it++) if (memcmp(a + it * rec, b + it * rec, rec)) bad++;
    printf("%%s %%d/%%d\n", names[fn], bad, n);
  }
  return 0;
}
"""


def strip_comments(text: str) -> str:
    """`text` with its comments blanked, every place where it was."""
    return re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.S)


def typedefs() -> dict[str, str]:
    """The headers' names for numbers: `typedef enum { ... } ECamProj;` and `typedef unsigned char u8;`, as C_TYPE
    kinds."""
    out: dict[str, str] = {}
    for header in sorted((ROOT / "include").glob("*.h")):
        text = strip_comments(header.read_text(encoding="utf-8", errors="replace"))
        for m in re.finditer(r"typedef\s+enum\b[^;{]*\{[^{}]*\}\s*([A-Za-z_]\w*)\s*;", text):
            out[m.group(1)] = "i"
        for m in re.finditer(r"typedef\s+([A-Za-z_][\w\s]*?)\s+([A-Za-z_]\w*)\s*;", text):
            if (k := SCALAR.get(re.sub(r"\s+", " ", m.group(1)).strip())) and k != "v":
                out[m.group(2)] = k
            elif re.sub(r"\s+", " ", m.group(1)).strip().startswith("enum "):
                out[m.group(2)] = "i"
    return out


_TYPEDEFS: dict[str, str] | None = None


def _kind(t: str) -> str | None:
    global _TYPEDEFS
    t = re.sub(r"\b(const|volatile|register)\b", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    if "*" in t or "[" in t:
        return "p"
    if t in SCALAR:
        return SCALAR[t]
    if t.startswith("enum "):
        return "i"
    if _TYPEDEFS is None:
        _TYPEDEFS = typedefs()
    return _TYPEDEFS.get(t)


def definitions(text: str) -> dict[str, tuple[str, list[str]]]:
    """name -> (what it returns, [each argument]) of each function `text` defines whose arguments the harness can
    make (a number, a pointer: not a struct by value, not `...`), in the kinds of C_TYPE."""
    out = {}
    for m in DEFINITION.finditer(strip_comments(text)):
        ret = re.sub(r"\b(static|inline|extern|__inline__|__inline)\b", "", m.group(1)).strip()
        if ret in ("if", "while", "for", "switch", "return", "else", "do") or (kind := _kind(ret)) is None:
            continue
        params = [p.strip() for p in m.group(3).split(",")] if m.group(3).strip() not in ("", "void") else []
        kinds = []
        for p in params:
            name = re.search(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])*$", p)
            kinds.append(None if p == "..." or name is None else
                         _kind(p[:name.start()] + ("*" if name.group(2) else "")))
        if None not in kinds:
            out[m.group(2)] = (kind, kinds)
    return out


def span(text: str, name: str) -> tuple[int, int] | None:
    """Where `name`'s definition is in `text`: from its line's start to after its closing brace."""
    plain = strip_comments(text)
    for m in DEFINITION.finditer(plain):
        if m.group(2) != name:
            continue
        depth = 0
        for i in range(m.end() - 1, len(plain)):
            depth += {"{": 1, "}": -1}.get(plain[i], 0)
            if depth == 0:
                return m.start(), i + 1
    return None


def harness(defs: dict) -> tuple[str, list[str]]:
    """The harness's C (for GCC 2.95), and the functions it calls in the order it numbers them."""
    decls, cases, order = [], [], sorted(defs)
    for k, name in enumerate(order):
        ret, params = defs[name]
        proto = ", ".join(C_TYPE[p] for p in params) or "void"
        decls.append(f"{RETURNED[ret]} {name}({proto}); {RETURNED[ret]} P_{name}({proto});")
        made, args, pointer = [], [], 0
        for j, p in enumerate(params):
            if p == "p":
                args.append(f"bufs[{pointer % 6}] + 64")
                pointer += 1
            else:
                made.append(f"a{j} = rf();" if p in "fdx" else f"a{j} = (int)(rnd() % 21) - 10;")
                args.append(f"({C_TYPE[p]})a{j}")
        local = " ".join(f"{'long double' if p in 'fdx' else 'int'} a{j};" for j, p in enumerate(params) if p != "p")
        to = "" if ret in "vp" else "r = " if ret in "fdx" else "ri = "  # (a pointer: each build's own statics')
        for alt, prefix in ((0, ""), (1, "P_")):
            cases.append(f"    case {2 * k + alt}: {{ {local} {' '.join(made)} {to}{prefix}{name}({', '.join(args)}); "
                         "break; }")
    names = ", ".join(f'"{n}"' for n in order) or '""'
    return HARNESS % {"decls": "\n".join(decls) + f"\nstatic const char *names[] = {{{names}}};",
                      "cases": "\n".join(cases), "count": len(order), "seconds": SECONDS}, order


def tool(name: str, tc: Path) -> str:
    """A binutils program: the system's, else the toolchain's."""
    found = shutil.which(name) or tc / "binutils" / "usr" / "bin" / name
    if not Path(found).exists():
        sys.exit(f"floatcheck: needs {name} (binutils)")
    return str(found)


def _binutils_env(tc: Path) -> dict:
    return {**os.environ, "LD_LIBRARY_PATH": f"{tc / 'binutils' / 'usr' / 'lib'}:{os.environ.get('LD_LIBRARY_PATH', '')}"}


def x87_functions(obj: Path, tc: Path) -> set[str]:
    """The functions of an object whose code uses the x87."""
    said = subprocess.run([tool("objdump", tc), "-d", "--no-show-raw-insn", str(obj)], capture_output=True, text=True,
                          env=_binutils_env(tc)).stdout
    out, current = set(), None
    for line in said.splitlines():
        if m := re.match(r"[0-9a-f]+ <([^>]+)>:", line):
            current = m.group(1)
        elif current and re.match(r"\s+[0-9a-f]+:\s+f(?!wait\b)[a-z0-9]+\b", line):
            out.add(current)
    return out


def undefined(objects: list[Path], tc: Path) -> dict[str, str]:
    """Each name the objects use and none defines: "f" where only calls reach it, else "d"."""
    defined, kinds = set(), {}
    for obj in objects:
        said = subprocess.run([tool("nm", tc), "-g", "--defined-only", str(obj)], capture_output=True, text=True,
                              env=_binutils_env(tc)).stdout
        defined |= {line.split()[-1] for line in said.splitlines() if line.strip()}
        said = subprocess.run([tool("objdump", tc), "-r", str(obj)], capture_output=True, text=True,
                              env=_binutils_env(tc)).stdout
        for m in re.finditer(r"^[0-9a-f]+ (R_386_\w+)\s+(\S+)$", said, re.M):
            name = m.group(2).split("+")[0].split("-")[0]
            if name.startswith("."):
                continue
            k = "f" if m.group(1) in ("R_386_PC32", "R_386_PLT32") else "d"
            kinds[name] = "d" if "d" in (k, kinds.get(name, k)) else "f"
    return {n: k for n, k in kinds.items() if n not in defined and not LIBRARY.match(n) and n not in library(tc)}


_LIBRARY: set[str] | None = None


def library(tc: Path) -> set[str]:
    """What the program's own C library, maths library and libgcc define: never a stub (a stub malloc returning 0
    stopped glibc's start-up before the harness ran)."""
    global _LIBRARY
    if _LIBRARY is None:
        _LIBRARY = set()
        archives = [tc / "crt" / "libc.a", tc / "crt" / "libm.a", *(tc / "gcc").rglob("libgcc.a")]
        for archive in archives:
            if archive.exists():
                said = subprocess.run([tool("nm", tc), "-g", "--defined-only", str(archive)], capture_output=True,
                                      text=True, env=_binutils_env(tc)).stdout
                _LIBRARY |= {line.split()[-1] for line in said.splitlines() if len(line.split()) >= 3}
    return _LIBRARY


def stubs(names: dict[str, str]) -> str:
    """The rest of the program, for the harness: functions that return 0, variables of that memory's words."""
    lines = [f"int {n}() {{ return 0; }}" if k == "f" else f"unsigned {n}[1024];" for n, k in sorted(names.items())]
    fill = "".join(f"  for (j = 0; j < 1024; j++) {n}[j] = word();\n" for n, k in sorted(names.items()) if k == "d")
    return "\n".join(lines) + f"\nvoid stub_fill(unsigned (*word)(void))\n{{\n  int j;\n{fill}}}\n"


class HarnessError(Exception):
    """The check's own program didn't run: not the plain build's fault, and no verdict on its floats."""


class Check:
    """One source file's check: its matching object and harness made once (prepare), then each plain C of it
    (run: the file as it is, or other text for it) compared with them."""

    def __init__(self, rel: str, work: Path, cc: list[str], cflags: list[str], tc: Path | None = None):
        build = json.loads((ROOT / "build.json").read_text(encoding="utf-8"))
        self.rel, self.work, self.cc, self.cflags = rel, work, cc, cflags
        self.tc = tc or Path(os.environ.get("TC") or ROOT / "tools" / (build.get("toolchain") or "gcc-2.95.3-linux"))
        unit = next((u for u in build.get("units") or [] if u.get("c") == rel), None) or \
            next((f for f in build["functions"] if f.get("c") == rel), None) or {}
        prelude = ["-include", "tools/prelude.h"] if (ROOT / "tools" / "prelude.h").exists() else []
        self.match_flags = [*prelude, *(unit.get("flags") or ["-O2"])]
        self.order: list[str] = []
        work.mkdir(parents=True, exist_ok=True)

    def _cc(self, source: str, obj: Path, flags: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", "tools/cc.sh", str(self.tc), source, str(obj), "-Iinclude", *flags], cwd=ROOT,
                              capture_output=True, text=True)

    def prepare(self, text: str | None = None) -> str | None:
        """The game's code (the file compiled as `make match` does) and the harness; why not, if it can't."""
        old = self.work / "old.o"
        said = self._cc(self.rel, old, self.match_flags)
        if said.returncode or not old.exists():
            return f"the matching build doesn't compile it: {said.stderr[-500:]}"
        text = text if text is not None else (ROOT / self.rel).read_text(encoding="utf-8")
        x87 = x87_functions(old, self.tc) - {"main"}  # (the program itself: it starts the game)
        self.defs = {n: d for n, d in definitions(text).items() if n in x87}
        self.untyped = sorted(x87 - set(self.defs))  # (a struct by value, `...`: the harness can't call them)
        source, self.order = harness(self.defs)
        (self.work / "h.c").write_text(source, encoding="utf-8")
        said = self._cc(str(self.work / "h.c"), self.work / "h.o", ["-O0", "-w"])
        if said.returncode:
            return f"the harness doesn't compile: {said.stderr[-500:]}"
        return None

    def compile_plain(self, text: str, headers: dict[str, str] | None = None) -> str | None:
        """The plain build's object of `text` (with `headers`' text in their place); why not, if it doesn't compile."""
        gcc_include = subprocess.run([*self.cc, "-print-file-name=include"], capture_output=True, text=True).stdout.strip()
        probe = (ROOT / self.rel).with_name(f".floatcheck-{Path(self.rel).name}")
        probe.write_text(text, encoding="utf-8")
        # (a header's other text in a copy of include/ the compile takes instead: the tree stays as it is, and a
        # header another includes by its own folder is the copy's too)
        shadow = self.work / "include"
        if headers:
            shutil.rmtree(shadow, ignore_errors=True)
            shutil.copytree(ROOT / "include", shadow)
            for name, body in headers.items():
                (shadow / Path(name).relative_to("include")).write_text(body, encoding="utf-8")
        try:
            said = subprocess.run([*self.cc, "-m32", "-std=gnu89", "-fno-pie", "-fcommon", "-fno-strict-aliasing",
                                   "-DNON_MATCHING", "-fno-stack-protector", "-fcf-protection=none", *self.cflags, "-w",
                                   "-nostdinc", "-isystem", gcc_include, f"-I{self.tc / 'include'}",
                                   f"-I{shadow}" if headers else "-Iinclude", "-iquote", str(probe.parent),
                                   "-c", str(probe), "-o", str(self.work / "new.o")],
                                  cwd=ROOT, capture_output=True, text=True)
        finally:
            probe.unlink(missing_ok=True)
        return None if said.returncode == 0 else said.stderr[-1000:]

    def run(self, text: str | None = None, headers: dict[str, str] | None = None, only: str | None = None,
            inputs: int = INPUTS) -> dict[str, int | None]:
        """Each function: how many of its calls differ (None: untestable); {} where the plain C doesn't compile."""
        text = text if text is not None else (ROOT / self.rel).read_text(encoding="utf-8")
        if not self.order or self.compile_plain(text, headers) is not None:
            return {}
        w, tc = self.work, self.tc
        renames = [a for name in self.defs for a in ("--redefine-sym", f"{name}=P_{name}")]
        subprocess.run([tool("objcopy", tc), "--weaken", *renames, str(w / "new.o"), str(w / "p.o")], check=True,
                       env=_binutils_env(tc))
        (w / "stubs.c").write_text(stubs(undefined([w / "old.o", w / "p.o"], tc)), encoding="utf-8")
        self._cc(str(w / "stubs.c"), w / "stubs.o", ["-O0", "-w", "-fno-builtin"])
        g = next((tc / "gcc").rglob("crtbegin.o"), None)
        crt = tc / "crt"
        said = subprocess.run([tool("ld", tc), "-m", "elf_i386", "-static", "-o", str(w / "h"), str(crt / "crt1.o"),
                               str(crt / "crti.o"), *([str(g)] if g else []), str(w / "h.o"), str(w / "old.o"),
                               str(w / "p.o"), str(w / "stubs.o"), "--allow-multiple-definition", "--no-warnings",
                               "--unresolved-symbols=ignore-all", "--start-group", str(crt / "libm.a"),
                               str(crt / "libc.a"), *([str(g.with_name("libgcc.a"))] if g else []), "--end-group",
                               *([str(g.with_name("crtend.o"))] if g else []), str(crt / "crtn.o")],
                              capture_output=True, text=True)
        if said.returncode:
            sys.exit(f"floatcheck: the harness doesn't link: {said.stderr[-1000:]}")
        argv = [str(w / "h"), str(inputs)] + ([str(self.order.index(only))] if only else [])
        said = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                              timeout=SECONDS * 4 * (1 if only else max(1, len(self.order))) + 60)  # (two kinds of
        # memory, two builds)
        if said.returncode != 0:
            raise HarnessError(f"the check itself stopped (exit {said.returncode}): {(said.stdout + said.stderr)[-300:]}")
        out: dict[str, int | None] = {}
        for line in said.stdout.splitlines():
            if m := re.match(r"(\S+) (\d+)/\d+$", line):
                out[m.group(1)] = int(m.group(2))
            elif m := re.match(r"(\S+) untestable$", line):
                out[m.group(1)] = None
        return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Compares the plain build's floats with the game's code")
    parser.add_argument("sources", nargs="+")
    parser.add_argument("-n", type=int, default=INPUTS, help="random calls of each function")
    parser.add_argument("--cc", default=os.environ.get("CC") or "gcc")
    parser.add_argument("--cflags", default=os.environ.get("CFLAGS") or "-O2",
                        help="the plain build's CFLAGS (a source's own, build.json's plain_flags, follow them)")
    args = parser.parse_args()
    build = json.loads((ROOT / "build.json").read_text(encoding="utf-8"))
    own = {u["c"]: u.get("plain_flags") or [] for u in build.get("units") or [] if u.get("c")}
    differ = failed = 0
    with tempfile.TemporaryDirectory(prefix="floatcheck-") as tmp:
        for rel in args.sources:
            check = Check(rel, Path(tmp) / Path(rel).stem, shlex.split(args.cc),
                          [*shlex.split(args.cflags), *own.get(rel, [])])
            why = check.prepare()
            if why:
                print(f"{rel}: {why}")
                continue
            if not check.defs:
                continue
            try:
                res = check.run(inputs=args.n)
            except HarnessError as e:
                print(f"{rel}: {e}")
                failed += 1
                continue
            if not res:
                why = check.compile_plain((ROOT / rel).read_text(encoding="utf-8"))
                print(f"{rel}: the plain build doesn't compile it: {(why or '').strip()[-300:]}")
                failed += 1
                continue
            bad = {n: c for n, c in res.items() if c}
            untestable = sorted(n for n, c in res.items() if c is None)
            differ += len(bad)
            print(f"{rel}: {len(res) - len(bad) - len(untestable)} of {len(res)} functions the game's, bit for bit"
                  + ("; differ: " + ", ".join(f"{n} ({c}/{args.n})" for n, c in sorted(bad.items())) if bad else "")
                  + (f"; untestable: {', '.join(untestable)}" if untestable else "")
                  + (f"; not called (their arguments): {', '.join(check.untyped)}" if check.untyped else ""))
    sys.exit(1 if differ or failed else 0)


if __name__ == "__main__":
    main()
