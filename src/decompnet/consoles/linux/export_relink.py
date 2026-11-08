#!/usr/bin/env python3
"""The relinked program's pieces, for the Makefile: no decompdecomp, nothing but Python's standard library (and, for
`move`, the capstone module).

    python3 tools/relink.py rules              build/rules.mk: how each function is built (its C, else asm/)
    python3 tools/relink.py asm NAME            asm/NAME.s, from your copy's bytes (what isn't C yet)
    python3 tools/relink.py fixup RAW OUT NAME  a function's object as the program takes it (its statics the game's)
    python3 tools/relink.py data OUT            data/program.s: the program's data, every global and pointer named
    python3 tools/relink.py stubs DIR           the libraries it imports from, as stubs to link against
    python3 tools/relink.py link OUT [move]     link the program (the linker script first)
    python3 tools/relink.py wrap DIR RUNTIME    make each 32-bit program in DIR start through RUNTIME's loader

Written by decompdecomp (https://github.com/n-delic/decompdecomp) with the export; build.json says what's where.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
B = json.loads((ROOT / "build.json").read_text(encoding="utf-8"))
TC = Path(os.environ.get("TC") or ROOT / "tools" / (B.get("toolchain") or "gcc-2.95.3-linux"))
DATA = (".rodata", ".data", ".bss")
LISTS = (".ctors", ".dtors", ".init_array", ".fini_array", ".preinit_array")
SHF_WRITE, SHF_ALLOC = 1, 2
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2


def fail(msg: str) -> None:
    sys.exit(f"error: {msg}")


class Elf:
    """A 32-bit little-endian ELF file, as much of it as the relink reads."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 1:
            raise ValueError("not a 32-bit ELF file")
        self.raw = data
        (self.type, self.machine, _, self.entry, _, self.shoff, _, _, _, _, self.shentsize, shnum,
         shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        self.sections = []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
                "<IIIIIIIIII", data, self.shoff + i * self.shentsize)
            self.sections.append({"index": i, "name_off": name, "type": typ, "flags": flags, "addr": addr,
                                  "offset": off, "size": size, "link": link, "info": info, "align": align,
                                  "entsize": entsize})
        names = self.sections[shstrndx] if shstrndx < len(self.sections) else None
        for sec in self.sections:
            sec["name"] = self.string(names, sec["name_off"]) if names else ""

    def string(self, sec, off: int) -> str:
        start = sec["offset"] + off
        return self.raw[start:self.raw.index(b"\0", start)].decode("latin-1")

    def section(self, name: str):
        return next((s for s in self.sections if s["name"] == name), None)

    def data(self, sec) -> bytes:
        return b"" if sec["type"] == 8 else self.raw[sec["offset"]:sec["offset"] + sec["size"]]  # (SHT_NOBITS)

    def symbols(self, sec) -> list[dict]:
        strings = self.sections[sec["link"]]
        out = []
        for k in range(sec["size"] // 16):
            at = sec["offset"] + k * 16
            name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", self.raw, at)
            out.append({"name": self.string(strings, name), "value": value, "size": size, "bind": info >> 4,
                        "type": info & 0xF, "shndx": shndx, "at": at, "name_off": name})
        return out

    def rels(self, sec) -> list[tuple[int, int, int]]:
        """(offset, symbol index, type) of a SHT_REL section."""
        out = []
        for k in range(sec["size"] // 8):
            off, info = struct.unpack_from("<II", self.raw, sec["offset"] + k * 8)
            out.append((off, info >> 8, info & 0xFF))
        return out


def game() -> tuple[bytes, Elf]:
    base = ROOT / B["image"]
    if not base.exists():
        fail(f"put your own copy of the program here as {B['image']} (see README.md)")
    data = base.read_bytes()
    import hashlib

    if hashlib.sha1(data).hexdigest() != B["sha1"]:
        fail(f"{B['image']} isn't the version this project decompiles (its SHA-1 differs)")
    return data, Elf(data)


def source_of(fn: dict) -> Path | None:
    path = ROOT / (fn.get("c") or "")
    if fn.get("c") and path.exists():
        return path
    found = sorted((ROOT / "src").glob(f"*/{fn['name']}.c"))
    return found[0] if found else None


def crt_files() -> tuple[list[Path], list[Path]]:
    """The C runtime objects before and after the program's own: crt1.o, crti.o, crtbegin.o ... crtend.o, crtn.o."""
    begin = next(iter(sorted(TC.glob("gcc/usr/lib/**/crtbegin.o"))), None)
    crt = TC / "crt"
    if begin is None or not (crt / "crt1.o").exists():
        fail(f"{TC} has no C runtime objects: run `make toolchain`")
    return [crt / "crt1.o", crt / "crti.o", begin], [begin.with_name("crtend.o"), crt / "crtn.o"]


def dynamic(elf: Elf) -> bool:
    return elf.section(".interp") is not None


# ------------------------------------------------------------------------------------------------------------ rules

def archive_defines(path: Path) -> set[str]:
    """The global symbols each object of an ar archive (libc_nonshared.a) defines."""
    raw = path.read_bytes()
    if raw[:8] != b"!<arch>\n":
        return set()
    out, at = set(), 8
    while at + 60 <= len(raw):
        name, size = raw[at:at + 16].decode("latin-1").strip(), int(raw[at + 48:at + 58].decode().strip() or 0)
        body = raw[at + 60:at + 60 + size]
        if body[:4] == b"\x7fELF" and not name.startswith("/"):
            obj = Elf(body)
            out |= {sym["name"] for sym in obj.symbols(obj.section(".symtab"))
                    if sym["name"] and sym["bind"] in (1, 2) and sym["shndx"] not in (SHN_UNDEF, SHN_COMMON)}
        at += 60 + size + (size & 1)
    return out


def from_library() -> set[str]:
    """The program's functions its link brings itself: libc_nonshared.a's (glibc's atexit, PIC code whose GOT
    offset is the original's) and the crt objects'. Never exported as C or bytes: the toolchain's copy is the one."""
    nonshared = TC / "crt" / "libc_nonshared.a"
    names = archive_defines(nonshared) if nonshared.exists() else set()
    for path in sum(crt_files(), []) if (TC / "crt" / "crt1.o").exists() else []:
        crt = Elf(path.read_bytes())
        names |= {s["name"] for s in crt.symbols(crt.section(".symtab")) if s["name"] and s["shndx"] != SHN_UNDEF}
    return names


def built() -> list[dict]:
    """The functions the relinked program takes from this tree (not the ones its libraries bring)."""
    library = from_library()
    return [fn for fn in B["functions"] if fn["name"] not in library]


PIC = re.compile(rb"\xe8\0\0\0\0[\x58-\x5f]\x81[\xc0-\xc7]")  # call +0; pop %reg; add $GOT, %reg


def assembly(name: str, code: bytes, refs: dict[int, str]) -> str:
    """A function that isn't C as GNU assembly: its bytes, each word in `refs` by name."""
    lines, i = [f".text\n.globl {name}\n.type {name},@function\n{name}:\n"], 0
    while i < len(code):
        if i in refs:
            lines.append(f".long {refs[i]}\n")
            i += 4
            continue
        stop = min([len(code), i + 16] + [a for a in refs if a > i])
        lines.append(f".byte {', '.join(str(b) for b in code[i:stop])}\n")
        i = stop
    return "".join(lines)


def write_asm(name: str) -> None:
    """asm/NAME.s from your copy's bytes and build.json's references (asm/ is your copy's code: never in git)."""
    raw, elf = game()
    fn = next((f for f in B["functions"] if f["name"] == name), None)
    if fn is None:
        fail(f"no function named {name} in build.json")
    text = elf.section(".text")
    at = text["offset"] + fn["vram"] - text["addr"]
    code = raw[at:at + fn["size"]]
    if PIC.search(code[:24]):  # (its GOT offset is the original's: raw, it reads past the relinked program)
        fail(f"{name} is code built with -fPIC: as bytes it would read the original's GOT; it needs its C")
    out = ROOT / "asm" / f"{name}.s"
    out.parent.mkdir(exist_ok=True)
    out.write_text(assembly(name, code, {int(k): v for k, v in (fn.get("refs") or {}).items()}), encoding="utf-8")


def rules() -> None:
    """build/rules.mk: each function's object from its C (with its flags), else from asm/ (written from your copy
    when it isn't there), and the list of them."""
    lines, objs = [], []
    raw, elf = game()
    text = elf.section(".text")
    for fn in built():
        at = text["offset"] + fn["vram"] - text["addr"]
        if source_of(fn) is None and PIC.search(raw[at:at + min(fn["size"], 24)]):
            fail(f"{fn['name']} is code built with -fPIC and isn't C yet: as bytes it would read the original's GOT")
        obj = f"build/relink/{fn['name']}.o"
        src = source_of(fn)
        if src is not None:
            flags = " ".join(fn.get("flags") or ["-O2"])
            rel = src.relative_to(ROOT).as_posix()
            lines.append(f"{obj}: {rel} $(HEADERS) | build/relink $(TOOLCHAIN_READY)\n"
                         f"\t$(CC) {rel} $@.raw -Iinclude $(PRELUDE) {flags}\n"
                         f"\t$(PY) tools/relink.py fixup $@.raw $@ {fn['name']}\n")
        else:
            asm = f"asm/{fn['name']}.s"
            lines.append(f"{asm}: | {B['image']}\n\t$(PY) tools/relink.py asm {fn['name']}\n"
                         f"{obj}: {asm} | build/relink $(TOOLCHAIN_READY)\n\t$(AS) -o $@ {asm}\n")
        objs.append(obj)
    print("OBJS := " + " \\\n  ".join(objs) + "\n\n" + "\n".join(lines))


# ------------------------------------------------------------------------------------------------------------ fixup

def fixup(raw_path: str, out_path: str, name: str) -> None:
    """A function's object as the relinked program takes it: what it reads and writes of its own statics is the
    game's (the address patched in, the relocation gone: a file's statics are shared by its functions, each compiled
    alone), its common symbols the game's globals of their names, and what else its file's C defines (a helper beside
    it) weak, so the program's own wins."""
    obj = Path(raw_path).read_bytes()
    elf = Elf(obj)
    data = bytearray(obj)
    fn = next((f for f in B["functions"] if f["name"] == name), {"name": name})
    statics = fn.get("statics") or {}
    known = set(B["symbols"])
    symtab = elf.section(".symtab")
    syms = elf.symbols(symtab)
    writable = {s["index"] for s in elf.sections if s["flags"] & SHF_WRITE and s["flags"] & SHF_ALLOC}
    covering: dict[int, list] = {}
    for sym in syms:
        if sym["shndx"] in writable and sym["type"] == 1 and sym["name"] in statics:  # (STT_OBJECT)
            covering.setdefault(sym["shndx"], []).append((sym["value"], max(sym["size"], 1), sym["name"]))

    def game_address(sym, addend: int) -> int | None:
        if sym["shndx"] not in writable:
            return None
        if sym["type"] == 3:  # STT_SECTION
            for value, size, sname in covering.get(sym["shndx"], ()):
                if value <= addend < value + size:
                    return statics[sname] + addend - value
            return None
        return statics[sym["name"]] + addend if sym["name"] in statics else None

    for rs in elf.sections:
        if rs["type"] != 9 or rs["info"] in writable:  # (SHT_REL)
            continue
        target = elf.sections[rs["info"]]
        kept = []
        for off, si, rtype in elf.rels(rs):
            at = target["offset"] + off
            addend = struct.unpack_from("<i", data, at)[0]
            addr = game_address(syms[si], addend) if rtype == 1 else None
            if addr is None:
                kept.append((off, (si << 8) | rtype))
            else:
                struct.pack_into("<I", data, at, addr & 0xFFFFFFFF)
        for k, (off, info) in enumerate(kept):
            struct.pack_into("<II", data, rs["offset"] + k * 8, off, info)
        struct.pack_into("<I", data, elf.shoff + rs["index"] * elf.shentsize + 20, len(kept) * 8)
    for sym in syms:
        if sym["shndx"] == SHN_COMMON and sym["name"] in known:  # (a tentative definition: the game's global)
            struct.pack_into("<II", data, sym["at"] + 4, 0, 0)
            struct.pack_into("<H", data, sym["at"] + 14, SHN_UNDEF)
        elif sym["bind"] == 1 and sym["name"] != name and sym["shndx"] not in (SHN_UNDEF, SHN_ABS, SHN_COMMON):
            data[sym["at"] + 12] = (2 << 4) | sym["type"]  # STB_WEAK
    Path(out_path).write_bytes(bytes(data))


# ------------------------------------------------------------------------------------------------------------- data

def plt(elf: Elf) -> dict[int, str]:
    """Each import's PLT stub in the original, by address: the n-th R_386_JUMP_SLOT is the n-th entry after PLT0."""
    rel, stubs = elf.section(".rel.plt"), elf.section(".plt")
    if rel is None or stubs is None:
        return {}
    syms = elf.symbols(elf.sections[rel["link"]])
    return {stubs["addr"] + 16 * (n + 1): syms[si]["name"].split("@")[0] for n, (_, si, _) in enumerate(elf.rels(rel))}


def copied(elf: Elf) -> set[int]:
    """The .dynsym entries the program's R_386_COPY relocations copy into its .bss (stdout, __ctype_toupper): defined
    there, so not UNDEF, but imports all the same (as globals of its own, the relinked program called
    setvbuf(stdout=NULL))."""
    dynsym = elf.section(".dynsym")
    if dynsym is None:
        return set()
    return {si for rs in elf.sections if rs["type"] == 9 and rs["link"] == dynsym["index"]
            for _, si, rtype in elf.rels(rs) if rtype == 5}


def imported(elf: Elf) -> set[str]:
    dynsym = elf.section(".dynsym")
    if dynsym is None:
        return set()
    copies = copied(elf)
    return {s["name"] for k, s in enumerate(elf.symbols(dynsym)) if s["name"] and (s["shndx"] == SHN_UNDEF or k in copies)}


def crt_defined(elf: Elf) -> set[str]:
    if not dynamic(elf):
        return set()
    before, after = crt_files()
    out = set()
    for path in before + after:
        crt = Elf(path.read_bytes())
        out |= {s["name"] for s in crt.symbols(crt.section(".symtab")) if s["name"] and s["shndx"] != SHN_UNDEF}
    return out


def labels_and_assigns(elf: Elf) -> tuple[dict[int, list[str]], list[str]]:
    """The program's globals: a label in data/program.s where its data is (it moves with it), else an assignment."""
    starts = {f["vram"]: f["name"] for f in B["functions"]}
    skip = set(starts.values()) | imported(elf) | crt_defined(elf)
    spans = [(s["addr"], s["addr"] + s["size"]) for n in DATA if (s := elf.section(n)) is not None]
    text = elf.section(".text")
    asm = sorted((f["vram"], f["vram"] + f["size"], f["name"]) for f in B["functions"] if source_of(f) is None)
    labels: dict[int, list[str]] = {}
    assigns, stray = [], []
    for name, addr in sorted(B["symbols"].items(), key=lambda kv: kv[1]):
        if name in skip:
            continue
        if addr in starts:
            assigns.append(f"{name} = {starts[addr]};")
        elif any(lo <= addr < hi for lo, hi in spans):
            labels.setdefault(addr, []).append(name)
        elif text is not None and text["addr"] <= addr < text["addr"] + text["size"]:
            # the old code isn't loaded: a name there is a place in a function still in assembly, or an error
            inner = next((f"{n} + {addr - lo}" for lo, hi, n in asm if lo < addr < hi), None)
            if inner is None:
                stray.append(f"{name} (0x{addr:X})")
            else:
                assigns.append(f"{name} = {inner};")
        else:
            assigns.append(f"{name} = 0x{addr:X};")
    if stray:
        fail("these name places in the original's code that no function of this tree has, and the relinked program "
             "doesn't load it: " + ", ".join(stray[:20]))
    return labels, assigns


def own_lists() -> set[str]:
    """The functions whose C makes its own constructor entry (`__attribute__((constructor))`): not listed twice."""
    out = set()
    for fn in B["functions"]:
        raw = ROOT / "build" / "relink" / f"{fn['name']}.o.raw"
        if raw.exists():
            if any(Elf(raw.read_bytes()).section(n) is not None for n in LISTS):
                out.add(fn["name"])
    return out


def write_data(out_path: str) -> None:
    """data/program.s: the program's data as assembly that names what it points at: its globals labelled, each word
    that pointed at a function, an import's PLT stub, or anywhere in its data written as that, one into a function
    still in assembly (its switch's jump table) as that place in it, its constructor and destructor lists by name."""
    raw, elf = game()
    starts = {f["vram"]: f["name"] for f in B["functions"]}
    imports = plt(elf)
    asm = sorted((f["vram"], f["vram"] + f["size"], f["name"]) for f in B["functions"] if source_of(f) is None)
    lows = [a for a, _, _ in asm]
    labels, _ = labels_and_assigns(elf)
    secs = {n: elf.section(n) for n in DATA}
    spans = [(s["addr"], s["addr"] + s["size"], f"__orig_{n[1:]}") for n, s in secs.items() if s]
    text = elf.section(".text")
    lo, hi = text["addr"], text["addr"] + text["size"]

    def named(word: int) -> str | None:
        if word in starts:
            return starts[word]
        if word in imports:
            return imports[word]
        k = bisect.bisect_right(lows, word) - 1
        if k >= 0 and asm[k][0] < word < asm[k][1]:
            return f"{asm[k][2]}+{word - asm[k][0]}"
        if word in labels:
            return labels[word][0]
        for start, end, label in spans:
            if start <= word <= end:  # (one past the end too: a loop's limit)
                return f"{label}+{word - start}"
        return None

    out, stray = [], 0
    for name in DATA:
        sec = secs[name]
        if sec is None:
            continue
        addr, size, nobits = sec["addr"], sec["size"], sec["type"] == 8
        flags = '"aw",@nobits' if nobits else ('"a"' if name == ".rodata" else '"aw"')
        out.append(f".section .orig{name},{flags}\n.globl __orig_{name[1:]}\n__orig_{name[1:]}:\n")
        marks = sorted(a for a in labels if addr <= a < addr + size)
        body = elf.data(sec)
        run: list[int] = []

        def flush(run=run):
            if run:
                out.append(f".byte {','.join(map(str, run))}\n")
                run.clear()
        i, m = 0, 0
        while i < size:
            while m < len(marks) and marks[m] - addr <= i:
                if marks[m] - addr == i:
                    flush()
                    out.append("".join(f".globl {n}\n{n}:\n" for n in labels[marks[m]]))
                m += 1
            following = marks[m] - addr if m < len(marks) else size  # (a word may not run over a label)
            if nobits:
                out.append(f".skip {following - i}\n")
                i = following
                continue
            word = struct.unpack_from("<I", body, i)[0] if i + 4 <= following and (addr + i) % 4 == 0 else None
            target = named(word) if word is not None else None
            if target:
                flush()
                out.append(f".long {target}\n")
                i += 4
                continue
            if word is not None and lo <= word < hi:
                stray += 1
            run.append(body[i])
            i += 1
            if len(run) == 32:
                flush()
        flush()
    own = own_lists()
    for name in LISTS:  # (the original's entries, between crtbegin.o's start and crtend.o's end marker)
        sec = elf.section(name)
        if sec is None or not sec["size"]:
            continue
        body = elf.data(sec)
        words = [struct.unpack_from("<I", body, k)[0] for k in range(0, len(body) - 3, 4)]
        entries = [w for w in words if w not in (0, 0xFFFFFFFF) and starts.get(w) not in own]
        if entries:
            out.append(f'.section {name},"aw"\n' + "".join(f".long {named(w) or hex(w)}\n" for w in entries))
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("".join(out), encoding="utf-8")
    note = f"; {stray} words still point into the old code, at C functions' own old tables" if stray else ""
    print(f"{out_path}: the program's data, written from your copy ({sum(map(len, labels.values()))} globals named{note})")


# ------------------------------------------------------------------------------------------------------------ stubs

def needed(elf: Elf) -> list[str]:
    dyn = elf.section(".dynamic")
    if dyn is None:
        return []
    strings = elf.sections[dyn["link"]]
    out = []
    for k in range(dyn["size"] // 8):
        tag, value = struct.unpack_from("<iI", elf.raw, dyn["offset"] + k * 8)
        if tag == 1:  # DT_NEEDED
            out.append(elf.string(strings, value))
    return out


def stubs(out_dir: str) -> None:
    """The libraries the program imports from, as stubs to link against: one per library it needs, holding what it
    imports from each at the versions it asked for (objects with their sizes, for the copies the linker makes): the
    program runs with the real ones. (A newer glibc's IFUNCs are data to a 2001 linker.) Writes <lib>.c, <lib>.map
    and stubs.txt (each library's name and stem) for the Makefile."""
    _, elf = game()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    libs = needed(elf)
    dynsym = elf.section(".dynsym")
    syms = elf.symbols(dynsym) if dynsym else []
    versym = elf.section(".gnu.version")
    verneed = elf.section(".gnu.version_r")
    index: dict[int, tuple[str, str]] = {}
    if verneed is not None:
        strings = elf.sections[verneed["link"]]
        at = verneed["offset"]
        for _ in range(verneed["info"]):
            _, cnt, file_off, aux, nxt = struct.unpack_from("<HHIII", elf.raw, at)
            a = at + aux
            for _ in range(cnt):
                _, _, other, name_off, anext = struct.unpack_from("<IHHII", elf.raw, a)
                index[other] = (elf.string(strings, file_off), elf.string(strings, name_off))
                a += anext
            at += nxt
    plain = next((lib for lib in libs if lib not in {v[0] for v in index.values()}), libs[0] if libs else None)
    by_lib: dict[str, dict[str | None, list[dict]]] = {lib: {} for lib in libs}
    copies = copied(elf)
    for k, sym in enumerate(syms):
        if not sym["name"] or (sym["shndx"] != SHN_UNDEF and k not in copies) or (sym["bind"] == 2 and k not in copies):
            continue  # (weak: nobody need define it)
        v = struct.unpack_from("<H", elf.raw, versym["offset"] + k * 2)[0] & 0x7FFF if versym else 0
        lib, ver = index.get(v, (plain, None))
        by_lib.setdefault(lib, {}).setdefault(ver, []).append(sym)
    listing = []
    for lib in libs:
        source, script, prev = [], [], None
        for ver, group in sorted(by_lib.get(lib, {}).items(), key=lambda kv: (kv[0] is not None, kv[0] or "")):
            for sym in group:
                source.append(f"char {sym['name']}[{max(sym['size'], 1)}] = {{ 1 }};" if sym["type"] == 1
                              else f"int {sym['name']}() {{ return 0; }}")
            if ver is not None:
                script.append(f"{ver} {{ global: {'; '.join(s['name'] for s in group)}; }}{(' ' + prev) if prev else ''};")
                prev = ver
        stem = re.sub(r"\W", "_", lib)
        (out / f"{stem}.c").write_text("\n".join(source) + "\nint __decompdecomp_stub;\n", encoding="utf-8")
        (out / f"{stem}.map").write_text("\n".join(script) + "\n" if script else "", encoding="utf-8")
        listing.append(f"{lib} {stem}")
    (out / "stubs.txt").write_text("\n".join(listing) + ("\n" if listing else ""), encoding="utf-8")


# ----------------------------------------------------------------------------------------------------------- script

def script(out_path: str, move: bool) -> None:
    """The linker script: the program's dynamic sections first, the data where the game has it (or, `move`, after the
    code), the code from above the data, where it may grow."""
    _, elf = game()
    dyn = dynamic(elf)
    starts = {f["vram"]: f["name"] for f in B["functions"]}
    if not dyn and starts.get(elf.entry) is None:
        fail(f"the program starts at 0x{elf.entry:X}, where none of its functions is")
    _, assigns = labels_and_assigns(elf)
    secs = {n: elf.section(n) for n in DATA}
    end = max(s["addr"] + s["size"] for s in secs.values() if s)
    code = (end + 0xFFFFF) & ~0xFFFFF
    before, after = crt_files() if dyn else ([], [])
    begin, ending = (before[2], after[0]) if dyn else (None, None)
    pinned = "" if move else "".join(f"  .orig{n} 0x{s['addr']:X} : {{ build/relink/data.o(.orig{n}) }} :{seg}\n"
                                     for n, s, seg in ((".rodata", secs[".rodata"], "rodata" if dyn else "text"),
                                                       (".data", secs[".data"], "data"), (".bss", secs[".bss"], "data"))
                                     if s)
    moved = {n: f"  .orig{n} : {{ build/relink/data.o(.orig{n}) }}\n" if move else "" for n in DATA}
    ctors = "".join(f"  .{k} : {{ KEEP ({begin}(.{k})) KEEP (*(EXCLUDE_FILE ({ending}) .{k})) KEEP (*(.{k})) }}\n"
                    for k in ("ctors", "dtors")) if dyn else ""
    phdrs = (("  headers PT_PHDR PHDRS ;\n  interp PT_INTERP ;\n" if dyn else "") + "  text PT_LOAD FILEHDR PHDRS ;\n"
             + ("  rodata PT_LOAD ;\n" if dyn and not move else "") + ("  data PT_LOAD ;\n" if not move else "")
             + "  code PT_LOAD ;\n  more PT_LOAD ;\n" + ("  dynamic PT_DYNAMIC ;\n" if dyn else ""))
    low = min(s["addr"] for s in elf.sections if s["addr"]) & ~0xFFF
    text = f"""OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY({"_start" if dyn else starts[elf.entry]})
PHDRS
{{
{phdrs}}}
SECTIONS
{{
  . = 0x{low:X} + SIZEOF_HEADERS;
  .interp : {{ *(.interp) }} :text {":interp" if dyn else ""}
  .hash : {{ *(.hash) }} :text
  .dynsym : {{ *(.dynsym) }}
  .dynstr : {{ *(.dynstr) }}
  .gnu.version : {{ *(.gnu.version) }}
  .gnu.version_d : {{ *(.gnu.version_d) }}
  .gnu.version_r : {{ *(.gnu.version_r) }}
  .rel.dyn : {{ *(.rel.init) *(.rel.text) *(.rel.fini) *(.rel.rodata) *(.rel.data) *(.rel.ctors) *(.rel.dtors) *(.rel.got) *(.rel.bss) }}
  .rel.plt : {{ *(.rel.plt) }}
{pinned}  . = 0x{code:X};
  .init : {{ KEEP (*(.init)) }} :code =0x9090
  .plt : {{ *(.plt) }}
  .text : {{ *(.text) *(.text.*) *(.gnu.linkonce.t.*) }} =0x9090
  .fini : {{ KEEP (*(.fini)) }} =0x9090
  .rodata : {{ *(.rodata) *(.rodata.*) *(.gnu.linkonce.r.*) }}
{moved[".rodata"]}  .gcc_except_table : {{ *(.gcc_except_table) }}
  . = ALIGN(0x1000) + (. & 0xFFF);
  .data : {{ *(.data) *(.data.*) *(.gnu.linkonce.d.*) }} :more
{moved[".data"]}  .eh_frame : {{ KEEP (*(.eh_frame)) }}
{ctors}  .preinit_array : {{ PROVIDE (__preinit_array_start = .); KEEP (*(.preinit_array)) PROVIDE (__preinit_array_end = .); }}
  .init_array : {{ PROVIDE (__init_array_start = .); KEEP (*(.init_array)) PROVIDE (__init_array_end = .); }}
  .fini_array : {{ PROVIDE (__fini_array_start = .); KEEP (*(.fini_array)) PROVIDE (__fini_array_end = .); }}
  .jcr : {{ KEEP (*(.jcr)) }}
  .got : {{ *(.got.plt) *(.got) }}
  .dynamic : {{ *(.dynamic) }} :more {":dynamic" if dyn else ""}
  _edata = .;
  __bss_start = .;
  .bss : {{ *(.dynbss) *(.bss) *(.bss.*) *(.gnu.linkonce.b.*) *(COMMON) . = ALIGN(4); }} :more
{moved[".bss"]}  _end = .;
  /DISCARD/ : {{ *(.comment) *(.note*) *(.stab*) }}
}}
""" + "\n".join(assigns) + "\n"
    Path(out_path).write_text(text, encoding="utf-8")
    # the link's inputs, in order, for the Makefile
    first = " ".join(str(p) for p in before)
    last = " ".join(str(p) for p in after)
    nonshared = TC / "crt" / "libc_nonshared.a"
    libgcc = begin.with_name("libgcc.a") if begin is not None else None
    Path(out_path).with_suffix(".inputs").write_text(
        f"{first}\n{last}\n{nonshared if dyn and nonshared.exists() else ''} "
        f"{libgcc if libgcc is not None and libgcc.exists() else ''}\n{'dynamic' if dyn else 'static'}\n",
        encoding="utf-8")


# ------------------------------------------------------------------------------------------------------------- move

def move(program_path: str) -> None:
    """The relinked program's code with the old data addresses its C still writes as numbers (and its statics,
    patched as the game's) moved with the data: every absolute operand in a data section's old span becomes the same
    place in the section where it is now."""
    try:
        import capstone
    except ImportError:
        fail("moving the data reads the code's operands with capstone: `pip install capstone`")
    _, original = game()
    old = {f"__orig_{n[1:]}": (s["addr"], s["addr"] + s["size"]) for n in DATA if (s := original.section(n))}
    path = Path(program_path)
    data = bytearray(path.read_bytes())
    elf = Elf(bytes(data))
    now = {s["name"]: s["value"] for s in elf.symbols(elf.section(".symtab")) if s["name"].startswith("__orig_")}
    moves = [(lo, hi, now[label] - lo) for label, (lo, hi) in old.items() if label in now and now[label] != lo]
    text = elf.section(".text")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True
    done = 0
    for ins in md.disasm(elf.data(text), text["addr"]):
        if ins.id == 0:
            continue
        for field, value in ((ins.imm_offset, next((o.imm for o in ins.operands if o.type == capstone.x86.X86_OP_IMM), None)),
                             (ins.disp_offset, next((o.mem.disp for o in ins.operands
                                                     if o.type == capstone.x86.X86_OP_MEM and o.mem.base == 0), None))):
            if not field or value is None or ins.size - field < 4:
                continue
            value &= 0xFFFFFFFF
            for lo, hi, delta in moves:
                if lo <= value <= hi:
                    struct.pack_into("<I", data, text["offset"] + ins.address - text["addr"] + field,
                                     (value + delta) & 0xFFFFFFFF)
                    done += 1
                    break
    path.write_bytes(bytes(data))
    print(f"{program_path}: its data laid out after the code ({done} addresses the C still wrote as the old data's "
          "moved with it)")


# ------------------------------------------------------------------------------------------------------------- link

def link(out_path: str, mode: str = "") -> None:
    """The program from build/relink: the C runtime objects, every function's object, the data, the libraries' stubs,
    by the linker script (written first)."""
    import subprocess

    move_data = mode == "move"
    _, elf = game()
    ld_script = ROOT / "build" / "relink" / "program.ld"
    script(str(ld_script), move_data)
    first, last, extra, kind = ld_script.with_suffix(".inputs").read_text(encoding="utf-8").split("\n")[:4]
    old_code(elf)
    objs = [f"build/relink/{fn['name']}.o" for fn in built()]
    listing = ROOT / "build" / "relink" / "objects.txt"
    listing.write_text("\n".join(objs) + "\n", encoding="utf-8")
    ld = str(TC.resolve() / "binutils" / "usr" / "bin" / "ld")
    if kind == "dynamic":
        stubs_dir = ROOT / "build" / "relink" / "stubs"
        libs = [f"build/relink/stubs/{line.split()[0]}" for line in
                (stubs_dir / "stubs.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
        cmd = [ld, "-m", "elf_i386", "-dynamic-linker", "/lib/ld-linux.so.2", "-rpath-link", str(stubs_dir),
               "-T", str(ld_script), "-o", out_path, *first.split(), *objs, "build/relink/data.o", *extra.split(), *libs, *last.split()]
    else:
        cmd = [ld, "-m", "elf_i386", "-static", "-T", str(ld_script), "-o", out_path, *objs, "build/relink/data.o"]
    env = {**os.environ, "LD_LIBRARY_PATH": f"{TC.resolve()}/binutils/usr/lib:{TC.resolve()}/lib"
           + (":" + os.environ["LD_LIBRARY_PATH"] if os.environ.get("LD_LIBRARY_PATH") else "")}
    res = subprocess.run([c for c in cmd if c], cwd=ROOT, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        fail(f"the program doesn't link:\n{(res.stdout + res.stderr)[-3000:]}")
    os.chmod(out_path, 0o755)
    if move_data:
        move(out_path)
    total = len(B["functions"])
    from_c = sum(1 for fn in B["functions"] if source_of(fn) is not None)
    print(f"{out_path}: relinked, a new program from the C ({from_c} of {total} functions from C, the rest from asm/; "
          f"the data from data/program.s, {'laid out after the code' if move_data else 'where the game has it'})")


def old_code(elf: Elf) -> None:
    """Refuse C that writes an address in the original's code as a number (`(void (*)())0x805bc24`): the relinked
    program doesn't load that code, so it would jump into nothing. Its name is the same bytes after linking."""
    text = elf.section(".text")
    lo, hi = text["addr"], text["addr"] + text["size"]
    starts = {f["vram"]: f["name"] for f in B["functions"]}
    found = []
    for fn in B["functions"]:
        src = source_of(fn)
        if src is None:
            continue
        for n, line in enumerate(src.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in re.finditer(r"\b0x([0-9a-fA-F]{6,8})\b", line):
                addr = int(m.group(1), 16)
                if lo <= addr < hi:
                    hint = f" (that's {starts[addr]})" if addr in starts else ""
                    found.append(f"{src.relative_to(ROOT)}:{n}: 0x{addr:x}{hint}")
    if found:
        fail("the C writes addresses in the original's code as numbers; write the functions' names (the same bytes "
             "after linking):\n  " + "\n  ".join(found[:30]))


def wrap(tree: str, runtime: str) -> None:
    """Each dynamic 32-bit x86 program in `tree` started through `runtime`'s loader and libraries (a system without
    32-bit glibc): `<name>` becomes `<name>.i386`, and `<name>` a script that runs it so. GCC still finds its passes
    beside itself (argv[0] stays its path)."""
    import shlex

    loader, libs = shlex.quote(f"{Path(runtime).resolve()}/ld-linux.so.2"), shlex.quote(str(Path(runtime).resolve()))
    n = 0
    for p in sorted(Path(tree).rglob("*")):
        if not p.is_file() or p.is_symlink() or p.suffix == ".i386" or Path(runtime).resolve() in p.resolve().parents:
            continue
        head = p.open("rb").read(64)
        if head[:4] != b"\x7fELF" or head[4] != 1 or struct.unpack_from("<H", head, 18)[0] != 3:
            continue
        try:
            if Elf(p.read_bytes()).section(".interp") is None:
                continue
        except (ValueError, struct.error):
            continue
        real = p.with_name(p.name + ".i386")
        p.replace(real)
        p.write_text(f'#!/bin/sh\nexec {loader} --library-path "{libs}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}" '
                     f'--argv0 "$0" "$0.i386" "$@"\n', encoding="utf-8")
        os.chmod(p, 0o755)
        os.chmod(real, 0o755)
        n += 1
    print(f"{n} 32-bit programs start through {runtime}")


if __name__ == "__main__":
    args = sys.argv[1:]
    commands = {"rules": (rules, 0), "fixup": (fixup, 3), "data": (write_data, 1), "stubs": (stubs, 1),
                "move": (move, 1), "wrap": (wrap, 2), "asm": (write_asm, 1)}
    if args[:1] == ["link"] and len(args) in (2, 3):
        link(args[1], args[2] if len(args) == 3 else "")
    elif args and args[0] in commands and len(args) - 1 == commands[args[0]][1]:
        commands[args[0]][0](*args[1:])
    else:
        sys.exit(__doc__)
