"""Linux (32-bit x86): games and programs built for Linux on PCs from 2000 to 2009, from the user's own copy of the
program (an i386 ELF executable). ROM mode: each function is split out by the program's own symbol table and judged
by linking the agents' C at its address in the game (arch/x86_link.py); calls into shared libraries go to the
program's PLT stubs, which its symbols name.

Files:
- split.py: the program's functions, globals and PLT imports, by its symbol table.
- debuginfo.py: the STABS GCC 2.95 and egcs wrote with -g (source files, prototypes, locals, types), read by the PS2
  console's STABS reader.
- drafts.py: Ghidra's machine drafts (m2c reads no x86) made C that GCC 2.95 compiles, for autopilot and redraft.
- export.py, export_build.py: the rebuildable tree, and its build.py (each function rebuilt where it lies in a copy
  of the program).
- guides/linux.md: matching GCC 2.95 on i386, given to every helper before its first claim.

The compilers are the distributions' own (toolchains.toml): gcc-2.95.3-linux, Slackware 8.0's GCC 2.95.3 and binutils
with glibc 2.2.3's headers; gcc-4.3.2-linux, Debian 5.0's GCC 4.3.2 and binutils 2.18 with glibc 2.7's; and
gcc-4.3.2-redhat-linux, Fedora 10's (Red Hat's 4.3.2-7, C and C++); egcs-1.1.2-linux, Slackware 7.0's egcs 1.1.2
(egcs-2.91.66) and binutils 2.9.1 with glibc 2.1.2's headers; all run on the pinned 32-bit runtime. The program's
.comment says which (default_compiler), and the import says when it names one there's none of."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ...arch import BOUNDARIES
from ...rom import Picked, RomError
from .. import BETA, EXPORT, ROM, Compiler, Console

ELF_MAGIC = b"\x7fELF"
EM_386 = 3
MAX_SIZE = 256 << 20
LIBRARY_LEVELS = ("-O0", "-O2", "-O1", "-O3", "-Os")
LIBRARY_MARCHES = ("", "amdfam10", "k8", "core2", "pentium4", "i686")  # (a build machine's -march=native)
DEMANGLE_SECONDS = 300  # (one c++filt run for every name: 54,000 of a 2008 program's in a few seconds)
PIC_PROLOGUE = re.compile(rb"\xe8\0\0\0\0[\x58-\x5f]\x81[\xc0-\xc7]")  # call +0; pop %reg; add $GOT, %reg
DEBUG_LINES = 1  # the version of what add_line_tables reads into a project imported before it


class Linux(Console):
    id = "linux"
    name = "Linux (x86)"
    short = "Linux"
    status = BETA
    arch = "x86"
    big_endian = False
    mode = ROM
    layout = "elf"
    compilers = (Compiler("gcc-2.95.3-linux", "GCC 2.95.3 (Slackware 8.0)", "Linux programs of 2001-2002",
                          "GCC: (GNU) 2.95.3 20010315 (release)"),
                 Compiler("egcs-1.1.2-linux", "egcs 1.1.2 (Slackware 7.0)", "Linux programs of 1999-2000",
                          "GCC: (GNU) egcs-2.91.66 19990314/Linux (egcs-1.1.2 release)"),
                 Compiler("gcc-4.3.2-linux", "GCC 4.3.2 (Debian 5.0)", "Linux programs of 2008-2009",
                          "GCC: (Debian 4.3.2-1.1) 4.3.2"),
                 Compiler("gcc-4.3.2-redhat-linux", "GCC 4.3.2 (Red Hat, Fedora 10)",
                          "Linux programs of 2008-2009 built on Fedora or Red Hat (C and C++)",
                          "GCC: (GNU) 4.3.2 20081105 (Red Hat 4.3.2-7)"))
    guides = ("linux",)  # (not the PC's x86 guide: its conventions are Visual C++'s)
    compiler_guide = "linux"  # (guides/linux.md: GCC 2.95's habits on i386, given every helper before its first claim)
    ram = (0x08048000, 0x10000000)
    demo = "demo-linux"
    demo_tools = ("gcc-2.95.3-linux",)
    # (the export assembles nothing: export.py builds each function's C into a copy of the program)
    as_flags = ("--32",)
    image_ext = ".elf"
    # search_flags: the build machine's processor (-march=native): a 2008 program's Lua was built for AMD's family 10h
    flag_extras = ("-march=amdfam10", "-march=k8", "-march=core2")
    # cutting a function (split.split_function, at an instruction's start); the export (export.py)
    own_features = frozenset({BOUNDARIES, EXPORT})
    plain_build = True  # (`make` and `make asan`: NON_MATCHING)

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        """The compiler of the GCC version the program's .comment names, whoever built that GCC: Debian's 4.3.2 says
        "GCC: (Debian 4.3.2-1.1) 4.3.2", Ubuntu's "GCC: (Ubuntu 4.3.2-1ubuntu12) 4.3.2", a GCC built from its
        release "GCC: (GNU) 4.3.2" (an exact match took only the first). A version none of them is takes the first."""
        said = info.get("compiler_guess", "")
        if (exact := next((c.id for c in self.compilers if c.guess == said), None)):
            return exact
        version = m.group(1) if (m := re.search(r"GCC: \([^)]*\) (\d+\.\d+(?:\.\d+)?)", said)) else None
        vendor = "redhat-" if "Red Hat" in said else ""  # (Red Hat's GCC is patched its own way: its own build)
        ids = {c.id for c in self.compilers}
        for wanted in (f"gcc-{version}-{vendor}linux", f"gcc-{version}-linux"):
            if version and wanted in ids:
                return wanted
        if said:  # (a sound program of egcs 1.1.2 was matched with GCC 2.95.3 for weeks: its `leal 0(,%reg,2)`, which
            # no C makes 2.95.3 write, read as "a different 2.95.3 build" by the agents. Say so at the import.)
            info["compiler_why"] = (f"the program's .comment says {said!r}, which no compiler decompdecomp has is: "
                                    f"{self.compilers[0].name} instead, whose code differs from it in places (no C "
                                    "makes it the game's there); ROADMAP.md, Linux, lists the compilers to come")
        return self.compilers[0].id

    def library_flags(self, flags: list[str]) -> list[list[str]]:
        """A library's own build: an optimisation level, and the processor it was tuned for. A 2008 program's Lua and
        luabind were built -O0 for the build machine's AMD processor (-march=amdfam10: 71 of lapi.c's 74 functions,
        none at the game's -O2), its TinyXML -O0 alone, its libogg and libpng -O2."""
        out = [list(flags)]
        for level in LIBRARY_LEVELS:
            for march in LIBRARY_MARCHES:
                variant = [level, *([f"-march={march}"] if march else [])]
                if variant not in out:
                    out.append(variant)
        return out

    def demangle(self, names: list[str], toolchain: str) -> dict[str, str]:
        """A C++ program's symbols (`_ZN14CRandStoryDataC1Ev`, GCC 2's `Get__C4Data`) as written, by the c++filt of
        the binutils the project's compiler comes with (the pinned toolchain's, in the sandbox: no tool of the
        host's), all in one run. {} when its compiler isn't installed or none is C++."""
        import tempfile

        from ... import compiler, toolchains
        from ...project import compiler_config

        mangled = sorted({n for n in names if n.startswith("_Z") or "__" in n.strip("_")})
        if not mangled:
            return {}
        try:  # (free software: installed when a program needs it, as its import does)
            toolchains.ensure(toolchain, log=lambda *_: None)
        except toolchains.ToolchainError:
            return {}
        with tempfile.TemporaryDirectory(prefix="decompnet-") as tmp:
            work = Path(tmp)
            (work / "names.txt").write_text("\n".join(mangled) + "\n", encoding="utf-8")
            cfg = compiler_config(work, {"compiler": {"toolchain": toolchain, "flags": []}})
            tc = toolchains.path(toolchain)
            res = compiler.run_in(cfg, work, ["/bin/sh", "-c", f'LD_LIBRARY_PATH="{tc}/lib:{tc}/binutils/usr/lib'
                                              '${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" exec '
                                              f'"{tc}/binutils/usr/bin/c++filt" < names.txt > demangled.txt'],
                                  timeout=DEMANGLE_SECONDS)
            out = (work / "demangled.txt").read_text(encoding="utf-8", errors="replace").splitlines() \
                if res.returncode == 0 and (work / "demangled.txt").exists() else []
        if len(out) != len(mangled):
            return {}
        return {m: d for m, d in zip(mangled, out) if d and d != m}

    def after_import(self, net, slug: str, *, chosen: bool, log=print) -> None:
        self.add_got(net, slug, log=log)

    def add_got(self, net, slug: str, log=print) -> None:
        """Where the program's GOT is and what its entries hold (split.got_info), for the judge of -fPIC code: a
        program imported before has none, and glibc's atexit, linked in from libc_nonshared.a, could never match."""
        proj = net.project_row(slug)
        cfg = net.cfg(proj)
        program = Path(proj["root"]) / cfg.get("rom", {}).get("program", "")
        if "got" in cfg or net._link(slug) or not cfg.get("rom", {}).get("program") or not program.is_file():
            return
        from .split import got_info, read_program

        info = got_info(read_program(program.read_bytes()))
        net._update_cfg(slug, lambda c: c.update(got=info))
        self.add_pic(net, slug, log=log)

    def add_pic(self, net, slug: str, log=print) -> int:
        """Functions built with -fPIC (their code starts by finding the GOT: `call +0; pop %ebx; add $GOT, %ebx`,
        glibc's atexit from libc_nonshared.a among them) get a compiler range with -fPIC added, and those agents set
        aside before the judge read -fPIC code are open again: five agents of two models had agreed no C makes
        glibc's own atexit.c, because nothing could match it. Returns how many."""
        from ...project import compiler_for

        proj = net.project_row(slug)
        cfg = net.cfg(proj)
        rows = [r for r in net.store.all("SELECT id, name, vram, size, status, meta, target FROM functions WHERE "
                                         "project_id=?", proj["id"]) if PIC_PROLOGUE.search(bytes(r["target"] or b"")[:24])]
        ranges = []
        for r in rows:
            current = compiler_for(cfg, r["vram"])
            if "-fPIC" not in (current.get("flags") or []):
                ranges.append({"start": r["vram"], "end": r["vram"] + r["size"], "toolchain": current["toolchain"],
                               "flags": [*(current.get("flags") or []), "-fPIC"]})
        if ranges:
            net._update_cfg(slug, lambda c: c.update(compiler_ranges=ranges + list(c.get("compiler_ranges") or [])))
        reopened = 0
        with net.store.tx() as db:
            for r in rows:
                meta = json.loads(r["meta"] or "{}")
                if r["status"] != "asm" or meta.get("set_aside"):
                    continue
                meta = {k: v for k, v in meta.items() if k not in ("not_c", "asm_code", "asm_twin")}
                reopened += db.execute("UPDATE functions SET status='open', meta=? WHERE id=? AND status='asm'",
                                       (json.dumps(meta), r["id"])).rowcount
                net._event(db, proj["id"], None, "reopen",
                           f"{r['name']}: open again (built with -fPIC, which the judge reads now)")
        if ranges or reopened:
            log(f"{slug}: {len(ranges)} functions built with -fPIC are compiled so now ({reopened} set aside before "
                "are open again)")
        return len(ranges)

    def on_start(self, net, slug: str, log=print) -> None:
        """A C++ program imported before its functions had their names as written (meta "demangled") gets them, and
        one imported before its STABS line tables were read gets those (add_line_tables), and its GOT (add_got)."""
        self.add_got(net, slug, log=log)
        self.add_line_tables(net, slug, log=log)
        proj = net.project_row(slug)
        if net.cfg(proj).get("demangled"):  # (done once: a C program's names stay as they are)
            return
        rows = net.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND (name LIKE '\\_Z%' ESCAPE '\\' "
                             "OR name LIKE '%\\_\\_%' ESCAPE '\\') AND (meta IS NULL OR meta NOT LIKE '%\"demangled\"%')",
                             proj["id"])
        names = self.demangle([r["name"] for r in rows], net.cfg(proj)["compiler"]["toolchain"]) if rows else {}
        if rows and not names and any(r["name"].startswith("_Z") for r in rows):
            return  # (its compiler couldn't run: the next start tries again)
        net._update_cfg(slug, lambda cfg: cfg.update(demangled=True))
        if not names:
            return
        with net.store.tx() as db:
            for r in rows:
                if r["name"] in names:
                    meta = json.loads(r["meta"] or "{}")
                    meta["demangled"] = names[r["name"]]
                    db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), r["id"]))
        log(f"{slug}: {len(names)} C++ functions have their names as written")

    def add_line_tables(self, net, slug: str, log=print) -> None:
        """Each function's line table, the lines its locals are declared on and the register a parameter lives in
        (debuginfo.read, ps2/debuginfo._line_table), for a project imported before they were read: its briefs said
        only which locals there were, and agents spent 273 compiles on a function whose table showed its shape."""
        from . import debuginfo

        proj = net.project_row(slug)
        cfg = net.cfg(proj)
        program = Path(proj["root"]) / cfg.get("rom", {}).get("program", "")
        if cfg.get("kind") != "rom" or cfg.get("debug_lines", 0) >= DEBUG_LINES or net._link(slug) \
                or not program.is_file():  # (a room's guest: the host reads it; the game's file gone: it may come back)
            return
        info = debuginfo.read(program.read_bytes())
        found = {address: known for address, known in (info.functions if info is not None else {}).items()
                 if known.get("lines")}
        changed = 0
        if found:
            rows = net.store.all("SELECT id, vram, meta FROM functions WHERE project_id=? AND meta LIKE '%\"debug\"%'",
                                 proj["id"])
            with net.store.tx() as db:
                for r in rows:
                    meta = json.loads(r["meta"] or "{}")
                    if (known := found.get(r["vram"])) is None or not isinstance(meta.get("debug"), dict):
                        continue
                    meta["debug"].update({k: known[k] for k in ("line", "params", "locals", "lines", "blocks") if k in known})
                    db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), r["id"]))
                    changed += 1
        net._update_cfg(slug, lambda c: c.update(debug_lines=DEBUG_LINES))
        if changed:
            log(f"{slug}: {changed} functions' briefs have the game's line table now (which source line each "
                "instruction came from)")

    def sniff(self, head: bytes, file) -> bool:
        """A 32-bit x86 ELF executable (an i386 Linux program): ELF class 1, little-endian, e_machine 3."""
        return (len(head) >= 20 and head[:4] == ELF_MAGIC and head[4] == 1 and head[5] == 1
                and int.from_bytes(head[18:20], "little") == EM_386 and int.from_bytes(head[16:18], "little") == 2)

    def read_game(self, file, name: str = "") -> Picked:
        from . import split

        data = Path(file).read_bytes() if isinstance(file, (str, Path)) else bytes(file)
        if len(data) > MAX_SIZE:
            raise RomError(f"this file is {len(data) >> 20} MiB: larger than a Linux program decompdecomp reads")
        split.read_program(data)  # (says why when it isn't one it can split)
        filename = Path(name or getattr(file, "name", "") or "program").name
        return Picked(self.id, data, filename or "program", split.info(data, filename), False)

    def split_game(self, workdir: Path, picked: Picked, *, symbols: list[str] | None = None, log=print):
        from . import split

        return split.split(workdir / picked.filename, log=log)

    def linked_libraries(self, program: bytes) -> list[str]:
        from io import BytesIO

        from elftools.common.exceptions import ELFError
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.elffile import ELFFile

        try:
            return [t.needed for s in ELFFile(BytesIO(program)).iter_sections() if isinstance(s, DynamicSection)
                    for t in s.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
        except (ELFError, ValueError):
            return []

    def debug_info(self, program: bytes, known: set[str]):
        from . import debuginfo

        return debuginfo.read(program, known)

    def debug_brief(self, known: dict) -> list[str]:
        from ..ps2 import debuginfo

        return debuginfo.brief_lines(known)

    def function_insns(self, fn) -> int:
        return fn.n_insns if hasattr(fn, "n_insns") else fn.get("n_insns") or 1

    def function_asm(self, fn) -> str:
        return fn.asm if hasattr(fn, "asm") else fn["asm"]

    def function_status(self, fn) -> str:
        return "asm" if getattr(fn, "runtime", False) else "open"

    def instruction_size(self, fn) -> int:
        return 1  # (x86 instructions are 1 to 15 bytes: none is a fixed size)

    def function_from_row(self, row: dict):
        from . import split

        return split.function_from_row(row)

    def parse_function(self, name: str, text: str, segment: str):
        """(a row's bytes are what the splitter's function needs: text alone has no code)"""
        from . import split

        return split.LinuxFunction(name, 0, 0, b"", text, max(1, len(text.splitlines())), [], segment)

    def split_function(self, fn: dict, at: int, new_name: str):
        from . import split

        return split.split_function(fn, at, new_name)

    def function_at(self, rom: bytes, addr: int, limit: int, name: str):
        from . import split

        return split.function_at(rom, addr, limit, name)

    def join_saved_functions(self, rows: list[dict], start: int, end: int, read):
        from . import split

        return split.join_saved_functions(rows, start, end, read)

    def target_from_split(self, fn, resolve, big_endian: bool, gp: int):
        from ...arch.x86_link import X86Target

        return X86Target(fn.name, fn.vram, fn.code, fn.refs or [])

    def target_from_row(self, fn: dict, cfg: dict):
        from ...arch.x86_link import X86Target

        got = cfg.get("got") or {}
        return X86Target(fn["name"], fn["vram"], fn["target"],
                         X86Target.relocs_from_json(json.loads(fn["relocs"] or "[]")), got.get("base"),
                         {int(k, 16): v for k, v in (got.get("slots") or {}).items()})

    def target_object(self, fn: dict, cfg: dict, symbols):
        from ...arch.x86_link import canonical_target

        return canonical_target(self.target_from_row(fn, cfg))

    def target_arch(self, fn) -> str:
        return "x86"

    def link_function(self, obj: bytes, name: str, target, symbols, read, placed=None):
        from ...arch import x86_link

        return x86_link.link(obj, name, target, symbols, read, placed)

    rom_drafts = True  # (Ghidra's: m2c reads no x86)

    def program_drafts(self, program: Path, cache: Path, wait: bool = True) -> dict[int, str] | None:
        from ...forks import ghidra

        return ghidra.decompile_program(program, cache, wait=wait) if ghidra.available() else None

    def draft_source(self, draft: str, name: str, header: str, data: dict[str, int] | None = None) -> str | None:
        from . import drafts

        return drafts.compilable(draft, name, header, data)

    def export_project(self, net, slug: str, out: Path, log=print) -> dict:
        from .export import export_linux

        return export_linux(net, slug, out, self, log=log)

    def compile_prelude(self, vram: int) -> str:
        """The function at its game offset modulo 16 in its object: GCC 2.95 pads its loops by that offset."""
        from ...arch.x86_link import prelude

        return prelude(vram)

    def compile_layouts(self, vram: int) -> list[str]:
        from ...arch.x86_link import layouts

        return layouts(vram)


LINUX = Linux()
