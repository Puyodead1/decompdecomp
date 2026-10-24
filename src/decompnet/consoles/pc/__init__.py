"""Windows PC games: 32-bit x86 programs (.exe) built with Microsoft Visual C++ 6.0, 7.0, 7.1 or 8.0 SP1,
PROJECT mode. Only
the game is a Windows program: decompdecomp runs on Linux, and so do the compilers (through wibo).

- scratch.py: a project for the user's .exe: Ghidra finds its functions, decompdecomp cuts each one out of the
  program into a COFF object of its own (the target objdiff compares with), and which Visual C++ built it comes
  from the program's Rich header.
- project_template/: what that project starts as (tools/configure.py writes its ninja build).
- guides/x86.md: what agents read about x86 and matching Visual C++'s code.
- ghidra_c.py: Ghidra's C made into drafts Visual C++ compiles, which autopilot tries (m2c reads no x86).

Its demo game is projects/demo-pc (the Demo Quest game built with Visual C++ 6.0). Older projects' configs say
"win32" (decomp.dev's id): that's this console too.
"""

from __future__ import annotations

import os
from pathlib import Path

from .. import BETA, PROJECT, Compiler, Console

MSVC_VERSIONS = ["MSVC/6.0", "MSVC/7.0", "MSVC/7.1", "MSVC/8.0-sp1"]  # the `msvc` pack


class WindowsPC(Console):
    id = "pc"
    name = "Windows PC"
    short = "PC"
    aliases = ("win32",)
    status = BETA
    arch = "x86"
    mode = PROJECT
    layout = "Ghidra + objdiff"
    compilers = tuple(Compiler(v, f"Visual C++ {v.removeprefix('MSVC/').replace('-sp', ' SP')}") for v in MSVC_VERSIONS)
    packs = (("msvc", "Visual C++ 6.0, 7.0, 7.1 and 8.0 SP1, the compilers of PC games (proprietary)"),
             ("ghidra", "finds a PC game's functions, and drafts for platforms m2c can't read (540 MB, needs Java 21+)"))
    guides = ("x86", "cpp")
    compiler_guide = "x86"
    ram = (0x00400000, 0x80000000)  # a 32-bit program's address space above its usual image base
    demo = "demo-pc"
    demo_tools = ("msvc", "objdiff-cli", "wibo", "ghidra", "java")  # Ghidra needs Java 21 or newer
    machine_drafts = "Ghidra"

    def sniff(self, head: bytes, file) -> bool:
        from .scratch import is_pe

        return is_pe(head)

    def upload_name(self, data: bytes) -> str:
        return "game.exe"

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        return ""  # the program's Rich header says which Visual C++ built it (scratch.guess_compiler)

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
        from . import scratch

        return scratch.create(root, game, compiler=compiler, log=log)

    def on_start(self, net, slug: str, log=print) -> None:
        """A project made with older tools (scratch.refresh_tools: a delinker that left functions called from their
        own file unmatchable, no real names) or before the fix of functions cut short (scratch.fix_short_ends) gets
        the fix, committed, and is measured again; and its open functions whose code no compiler makes (arch/x86.py
        asm_reason: /LTCG's register conventions, exception funclets and stubs, address tables) are set aside, out of
        agents' way. (Seconds, in the background: a project done already has nothing to change.)"""
        from . import scratch

        if not net.fork_slug(slug):
            return
        proj, fp, cfg = net.forks.get(slug)
        manifest = fp.manifest or {}
        if manifest.get("created") != "from scratch":
            return
        rel = f"config/{manifest.get('version')}/functions.json"
        if not (fp.root / rel).exists():
            return
        cut_again, was = False, (fp.root / rel).stat()
        if (tools := scratch.refresh_tools(fp.root)):
            net.forks._commit_paths(proj, fp, tools, f"Update {', '.join(tools)} from decompdecomp\n\nWritten by "
                                    "decompdecomp: the project's copies were an older one's, unchanged.")
            log(f"{slug}: {', '.join(tools)} updated: measuring the project again")
            cut_again = True
        fixed = scratch.fix_short_ends(fp.root, str(manifest.get("version")))
        if fixed:
            net.forks._commit(proj, fp, rel, f"Lengthen {len(fixed)} functions cut short in the middle of their last "
                              "instruction\n\nWritten by decompdecomp: their sizes stopped at trailing zero bytes "
                              "(a jmp or ret N), and objdiff could never match them.")
            log(f"{slug}: {len(fixed)} functions that were cut short end at their last whole instruction now")
            cut_again = True
        keep = {r["name"] for r in net.store.all(  # (a match proves its extent; set-aside code isn't worked on)
            "SELECT name FROM functions WHERE project_id=? AND status IN ('matched', 'asm')", proj["id"])}
        made = scratch.split_merged(fp.root, str(manifest.get("version")), keep=keep)
        if made:
            net.forks._commit(proj, fp, rel, f"Split {len(made)} functions off the ones Ghidra had merged them into"
                              "\n\nWritten by decompdecomp: one function, then the next (after int3 padding, or right "
                              "after its last instruction), taken for one, which objdiff could never match.")
            log(f"{slug}: {len(made)} functions Ghidra had merged into others are functions of their own now: "
                "measuring the project again")
            cut_again = True
        if cut_again:
            from ...forks.project import _tool
            target = next((u.target for u in fp.units() if u.target is not None), None)
            if target is not None:  # the original's objects, cut again (one step makes them all), then measured
                fp.run([_tool("ninja") or "ninja", str(target.relative_to(fp.root))], log=lambda *_: None)
                # every compile depends on functions.json (tools/names.py reads it), but what's built is what it
                # was: new functions have no code yet, and a length isn't a name. Its time as before, or the next
                # full build (a rename's) recompiled 9,600 files holding the project, on a big game
                os.utime(fp.root / rel, ns=(was.st_atime_ns, was.st_mtime_ns))
            net.forks.sync(slug, log=log)
        if (n := scratch.set_aside(net, proj, fp, str(manifest.get("version")), self.asm_reason)):
            log(f"{slug}: {n} functions no compiler makes are set aside (agents don't get them)")

    def rename_symbol(self, fp, version: str, old: str, new: str) -> dict:
        """config/<version>/names.json: tools/names.py pairs the real name with the original's symbol, and
        tools/delink.py gives the original's objects the same name."""
        from . import scratch

        return scratch.rename(fp.root, version, old, new)

    def source_name(self, symbol: str) -> str:
        from . import scratch

        return scratch.c_name(symbol)

    def draft_types(self, header: str) -> str | None:
        from .ghidra_c import add_types

        return add_types(header)

    def machine_draft(self, fp, symbol: str, log=print) -> tuple[str, str] | None:
        from .ghidra_c import program_draft

        return program_draft(fp, symbol, log=log)

    def machine_draft_text(self, fp, symbol: str) -> str | None:
        from .ghidra_c import program_c

        return program_c(fp, symbol)

    def file_flags(self, fp, source: str) -> tuple[str, list[str]] | None:
        from . import scratch

        return scratch.file_flags(fp, source)

    def build_file_with(self, fp, unit, text: str, flags: list[str], log=print) -> tuple[Path | None, str]:
        from . import scratch

        return scratch.build_file_with(fp, unit, text, flags, log=log)

    def set_file_flags(self, fp, source: str, flags: list[str]) -> str:
        from . import scratch

        return scratch.set_file_flags(fp, source, flags)

    def game_info(self, game: Path) -> dict:
        from . import scratch

        return scratch.game_info(game)

    def tool_args(self) -> list[str]:
        from . import scratch

        return scratch.tool_args()

    def read_data(self, fp, name: str, length: int) -> str | None:
        """The program's data isn't in the target objects: it's read from the user's copy."""
        from . import scratch

        return scratch.read_data(fp.root, fp.manifest or {}, name, length)

    def data_bytes(self, fp, addr: int, length: int) -> bytes | None:
        from . import scratch

        return scratch.data_bytes(fp.root, fp.manifest or {}, addr, length)


PC = WindowsPC()
