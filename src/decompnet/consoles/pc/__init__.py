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
        """A project made before the fix of functions cut short (scratch.fix_short_ends) gets it, committed. (Seconds
        of disassembly, in the background: a project fixed already has nothing to change.)"""
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
        fixed = scratch.fix_short_ends(fp.root, str(manifest.get("version")))
        if fixed:
            net.forks._commit(proj, fp, rel, f"Lengthen {len(fixed)} functions cut short in the middle of their last "
                              "instruction\n\nWritten by decompdecomp: their sizes stopped at trailing zero bytes "
                              "(a jmp or ret N), and objdiff could never match them.")
            log(f"{slug}: {len(fixed)} functions that were cut short end at their last whole instruction now")

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


PC = WindowsPC()
