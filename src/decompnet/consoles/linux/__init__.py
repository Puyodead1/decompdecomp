"""Linux (32-bit x86): games and programs built for Linux on PCs around 2000-2002, from the user's own copy of the
program (an i386 ELF executable). ROM mode: each function is split out by the program's own symbol table and judged
by linking the agents' C at its address in the game (arch/x86_link.py); calls into shared libraries go to the
program's PLT stubs, which its symbols name.

Files:
- split.py: the program's functions, globals and PLT imports, by its symbol table.
- debuginfo.py: the STABS GCC 2.95 and egcs wrote with -g (source files, prototypes, locals, types), read by the PS2
  console's STABS reader.

The compiler is the distribution's own (toolchains.toml, gcc-2.95.3-linux: Slackware 8.0's GCC 2.95.3 and binutils,
with glibc 2.2.3's headers), run on the pinned 32-bit runtime."""

from __future__ import annotations

import json
from pathlib import Path

from ...rom import Picked, RomError
from .. import BETA, ROM, Compiler, Console

ELF_MAGIC = b"\x7fELF"
EM_386 = 3
MAX_SIZE = 256 << 20


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
                          "GCC: (GNU) 2.95.3 20010315 (release)"),)
    guides = ("x86",)
    ram = (0x08048000, 0x10000000)
    demo = "demo-linux"
    demo_tools = ("gcc-2.95.3-linux",)
    # ROM mode's export (not written for Linux programs yet: ROADMAP): the GNU assembler's flags and the program's
    as_flags = ("--32",)
    image_ext = ".elf"
    asm_preamble = ".intel_syntax noprefix\n.text\n"

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

    def target_from_split(self, fn, resolve, big_endian: bool, gp: int):
        from ...arch.x86_link import X86Target

        return X86Target(fn.name, fn.vram, fn.code, fn.refs or [])

    def target_from_row(self, fn: dict, cfg: dict):
        from ...arch.x86_link import X86Target

        return X86Target(fn["name"], fn["vram"], fn["target"],
                         X86Target.relocs_from_json(json.loads(fn["relocs"] or "[]")))

    def target_object(self, fn: dict, cfg: dict, symbols):
        from ...arch.x86_link import canonical_target

        return canonical_target(self.target_from_row(fn, cfg))

    def target_arch(self, fn) -> str:
        return "x86"

    def link_function(self, obj: bytes, name: str, target, symbols, read):
        from ...arch import x86_link

        return x86_link.link(obj, name, target, symbols, read)

    def compile_prelude(self, vram: int) -> str:
        """The function at its game offset modulo 16 in its object: GCC 2.95 pads its loops by that offset."""
        from ...arch.x86_link import prelude

        return prelude(vram)


LINUX = Linux()
