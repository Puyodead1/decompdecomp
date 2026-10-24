"""VTech V.Flash: an ARM9 (ARM code, built for the ARM9TDMI) programmed in C and C++ with GCC 3.2.3, PROJECT mode. A
game is its firmware (FA: kernel, drivers, runtime, libraries, the 3D engine) and its game modules, overlays that
share addresses.

- disc.py: the game's FA and modules from the user's own copy: a disc image (.iso; .bin or .cue), the disc's
  folder, or its files (0SYSTEM\\BOOT.BIN or FA.VFF, the modules' .VFF, OUTPUT.BIN). Standard library only; a
  project gets a copy as tools/vflash.py.
- analysis.py: each function's extent and relocations, from where Ghidra says functions start.
- scratch.py: the project: Ghidra finds where the functions start, decompdecomp cuts each one out of its program
  into an ELF object (the target objdiff compares with), and GCC 3.2.3 builds src/.
- project_template/: what that project starts as (tools/configure.py writes its ninja build).
- guides/vflash.md: what agents read about matching GCC 3.2.3's ARM code.

Its demo game is projects/demo-vflash (the Demo Quest game built with GCC 3.2.3 into a V.Flash disc image).
"""

from __future__ import annotations

from pathlib import Path

from .. import BETA, HEAD_BYTES, PROJECT, Compiler, Console

TOOLCHAIN = "gcc-3.2.3-arm-elf"


class VFlash(Console):
    id = "vflash"
    name = "V.Flash"
    short = "V.Flash"
    status = BETA
    arch = "arm"
    mode = PROJECT
    layout = "Ghidra + objdiff"
    compilers = (Compiler(TOOLCHAIN, "GCC 3.2.3 (ARM)", "every V.Flash game: firmware and game modules"),)
    packs = ((TOOLCHAIN, "GCC 3.2.3 for ARM, the compiler of V.Flash games (free software, 2 MB)"),
             ("ghidra", "finds where a V.Flash game's functions start (540 MB, needs Java 21+)"))
    guides = ("arm", "vflash")
    compiler_guide = "vflash"
    # no m2c: it reads assembly files, and these projects cut the original into objects (drafts come from Ghidra,
    # forkengine._draft; ROADMAP.md)
    ram = (0x10000000, 0x11000000)  # the console's 16 MB of RAM, where FA and the modules are loaded
    demo = "demo-vflash"
    demo_tools = (TOOLCHAIN, "objdiff-cli", "ghidra", "java")

    def sniff(self, head: bytes, file) -> bool:
        from . import disc

        path = Path(file) if isinstance(file, (str, Path)) else None
        if path is not None and path.is_dir():  # the disc's files
            system = path / "0SYSTEM"
            return any((system / f).is_file() for f in ("BOOT.BIN", "FA.VFF"))
        if path is not None and path.suffix.lower() == ".cue":
            try:
                path = disc.cue_data_file(path)
                with open(path, "rb") as f:
                    head = f.read(HEAD_BYTES)
            except (OSError, disc.DiscError):
                return False
        return disc.is_vflash(head, path)

    def upload_name(self, data: bytes) -> str:
        if data[:4] == b"BOOT":
            return "BOOT.BIN"
        return "game.vff" if data[:2] == b"vf" else "game.iso"

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        return TOOLCHAIN

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
        from . import scratch

        return scratch.create(root, game, compiler=compiler, log=log)

    def game_info(self, game: Path) -> dict:
        from . import scratch

        return scratch.game_info(game)

    def identity(self, path: Path) -> str | None:
        from . import scratch

        return scratch.identity(path)

    def tool_args(self) -> list[str]:
        from . import scratch

        return scratch.tool_args()

    def on_start(self, net, slug: str, log=print) -> None:
        """Its open functions whose code no compiler makes (arch/arm.py asm_reason: the CPU's mode or coprocessor 15,
        a piece cut out of another function) are set aside, out of agents' way: once each, in seconds."""
        from . import scratch

        if not net.fork_slug(slug):
            return
        proj, fp, _ = net.forks.get(slug)
        manifest = fp.manifest or {}
        if manifest.get("created") != "from scratch":
            return
        if (n := scratch.set_aside(net, proj, fp, str(manifest.get("version")), self.asm_reason)):
            log(f"{slug}: {n} functions no compiler makes are set aside (agents don't get them)")

    def asm_reason(self, code: bytes) -> str | None:
        from ...arch import arm

        return arm.asm_reason(code, False, thumb=False, pieces=False)

    def rename_symbol(self, fp, version: str, old: str, new: str) -> dict:
        """config/<version>/names.json: tools/names.py pairs the real name with the original's symbol, and
        tools/delink.py gives the original's objects the same name."""
        from . import scratch

        return scratch.rename(fp.root, version, old, new)

    def file_flags(self, fp, source: str) -> tuple[str, list[str]] | None:
        from . import scratch

        return scratch.file_flags(fp, source)

    def build_file_with(self, fp, unit, text: str, flags: list[str], log=print) -> tuple[Path | None, str]:
        from . import scratch

        return scratch.build_file_with(fp, unit, text, flags, log=log)

    def set_file_flags(self, fp, source: str, flags: list[str]) -> str:
        from . import scratch

        return scratch.set_file_flags(fp, source, flags)

    def read_data(self, fp, name: str, length: int) -> str | None:
        """The game's data isn't in the target objects: it's read from the programs made from the user's copy."""
        from . import scratch

        return scratch.read_data(fp.root, fp.manifest or {}, name, length)

    def data_bytes(self, fp, addr: int, length: int) -> bytes | None:
        from . import scratch

        return scratch.data_bytes(fp.root, fp.manifest or {}, addr, length)


VFLASH = VFlash()
