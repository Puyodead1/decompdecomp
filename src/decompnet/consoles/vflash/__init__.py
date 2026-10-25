"""VTech V.Flash: an ARM9 (ARM code, built for the ARM9TDMI) programmed in C and C++ with GCC 3.2.3, PROJECT mode. A
game is its firmware (FA: kernel, drivers, runtime, libraries, the 3D engine) and its game modules, overlays that
share addresses.

- disc.py: the game's FA and modules from the user's own copy: a disc image (.iso; .bin or .cue), the disc's
  folder, or its files (0SYSTEM\\BOOT.BIN or FA.VFF, the modules' .VFF, OUTPUT.BIN). Standard library only; a
  project gets a copy as tools/vflash.py.
- analysis.py: each function's extent and relocations, from where Ghidra says functions start.
- scratch.py: the project: Ghidra finds where the functions start, decompdecomp cuts each one out of its program
  into an ELF object (the target objdiff compares with), and GCC 3.2.3 builds src/; its tools/rebuild.py rebuilds
  the programs in place from what matches (the rebuild check).
- project_template/: what that project starts as (tools/configure.py writes its ninja build).
- guides/vflash.md: what agents read about matching GCC 3.2.3's ARM code.

Its demo game is projects/demo-vflash (the Demo Quest game built with GCC 3.2.3 into a V.Flash disc image).
"""

from __future__ import annotations

from pathlib import Path

from .. import BETA, HEAD_BYTES, PROJECT, REBUILD_CHECK, Compiler, Console

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
    m2c = "arm-gcc"  # (from each function's assembly, made when it's asked for: function_asm)
    ram = (0x10000000, 0x11000000)  # the console's 16 MB of RAM, where FA and the modules are loaded
    demo = "demo-vflash"
    demo_tools = (TOOLCHAIN, "objdiff-cli", "ghidra", "java")
    own_features = frozenset({REBUILD_CHECK})  # (in place: every function at its address, tools/rebuild.py)
    chooses_parts = True  # (its game modules: a game's repeat their engine's code, and each takes Ghidra a minute)
    cuts_pieces = False  # (analysis.py follows each function's code to its end)

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

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, parts: list[str] | None = None,
                       log=print) -> dict:
        from . import scratch

        return scratch.create(root, game, compiler=compiler, parts=parts, log=log)

    def parts_of(self, file: Path) -> list[dict]:
        from . import scratch

        return scratch.parts_of(Path(file))

    def game_parts(self, fp) -> list[dict]:
        from . import scratch

        try:
            return scratch.game_parts(Path(fp.root), str((fp.manifest or {}).get("version")))
        except (OSError, ValueError, KeyError):
            return []

    def add_parts(self, net, slug: str, names: list[str], log=print) -> str | None:
        """The modules' functions, library code and source files join the project's (forkengine.reanalyse: set up,
        committed and measured again)."""
        from . import scratch

        version = str((net.forks.get(slug)[1].manifest or {}).get("version"))
        return net.forks.reanalyse(slug, lambda fp: scratch.add_modules(Path(fp.root), version, names, log=log),
                                   paths=("config", "src", "include"), log=log)

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
        """Its tools, when they're an older template's untouched (scratch.refresh_tools); a project made by an older
        analysis, analysed again once (reanalyse_functions); and its open functions whose code no compiler makes
        (arch/arm.py asm_reason: the CPU's mode or coprocessor 15) are set aside, out of agents' way."""
        from . import scratch

        if not net.fork_slug(slug):
            return
        proj, fp, _ = net.forks.get(slug)
        manifest = fp.manifest or {}
        if manifest.get("created") != "from scratch":
            return
        if (tools := scratch.refresh_tools(Path(fp.root))):
            net.forks._commit_paths(proj, fp, tools, f"Update {', '.join(tools)} from decompdecomp\n\nWritten by "
                                    "decompdecomp: the project's copies were an older one's, unchanged.")
            log(f"{slug}: {', '.join(tools)} updated from decompdecomp")
            if scratch.MEASURED & set(tools):  # (the same code, read by objdiff as instructions now: built again)
                from ...forks.project import _tool
                target = next((u.target for u in fp.units() if u.target is not None), None)
                if target is not None:  # the original's objects (one step makes them all: all_source doesn't)
                    fp.run([_tool("ninja") or "ninja", str(target.relative_to(fp.root))], log=lambda *_: None)
                net.forks.check(slug, log=log, build=True)
        if (n := scratch.reopen_pieces(net, proj)):
            log(f"{slug}: {n} whole functions set aside as pieces of others are open again")
        if manifest.get("analysis", 1) < scratch.ANALYSIS:
            # (matches judged before references were checked: one stored to two variables in the other order)
            if (n := net.forks.recheck_matches(slug, log=log)):
                log(f"{slug}: {n} functions that read as matched refer to other symbols than the original's: open again")
            self.reanalyse_functions(net, slug, log=log)
        if (n := scratch.set_aside(net, proj, fp, str(manifest.get("version")), self.asm_reason)):
            log(f"{slug}: {n} functions no compiler makes are set aside (agents don't get them)")

    def reanalyse_functions(self, net, slug: str, log=print) -> str | None:
        """The project's functions as today's analysis finds them (scratch.ANALYSIS): Ghidra runs again first, while
        agents work on, then only what changed is changed (scratch.rearrange: never a matched function), set up and
        checked by rebuilding the game (forkengine.reanalyse takes it back if the rebuild no longer matches). Each
        new function that replaces old pieces gets a note: their attempts stay under their names. Once per project,
        whatever came of it. Returns what changed, as a sentence (None: nothing)."""
        import json

        from ...network import NetworkError
        from . import scratch

        proj, fp, _ = net.forks.get(slug)
        root, version = Path(fp.root), str((fp.manifest or {}).get("version"))
        try:
            programs = scratch.analyse_again(root, version, log=log)
        except Exception as e:  # (Ghidra missing or failing: tried again at the next start)
            log(f"{slug}: the new analysis couldn't run: {e}")
            return None
        changes: list[tuple[list[str], list[str]]] = []

        def step(fp):
            by_name = {v: k for k, v in scratch.real_names(root, version).items()}  # (a renamed one: by its address)
            keep = set()
            for r in net.store.all("SELECT name, meta FROM functions WHERE project_id=? AND status='matched'",
                                   proj["id"]):
                sym = json.loads(r["meta"] or "{}").get("symbol") or r["name"]
                keep.add(by_name.get(sym, sym))
            changes[:] = scratch.reanalyse(Path(fp.root), version, programs, keep)
            if not changes:
                return None
            cut = sum(1 for old, _ in changes if old)
            return (f"{cut} functions cut in the wrong place start where they do now, and "
                    f"{len(changes) - cut} more were found where no function was (loops that return only on a "
                    "condition, or never)")
        said = net.forks.reanalyse(slug, step, log=log)
        if said:
            agent, _ = net.local_agent("decompdecomp")
            real = scratch.real_names(root, version)
            for old, new in changes:
                if not old:
                    continue
                was = ", ".join(real.get(o, o) for o in old)
                for name in new:
                    try:
                        net.add_note(agent, slug, f"decompdecomp's new analysis: this is the whole function. It was "
                                                  f"cut in the wrong place before, as {was} (attempts and notes on "
                                                  "that are about a piece, not this function).", name)
                    except NetworkError:  # (not in the project's records: a copy)
                        pass
        now = net.forks.get(slug)[1].manifest or {}  # (with the rebuild reanalyse wrote)
        (root / ".decomp.wtf.json").write_text(json.dumps({**now, "analysis": scratch.ANALYSIS}, indent=2),
                                               encoding="utf-8")
        return said

    def check_rebuild(self, fp, version: str, log=print) -> dict:
        from . import scratch

        return scratch.check_rebuild(Path(fp.root), version, log=log)

    def asm_reason(self, code: bytes) -> str | None:
        from ...arch import arm

        return arm.asm_reason(code, False, thumb=False, pieces=self.cuts_pieces)

    def rename_symbol(self, fp, version: str, old: str, new: str) -> dict:
        """config/<version>/names.json: tools/names.py pairs the real name with the original's symbol, and
        tools/delink.py gives the original's objects the same name."""
        from . import scratch

        return scratch.rename(fp.root, version, old, new)

    def function_asm(self, root: Path, unit: str, symbol: str) -> str | None:
        from . import scratch

        return scratch.function_asm(Path(root), unit, symbol)

    def file_flags(self, fp, source: str) -> list[str] | None:
        from . import scratch

        return scratch.file_flags(fp, source)

    def set_file_flags(self, fp, source: str, flags: list[str]) -> str:
        from . import scratch

        return scratch.set_file_flags(fp, source, flags)

    def flag_variants(self, flags: list[str]) -> list[list[str]]:
        from . import scratch

        return scratch.flag_variants(flags)

    def read_data(self, fp, name: str, length: int) -> str | None:
        """The game's data isn't in the target objects: it's read from the programs made from the user's copy."""
        from . import scratch

        return scratch.read_data(fp.root, fp.manifest or {}, name, length)

    def data_bytes(self, fp, addr: int, length: int) -> bytes | None:
        from . import scratch

        return scratch.data_bytes(fp.root, fp.manifest or {}, addr, length)


VFLASH = VFlash()
