"""Windows PC games: 32-bit x86 programs (.exe) built with Microsoft Visual C++ 6.0 to 2010, PROJECT mode. Only
the game is a Windows program: decompdecomp runs on Linux and macOS, and so do the compilers (through wibo; Visual
C++ 2017's, which wibo can't run, through wine: wine.py). Visual C++ 2017 (its 32-bit and 64-bit compilers) can be
chosen for a source file in Settings; games built with it are next (ROADMAP.md, Newer Windows games).

- scratch.py: a project for the user's .exe: Ghidra finds its functions, decompdecomp joins the pieces Ghidra cut
  off them back to them (merge_pieces, by arch/x86.piece) and cuts each one out of the program into a COFF object
  of its own (the target objdiff compares with); which Visual C++ built it comes from the program's Rich header,
  which also says (with its sections) whether decompdecomp can start it at all: 64-bit, Visual C++ 2017 and newer,
  mostly whole-program optimised, or wrapped in DRM (scratch.describe). The rebuild check, which is also the
  project's export, puts the whole program back together from the project (`ninja rebuild`, check_code): each
  function from its C where that compiles to the game's code, else from those objects. Visual C++'s
  exception-handling stubs are set aside (exception_stubs), and so are the import thunks, named after their imports
  (name_import_thunks). Projects made before get what the import learnt since when the app starts (on_start,
  ANALYSIS).
  Each source file can have its own Visual C++ (file_compiler, set_file_compiler: config/<version>/file_compilers.json)
  and split_file divides one (split_source: a unit of functions.json). The game's own DLLs beside the .exe are
  programs of the project too (find_modules; a game given as its folder: program_in), each in a folder of src/auto/.
- rtti.py: the C++ classes the program's run-time type information names, those of its code built without it (from
  the vtables constructors store), their fields and the struct layouts of every function's pointers, read by
  arch/x86_fields.py (get_class, guess_struct, drafts as `Class::method`).
- debuginfo.py, pdb.py: the game's own debug information, when it has it (a .pdb beside it, the linker's .map, COFF
  symbols): real names, the game's source files, types for include/debug_types.h and prototypes for briefs
  (debug_of).
- drafts.py: what autopilot tries where m2c can't read x86: exact drafts of the tiny shapes Visual C++ makes, read from
  the code, and Ghidra's drafts made into C++ that compiles in the project (also in briefs, the background drafter and
  redraft). Each file may be built with more flags (file_flags: /Oy- where its functions keep an ebp frame, found by
  the import: scratch.frame_flags), which search_flags tries.
- project_template/: what that project starts as (tools/configure.py writes its ninja build).
- guides/x86.md: what agents read about x86 and matching Visual C++'s code.

Its demo game is projects/demo-pc (the Demo Quest game built with Visual C++ 6.0, or with any compiler of the
packs: build.py 10.0SP1). Older projects' configs say "win32" (decomp.dev's id): that's this console too.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ...network import NetworkError
from .. import BETA, PROJECT, REBUILD_CHECK, Compiler, Console

MSVC_VERSIONS = ["MSVC/6.0", "MSVC/7.0", "MSVC/7.1",  # the `msvc` pack
                 "MSVC/8.0", "MSVC/8.0SP1", "MSVC/9.0", "MSVC/9.0SP1", "MSVC/10.0", "MSVC/10.0SP1",  # `msvc2005`
                 "MSVC/14.16", "MSVC/14.16-x64"]  # `msvc2015`: its 32-bit compiler and its 64-bit one
# what the app calls a version whose number alone doesn't say it: 2017's (Visual Studio's year, and its target)
MSVC_NAMES = {"14.16": "Visual C++ 14.16 (2017)", "14.16-x64": "Visual C++ 14.16 (2017, 64-bit)"}


class WindowsPC(Console):
    id = "pc"
    name = "Windows PC"
    short = "PC"
    aliases = ("win32",)
    status = BETA
    arch = "x86"
    mode = PROJECT
    layout = "Ghidra + objdiff"
    compilers = tuple(Compiler(v, MSVC_NAMES.get(v.removeprefix("MSVC/"),
                                                 f"Visual C++ {v.removeprefix('MSVC/').replace('SP', ' SP')}"))
                      for v in MSVC_VERSIONS)
    packs = (("msvc", "Visual C++ 6.0, 7.0 and 7.1, the compilers of PC games (proprietary)"),
             ("msvc2005", "Visual C++ 2005, 2008 and 2010, the compilers of newer PC games (proprietary, 600 MB)"),
             ("msvc2015", "Visual C++ 2017, 32- and 64-bit, with its Windows 10 SDK (proprietary, 220 MB; runs "
                          "through wine on Linux and macOS, which you install)"),
             ("ghidra", "finds a PC game's functions, and drafts for platforms m2c can't read (540 MB, needs Java 21+)"))
    guides = ("x86", "cpp")
    compiler_guide = "x86"
    ram = (0x00400000, 0x80000000)  # a 32-bit program's address space above its usual image base
    demo = "demo-pc"
    demo_tools = ("msvc", "objdiff-cli", "wibo", "ghidra", "java")  # Ghidra needs Java 21 or newer
    # the whole program rebuilt from the project: like GameCube's and DS's, the project is the export
    own_features = frozenset({REBUILD_CHECK})
    reimports = True  # Ghidra again, read by the newest rules, matches kept (reimport)
    # what a project's config holds, in its manifest's "analysis" (on_start brings one with less up, step by step):
    # 1 (or none: every project made before 2) Ghidra's functions as it found them; 2 no jump table's entries
    # relocated twice (scratch.drop_repeated_relocations), no far call relocated (drop_far_call_relocations) and
    # every function's last instruction whole (complete_last_instructions); 3 Visual C++'s exception-handling stubs set aside (scratch.mark_exception_stubs);
    # 4 the pieces of functions Ghidra cut off joined to them (scratch.merge_pieces), never a stub; 5 the import thunks
    # functions of their own, named after their imports and set aside (scratch.name_import_thunks); 6 the files whose
    # functions keep an ebp frame built with /Oy- (scratch.set_frame_flags), but for files with matched code: after
    # the thunks, which keep no frame and would count against their file's; 7 the stubs again, now that Visual C++
    # 2005's /GS handlers are known (a 2007 game's 2,860 stubs were open: none of its handlers had the older shape); 8
    # the joins again, for the jump tables Ghidra made functions of (scratch.merge_pieces); 9 the functions Ghidra didn't
    # know the stack arguments of named by their `ret N` (scratch.fix_unknown_purges), their rows renamed with them;
    # 10 the int3 Visual C++ ends a function with after a call that doesn't return (scratch.take_noreturn_int3s);
    # 11 /GS for the files whose functions make its cookie (scratch.set_gs_flags); 12 the functions Ghidra took
    # several for cut into them (scratch.split_merged_functions); 13 again, where a matched function refers to the
    # cut's address too (12 left those whole); 14 Visual C++'s runtime library set aside as library code, as
    # Ghidra's Function ID knows it (scratch.recognise_library: Ghidra runs again, once); 15 the runtime libraries'
    # own code, where the game's Visual C++ has them (scratch.runtime_matches); 16 that list found again, its helpers
    # beside the runtime's code and never what its startup calls (15's took a 2003 game's WinMain and what it calls);
    # 17 the C runtime the game links (/MT, /MD) in every file's flags (scratch.set_runtime_flag).
    # Its build tools have a version of their own (the manifest's "tools": scratch.tools_version), so each change to
    # them reaches it
    ANALYSIS = 17

    def sniff(self, head: bytes, file) -> bool:
        """Any Windows program, 64-bit ones too: the import says exactly why one it can't start can't start."""
        from .scratch import is_windows_program

        return is_windows_program(head)

    def upload_name(self, data: bytes) -> str:
        return "game.exe"

    def program_in(self, folder: Path) -> Path | None:
        """A PC game is a folder: its .exe, and the DLLs of its own create takes along (scratch.find_modules)."""
        from .scratch import program_in

        return program_in(folder)

    def default_compiler(self, info: dict, splat_guess: str) -> str:
        return ""  # the program's Rich header says which Visual C++ built it (scratch.guess_compiler)

    def create_project(self, root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
        from . import scratch

        return scratch.create(root, game, compiler=compiler, log=log)

    def game_info(self, game: Path) -> dict:
        from . import scratch

        return scratch.game_info(game)

    def tool_args(self) -> list[str]:
        from . import scratch

        return scratch.tool_args()

    def build_env(self) -> dict[str, str]:
        """Where wine and the app's prefix are, which tools/compile.py reads when a Visual C++ 2015+ file builds: read
        then, not written into build.ninja, so a project configured before the pack or wine was installed builds such
        a file as soon as they are, and an older configure.py is never given an argument it doesn't know."""
        from ... import wine

        return wine.build_env()

    def on_start(self, net, slug: str, log=print) -> None:
        """A project made by an older decompdecomp gets what its import has learnt since, one step at a time from the
        level its manifest's "analysis" says (ANALYSIS lists them), each through forkengine.reanalyse: one commit and
        one line in the project's feed per step. A step that changes code (the repairs, the joins) is kept only when
        the program's code still rebuilds byte for byte from the delinked functions (check_rebuild), else taken back.
        The repairs go first: without them the rebuild can't be identical, and the joins need it to be. The stubs
        come next, found on the repaired functions, so the joins never take one (the function before the run, a C
        runtime function with a frame, would look continued by a funclet that reads ebp). The functions that grew
        are open again, with a note: what set them aside, and older notes, were about a part. A project without the
        user's copy of the program in it yet waits for the next start: every step reads it. Last, a project whose
        build tools aren't the template's (its manifest's "tools", scratch.tools_version) gets them, the same way:
        one commit and feed line, kept only when the rebuild check stays as it was, and tried once per version."""
        from . import scratch

        if not net.fork_slug(slug):
            return
        fp = net.forks.get(slug)[1]
        manifest = fp.manifest or {}
        if manifest.get("created") != "from scratch" or (manifest.get("analysis", 1) >= self.ANALYSIS and
                                                          manifest.get("tools") == scratch.tools_version()):
            return
        version = manifest["version"]
        if not (fp.root / manifest.get("game", {}).get("path", f"orig/{version}.exe")).is_file() or \
                scratch.missing(fp.root, version):  # (the game's DLLs too: each step reads every program)
            return
        if (why := scratch.compiler_missing(fp.root)):  # (each step builds: taken back for want of it, and not tried
            log(f"{slug}: {why}")                        # again)
            return
        changed, compiler = scratch.adopt_fork_layout(fp.root, version)
        if changed:  # (first: the steps below build with the tools that read its names)
            proj = net.project_row(slug)
            rows = {r["name"]: r for r in net.store.all("SELECT id, name, meta FROM functions WHERE project_id=?",
                                                         proj["id"])}
            renamed = scratch.fork_row_names(rows, _functions_json(fp, version).get("names") or {})
            with net.store.tx() as db:
                for old, new in renamed.items():
                    meta = json.loads(rows[old]["meta"] or "{}")
                    if meta.get("symbol") == old:
                        meta["symbol"] = new
                    db.execute("UPDATE functions SET name=?, meta=? WHERE id=?", (new, json.dumps(meta), rows[old]["id"]))
            if compiler:
                manifest = fp.update_manifest(compiler=f"MSVC/{compiler}")
                net._update_cfg(slug, lambda cfg: cfg.update(compiler=f"MSVC/{compiler}"))
                changed.append(".decomp.wtf.json")
            manifest = fp.update_manifest(tools=scratch.tools_version())
            net.forks._commit_paths(proj, fp, sorted(set(changed)), "Take decompdecomp's own layout for PC projects\n\n"
                                    "Written by decompdecomp: real names in functions.json, each file's flags in "
                                    "file_flags.json, and its build tools, which read them.")
            log(f"{slug}: made by a fork of decompdecomp: its names, flags and tools are this one's now")
            for cmd in fp.setup_commands(version):  # (its build.ninja named the files that are gone: written again)
                ok, out = fp.run(cmd, log=lambda *_: None, timeout=scratch.TOOL_SECONDS)
                if not ok:
                    log(f"{slug}: {' '.join(cmd[:2])} failed after the change: {out[-scratch.ERROR_TAIL:]}")
                    break
            net.forks.check(slug, log=log, build=True)

        def matched() -> set[str]:  # not into or out of a matched function: its C would no longer be the whole one
            return {r["name"] for r in net.store.all("SELECT name FROM functions WHERE project_id=? AND "
                                                     "status='matched'", net.project_row(slug)["id"])}

        def repairs(fp):
            n = scratch.drop_repeated_relocations(fp.root, version)
            far = scratch.drop_far_call_relocations(fp.root, version)
            cut = scratch.complete_last_instructions(fp.root, version, keep=matched())
            said = [f"{n} functions had a jump table's entries relocated twice, and once now"] if n else []
            if far:
                said.append(f"{far} functions had a far call's address taken for a call to another function, and keep "
                            "it as it is now")
            if cut:
                said.append(f"{cut} functions that ended in the middle of their last instruction have all of it now")
            return "; ".join(said) or None

        def stubs(fp):
            n = scratch.mark_exception_stubs(fp.root, version)
            return (f"{n} functions are exception-handling code Visual C++ makes from the function they belong to "
                    "(its .text$x): set aside, as no C of their own makes them" if n else None)
        joined: dict[str, list[str]] = {}

        def pieces(fp):
            took = scratch.merge_project_pieces(fp.root, version, keep=matched(), log=log)
            joined.update(took)  # (each step's own: step 8 runs it again)
            n = sum(len(v) for v in took.values())
            return f"{n} pieces of functions Ghidra cut off are part of the function they belong to again" if n else None
        def thunks(fp):
            n = scratch.name_import_thunks(fp.root, version, keep=matched())
            return (f"{n} functions are import thunks the linker adds for calls to DLLs' functions: named after the "
                    "function each calls, and set aside" if n else None)

        def frames(fp):  # (files with matched code keep their flags: that C matches with them)
            done = {scratch._source(fp.root, r["unit"]) for r in net.store.all(
                "SELECT DISTINCT unit FROM functions WHERE project_id=? AND status='matched'", net.project_row(slug)["id"])}
            n = scratch.set_frame_flags(fp.root, version, keep=done)
            return (f"{n} source files whose functions keep an ebp frame build with {scratch.FRAME_FLAG} now (Visual "
                    "C++ keeps the frame pointer), as the game's were" if n else None)

        renamed: dict[str, str] = {}

        def rename_rows(names: dict[str, str]) -> None:  # (their attempts, notes and claims hang off the row)
            rows = net.store.all("SELECT id, name, meta FROM functions WHERE project_id=?", net.project_row(slug)["id"])
            with net.store.tx() as db:
                for r in rows:
                    meta = json.loads(r["meta"] or "{}")
                    if (old := meta.get("symbol")) in names:
                        meta["symbol"] = names[old]
                        db.execute("UPDATE functions SET name=?, meta=? WHERE id=?",
                                   (names[old] if r["name"] == old else r["name"], json.dumps(meta), r["id"]))

        def purges(fp):  # (before the sync: the rows keep their history under the new names)
            renamed.update(scratch.fix_unknown_purges(fp.root, version, keep=matched()))
            rename_rows(renamed)
            return (f"{len(renamed)} functions whose stack arguments Ghidra didn't know are named by what their `ret` "
                    "takes off the stack (no C declaration made the old names)" if renamed else None)

        def int3s(fp):
            n = scratch.take_noreturn_int3s(fp.root, version, keep=matched())
            return (f"{n} functions ending in a call that doesn't return have the int3 their compiler puts after it "
                    "(it was taken for padding, so no C matched them)" if n else None)

        def gs(fp):  # (files with matched code keep their flags: agents' C with an array where the game has none
            #           took the cookie, and five matched functions of a 2002 game stopped matching. search_flags tries
            #           /GS on those, kept when the file's matched functions still match)
            done = {scratch._source(fp.root, r["unit"]) for r in net.store.all(
                "SELECT DISTINCT unit FROM functions WHERE project_id=? AND status='matched'", net.project_row(slug)["id"])}
            n = scratch.set_gs_flags(fp.root, version, keep=done)
            return (f"{n} source files whose functions make a buffer security cookie build with {scratch.GS_FLAG} now, "
                    "as the game's were" if n else None)

        def merged(fp):
            n = scratch.split_merged_functions(fp.root, version, keep=matched())
            return (f"{n} functions Ghidra took for part of the one before them (only a table of pointers reaches "
                    "them) are functions of their own" if n else None)

        def library(fp):  # (set_aside.json: what's matched stays matched, off the progress like the rest)
            return _library_said(scratch.recognise_library(fp.root, version, _compiler(fp), log=log),
                                 "Visual C++'s runtime library (Ghidra's Function ID knows them) or helpers only it uses")

        def runtime_code(fp):
            return _library_said(scratch.set_library_aside(fp.root, version, {}, _compiler(fp)),
                "Visual C++'s runtime library, found by Function ID or by its own code in the libraries its compiler "
                "has, or helpers only it uses")

        def runtime_flag(fp):
            flag = scratch.set_runtime_flag(fp.root, version)
            return (f"every source file builds with {flag} now, for the C runtime the game links (its headers make "
                    "that runtime's code: errno, the STL's locks)" if flag else None)

        def tools(fp):  # (no source file changes: agents' C stays as it is)
            changed = scratch.write_tools(fp.root, version)
            return (f"its build has the fixes decompdecomp's has had since the project was made ({', '.join(changed)})"
                    if changed else None)
        # (fix for the stubs: a step that changes no code can't break the rebuild, so it's kept where the rebuild
        # isn't identical yet too)
        steps = {2: (repairs, False), 3: (stubs, True), 4: (pieces, False), 5: (thunks, False), 6: (frames, True),
                 7: (stubs, True), 8: (pieces, False), 9: (purges, True), 10: (int3s, False),
                 11: (gs, True), 12: (merged, False), 13: (merged, False), 14: (library, True),
                 15: (runtime_code, True), 16: (runtime_code, True), 17: (runtime_flag, False)}
        kept = {}
        for level, (step, fix) in steps.items():
            if manifest.get("analysis", 1) < level:
                kept[level] = net.forks.reanalyse(slug, step, paths=("tools",) if level == 17 else ("config",),
                                                  fix=fix, log=log)  # (17 changes configure.py's CL_FLAGS)
                if level == 9 and renamed and not kept[level]:  # (taken back: the rows go back to their names)
                    rename_rows({new: old for old, new in renamed.items()})
                net.forks.get(slug)[1].update_manifest(analysis=level)  # tried: a step taken back isn't tried again
        if manifest.get("tools") != scratch.tools_version():
            net.forks.reanalyse(slug, tools, paths=("tools",), log=log)
            net.forks.get(slug)[1].update_manifest(tools=scratch.tools_version())  # (tried: not again until they change)
        if kept.get(4) or kept.get(8):  # (taken back: nothing was joined)
            agent, _ = net.local_agent("decompdecomp")
            for name, took in joined.items():
                net.joined(name, slug)
                try:
                    net.add_note(agent, slug, f"decompdecomp joined {', '.join(took)} to this function: it's the whole "
                                              "function now, not a fragment, whatever older notes say. Worth a try.",
                                 name)
                except NetworkError:  # gone meanwhile
                    pass

    def reimport(self, net, slug: str, game: Path, log=print) -> str | None:
        """Ghidra's analysis again, read by this decompdecomp's rules (scratch.reanalyse_program), of the program and
        each of the game's DLLs in the project, through forkengine.reanalyse: kept only when every program's code
        still rebuilds byte for byte."""
        import hashlib

        from ...forks import ghidra
        from . import scratch

        fp = net.forks.get(slug)[1]
        manifest = fp.manifest or {}
        if hashlib.sha1(game.read_bytes()).hexdigest() != manifest.get("game", {}).get("sha1", ""):
            raise NetworkError("that isn't this project's program (its SHA-1 differs): choose the same .exe, or start "
                               "a new project for another one")
        if scratch.missing(fp.root, manifest["version"]):
            raise NetworkError("the project is missing the game's DLLs it was made with (in orig/): put your copies "
                               "there, then reimport")
        log(f"analysing {game.name} with Ghidra again (a big game takes a few minutes)")
        found = {"": ghidra.functions(game)}
        for m in _functions_json(fp, manifest["version"]).get("modules", []):
            log(f"analysing {m['exe'].removeprefix('orig/')} with Ghidra again")
            found[m["name"]] = scratch.module_rows(ghidra, fp.root / m["exe"], m["image_base"] - m["preferred_base"])
        matched = {r["name"] for r in net.store.all("SELECT name FROM functions WHERE project_id=? AND "
                                                     "status='matched'", net.project_row(slug)["id"])}
        return net.forks.reanalyse(slug, lambda fp: scratch.reanalyse_program(fp.root, manifest["version"], found,
                                                                                keep=matched), log=log)

    def check_rebuild(self, fp, version: str, log=print) -> dict:
        """The program rebuilt from what the project builds now: its objects first (a file that no longer compiles
        keeps the object it had, whose functions are checked against the game's code as any)."""
        from . import scratch

        fp.run(["ninja", "prepare"], log=lambda *_: None, timeout=scratch.TOOL_SECONDS)
        return scratch.check_code(fp.root, version, log=log)

    def join_functions(self, fp, first: str, last: str, keep: set[str], log=print) -> str:
        from . import scratch

        return scratch.join_functions(fp.root, (fp.manifest or {})["version"], first, last, keep=keep)

    def function_extent(self, fp, symbol: str) -> tuple[int, int] | None:
        from . import scratch

        manifest = fp.manifest or {}
        return scratch.function_extent(fp.root, manifest["version"], symbol) if "version" in manifest else None

    def cut_function(self, fp, symbol: str, at: int, keep: set[str], why: str = "") -> str:
        from . import scratch

        return scratch.cut_function(fp.root, (fp.manifest or {})["version"], symbol, at, keep=keep, why=why)

    splits_sources = True  # a source file is a unit of functions.json (scratch.split_unit)

    def split_source(self, fp, version: str, source: str, at: str, new: str) -> dict:
        from . import scratch

        return scratch.split_unit(fp.root, version, source, at, new)

    # Each source file can have its own Visual C++ (config/<version>/file_compilers.json, which tools/configure.py
    # reads): a game's Rich header often counts objects of two versions (6.0 and 7.1), as DS games mix CodeWarrior's
    def file_compiler(self, fp, source: str) -> str | None:
        from . import scratch

        manifest = fp.manifest or {}
        # a project made before (its configure.py reads no map until on_start brings its tools up to date)
        if "version" not in manifest or not scratch.compilers_file(fp.root, manifest["version"]).exists():
            return None
        own = scratch.file_compilers(fp.root, manifest["version"]).get(source)
        return f"MSVC/{own}" if own else manifest.get("compiler", f"MSVC/{scratch.MSVC_DEFAULT}")

    def set_file_compiler(self, fp, source: str, compiler: str) -> str:
        from . import scratch

        manifest = fp.manifest or {}
        scratch.set_file_compiler(fp.root, manifest["version"], source, compiler,
                                  manifest.get("compiler", f"MSVC/{scratch.MSVC_DEFAULT}"))
        return scratch.compilers_file(fp.root, manifest["version"]).relative_to(fp.root).as_posix()

    def file_flags(self, fp, source: str) -> list[str] | None:
        from . import scratch

        version = (fp.manifest or {}).get("version")
        if not version or not scratch.flags_file(fp.root, version).exists():  # older tools: no flags of its own yet
            return None
        return scratch.file_flags(fp.root, version).get(source, [])

    def set_file_flags(self, fp, source: str, flags: list[str]) -> str:
        from . import scratch

        version = (fp.manifest or {})["version"]
        scratch.set_file_flags(fp.root, version, source, flags)
        return scratch.flags_file(fp.root, version).relative_to(fp.root).as_posix()

    # What search_flags tries on a file: the frame pointer kept or not (/Oy-: about half of a 2010 game's code keeps
    # it), optimised for size (/O1: some of a game's libraries were), inlining only what's marked inline (/Ob1), and
    # the buffer security check 7.0 and 7.1 make only when asked (/GS; 2005 on make it unasked)
    FLAG_TOGGLES = (("/Oy-",), ("/O1",), ("/Ob1",), ("/O1", "/Oy-"), ("/GS",))

    def flag_variants(self, flags: list[str]) -> list[list[str]]:
        out = [list(flags)]
        for toggle in self.FLAG_TOGGLES:
            new = [f for f in flags if f not in toggle] if all(f in flags for f in toggle) else \
                [*flags, *(f for f in toggle if f not in flags)]
            if new not in out:
                out.append(new)
        return out

    def file_ranges(self, fp) -> dict[str, list[tuple[int, int]]]:
        from . import scratch

        manifest = fp.manifest or {}
        return scratch.file_ranges(fp.root, manifest["version"]) if "version" in manifest else {}

    def program_compilers(self, fp) -> list[tuple[str, int, str, bool]]:
        """The Rich header's compilers: a game of about 2000 counts files of five Visual C++ 6.0 builds (its own
        code, MFC's, the C runtime's), a later one 6.0's and 7.1's. The game's DLLs' headers count too."""
        from . import scratch

        manifest = fp.manifest or {}
        path = fp.root / manifest.get("game", {}).get("path", f"orig/{manifest.get('version')}.exe")
        paths = [path, *(fp.root / m["exe"] for m in _functions_json(fp, manifest.get("version", "")).get("modules", []))]
        counted: dict[str, list] = {}
        for found in (scratch.program_compilers(p.read_bytes()) for p in paths if p.is_file()):
            for compiler, n, name, installed in found:
                counted.setdefault(name, [compiler, 0, name, installed])[1] += n
        return sorted((tuple(row) for row in counted.values()), key=lambda row: -row[1])

    def set_own_compiler(self, fp, compiler: str, sources: list[str]) -> list[str]:
        from . import scratch

        return scratch.set_own_compiler(fp.root, fp.manifest or {}, compiler, sources)

    def read_data(self, fp, name: str, length: int) -> str | None:
        """The program's data isn't in the target objects: it's read from the user's copy."""
        from . import scratch

        return scratch.read_data(fp.root, fp.manifest or {}, name, length)

    def data_bytes(self, fp, addr: int, length: int) -> bytes | None:
        from . import scratch

        return scratch.data_bytes(fp.root, fp.manifest or {}, addr, length)

    def debug_of(self, fp, version: str, symbol: str) -> dict | None:
        """The prototype, parameters and locals the game's program database gave a function at import
        (config/<version>/debug.json, debuginfo.py)."""
        from . import scratch

        return scratch.debug_of(fp.root, version, symbol)

    def debug_brief(self, known: dict) -> list[str]:
        from ..ps2.debuginfo import brief_lines

        return brief_lines(known, "include/debug_types.h (common.h includes it)")

    def classes(self, fp):
        from . import rtti

        return rtti.for_project(fp.root, fp.manifest or {})

    def structs(self, fp):
        from . import rtti

        return rtti.structs_for_project(fp.root, fp.manifest or {})

    # Autopilot's drafts: Ghidra's made compilable, and exact ones for the tiny shapes Visual C++ makes (drafts.py)
    own_drafts = True
    own_tools = frozenset({"redraft", "search_flags", "name_instance"})

    def prepare_drafts(self, fp) -> str | None:
        from .drafts import GHIDRA_H, GHIDRA_HEADER

        path = fp.root / "include" / GHIDRA_HEADER
        if path.exists():
            return None
        path.write_text(GHIDRA_H, encoding="utf-8")
        return path.relative_to(fp.root).as_posix()

    def exact_drafts(self, fp, symbol: str, known: str = "") -> list[tuple[str, str]]:
        from . import drafts, scratch

        entry = _entries(fp).get(symbol)
        code = entry and scratch.data_bytes(fp.root, fp.manifest or {}, entry["addr"], entry["size"])
        return drafts.exact(code, entry["addr"], entry["relocs"], known) if code else []

    def compilable_draft(self, fp, symbol: str, draft: str, known: str = "") -> tuple[str, str] | None:
        from . import drafts

        entries = _entries(fp)
        return drafts.compilable(draft, symbol, {f"func_{e['addr']:08X}": n for n, e in entries.items()}, known)

    # The game's names are its addresses (func_0041B470, D_0066DDA4): objdiff pairs a function with the original's by
    # the symbol tools/names.py gives it, and the report keeps that symbol. A real name is kept by address in
    # functions.json's "names", which names.py reads too, so a renamed function still pairs (and so do its callers).
    renames_in_report = False
    names_structors = True  # names.py pairs ??0CFoo@@... and ??1CFoo@@... with the function named CFoo::CFoo, ~CFoo

    def rename_symbol(self, fp, version: str, old: str, new: str) -> dict:
        """functions.json's "names": `old`'s address (func_0041B470, _func_0041B470@8, D_0066DDA4, or a real name
        given before) gets the name `new`."""
        import json

        from ...forks.project import ForkError

        path = fp.root / "config" / version / "functions.json"
        text = path.read_text(encoding="utf-8")
        info = json.loads(text)
        names = dict(info.get("names") or {})
        key = _address_key(old) or next((k for k, v in names.items() if v == old), None)
        functions = {f"func_{fn['addr']:08X}" for fns in info["units"].values() for fn in fns}
        if key is None or (key.startswith("func_") and key not in functions):
            raise ForkError(f"{old} isn't one of the game's functions or data (func_<address>, D_<address>)")
        if names.get(key) == new:  # named so already (each attempt at a constructor names it: ForkEngine._attempt)
            return {}
        if new in names.values() or _address_key(new):
            raise ForkError(f"{new} names another of the game's symbols already: pick another name")
        names[key] = new
        path.write_text(json.dumps({**info, "names": dict(sorted(names.items()))}, indent=1), encoding="utf-8")
        return {path: text}

    def instance_names(self, fp, version: str, unit, symbol: str, taken=frozenset()) -> dict[str, str]:
        """The game's functions (by symbol) that functions the unit's source compiles to are, byte for byte where
        relocations fill in: `symbol`'s, and from it each function its code calls that one of them calls at the same
        place (an STL template's instance and the instances it calls: std::map's erase(first, last), _Erase, erase).
        -> the compiled function's symbol, as the compiler names it. Only a compiled function no func_<address> or
        D_<address> names (the agents' own C pairs by its name already), and not `taken`'s nor one a function of the
        file has already: identical instances (do_get for long and for unsigned long) each take one of their own."""
        from ... import coffobj

        info = _functions_json(fp, version)
        where = {fn["name"]: u for u, fns in info.get("units", {}).items() for fn in fns}
        targets: dict[str, dict] = {}

        def target(sym: str):
            u = where.get(sym)
            if u is None:
                return None
            if u not in targets:
                t = fp.unit(u).target if fp.unit(u) is not None else None
                targets[u] = {o: (b, r) for o, b, r in coffobj.sections(t.read_bytes())} if t and t.is_file() else {}
            return targets[u].get(sym)
        if unit.base is None or not unit.base.is_file():
            return {}
        built = {o: (b, r) for o, b, r in coffobj.sections(unit.base.read_bytes())
                 if o and not re.search(r"(?:func|D)_[0-9A-Fa-f]{8}", o)}
        def same(game, compiled) -> bool:  # (game, compiled): (code, relocations)
            # every relocation the game's has, the compiled one has; what only the compiled one relocates is a call
            # to itself or to a function beside it, which the cut-out code has as plain bytes (_Erase is recursive)
            mine = {off for off, *_ in compiled[1]}
            if len(game[0].rstrip(b"\x90\xcc")) != len(compiled[0].rstrip(b"\x90\xcc")) or \
                    not {off for off, *_ in game[1]} <= mine:
                return False
            return _masked(game[0], compiled[1]) == _masked(compiled[0], compiled[1])
        first = target(symbol)
        if first is None:
            return {}
        names = info.get("names") or {}
        taken = {*taken, *(names.get(m.group(0)) for s, u in where.items() if u == where.get(symbol)
                           and (m := re.search(r"func_[0-9A-Fa-f]{8}", s)))}  # (one name per function in a file)
        found = next((c for c, code in built.items() if c not in taken and same(first, code)), None)
        if found is None:
            return {}
        out, queue = {symbol: found}, [(symbol, found)]
        while queue:
            t, c = queue.pop()
            for (off, _, tname, _, _), (coff, _, cname, _, _) in zip(sorted(target(t)[1]), sorted(built[c][1])):
                if off != coff or tname in out or cname in out.values() or cname not in built or target(tname) is None:
                    continue
                if same(target(tname), built[cname]):
                    out[tname] = cname
                    queue.append((tname, cname))
        return out

    def stl_matches(self, fp, version: str, wanted: set[str], log=print) -> dict[str, dict[str, str]]:
        """The functions of `wanted` (symbols) that an STL probe compiles to with their file's compiler and flags
        (stl.PROBES), by unit: {unit: {symbol: the probe's explicit instantiation}}. The probes are compiled once
        per compiler and flags, into the build folder."""
        from . import scratch, stl

        ninja = (fp.root / "build.ninja").read_text(encoding="utf-8") if (fp.root / "build.ninja").is_file() else ""
        compilers = stl.unit_compilers(ninja)
        if not compilers:
            return {}
        _, info, pes, functions = scratch._project_functions(fp.root, version)
        run_with, cache = stl.wrapper(ninja), fp.root / "build" / version / "stl"
        made: dict = {}
        out: dict[str, dict[str, str]] = {}
        for f in functions:
            if f.name not in wanted or f.size < runtime_shortest():
                continue
            unit = fp.unit(f.unit)
            obj = unit.base.relative_to(fp.root).as_posix() if unit is not None and unit.base is not None else None
            compiler = compilers.get(obj or "")
            if compiler is None:
                continue
            if compiler not in made:
                made[compiler] = stl.prints(fp.root, run_with, compiler, cache, log=log)
            if (hit := made[compiler].find(pes[scratch.unit_module(f.unit)].read(f.addr, f.size))):
                out.setdefault(f.unit, {})[f.name] = stl.PROBES[int(hit[0].library)]
        return out

    def instance_spoiler(self, line: str):
        from . import stl

        return stl.spoiler(line)

    def real_names(self, fp, version: str) -> dict[str, str]:
        """(a function's report name is its entry's in functions.json: the target objects are cut out with it)"""
        info = _functions_json(fp, version)
        names = info.get("names") or {}
        return {fn["name"]: names[key] for fns in info.get("units", {}).values() for fn in fns
                if (key := f"func_{fn['addr']:08X}") in names}

    def generated_functions(self, fp, version: str) -> dict[str, str]:
        """functions.json's `generated` entries: the exception-handling stubs (scratch.mark_exception_stubs)."""
        return {fn["name"]: fn["generated"] for fns in _functions_json(fp, version).get("units", {}).values()
                for fn in fns if fn.get("generated")}

    def register_args(self, fp, version: str) -> dict[str, str]:
        """Each function's register argument (arch/x86.register_args), read from the user's copies of the programs
        once per change of functions.json; not one static_register_args has."""
        return self._register_args(fp, version)[0]

    def static_register_args(self, fp, version: str) -> dict[str, str]:
        """The register-argument functions whose code only their own source file calls or takes the address of: a
        2002 game's signal lookup took its argument in edx from its one caller, and agents set it aside as link-time
        code; written `static` (with its caller in the file) it matched. Of a 2007 game's 970, 196 were such."""
        return self._register_args(fp, version)[1]

    def static_callees(self, fp, version: str) -> dict[str, list[str]]:
        """The callers of static_register_args' functions: agents on a 2002 game's _setargv, _output and C++ catch
        code, each calling such a helper of its file, said link-time code generation and gave up."""
        return self._register_args(fp, version)[2]

    def _register_args(self, fp, version: str) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]]]:
        from ...arch import x86
        from . import scratch

        path = fp.root / "config" / version / "functions.json"
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            return {}, {}, {}
        if (kept := _REGISTER_ARGS.get(str(path))) is None or kept[0] != mtime:
            info = _functions_json(fp, version)
            try:
                if scratch.missing(fp.root, version):  # (the user's copies of the programs aren't in the project)
                    return {}, {}, {}
                pes = scratch.programs(fp.root, info)
            except (OSError, ValueError, KeyError):  # (a config without them: an older project's, a test's)
                return {}, {}, {}
            users: dict[str, set[str]] = {}  # a function -> the source files whose code refers to it
            callers: dict[str, set[str]] = {}  # ... and the functions
            for unit, fns in info.get("units", {}).items():
                for fn in fns:
                    for reloc in fn.get("relocs") or ():
                        if reloc[2]:
                            users.setdefault(reloc[2], set()).add(unit)
                            callers.setdefault(reloc[2], set()).add(fn["name"])
            found, static = {}, {}
            for unit, fns in info.get("units", {}).items():
                pe = pes.get(scratch.unit_module(unit))
                for fn in fns if pe is not None else ():
                    if not fn.get("generated") and (reg := x86.register_args(
                            pe.read(fn["addr"], min(fn["size"], x86.REGISTER_ARGS_READ)))):
                        (static if users.get(fn["name"]) == {unit} else found)[fn["name"]] = reg
            calls: dict[str, list[str]] = {}
            for callee in sorted(static):
                for caller in callers.get(callee, ()):
                    if caller != callee:
                        calls.setdefault(caller, []).append(callee)
            kept = _REGISTER_ARGS[str(path)] = (mtime, (found, static, calls))
        return kept[1]

    def rename_pattern(self, old: str) -> str:
        """func_0041B470 however a source spells it (a report's _func_0041B470@8 is func_0041B470 there, a method's
        Town::func_0041B470 too); a real name given before as itself."""
        key = _address_key(old)
        return rf"\b_*{key}\b" if key else super().rename_pattern(old)


def _compiler(fp) -> str | None:
    """The project's Visual C++ as its pack names it ("7.0", "8.0SP1"), from its manifest."""
    return str((fp.manifest or {}).get("compiler") or "").removeprefix("MSVC/") or None


def _library_said(changed: tuple[int, int] | None, what: str) -> str | None:
    """What a step that found the runtime library says (scratch.set_library_aside's added and dropped), or None."""
    added, dropped = changed or (0, 0)
    said = ([f"{added} functions are {what}: set aside as library code, not the game's own"] if added else []) + \
        ([f"{dropped} it had set aside are the game's own code after all: given back"] if dropped else [])
    return "; ".join(said) or None


def runtime_shortest() -> int:
    from .runtime import SHORTEST

    return SHORTEST


def _masked(code: bytes, relocs) -> bytes:
    """A function's code with what its relocations fill in zeroed, and the padding after it off."""
    out = bytearray(code)
    for off, *_ in relocs:
        out[off:off + 4] = bytes(len(out[off:off + 4]))
    return bytes(out).rstrip(b"\x90\xcc")


def _functions_json(fp, version: str) -> dict:
    """The project's config/<version>/functions.json, or {} (none, or unreadable)."""
    import json

    try:
        return json.loads((fp.root / "config" / version / "functions.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_REGISTER_ARGS: dict[str, tuple[int, tuple]] = {}  # functions.json's path -> (its mtime, _register_args' answer)
_ENTRIES: dict[str, tuple[int, dict]] = {}  # functions.json's path -> (its mtime, its functions by name)


def _entries(fp) -> dict[str, dict]:
    """Every function of the project's functions.json by its name, read once per change of the file (autopilot asks
    for each function's: a big game's file is megabytes)."""
    path = fp.root / "config" / (fp.manifest or {}).get("version", "") / "functions.json"
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return {}
    if (kept := _ENTRIES.get(str(path))) is None or kept[0] != mtime:
        info = _functions_json(fp, (fp.manifest or {})["version"])
        kept = _ENTRIES[str(path)] = (mtime, {fn["name"]: fn for fns in info.get("units", {}).values() for fn in fns})
    return kept[1]


def _address_key(name: str) -> str | None:
    """func_XXXXXXXX / D_XXXXXXXX (upper case address) in a name, as tools/names.py keys them; None without one."""
    import re

    m = re.search(r"\b_*(func|D)_([0-9A-Fa-f]{8})(?![0-9A-Fa-f])", name)
    return f"{m.group(1)}_{m.group(2).upper()}" if m else None


PC = WindowsPC()
