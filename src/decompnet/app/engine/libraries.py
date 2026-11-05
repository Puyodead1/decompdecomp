"""Library sources: the open-source libraries a game has built into it, from their own source, which the user puts
in the project's `libs/` folder (one folder per library: libs/lua-5.1.4, libs/boost_1_36_0).

An 84 MB C++ Linux program of 2008 has Lua, luabind, OIS, TinyXML and a particle library compiled into it (about
10,000 functions), and template code of boost and the C++ library in its own files. Agents would decompile each by
hand; the library's own source makes it with the game's compiler.

Two uses:
- its headers for every compile (Network._compile, project.compiler_config's `library_includes`): mounted read-only
  in the sandbox and searched after the game's own header, never copied (boost's are thousands of files), so C can
  `#include <boost/shared_ptr.hpp>` as the game's did;
- match_libraries: every source file compiled with the game's compiler, with the builds the library may have had
  (its own configure's flags first, from libs/<name>/decompdecomp-flags.txt, then the console's guesses: a 2008
  program's libtheora was its configure's -O3 -fomit-frame-pointer...), and every function it defines linked at the
  game's address by the judge: one
  that comes out byte for byte is the library's code, set aside as such (as a PC game's runtime library is), with
  the file that proved it. Its C isn't the game's to write: it's the library's, the same file every game uses.
"""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path

from ...network import NetworkError

LIBS = "libs"  # the project's folder of library sources
FRUITLESS = 2  # flag sets tried on a file, after one worked for its library, that bring nothing before it stops
# files of a library each tried with every flag set while none has worked: then only the first set (a library the
# game uses little of, as one it loads as a shared library: 391 of Ogre's files took over an hour)
EXPLORED = 6
FLAGS_FILE = "decompdecomp-flags.txt"  # a library's own build's flags (and -D defines), one line: tried first
SOURCES = (".c", ".cc", ".cpp", ".cxx")
HEADERS = (".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp")
INCLUDE_NAMES = ("include", "includes", "inc", "src")  # where a library keeps the headers its users include
MAX_DEPTH = 5  # how deep include folders are looked for in a library
# folders of a library that aren't the library: its tests, examples, documentation and tools (boost's 4,698 source
# files are mostly these; its libraries' own are in libs/<name>/src)
NOT_LIBRARY = {"test", "tests", "testing", "example", "examples", "sample", "samples", "demo", "demos", "doc", "docs",
               "contrib", "tools", "tool", "bench", "benchmark", "benchmarks", "perf", "tutorial", "tutorials",
               "build", "win32", "win32s", "macosx", "osx", "msvc", "vc6", "vc7", "vc8", "vs2005", "vs2008", "android",
               "iphone", "dox", "scripts", "etc"}
HEADER_ROOTS = ("boost", "luabind", "OIS", "Ogre", "ParticleUniverse")  # a folder named so: its parent is a root


def library_folders(root: Path) -> list[Path]:
    """The libraries in a project's libs/ folder, each a folder of its own."""
    libs = root / LIBS
    return sorted(p for p in libs.iterdir() if p.is_dir() and not p.name.startswith(".")) if libs.is_dir() else []


def include_dirs(library: Path) -> list[Path]:
    """Where a library's users include its headers from: the library itself when its headers are at its top,
    its include/, includes/, inc/ or src/ folders, and the parent of a folder named like its headers' own
    (boost_1_36_0 for <boost/...>)."""
    found: list[Path] = []

    def has_headers(folder: Path) -> bool:
        return any(p.suffix in HEADERS for p in folder.iterdir() if p.is_file())

    if any((library / name).is_dir() for name in HEADER_ROOTS):  # (<boost/...>: its top, and nothing inside it)
        return [library]
    stack = [(library, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            children = sorted(p for p in folder.iterdir() if p.is_dir() and not p.name.startswith("."))
        except OSError:
            continue
        if folder == library and has_headers(folder):
            found.append(folder)
        children = [c for c in children if c.name.lower() not in NOT_LIBRARY]  # (not its tools' or samples' own)
        for child in children:
            if child.name in HEADER_ROOTS and folder not in found:
                found.append(folder)
            if child.name.lower() in INCLUDE_NAMES and has_headers_below(child):
                found.append(child)
            if depth + 1 < MAX_DEPTH:
                stack.append((child, depth + 1))
    return list(dict.fromkeys(found))


def library_sources(library: Path) -> list[Path]:
    """A library's own source files: not its tests', examples' or tools' (NOT_LIBRARY)."""
    return sorted(p for p in library.rglob("*") if p.suffix in SOURCES and p.is_file()
                  and not any(part.lower() in NOT_LIBRARY for part in p.relative_to(library).parts[:-1]))


def has_headers_below(folder: Path) -> bool:
    return any(p.suffix in HEADERS for p in folder.rglob("*") if p.is_file())


def library_includes(root: Path) -> list[str]:
    """Every library's include folders, relative to the project's root (what `library_includes` keeps)."""
    return [str(d.relative_to(root)) for lib in library_folders(root) for d in include_dirs(lib)]


class LibraryMixin:
    def scan_libraries(self, slug: str) -> dict:
        """Look at the project's libs/ folder again: its libraries' include folders for every compile."""
        proj = self._project(slug)
        root = Path(proj["root"])
        found = library_includes(root)
        self._update_cfg(slug, lambda cfg: cfg.update(library_includes=found))
        return {"libraries": [lib.name for lib in library_folders(root)], "includes": found}

    def match_libraries(self, slug: str, log=print) -> dict:
        """Compile every library source file with the game's compiler and set aside, as the library's code, every
        open function it makes byte for byte at the game's address."""
        from ...compiler import compile_source
        from ...elfobj import _function_symbols
        from ...project import compiler_config

        proj = self._project(slug)
        if not self.is_rom(proj):
            raise NetworkError("library sources are matched in ROM projects (a PC project's runtime library is "
                               "recognised by its own analysis)")
        root = Path(proj["root"])
        libraries = library_folders(root)
        if not libraries:
            raise NetworkError(f"put each library's source in a folder of its own in {root / LIBS}, as it was "
                               f"released (libs/lua-5.1.4, libs/boost_1_36_0), then try again")
        includes = self.scan_libraries(slug)["includes"]
        cfg = self.cfg(proj)
        open_rows = {r["name"]: r for r in self.store.all(
            "SELECT * FROM functions WHERE project_id=? AND status='open'", proj["id"])}
        log(f"{len(libraries)} libraries ({', '.join(lib.name for lib in libraries)}); "
            f"{len(open_rows):,} open functions")
        found, compiled, failed, started = 0, 0, 0, time.time()
        console = self.console(proj)
        for library in libraries:
            own_flags = (library / FLAGS_FILE).read_text(encoding="utf-8").split() \
                if (library / FLAGS_FILE).is_file() else None
            # a library's own build had flags of its own: each set is tried, the ones that make its functions first
            variants = [own_flags] if own_flags is not None else []  # (the library's own build first, if known)
            variants += [v for v in console.library_flags(cfg["compiler"]["flags"]) if v not in variants]
            wins = {i: 0 for i in range(len(variants))}
            files = library_sources(library)
            own = [str(d.resolve()) for d in include_dirs(library)]
            # its own folders first, then the other libraries' (each once: zlib's scan_tree came out otherwise when
            # its folder was given as a system one too)
            others = [f for f in includes if str((root / f).resolve()) not in own]
            lib_found, explored = 0, 0
            for source in files:
                text = source.read_text(encoding="utf-8", errors="replace")
                cpp = source.suffix != ".c"
                # the flags that worked most first; once some have, a file stops after a few that bring nothing
                order = sorted(wins, key=lambda i: (-wins[i], i))
                if not any(wins.values()) and explored >= EXPLORED:
                    order = order[:1]
                fruitless = 0
                for i in order:
                    settings = dict(cfg["compiler"], flags=variants[i])
                    # the file's own folder for its "local.h", then its library's, then the others': in that order
                    # (an earlier one's png.h was libpng's, and libpng's own files compiled to nothing)
                    first = list(dict.fromkeys([str(source.parent.resolve()), *own]))
                    base = compiler_config(root, {**cfg, "compiler": settings, "library_includes": [*first, *others]})
                    config = dataclasses.replace(base, ro_paths=(*base.ro_paths, str(library.resolve())))
                    res = compile_source(config, "", text, trusted=True, language="c++" if cpp else "c")
                    if not res.ok:
                        failed += i == order[0]
                        break  # (a file that doesn't build doesn't build with other flags either)
                    compiled += i == order[0]
                    wanted = [n for n in _function_symbols_of(res.obj, _function_symbols) if n in open_rows]
                    if not wanted:
                        break
                    explored += i == order[0]
                    new = 0
                    for name in wanted:
                        fn = open_rows[name]
                        cand, verdict, _ = self._evaluate(fn, proj, res.obj)
                        if cand is None or not verdict:
                            continue
                        self._library_code(fn, f"{library.name}/{source.relative_to(library)}",
                                           " ".join(variants[i]))
                        open_rows.pop(name)
                        new += 1
                    lib_found += new
                    wins[i] += new
                    fruitless = 0 if new else fruitless + 1
                    if new == len(wanted) or (any(wins.values()) and fruitless >= FRUITLESS):
                        break
            found += lib_found
            best = [" ".join(variants[i]) for i in sorted(wins, key=lambda i: -wins[i]) if wins[i]][:2]
            log(f"{library.name}: {len(files)} source files, {lib_found:,} functions are its code"
                + (f" (built {' or '.join(best)})" if best else ""))
        log(f"{found:,} functions set aside as library code; {compiled} files compiled, {failed} didn't "
            f"({time.time() - started:.0f}s)")
        return {"found": found, "compiled": compiled, "failed": failed}

    def _library_code(self, fn, where: str, flags: str) -> None:
        meta = json.loads(fn["meta"] or "{}")
        meta["set_aside"] = f"library code: {where} makes it byte for byte with the game's compiler ({flags})"
        meta["library"] = where
        with self.store.tx() as db:
            db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            db.execute("UPDATE functions SET status='asm', meta=? WHERE id=? AND status='open'",
                       (json.dumps(meta), fn["id"]))
            self._event(db, fn["project_id"], None, "not_c", f"{fn['name']}: library code ({where})")


def _function_symbols_of(obj: bytes, reader) -> list[str]:
    from io import BytesIO

    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    try:
        return list(reader(ELFFile(BytesIO(obj))))
    except (ELFError, ValueError):
        return []
