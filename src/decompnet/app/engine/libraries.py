"""Library sources: the open-source libraries a game has built into it, from their own source, which the user puts
in the project's `libs/` folder (one folder per library: libs/lua-5.1.4, libs/boost_1_36_0).

An 84 MB C++ Linux program of 2008 has Lua, luabind, OIS, TinyXML and a particle library compiled into it (about
10,000 functions), and template code of boost and the C++ library in its own files. Agents would decompile each by
hand; the library's own source makes it with the game's compiler.

Two uses:
- its headers for every compile (Network._compile, project.compiler_config's `library_includes`): mounted read-only
  in the sandbox and searched after the game's own header, never copied (boost's are thousands of files), so C can
  `#include <boost/shared_ptr.hpp>` as the game's did;
- match_libraries: every source file compiled with the game's compiler (and its flags, or a library's own in
  libs/<name>/decompdecomp-flags.txt), and every function it defines linked at the game's address by the judge: one
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
FLAGS_FILE = "decompdecomp-flags.txt"  # a library's own flags (and -D defines), one line, replacing the game's
SOURCES = (".c", ".cc", ".cpp", ".cxx")
HEADERS = (".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp")
INCLUDE_NAMES = ("include", "includes", "inc", "src")  # where a library keeps the headers its users include
MAX_DEPTH = 5  # how deep include folders are looked for in a library
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

    stack = [(library, 0)]
    while stack:
        folder, depth = stack.pop()
        try:
            children = sorted(p for p in folder.iterdir() if p.is_dir() and not p.name.startswith("."))
        except OSError:
            continue
        if folder == library and has_headers(folder):
            found.append(folder)
        for child in children:
            if child.name in HEADER_ROOTS and folder not in found:
                found.append(folder)
            if child.name.lower() in INCLUDE_NAMES and has_headers_below(child):
                found.append(child)
            if depth + 1 < MAX_DEPTH:
                stack.append((child, depth + 1))
    return list(dict.fromkeys(found))


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
        for library in libraries:
            own_flags = (library / FLAGS_FILE).read_text(encoding="utf-8").split() \
                if (library / FLAGS_FILE).is_file() else None
            files = sorted(p for p in library.rglob("*") if p.suffix in SOURCES and p.is_file())
            own = [str(d.resolve()) for d in include_dirs(library)]
            # its own folders first, then the other libraries' (each once: zlib's scan_tree came out otherwise when
            # its folder was given as a system one too)
            others = [f for f in includes if str((root / f).resolve()) not in own]
            settings = dict(cfg["compiler"], **({"flags": own_flags} if own_flags is not None else {}))
            base = compiler_config(root, {**cfg, "compiler": settings, "library_includes": others})
            lib_found = 0
            for source in files:
                # the file's own folder for its "local.h", then its library's, read-only like the rest of it
                config = dataclasses.replace(
                    base, cmd=[*base.cmd, *(x for d in dict.fromkeys([str(source.parent.resolve()), *own])
                                            for x in ("-I", d))],
                    ro_paths=(*base.ro_paths, str(library.resolve())))
                text = source.read_text(encoding="utf-8", errors="replace")
                cpp = source.suffix != ".c"
                res = compile_source(config, "", text, trusted=True, language="c++" if cpp else "c")
                if not res.ok:
                    failed += 1
                    continue
                compiled += 1
                for name in _function_symbols_of(res.obj, _function_symbols):
                    fn = open_rows.get(name)
                    if fn is None:
                        continue
                    cand, verdict, _ = self._evaluate(fn, proj, res.obj)
                    if cand is None or not verdict:
                        continue
                    self._library_code(fn, f"{library.name}/{source.relative_to(library)}")
                    open_rows.pop(name)
                    lib_found += 1
            found += lib_found
            log(f"{library.name}: {len(files)} source files, {lib_found:,} functions are its code")
        log(f"{found:,} functions set aside as library code; {compiled} files compiled, {failed} didn't "
            f"({time.time() - started:.0f}s)")
        return {"found": found, "compiled": compiled, "failed": failed}

    def _library_code(self, fn, where: str) -> None:
        meta = json.loads(fn["meta"] or "{}")
        meta["set_aside"] = f"library code: {where} makes it byte for byte with the game's compiler"
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
