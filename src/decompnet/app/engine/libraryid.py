"""Find libraries: which libraries a game has built in (libid/), set aside what's theirs, and fetch their source.

Every console and both kinds of project: a ROM project's functions are read from the database (their bytes and
relocations), a project's from its target objects (COFF or ELF, a function per symbol). The program's own file is
read for its text. What's found is kept in the project's settings (`libraries_found`) for the Libraries panel:
each library with its version, what said it's there, its functions, and where its source is.

A library the catalog says is set aside without asking (`aside`) has its open functions set aside as library code
at once, as a PC game's runtime library is: in a ROM project in the database, in a project in its set_aside.json
too (forkengine reads that on every refresh, so it stays). The rest wait for the user's word (`set_aside_library`).
It runs on Check again (so after every update, once per project) and from the panel; Ghidra's Function ID with the
user's own databases only from the panel (it analyses the whole program again: minutes). A public decomp's own
project says what's its game's: there the report only lists what's found.
"""

from __future__ import annotations

import bisect
import functools
import json
import re
import shutil
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from ... import kits, libid
from ...network import NetworkError

# report_library: agents recognise library code by what it does (MD5's rounds, zlib's inflate) where nothing in the
# catalog fingerprints it (an RC5 with its key already expanded holds none of RC5's constants). Once this many agents
# say so of one function, it's set aside as that library's code; the user can give it back.
LIBRARY_AGENTS = 2
DOWNLOAD_BYTES = 200 << 20  # a library's source archive, at most
DOWNLOAD_SECONDS = 300
FUNCTION_NAME = re.compile(r"func_([0-9A-Fa-f]{6,8})")
# a name the import gave a function for want of one (its address's): func_00104610, fn_80003100, FUN_00401000
AUTO_NAME = re.compile(r"(?:func|fn|FUN|sub)_[0-9A-Fa-f]{6,8}")
# a function of the user's SDK libraries with fewer bytes no relocation fills is too short to say it's theirs: a
# GameCube SDK's OSInitThreadQueue (li, stw, stw, blr) is the game's own list initialiser's code too
KIT_SHORTEST = 24
LIBRARY_WHY = "library code: {why}; its own source is the decomp's, not the game's to write"
BY_NAME = "by its name ("  # (in the why of what libid's `named` found: set_library_names gives those back)


def _wild(relocs, arch: str) -> frozenset[int]:
    """The byte offsets relocations fill in: (offset, type) each, by the processor's masks."""
    from ...elfobj import MASKS_BY_ARCH

    out: set[int] = set()
    for off, kind in relocs:
        delta, length, _ = MASKS_BY_ARCH.get((arch, kind), MASKS_BY_ARCH.get(("thumb", kind), (0, 4, 0)))
        out.update(range(off + delta, off + delta + length))
    return frozenset(out)


def object_code(data: bytes) -> dict[str, tuple[bytes, frozenset[int], frozenset[str]]]:
    """symbol -> (its code, the offsets relocations fill in, what they name), for each function an object file
    defines (COFF: a section per function, as decompdecomp delinks; ELF: STT_FUNC symbols, the names not read: the
    header wrappers they're for, glut.h's, are Windows' alone)."""
    from io import BytesIO

    from ... import coffobj

    out: dict[str, tuple[bytes, frozenset[int], frozenset[str]]] = {}
    if coffobj.is_coff(data):
        for owner, raw, relocs in coffobj.sections(data):
            if owner:
                out[owner] = (raw, frozenset(i for off, *_ in relocs for i in range(off, off + 4)),
                              frozenset(libid.called(name) for _, _, name, *_ in relocs if name))
        return out
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    elf = ELFFile(BytesIO(data))
    arch = {"EM_PPC": "ppc", "EM_MIPS": "mips", "EM_ARM": "arm", "EM_386": "x86"}.get(elf["e_machine"], "")
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return out
    relocs: dict[int, list[tuple[int, int]]] = {}
    for rs in elf.iter_sections():
        if isinstance(rs, RelocationSection):
            relocs.setdefault(rs["sh_info"], []).extend((r["r_offset"], r["r_info_type"]) for r in rs.iter_relocations())
    for rs in relocs.values():  # (by offset: a function's own are found by bisection, not by reading them all)
        rs.sort()
    raw_of: dict[int, bytes] = {}
    for s in symtab.iter_symbols():
        if s["st_info"]["type"] != "STT_FUNC" or not isinstance(s["st_shndx"], int) or not s["st_size"] or not s.name:
            continue
        shndx = s["st_shndx"]
        if shndx not in raw_of:
            sec = elf.get_section(shndx)
            raw_of[shndx] = b"" if sec["sh_type"] == "SHT_NOBITS" else sec.data()
        lo = s["st_value"] & ~1 if arch == "arm" else s["st_value"]
        # (a dtk project's whole program is a few objects: a GameCube game's 20,000 functions read every one of
        # their section's relocations each, and Find libraries took eight minutes)
        rs = relocs.get(shndx, [])
        mine = [(o - lo, t) for o, t in rs[bisect.bisect_left(rs, (lo,)):bisect.bisect_left(rs, (lo + s["st_size"],))]]
        out[s.name] = (raw_of[shndx][lo:lo + s["st_size"]], _wild(mine, arch), frozenset())
    return out


def archive_members(data: bytes):
    """(name, bytes) of every object in a System V or GNU archive (.a)."""
    if data[:8] != b"!<arch>\n":
        return
    at, longnames = 8, b""
    while at + 60 <= len(data):
        head = data[at:at + 60]
        name = head[:16].decode("latin-1").rstrip()
        try:
            size = int(head[48:58].decode("latin-1").strip())
        except ValueError:
            return
        body = data[at + 60:at + 60 + size]
        if name == "//":
            longnames = body
        elif name.startswith("/") and name[1:].isdigit() and longnames:
            off = int(name[1:])
            end = longnames.find(b"/\n", off)
            yield longnames[off:end if end >= 0 else None].decode("latin-1"), body
        elif name not in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            yield name.rstrip("/"), body
        at += 60 + size + (size & 1)


def kit_signatures(archives: list[Path]) -> list[libid.Signature]:
    """Every function of the user's library archives (a console's kits: kits.libraries) as a signature, its
    relocated bytes left out: the library is the archive's ("os.a"), the origin the object it's in."""
    out: list[libid.Signature] = []
    for path in archives:
        try:
            st = path.stat()
        except OSError:
            continue
        out += _archive_signatures(str(path), st.st_size, st.st_mtime_ns)
    return out


@functools.lru_cache(maxsize=256)
def _archive_signatures(path: str, size: int, mtime_ns: int) -> tuple[libid.Signature, ...]:
    from elftools.common.exceptions import ELFError

    lib = Path(path).name
    out = []
    try:
        data = Path(path).read_bytes()
    except OSError:
        return ()
    for member, obj in archive_members(data):
        try:
            found = object_code(obj)
        except (ELFError, ValueError, KeyError, AttributeError, TypeError):
            continue
        for symbol, (raw, wild, _) in found.items():
            mask = bytes(0 if i in wild else 1 for i in range(len(raw)))
            if sum(mask) < KIT_SHORTEST:
                continue
            out.append(libid.Signature(lib, "", symbol, len(raw), raw, mask, origin=f"{member}, your own copy",
                                      unit=member))
    return tuple(out)


def kit_names(archives: list[Path]) -> dict[str, tuple[str, str]]:
    """{function name: (archive, "its object, your own copy")} of the functions the user's library archives export
    (ELF: global and weak STT_FUNC symbols they define: odenotstub.a has only a weak Hu_IsStub), for Find libraries' names (libid.identify `named`). A file's own
    static functions are left out: their names (TimeoutHandler, bitrev) are anyone's."""
    out: dict[str, tuple[str, str]] = {}
    for path in archives:
        try:
            st = path.stat()
        except OSError:
            continue
        for name, lib, member in _archive_names(str(path), st.st_size, st.st_mtime_ns):
            out.setdefault(name, (lib, f"{member}, your own copy"))
    return out


@functools.lru_cache(maxsize=256)
def _archive_names(path: str, size: int, mtime_ns: int) -> tuple[tuple[str, str, str], ...]:
    from io import BytesIO

    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile

    lib = Path(path).name
    out = []
    try:
        data = Path(path).read_bytes()
    except OSError:
        return ()
    for member, obj in archive_members(data):
        if not obj.startswith(b"\x7fELF"):
            continue
        try:
            symtab = ELFFile(BytesIO(obj)).get_section_by_name(".symtab")
            for sym in symtab.iter_symbols() if symtab is not None else ():
                if sym["st_info"]["type"] == "STT_FUNC" and sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK") \
                        and sym["st_shndx"] != "SHN_UNDEF" and sym.name and sym.name != "main":
                    out.append((sym.name, lib, member))
        except (ELFError, ValueError, KeyError, AttributeError, TypeError):
            continue
    return tuple(out)


def _holds(folder: str, library: str) -> bool:
    """Whether a libs/ folder, by its name, is a library's: zlib-1.2.3, and a fork's or a pack's names too
    (freealut-1.0.1 for ALUT, openal-1.1-core-sdk for OpenAL, freeglut for GLUT; not glut-3.7.6 for GLU)."""
    head = re.match(r"[a-z0-9]*?(?=[-_ .]?\d|[-_ .]|$)", folder.lower())
    word = head.group(0) if head else folder.lower()
    return word == library or word.endswith(library) and word[:-len(library)] in ("free", "lib", "open") \
        or library.startswith("lib") and word == library[3:]  # (jpeg-6b: libjpeg's own release)


def _safe_extract(archive: Path, into: Path) -> None:
    """A source archive's files into `into`, none outside it (a tar's or zip's `..` and absolute names refused)."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                target = (into / info.filename).resolve()
                if not str(target).startswith(str(into.resolve())):
                    raise NetworkError(f"the archive has a file outside its folder: {info.filename}")
            z.extractall(into)
        return
    with tarfile.open(archive) as t:
        t.extractall(into, filter="data")


class LibraryIdMixin:
    # ------------------------------------------------------------------ the game's code, as identify reads it

    def _library_codes(self, proj) -> tuple[list[libid.Code], dict[int, dict]]:
        """Every function of the project as libid.Code (its id the key), and the rows by id."""
        rows = {r["id"]: r for r in self.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"])}
        from ..twins import object_prints, rom_print

        codes: list[libid.Code] = []
        if self.is_rom(proj):
            arch = proj["arch"] or "mips"
            big = bool(self.cfg(proj).get("big_endian", self.console(proj).big_endian))
            for r in rows.values():
                if not r["target"]:
                    continue
                relocs = [(int(x[0]), int(x[1])) for x in json.loads(r["relocs"] or "[]") if len(x) >= 2]
                codes.append(libid.Code(r["id"], r["name"], r["vram"], bytes(r["target"]), _wild(relocs, arch),
                                        fingerprint=rom_print(r, arch, big, str).key))
            return codes, rows
        from ...forks.project import ForkError, ForkProject

        fp = ForkProject(Path(proj["root"]))
        addrs = self._fork_addresses(fp)
        by_unit: dict[str, list] = {}
        for r in rows.values():
            by_unit.setdefault(r["unit"], []).append(r)
        for uname, urows in by_unit.items():
            try:
                unit = fp.unit(uname)
            except (ForkError, ValueError):
                continue
            if unit.target is None or not unit.target.is_file():
                continue
            try:
                data = unit.target.read_bytes()
                found = object_code(data)
            except Exception:  # (an object neither reader takes: nothing of it is read)
                continue
            try:
                prints = object_prints(data)
            except Exception:  # (then found by everything but the console's fingerprint tables)
                prints = {}
            for r in urows:
                sym = json.loads(r["meta"] or "{}").get("symbol") or r["name"].split("@")[0]
                if sym not in found:
                    continue
                raw, wild, calls = found[sym]
                m = FUNCTION_NAME.search(sym)
                # where it is: the import's own record (PC), objdiff's (the row's vram: a dtk project's), its name's
                addr = addrs.get(sym, r["vram"] if r["vram"] is not None else int(m.group(1), 16) if m else None)
                codes.append(libid.Code(r["id"], r["name"], addr, raw, wild, calls,
                                        prints[sym].key if sym in prints else ""))
        return codes, rows

    @staticmethod
    def _fork_addresses(fp) -> dict[str, int]:
        """symbol -> address, from a project's functions.json where its import wrote one (PC, Xbox)."""
        version = (fp.manifest or {}).get("version")
        out: dict[str, int] = {}
        for path in fp.root.glob(f"config/{version}/**/functions.json") if version else ():
            try:
                info = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for fns in (info.get("units") or {}).values():
                for f in fns:
                    if isinstance(f, dict) and "name" in f and "addr" in f:
                        out[f["name"]] = int(f["addr"])
        return out

    def _program_file(self, proj) -> Path | None:
        """The game's own program, as the project keeps it (its text is read)."""
        root = Path(proj["root"])
        if self.is_rom(proj):
            rel = (self.cfg(proj).get("rom") or {}).get("file")
        else:
            from ...forks.project import ForkProject

            game = (ForkProject(root).manifest or {}).get("game")
            rel = game.get("path") if isinstance(game, dict) else None
        path = root / rel if rel else None
        return path if path is not None and path.is_file() else None

    # ------------------------------------------------------------------ finding them

    def find_libraries(self, slug: str, log=print, fid: bool = True) -> dict:
        """Which libraries the game has built in; those its catalog entry says to set aside are set aside now.
        `fid`: also run Ghidra's Function ID with the user's own databases (minutes). Returns the report."""
        proj = self._project(slug)
        console = self.console(proj)
        catalog = libid.load(console=console.library_catalog())
        for f in catalog.files:
            if "error" in f:
                log(f"your signatures: {f['file']} wasn't read: {f['error']}")
        if (own := console.library_signatures()):  # (its libraries' code, from a tool it installs: dtk's)
            catalog.signatures += own
            log(f"{console.name}'s libraries: {len(own):,} functions' signatures")
        for library, table in console.library_prints:  # (its SDK's library, rebuilt from public source: no SDK needed)
            try:
                catalog.prints += libid.read_fingerprints(Path(table), library)
            except (OSError, ValueError) as e:
                log(f"{console.name}'s own {library} fingerprints weren't read: {e}")
        named = {}
        if (archives := kits.libraries(console.kits)):  # (the console's SDK, the user's own copy: Setup)
            own = kit_signatures(archives)
            catalog.signatures += own
            log(f"your {console.name} libraries: {len(own):,} functions in {len(archives)} archives")
            if self.cfg(proj).get("library_names", True):  # (the project's choice: the Libraries panel)
                named = kit_names(archives)
        started = time.time()
        try:  # (the libraries the user put in libs/: their headers for every compile)
            self.scan_libraries(slug)
        except (OSError, NetworkError) as e:
            log(f"the libs/ folder wasn't read: {e}")
        codes, rows = self._library_codes(proj)
        program = self._program_file(proj)
        data = program.read_bytes() if program else None
        extra = self._fid_findings(proj, codes, catalog, program, log) if fid and catalog.fid and program else {}
        big = self.cfg(proj).get("big_endian", console.big_endian) if self.is_rom(proj) else console.big_endian
        report = libid.identify(data, codes, catalog, arch=proj["arch"] or console.arch, big_endian=bool(big),
                                extra=extra, links=console.linked_libraries(data) if data else [], named=named)
        set_aside = 0
        real: list[tuple[str, str]] = []  # (the game's automatic name, the library's own) of what its code says
        for lib in report["libraries"]:
            keys = lib.pop("keys")
            if lib["aside"] and keys:
                set_aside += self._library_aside(proj, rows, {k: w for k, w in zip(
                    keys, [f["why"] for f in lib["functions"]])}, lib)
            real += [(rows[k]["name"], f["real"]) for k, f in zip(keys, lib["functions"]) if f.get("real") and k in rows]
        renamed = dict(self._name_library_functions(proj, real, log))
        for lib in report["libraries"]:  # (the report says the names they have now)
            for f in lib["functions"]:
                f["name"] = renamed.get(f["name"], f["name"])
        report.update(t=time.time(), signatures=len(catalog.signatures), files=catalog.files,
                      folder=str(libid.signature_folder()), fid=[str(p.name) for p in catalog.fid])
        self._update_cfg(slug, lambda c: c.update(libraries_found=report))
        named = ", ".join(f"{lib['name']}{' ' + lib['version'] if lib['version'] else ''}"
                          + (f" ({len(lib['functions'])} functions)" if lib["functions"] else "")
                          for lib in report["libraries"])
        log(f"{len(report['libraries'])} libraries found in {len(codes):,} functions"
            + (f" and {program.name}'s text" if program else "") + f" ({time.time() - started:.0f}s)"
            + (f": {named}" if named else ""))
        if set_aside:
            log(f"{set_aside} function{'' if set_aside == 1 else 's'} set aside as library code")
        if (n := len(renamed)):
            log(f"{n} function{'' if n == 1 else 's'} named as {'its library names it' if n == 1 else 'their libraries name them'}")
        report["named"] = n
        report["set_aside"] = set_aside
        return report

    def _name_library_functions(self, proj, pairs: list[tuple[str, str]], log) -> list[tuple[str, str]]:
        """A stripped game's library functions, found by their code, renamed from their automatic names (func_...)
        to the library's own (sceMcOpen), where that name is a C identifier and no other function has it: the
        game's calls to them say what they call. A PS2 game of 3,223 functions had 195 of Sony's, called from
        everywhere as func_00..., and agents read those calls in every brief. Returns the renames made."""
        if not pairs or self._link(proj["slug"]) is not None:  # (a room's member: the host names its copy)
            return []
        taken = {r["name"] for r in self.store.all("SELECT name FROM functions WHERE project_id=?", proj["id"])}
        wanted = [new for _, new in pairs]  # (the same code twice in the game: which is the library's isn't said)
        pairs = [(old, new) for old, new in dict(pairs).items() if AUTO_NAME.fullmatch(old)
                 and wanted.count(new) == 1 and new not in taken and re.fullmatch(r"[A-Za-z_]\w*", new)]
        if not pairs:
            return []
        agent, _ = self.local_agent("decompdecomp")
        message = "Name library functions as their libraries do"
        try:
            if self.is_rom(proj):
                said = self.rename_symbols(agent, proj["slug"], pairs, message)
                if not said.startswith("✅"):
                    log(f"the library functions weren't named: {said.splitlines()[0]}")
                    return []
                return pairs
            done = []
            for old, new in pairs:  # (a project's own files and config, one rename at a time)
                if self.rename_symbol(agent, proj["slug"], old, new, message).startswith("✅"):
                    done.append((old, new))
            return done
        except NetworkError as e:
            log(f"the library functions weren't named: {e}")
            return []

    def _fid_findings(self, proj, codes, catalog, program: Path, log) -> dict:
        """Ghidra's Function ID with the user's databases: {(library, version, name): {function id: why}}."""
        from ...forks import ghidra

        if not ghidra.available():
            log("your Function ID databases need Ghidra (Setup): skipped")
            return {}
        log(f"Ghidra reads {program.name} with your Function ID databases ({', '.join(p.name for p in catalog.fid)})")
        try:
            found = ghidra.function_ids(program, catalog.fid)
        except NetworkError as e:
            log(f"Ghidra's Function ID didn't run: {e}")
            return {}
        by_addr = {c.addr: c for c in codes if c.addr is not None}
        out: dict = {}
        for addr, (name, library) in found.items():
            code = by_addr.get(addr)
            if code is None or "Visual Studio" in library:  # (the runtime: the PC import's own business)
                continue
            lib, _, version = library.partition(" ")
            out.setdefault((lib.lower() or "fid", version, library or "a Function ID library"), {})[code.key] = \
                f"{name} of {library}, by Ghidra's Function ID (your databases)"
        return out

    def _library_aside(self, proj, rows: dict, functions: dict, lib: dict) -> int:
        """Set a library's open functions aside as its code. Returns how many weren't already."""
        label = lib["name"] + (f" {lib['version']}" if lib.get("version") else "")
        changes = []
        for fid, why in functions.items():
            r = rows.get(fid)
            if r is None or r["status"] != "open":
                continue
            meta = json.loads(r["meta"] or "{}")
            if meta.get("reopened"):  # (the user gave it back: their word stands)
                continue
            text = LIBRARY_WHY.format(why=why)
            meta.update(asm_code=text, set_aside=text if self.is_rom(proj) else True, library=label)
            changes.append((json.dumps(meta), fid, r))
        if not changes:
            return 0
        if not self.is_rom(proj) and self.cfg(proj).get("origin") != "scratch":
            return 0  # (a public decomp says itself what's its game's: the report only lists what's found)
        if not self.is_rom(proj):
            self._fork_set_aside(proj, {json.loads(m).get("symbol") or r["name"].split("@")[0]:
                                        json.loads(m)["asm_code"] for m, _, r in changes}, label)
        with self.store.tx() as db:
            db.executemany("DELETE FROM claims WHERE function_id=?", [(fid,) for _, fid, _ in changes])
            db.executemany("UPDATE functions SET status='asm', meta=? WHERE id=? AND status='open'",
                           [(m, fid) for m, fid, _ in changes])
            self._event(db, proj["id"], None, "not_c", f"{len(changes)} function{'' if len(changes) == 1 else 's'} "
                        f"set aside as {label}'s code: " + ", ".join(r["name"] for _, _, r in changes[:6]))
        return len(changes)

    def _fork_set_aside(self, proj, entries: dict[str, str], label: str = "library") -> None:
        """Symbol -> why, into the project's set_aside.json (forkengine's _set_aside reads it on every refresh), and
        committed: config/ is the app's, so a change no commit has is put back as a try's leftover (the next start,
        the next split), and a room's members follow the host's commits, not its files."""
        from ...forks.project import ForkProject

        fp = ForkProject(Path(proj["root"]))
        manifest = fp.manifest or {}
        rel = manifest.get("set_aside") or f"config/{manifest.get('version')}/set_aside.json"
        path = fp.root / rel
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except ValueError:
            data = {}
        data.update(entries)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=1), encoding="utf-8")
        if (fp.root / ".git").exists():
            self.forks._commit(proj, fp, rel, f"Set aside {len(entries)} function{'' if len(entries) == 1 else 's'} "
                                              f"as {label}'s code\n\nFound by decompdecomp.")

    def libraries_found(self, slug: str) -> dict:
        """The last report (find_libraries), with what's in the user's signatures folder now."""
        proj = self._project(slug)
        report = dict(self.cfg(proj).get("libraries_found") or {})
        catalog = libid.load()
        root = Path(proj["root"])
        have = {p.name.lower() for p in (root / "libs").iterdir()} if (root / "libs").is_dir() else set()
        status = {r["name"]: r["status"] for r in self.store.all(
            "SELECT name, status FROM functions WHERE project_id=?", proj["id"])}
        for lib in report.get("libraries", []):
            lib["have_source"] = any(_holds(n, lib["id"]) for n in have)
            for f in lib["functions"]:
                f["status"] = status.get(f["name"], "gone")
            lib["open"] = sum(1 for f in lib["functions"] if f["status"] == "open")
        return report | {"folder": str(libid.signature_folder()), "files": catalog.files,
                         "signatures": len(catalog.signatures), "fid": [p.name for p in catalog.fid],
                         # (the choice is there for a console whose libraries the user brings: kits)
                         "kits": bool(self.console(proj).kits), "names": self.cfg(proj).get("library_names", True)}

    def set_library_names(self, slug: str, on: bool) -> bool:
        """The project's choice: Find libraries also takes a function named as one the user's library copies export
        for that library's code, when its code is another version's (a game's SDK between two copies the user has).
        Off: by its code alone, and what its names set aside is open to agents again. On: the next Find libraries
        sets them aside (the panel runs it). Returns how many came back."""
        proj = self._project(slug)
        self._update_cfg(slug, lambda c: c.update(library_names=bool(on)))
        if on:
            return 0
        back = [r for r in self.store.all("SELECT * FROM functions WHERE project_id=? AND status='asm'", proj["id"])
                if BY_NAME in str(json.loads(r["meta"] or "{}").get("asm_code") or "")]
        if not back:
            return 0
        if not self.is_rom(proj):
            from ...forks.project import ForkProject

            fp = ForkProject(Path(proj["root"]))
            manifest = fp.manifest or {}
            rel = manifest.get("set_aside") or f"config/{manifest.get('version')}/set_aside.json"
            path = fp.root / rel
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            for r in back:
                data.pop(json.loads(r["meta"] or "{}").get("symbol") or r["name"].split("@")[0], None)
            path.write_text(json.dumps(data, indent=1), encoding="utf-8")
            if (fp.root / ".git").exists():
                self.forks._commit(proj, fp, rel, f"Give {len(back)} functions set aside by their names back\n\n"
                                                  "Library code by its code alone, as the user chose.")
        with self.store.tx() as db:
            for r in back:
                meta = {k: v for k, v in json.loads(r["meta"] or "{}").items()
                        if k not in ("asm_code", "set_aside", "library")}
                db.execute("UPDATE functions SET status='open', meta=? WHERE id=? AND status='asm'",
                           (json.dumps(meta), r["id"]))
            self._event(db, proj["id"], None, "reopen", f"{len(back)} functions set aside by their names are open again")
        return len(back)

    def set_aside_library(self, slug: str, library: str) -> int:
        """The user's word: a found library's functions are its code (one the catalog doesn't set aside itself)."""
        proj = self._project(slug)
        report = self.cfg(proj).get("libraries_found") or {}
        lib = next((x for x in report.get("libraries", []) if x["id"] == library), None)
        if lib is None:
            raise NetworkError(f"no library {library!r} was found in this game: Find libraries first")
        rows = {r["id"]: r for r in self.store.all("SELECT * FROM functions WHERE project_id=?", proj["id"])}
        by_name = {r["name"]: r["id"] for r in rows.values()}
        functions = {by_name[f["name"]]: f["why"] for f in lib["functions"] if f["name"] in by_name}
        return self._library_aside(proj, rows, functions, lib)

    def report_library(self, agent, function: str, library: str, why: str, project: str | None = None) -> str:
        """An agent's word that a function is a known library's code (report_library). Counted on the function;
        with LIBRARY_AGENTS agents saying so it's set aside as that library's code. The agent's claim on it ends
        either way (its notes say why), so it moves on."""
        library, why = library.strip(), why.strip()
        if not library or not why:
            raise NetworkError("name the library (\"zlib 1.1.3\", \"RSA's MD5, RFC 1321\") and say how you can tell")
        fn = self._function(function, project)
        if (link := self._link(project)) is not None:
            # a member's word counts on the host, as its own agents' does (refused here, a GameCube room's SDK
            # functions stayed open for members' agents to try again and again); the host ended the claim there
            text = link.call("/collab/report_library", agent, function=fn["name"], library=library, why=why)
            with self.store.tx() as db:
                db.execute("DELETE FROM claims WHERE function_id=? AND agent_id=?", (fn["id"], agent.id))
            if "set aside as" in text:
                text += link.follow()  # (the host committed it: this copy follows)
            return text
        proj = self.store.one("SELECT * FROM projects WHERE id=?", fn["project_id"])
        with self.store.tx() as db:
            row = db.execute("SELECT meta, status FROM functions WHERE id=?", (fn["id"],)).fetchone()
            meta = json.loads(row["meta"] or "{}")
            said = meta.setdefault("library_said", {})
            said[agent.name] = {"library": library[:120], "why": why[:600], "t": time.time()}
            db.execute("UPDATE functions SET meta=? WHERE id=?", (json.dumps(meta), fn["id"]))
        held = self.store.one("SELECT agent_id FROM claims WHERE function_id=?", fn["id"])
        if held is not None and held["agent_id"] == agent.id:
            self.release(agent, function, f"Library code ({library}): {why}", project)
        if meta.get("reopened"):
            return (f"Counted, but the user gave {fn['name']} back to the agents: it stays open. Your claim on it "
                    "ended; claim the next function.")
        if len(said) < LIBRARY_AGENTS:
            return (f"Counted ({len(said)} of {LIBRARY_AGENTS} agents): {fn['name']} is set aside as library code once "
                    f"another agent agrees. Your claim on it ended; claim the next function.")
        names = [v["library"] for v in said.values()]
        label = max(set(names), key=names.count)
        rows = {fn["id"]: self.store.one("SELECT * FROM functions WHERE id=?", fn["id"])}
        n = self._library_aside(proj, rows, {fn["id"]: f"{label}, as {len(said)} agents recognised it ({why[:200]})"},
                                {"name": label})
        return (f"{fn['name']} is set aside as {label}'s code ({len(said)} agents agree). Claim the next function."
                if n else f"Counted ({len(said)} agents agree; it isn't open, so nothing changed). Claim the next.")

    # ------------------------------------------------------------------ its source

    def get_library_source(self, slug: str, library: str, log=print) -> dict:
        """Download a found library's source (the catalog's address for its version) into the project's libs/."""
        import httpx

        proj = self._project(slug)
        report = self.cfg(proj).get("libraries_found") or {}
        lib = next((x for x in report.get("libraries", []) if x["id"] == library), None)
        if lib is None or not lib.get("download"):
            raise NetworkError("decompdecomp doesn't know where this library's source for this version is: "
                               f"get it from {lib['home'] if lib else 'its home page'} and put it in the project's "
                               "libs/ folder, one folder for it (libs/zlib-1.1.3)")
        url = lib["download"]
        dest = Path(proj["root"]) / "libs" / f"{lib['id']}-{lib['version']}"
        if dest.exists():
            return {"folder": str(dest), "already": True}
        log(f"downloading {url}")
        with tempfile.TemporaryDirectory(prefix="decomp-lib-") as tmp:
            archive = Path(tmp) / url.rsplit("/", 1)[-1]
            got = 0
            with httpx.stream("GET", url, follow_redirects=True, timeout=DOWNLOAD_SECONDS) as r:
                if r.status_code != 200:
                    raise NetworkError(f"{url} answered {r.status_code}: get the source from {lib['home']} and put "
                                       f"it in {dest}")
                with archive.open("wb") as f:
                    for chunk in r.iter_bytes():
                        got += len(chunk)
                        if got > DOWNLOAD_BYTES:
                            raise NetworkError(f"{url} is bigger than {DOWNLOAD_BYTES >> 20} MB: not a library's source")
                        f.write(chunk)
            unpacked = Path(tmp) / "unpacked"
            unpacked.mkdir()
            try:
                _safe_extract(archive, unpacked)
            except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
                raise NetworkError(f"{archive.name} didn't unpack: {e}") from e
            inner = list(unpacked.iterdir())
            top = inner[0] if len(inner) == 1 and inner[0].is_dir() else unpacked
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(top), str(dest))
        log(f"{lib['name']} {lib['version']}'s source is in {dest}")
        self.scan_libraries(slug)
        return {"folder": str(dest), "already": False}
