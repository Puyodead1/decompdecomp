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

import json
import re
import shutil
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from ... import libid
from ...network import NetworkError

# report_library: agents recognise library code by what it does (MD5's rounds, zlib's inflate) where nothing in the
# catalog fingerprints it (an RC5 with its key already expanded holds none of RC5's constants). Once this many agents
# say so of one function, it's set aside as that library's code; the user can give it back.
LIBRARY_AGENTS = 2
DOWNLOAD_BYTES = 200 << 20  # a library's source archive, at most
DOWNLOAD_SECONDS = 300
FUNCTION_NAME = re.compile(r"func_([0-9A-Fa-f]{6,8})")
LIBRARY_WHY = "library code: {why}; its own source is the decomp's, not the game's to write"


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
    raw_of: dict[int, bytes] = {}
    for s in symtab.iter_symbols():
        if s["st_info"]["type"] != "STT_FUNC" or not isinstance(s["st_shndx"], int) or not s["st_size"] or not s.name:
            continue
        shndx = s["st_shndx"]
        if shndx not in raw_of:
            sec = elf.get_section(shndx)
            raw_of[shndx] = b"" if sec["sh_type"] == "SHT_NOBITS" else sec.data()
        lo = s["st_value"] & ~1 if arch == "arm" else s["st_value"]
        mine = [(o - lo, t) for o, t in relocs.get(shndx, []) if lo <= o < lo + s["st_size"]]
        out[s.name] = (raw_of[shndx][lo:lo + s["st_size"]], _wild(mine, arch), frozenset())
    return out


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
        codes: list[libid.Code] = []
        if self.is_rom(proj):
            arch = proj["arch"] or "mips"
            for r in rows.values():
                if not r["target"]:
                    continue
                relocs = [(int(x[0]), int(x[1])) for x in json.loads(r["relocs"] or "[]") if len(x) >= 2]
                codes.append(libid.Code(r["id"], r["name"], r["vram"], bytes(r["target"]), _wild(relocs, arch)))
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
                found = object_code(unit.target.read_bytes())
            except Exception:  # (an object neither reader takes: nothing of it is read)
                continue
            for r in urows:
                sym = json.loads(r["meta"] or "{}").get("symbol") or r["name"].split("@")[0]
                if sym not in found:
                    continue
                raw, wild, calls = found[sym]
                m = FUNCTION_NAME.search(sym)
                addr = addrs.get(sym, int(m.group(1), 16) if m else None)
                codes.append(libid.Code(r["id"], r["name"], addr, raw, wild, calls))
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
        catalog = libid.load()
        for f in catalog.files:
            if "error" in f:
                log(f"your signatures: {f['file']} wasn't read: {f['error']}")
        started = time.time()
        try:  # (the libraries the user put in libs/: their headers for every compile)
            self.scan_libraries(slug)
        except (OSError, NetworkError) as e:
            log(f"the libs/ folder wasn't read: {e}")
        codes, rows = self._library_codes(proj)
        program = self._program_file(proj)
        data = program.read_bytes() if program else None
        extra = self._fid_findings(proj, codes, catalog, program, log) if fid and catalog.fid and program else {}
        console = self.console(proj)
        big = self.cfg(proj).get("big_endian", console.big_endian) if self.is_rom(proj) else console.big_endian
        report = libid.identify(data, codes, catalog, arch=proj["arch"] or console.arch, big_endian=bool(big),
                                extra=extra, links=console.linked_libraries(data) if data else [])
        set_aside = 0
        for lib in report["libraries"]:
            keys = lib.pop("keys")
            if lib["aside"] and keys:
                set_aside += self._library_aside(proj, rows, {k: w for k, w in zip(
                    keys, [f["why"] for f in lib["functions"]])}, lib)
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
        report["set_aside"] = set_aside
        return report

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
                                        json.loads(m)["asm_code"] for m, _, r in changes})
        with self.store.tx() as db:
            db.executemany("DELETE FROM claims WHERE function_id=?", [(fid,) for _, fid, _ in changes])
            db.executemany("UPDATE functions SET status='asm', meta=? WHERE id=? AND status='open'",
                           [(m, fid) for m, fid, _ in changes])
            self._event(db, proj["id"], None, "not_c", f"{len(changes)} function{'' if len(changes) == 1 else 's'} "
                        f"set aside as {label}'s code: " + ", ".join(r["name"] for _, _, r in changes[:6]))
        return len(changes)

    @staticmethod
    def _fork_set_aside(proj, entries: dict[str, str]) -> None:
        """Symbol -> why, into the project's set_aside.json (forkengine's _set_aside reads it on every refresh)."""
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
            lib["have_source"] = any(n == lib["id"] or n.startswith(lib["id"] + "-") for n in have)
            for f in lib["functions"]:
                f["status"] = status.get(f["name"], "gone")
            lib["open"] = sum(1 for f in lib["functions"] if f["status"] == "open")
        return report | {"folder": str(libid.signature_folder()), "files": catalog.files,
                         "signatures": len(catalog.signatures), "fid": [p.name for p in catalog.fid]}

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
        if self._link(project) is not None:
            raise NetworkError("in a room, the room's host decides what's library code: say so in your notes instead")
        fn = self._function(function, project)
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
