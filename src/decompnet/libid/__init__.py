"""Which libraries a game has built into it, found in its own code and text, so agents never work on them: zlib,
libpng, Lua, RSA's MD5, a middleware's engine. Library code isn't the game's to write; a decomp uses the library's
own source wherever it can (libs/, app/engine/libraries.py), and what has no source stays the program's assembly.

On a 1999 PC game, 6 of its last 7 open functions were RSA's MD5 (md5c.c) and an RC5 key schedule, which agents
worked on for days: the PC import only knew Visual C++'s runtime. What finds them here:

- signatures: a library function's bytes, those a relocation fills in left out, matched whole against each of the
  game's functions. Our own format (`.json`, SIGNATURE_FORMAT), and other tools' converted as they're read: IDA's
  FLIRT (`.pat`, `.sig`: libid/flirt.py). Ghidra's Function ID databases (`.fidb`) are Ghidra's own hashes, so
  Ghidra itself reads them (forks/ghidra.py's `fid_files`). The user keeps them in their signatures folder
  (`signature_folder`), any of them, by library;
- the catalog (catalog.toml, and the user's own `.toml` files there): what needs no signature. A library's text says
  it's there and which version (zlib's "inflate 1.1.3 Copyright 1995-1998 Mark Adler"); an algorithm's constants
  say which function is it (MD5's 0xd76aa478...), wherever the code came from, and the functions between two of
  them, or beside one, are the same library's (RSA's MD5Update sits between MD5Init and MD5Transform);
- with neither: the program's own text still names what it has built in, in copyright notices and the source paths
  its assertions keep ("..\\zlib\\inflate.c"), which the report lists for the user to look up and add.

`identify` only reads; the engine (app/libraryid.py) sets aside what it finds and keeps the report for the
project's Libraries panel.
"""

from __future__ import annotations

import json
import re
import struct
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

SIGNATURE_FORMAT = "decompdecomp-signatures"  # our format's `format`; its `version` is 1
CATALOG_SUFFIX = ".toml"
SIGNATURE_SUFFIXES = (".json", ".pat", ".sig")
FID_SUFFIXES = (".fidb",)
SPLIT_IMMEDIATES = ("mips", "ppc", "ppc64")  # processors whose code builds a 32-bit constant from two 16-bit halves
MAX_BETWEEN = 8  # functions between two of a library's own that are taken as its too, at most
MAX_SPAN = 0x8000  # bytes they span, at most
MIN_STRING = 6  # characters in a run of text that counts as a string
SHORTEST = 16  # a signature shorter than this says too little whose code it is (`xor eax, eax; ret`)
PADDING = b"\x90\xcc\x00"
# text that says a program has someone else's code built in (a copyright notice, a version control stamp)
NOTICE = re.compile(r"(?i)\bcopyright\b|\(c\)\s*(?:19|20)\d\d|\xa9\s*(?:19|20)\d\d|all rights reserved|\$Id: |@\(#\)"
                    r"|\bversion \d+\.\d+")
# a source file's path, as an assertion or a debug message keeps it ("..\\zlib\\inflate.c", "src/lua/lapi.c")
SOURCE_PATH = re.compile(r"(?:[A-Za-z]:)?(?:[\w .~+-]*[\\/])+[\w .~+-]+\.(?:c|cc|cpp|cxx|h|hh|hpp|inl)\b")
MAX_UNKNOWN = 60  # notices and folders the report lists
MIN_NOTICE = 16  # characters of a notice ("Copyright:" alone is a word of the game's menus)
NOTICE_DATED = re.compile(r"(?:19|20)\d\d|\$Id: |@\(#\)")  # a real notice names its years (or is a stamp)
STAMP = re.compile(r"\$Id: |@\(#\)")
MAX_STAMPS = 20  # version control stamps ($Id: ...) beyond this many are the game's own files'
# the system's headers, as a Linux program's assertions keep them: not something it has built in
SYSTEM_FOLDER = re.compile(r"^(?:usr/|sysdeps/|(?:include|bits|sys|linux|asm)$|include/(?:bits|sys|linux|asm)$)")


@dataclass
class Code:
    """A function of the game, as its code is: what identify reads."""
    key: object  # the caller's (a function's id)
    name: str
    addr: int | None  # where it is, when known (functions beside a library's own are found by it)
    raw: bytes
    wild: frozenset[int] = frozenset()  # byte offsets a relocation fills in


@dataclass
class Library:
    """A library the catalog knows (catalog.toml)."""
    id: str
    name: str
    kind: str = "source"  # source, middleware, algorithm
    home: str = ""
    download: str = ""
    strings: list[re.Pattern] = field(default_factory=list)
    versions: list[re.Pattern] = field(default_factory=list)
    constants: list[int] = field(default_factory=list)
    needs: int = 2
    companions: list[int] = field(default_factory=list)
    tables: list[bytes] = field(default_factory=list)
    aside: bool = False
    origin: str = "built in"


@dataclass
class Signature:
    """One library function's code: `pattern`'s bytes where `mask` is 1, its size, and for a FLIRT signature the
    CRC-16 of the bytes after its pattern and its tail bytes."""
    library: str
    version: str
    name: str
    size: int | None
    pattern: bytes
    mask: bytes
    crc: tuple[int, int, int] | None = None  # (from, length, crc16): FLIRT's
    tail: tuple[tuple[int, int], ...] = ()  # (offset, byte)
    origin: str = ""


@dataclass
class Catalog:
    libraries: list[Library]
    signatures: list[Signature]
    fid: list[Path]  # Ghidra Function ID databases, for Ghidra to read
    files: list[dict]  # what was read from the user's folder: {"file", "kind", "count"} or {"file", "error"}


def signature_folder() -> Path:
    """Where the user keeps library signatures and catalog entries: <home>/.decomp/extra_data/signatures."""
    from ..app import edition

    return edition.home_dir() / ".decomp" / "extra_data" / "signatures"


def _library(d: dict, origin: str) -> Library:
    def rx(items) -> list[re.Pattern]:
        return [re.compile(s.encode("latin-1")) for s in items or []]

    return Library(id=str(d["id"]), name=str(d.get("name") or d["id"]), kind=str(d.get("kind") or "source"),
                   home=str(d.get("home") or ""), download=str(d.get("download") or ""), strings=rx(d.get("strings")),
                   versions=rx(d.get("versions")), constants=[int(c) for c in d.get("constants") or []],
                   needs=int(d.get("needs") or 2), companions=[int(c) for c in d.get("companions") or []],
                   tables=[bytes.fromhex(b) for b in d.get("bytes") or []], aside=bool(d.get("aside")), origin=origin)


def builtin() -> list[Library]:
    text = resources.files("decompnet.libid").joinpath("catalog.toml").read_text(encoding="utf-8")
    return [_library(d, "built in") for d in tomllib.loads(text)["library"]]


def parse_pattern(text: str) -> tuple[bytes, bytes]:
    """A pattern written as hex with ".." for a byte that can be anything ("558bec..e8........"): (bytes, mask)."""
    text = re.sub(r"\s+", "", text)
    if len(text) % 2:
        raise ValueError(f"a pattern has two characters a byte: {text[:40]!r}")
    pattern, mask = bytearray(), bytearray()
    for i in range(0, len(text), 2):
        pair = text[i:i + 2]
        if pair == "..":
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(pair, 16))
            mask.append(1)
    return bytes(pattern), bytes(mask)


def write_pattern(raw: bytes, wild) -> str:
    return "".join(".." if i in wild else f"{b:02x}" for i, b in enumerate(raw))


def read_signatures(path: Path) -> list[Signature]:
    """A signature file's signatures: ours (.json), FLIRT's (.pat, .sig). Raises ValueError for one it can't read."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != SIGNATURE_FORMAT:
            raise ValueError(f"not a signature file: its format isn't {SIGNATURE_FORMAT!r}")
        library, version = str(data.get("library") or path.stem), str(data.get("library_version") or "")
        out = []
        for f in data.get("functions") or []:
            pattern, mask = parse_pattern(f["pattern"])
            out.append(Signature(str(f.get("library") or library), str(f.get("library_version") or version),
                                 str(f["name"]), int(f["size"]) if f.get("size") else len(pattern), pattern, mask,
                                 origin=path.name))
        return out
    from . import flirt

    if suffix == ".pat":
        return flirt.read_pat(path.read_text(encoding="latin-1"), path.stem, path.name)
    if suffix == ".sig":
        return flirt.read_sig(path.read_bytes(), path.name)
    raise ValueError(f"{path.name}: not a signature file decompdecomp reads")


def signature_file(library: str, version: str, functions: list[tuple[str, bytes, frozenset[int]]]) -> dict:
    """Our format for a library's functions: (name, code, offsets a relocation fills in) each."""
    return {"format": SIGNATURE_FORMAT, "version": 1, "library": library, "library_version": version,
            "functions": [{"name": n, "size": len(raw), "pattern": write_pattern(raw, wild)}
                          for n, raw, wild in functions if len(raw) - len(wild) >= SHORTEST]}


def load(folder: Path | None = None) -> Catalog:
    """The built-in catalog and everything in the user's signatures folder (and its folders)."""
    libraries = builtin()
    signatures: list[Signature] = []
    fid: list[Path] = []
    files: list[dict] = []
    folder = signature_folder() if folder is None else folder
    try:
        paths = sorted(p for p in folder.rglob("*") if p.is_file()) if folder.is_dir() else []
    except OSError:
        paths = []
    for p in paths:
        rel = str(p.relative_to(folder))
        suffix = p.suffix.lower()
        try:
            if suffix == CATALOG_SUFFIX:
                found = [_library(d, rel) for d in tomllib.loads(p.read_text(encoding="utf-8")).get("library", [])]
                by_id = {lib.id: i for i, lib in enumerate(libraries)}
                for lib in found:  # (the user's entry for a library replaces the built-in one)
                    if lib.id in by_id:
                        libraries[by_id[lib.id]] = lib
                    else:
                        libraries.append(lib)
                files.append({"file": rel, "kind": "catalog", "count": len(found)})
            elif suffix in SIGNATURE_SUFFIXES:
                sigs = read_signatures(p)
                signatures += sigs
                files.append({"file": rel, "kind": {"json": "signatures", "pat": "FLIRT patterns",
                                                     "sig": "FLIRT signatures"}[suffix[1:]], "count": len(sigs)})
            elif suffix in FID_SUFFIXES:
                fid.append(p)
                files.append({"file": rel, "kind": "Ghidra Function ID", "count": None})
        except (OSError, ValueError, KeyError, TypeError, re.error, tomllib.TOMLDecodeError) as e:
            files.append({"file": rel, "error": str(e)[:300]})
    return Catalog(libraries, signatures, fid, files)


# ---------------------------------------------------------------------------------------------- reading the code


def strings(data: bytes) -> list[bytes]:
    """Every run of printable text in `data` at least MIN_STRING long (ASCII, as C keeps its strings)."""
    return re.findall(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING, data)


def _immediates(code: Code, big_endian: bool) -> set[int]:
    """The 16-bit halves a processor that splits constants (MIPS's lui/ori, PowerPC's lis/ori) has in its words."""
    fmt = ">" if big_endian else "<"
    n = len(code.raw) // 4
    return {w & 0xFFFF for w in struct.unpack(f"{fmt}{n}I", code.raw[:n * 4])}


def constants_in(code: Code, wanted: list[int], arch: str, big_endian: bool, imms: set[int] | None = None) -> set[int]:
    """Which of `wanted` the function's code holds: as a word (an immediate, a literal pool, a table), either byte
    order, or on MIPS and PowerPC as two halves (the high one +1 where an addiu's low half is negative)."""
    found = {c for c in wanted if struct.pack("<I", c) in code.raw or struct.pack(">I", c) in code.raw}
    if arch in SPLIT_IMMEDIATES and len(found) < len(wanted):
        imms = _immediates(code, big_endian) if imms is None else imms
        for c in wanted:
            hi, lo = c >> 16, c & 0xFFFF
            if lo in imms and (hi in imms or (lo & 0x8000 and ((hi + 1) & 0xFFFF) in imms)):
                found.add(c)
    return found


def _crc16(data: bytes) -> int:
    """FLIRT's CRC-16 (as IDA's sigmake writes it)."""
    crc = 0xFFFF
    for b in data:
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if (crc ^ b) & 1 else crc >> 1
            b >>= 1
    crc = ~crc & 0xFFFF
    return ((crc << 8) | (crc >> 8)) & 0xFFFF


def _trimmed(raw: bytes) -> int:
    n = len(raw)
    while n and raw[n - 1] in PADDING:
        n -= 1
    return n


def signature_matches(sig: Signature, code: Code) -> bool:
    raw = code.raw
    if sig.size is not None and sig.size not in (len(raw), _trimmed(raw)):
        return False
    if len(raw) < len(sig.pattern):
        return False
    for i, (p, m) in enumerate(zip(sig.pattern, sig.mask)):
        if m and i not in code.wild and raw[i] != p:
            return False
    if sig.crc is not None:
        start, length, crc = sig.crc
        if length and (start + length > len(raw) or _crc16(raw[start:start + length]) != crc):
            return False
    return all(off < len(raw) and raw[off] == b for off, b in sig.tail)


# ---------------------------------------------------------------------------------------------- the report


@dataclass
class Finding:
    library: str  # its id
    name: str
    kind: str
    version: str = ""
    home: str = ""
    download: str = ""
    evidence: list[str] = field(default_factory=list)
    functions: dict = field(default_factory=dict)  # Code.key -> why it's the library's
    aside: bool = False  # its functions are set aside without asking

    def as_dict(self, names: dict) -> dict:
        return {"id": self.library, "name": self.name, "kind": self.kind, "version": self.version, "home": self.home,
                "download": self.download.format(version=self.version) if self.download and self.version else "",
                "evidence": self.evidence[:8], "aside": self.aside,
                "functions": [{"name": names.get(k, str(k)), "why": w} for k, w in self.functions.items()]}


def _line(joined: bytes, m: re.Match) -> bytes:
    end = joined.find(b"\n", m.end())
    return joined[joined.rfind(b"\n", 0, m.start()) + 1:end if end >= 0 else len(joined)]


def _finding(found: dict[str, Finding], lib: Library | None, lid: str, name: str = "", version: str = "") -> Finding:
    key = f"{lid}@{version}" if lib is None else lid
    if key not in found:
        found[key] = Finding(lid, lib.name if lib else name or lid, lib.kind if lib else "source", version,
                             lib.home if lib else "", lib.download if lib else "", aside=lib.aside if lib else True)
    return found[key]


def identify(program: bytes | None, codes: list[Code], catalog: Catalog, arch: str = "", big_endian: bool = False,
             extra: dict | None = None) -> dict:
    """What libraries the program has built in. `program`: its file (its text says what's there); `codes`: its
    functions; `extra`: findings someone else made, {(library, version, name): {key: why}} (Ghidra's Function ID).
    Returns {"libraries": [Finding.as_dict...], "notices": [...], "paths": [...]}, with each function key taken by
    the first finding that has it."""
    found: dict[str, Finding] = {}
    text = strings(program or b"")
    joined = b"\n".join(text)
    known_text: set[bytes] = set()
    for lib in catalog.libraries:  # the program's text: which libraries, which versions
        hits = [m for rx in lib.strings for m in [rx.search(joined)] if m]
        if not hits:
            continue
        version = next((m.group("version").decode("latin-1") for m in hits if "version" in m.re.groupindex), "")
        if not version:
            version = next((m.group("version").decode("latin-1") for rx in lib.versions for m in [rx.search(joined)]
                            if m and "version" in m.re.groupindex), "")
        f = _finding(found, lib, lib.id)
        f.version = f.version or version
        for m in hits:
            f.evidence.append(f"its text: {_line(joined, m).decode('latin-1')[:160]!r}")
        known_text.update(_line(joined, m) for rx in lib.strings + lib.versions for m in rx.finditer(joined))
        for table in lib.tables:
            if program and table in program:
                f.evidence.append(f"its table {table[:8].hex()}…")

    # signatures: the user's and converted ones, by size first
    by_size: dict[int | None, list[Signature]] = defaultdict(list)
    for s in catalog.signatures:
        if int(sum(s.mask)) >= SHORTEST or s.crc:
            by_size[s.size].append(s)
    for code in codes:
        cands = by_size.get(len(code.raw), []) + by_size.get(_trimmed(code.raw), []) + by_size.get(None, [])
        hits = [s for s in cands if signature_matches(s, code)]
        if not hits:
            continue
        names = sorted({s.name for s in hits})
        s = hits[0]
        lib = next((lb for lb in catalog.libraries if lb.id == s.library.lower()), None)
        f = _finding(found, lib, s.library, s.library, s.version)
        f.version = f.version or s.version
        f.functions.setdefault(code.key, f"{' or '.join(names[:3])} of {s.library}"
                               + (f" {s.version}" if s.version else "") + f" ({s.origin})")

    for (lid, version, name), funcs in (extra or {}).items():
        lib = next((lb for lb in catalog.libraries if lb.id == lid), None)
        f = _finding(found, lib, lid, name, version)
        for k, why in funcs.items():
            f.functions.setdefault(k, why)

    # constants: which functions are an algorithm's or a library's, and the ones between them
    order = sorted((c for c in codes if c.addr is not None), key=lambda c: c.addr)
    index = {c.key: i for i, c in enumerate(order)}
    imms_cache: dict[object, set[int]] = {}
    for lib in catalog.libraries:
        if not lib.constants:
            continue
        strong: dict[object, set[int]] = {}
        weak: dict[object, set[int]] = {}
        for code in codes:
            imms = None
            if arch in SPLIT_IMMEDIATES:
                imms = imms_cache.setdefault(code.key, _immediates(code, big_endian))
            got = constants_in(code, lib.constants, arch, big_endian, imms)
            if len(got) >= lib.needs:
                strong[code.key] = got
            elif lib.companions:
                comp = constants_in(code, lib.companions, arch, big_endian, imms)
                if len(comp) >= min(lib.needs, len(lib.companions)):
                    weak[code.key] = comp
        if not strong:
            continue
        f = _finding(found, lib, lib.id)
        f.evidence.append(f"the constants of {len(strong)} of its functions")
        for k, got in strong.items():
            f.functions.setdefault(k, f"{lib.name}: its code holds {len(got)} of its constants "
                                      f"({', '.join(f'0x{c:08x}' for c in sorted(got)[:3])}…)")
        # beside them (by address): a companion within reach, and what lies between two of its own
        mine = sorted(index[k] for k in strong if k in index)
        near = sorted(index[k] for k in weak if k in index)
        for i in near:
            if any(abs(i - j) <= MAX_BETWEEN + 1 and abs(order[i].addr - order[j].addr) <= MAX_SPAN for j in mine):
                f.functions.setdefault(order[i].key, f"{lib.name}: its starting values, beside its own code")
                mine.append(i)
        mine.sort()
        for a, b in zip(mine, mine[1:]):
            if 1 < b - a <= MAX_BETWEEN + 1 and order[b].addr - order[a].addr <= MAX_SPAN:
                for i in range(a + 1, b):
                    f.functions.setdefault(order[i].key, f"{lib.name}: between two of its own functions "
                                                         f"({order[a].name}, {order[b].name})")

    # each function the first finding's (signatures, then the catalog's constants)
    taken: set = set()
    for f in found.values():
        for k in [k for k in f.functions if k in taken]:
            del f.functions[k]
        taken |= set(f.functions)

    notices: dict[str, int] = defaultdict(int)
    for s in text:
        line = s.decode("latin-1").strip()
        if len(line) >= MIN_NOTICE and NOTICE.search(line) and NOTICE_DATED.search(line) and s not in known_text:
            notices[line[:200]] += 1
    stamps = [n for n in notices if STAMP.search(n)]
    if len(stamps) > MAX_STAMPS:  # (one per source file: the game's own repository's, not a library's)
        for n in stamps:
            del notices[n]
    folders: dict[str, list[str]] = defaultdict(list)
    for s in text:
        for m in SOURCE_PATH.finditer(s.decode("latin-1")):
            parts = re.split(r"[\\/]", m.group(0))
            folder = "/".join(p for p in parts[:-1] if p not in ("", ".", "..")) or "."
            if SYSTEM_FOLDER.match(folder):
                continue
            if parts[-1] not in folders[folder]:
                folders[folder].append(parts[-1])
    names = {c.key: c.name for c in codes}
    libraries = sorted((f for f in found.values()), key=lambda f: (-len(f.functions), f.name))
    return {"libraries": [f.as_dict(names) | {"keys": list(f.functions)} for f in libraries],
            "notices": [{"text": t, "count": n} for t, n in sorted(notices.items(), key=lambda x: -x[1])][:MAX_UNKNOWN],
            "paths": [{"folder": d, "files": sorted(fs)[:12], "count": len(fs)}
                      for d, fs in sorted(folders.items(), key=lambda x: -len(x[1]))][:MAX_UNKNOWN]}
