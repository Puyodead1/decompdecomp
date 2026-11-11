"""Nintendo's libraries linked into a DS or DSi game (NitroSDK, TwlSDK, NitroSystem, NitroWiFi, DWC, CodeWarrior's
runtime), found by the user's own copies (kits/nitro.py) so they can be named and set aside: they're Nintendo's code,
linked prebuilt, not the game's, and agents shouldn't spend time decompiling them.

Every function of a library is a byte pattern in which the fields its relocations fill in are wildcards (the
linker's `bl` to `blx` for interworking too: the whole word), as xbox/xdklib.py does for the XDK; CodeWarrior gives
each function a .text section of its own, its literal pool included, so a function is its section. A pattern that
fits where ds-decomp found a function makes it that library function: its symbol gets the library's name (OS_Init,
not func_02000C44) in symbols.txt, and config/<version>/arm9/set_aside.json says why it's set aside. Only names and
reasons are written to the project, never the libraries' bytes; they're read where the user keeps them.
"""

from __future__ import annotations

import hashlib
import io
import json
import pickle
import re
from dataclasses import dataclass
from pathlib import Path

from ..xbox.xdklib import LibraryFunction

# ARM relocation types that fill less than a word -> how many bytes (ABS16, THM_ABS5, ABS8, THM_PC8, THM_SWI8); the
# rest fill a word: ABS32, PC24, CALL, JUMP24, THM_CALL (a Thumb bl's two halves)
RELOC_BYTES = {5: 2, 7: 2, 8: 1, 11: 2, 14: 2}
MIN_BYTES = 12  # (three ARM instructions: shorter ones fit in too many places, and are matched next to others)
# bytes no relocation fills that a function on its own needs (fewer: it counts beside library code). Every SDK
# version together is 120,000 functions: a getter's few fixed bytes (ldr, ldr, bx lr) fit some of them, and the
# game's own getters too
MIN_FIXED = 16
KEY = 4  # the fixed run a function is looked up by
CACHE_VERSION = 1


@dataclass
class NitroFunction(LibraryFunction):
    @property
    def names(self) -> list[str]:
        """The library functions it is: one, or several whose code is the same, relocated fields aside (a function
        that returns the address of a string, and one that returns a table's)."""
        return self.symbol.split("|")

    @property
    def reason(self) -> str:
        if len(self.names) > 1:
            return f"Nintendo library code: one of {', '.join(self.names)} (the same code) from {self.library}"
        return f"Nintendo library code: {self.symbol} from {self.library} ({self.member})"


def members(data: bytes):
    """(name, bytes) of every object in a GNU or System V archive (.a)."""
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


def functions(obj: bytes):
    """(symbol, bytes, relocated-bytes mask) of each function of an ARM ELF object: each function symbol with a size,
    its bytes from its section, its relocations' fields masked."""
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    try:
        elf = ELFFile(io.BytesIO(obj))
        if elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_REL":
            return
        masks: dict[int, bytearray] = {}
        datas: dict[int, bytes] = {}
        for i, sec in enumerate(elf.iter_sections()):
            if sec["sh_type"] == "SHT_PROGBITS" and sec["sh_flags"] & 0x4:  # SHF_EXECINSTR
                datas[i] = sec.data()
                masks[i] = bytearray(len(datas[i]))
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection) or sec["sh_info"] not in masks:
                continue
            mask = masks[sec["sh_info"]]
            for r in sec.iter_relocations():
                off, n = r["r_offset"], RELOC_BYTES.get(r["r_info_type"], 4)
                mask[off:off + n] = b"\1" * len(mask[off:off + n])
        symtab = elf.get_section_by_name(".symtab")
        for s in symtab.iter_symbols() if symtab is not None else ():
            shndx = s["st_shndx"]
            if s["st_info"]["type"] != "STT_FUNC" or not s["st_size"] or not isinstance(shndx, int) or \
                    shndx not in datas or s.name.startswith("$"):
                continue
            lo = s["st_value"] & ~1
            hi = lo + s["st_size"]
            if hi <= len(datas[shndx]):
                yield s.name, datas[shndx][lo:hi], bytes(masks[shndx][lo:hi])
    except (ELFError, KeyError, ValueError, AttributeError, TypeError):
        return


def _cache_dir() -> Path:
    from ... import toolchains

    return toolchains.root() / "cache" / "nitro"


def _archive_functions(lib: Path) -> list[tuple[str, bytes, bytes, str]]:
    """(symbol, bytes, mask, member) of an archive's functions, read once: kept in the toolchains folder's cache by
    the archive's path, size and time (every SDK version together is thousands of archives)."""
    try:
        st = lib.stat()
    except OSError:
        return []
    key = hashlib.sha1(f"{CACHE_VERSION}|{lib.resolve()}|{st.st_size}|{st.st_mtime_ns}".encode()).hexdigest()
    cached = _cache_dir() / f"{key}.pickle"
    try:
        return pickle.loads(cached.read_bytes())
    except (OSError, pickle.UnpicklingError, EOFError, ValueError):
        pass
    try:
        out = [(symbol, body, mask, member) for member, obj in members(lib.read_bytes())
               for symbol, body, mask in functions(obj)]
    except OSError:
        return []
    try:
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(pickle.dumps(out))
    except OSError:
        pass
    return out


def entries(archives: list[Path]) -> list[tuple[str, bytes, bytes, str, str]]:
    """(symbol, bytes, mask, library, member) of every function in `archives`, each body and mask once: where
    functions of different names have the same, their names joined by `|` (NitroFunction.names)."""
    out: dict[tuple[bytes, bytes], list] = {}
    for lib in archives:
        for symbol, body, mask, member in _archive_functions(lib):
            if (key := (body, mask)) not in out:
                out[key] = [symbol, body, mask, lib.name, member]
            elif symbol not in out[key][0].split("|"):
                out[key][0] += "|" + symbol
    return [tuple(e) for e in out.values()]


def _key(body: bytes, mask: bytes) -> int | None:
    """Where the function's first run of KEY bytes no relocation fills starts, when it has MIN_FIXED such bytes in
    all and MIN_BYTES in all: what it's looked up by. None: it counts only beside library code."""
    if len(body) < MIN_BYTES or len(mask) - sum(1 for m in mask if m) < MIN_FIXED:
        return None
    at = bytes(mask).find(bytes(KEY))
    return at if at >= 0 else None


def _either(f: NitroFunction, symbol: str) -> NitroFunction:
    """`f`, or the library function `symbol`, as good a fit: its names are both's."""
    names = list(dict.fromkeys(f.names + symbol.split("|")))
    return NitroFunction(f.addr, f.size, "|".join(names), f.library, f.member)


def _better(size: int, than: int, analysed: int) -> bool:
    """Whether a library function of `size` bytes that fits is the one, before one of `than` that fits too: the size
    the analysis gave the game's function, else the longer (a shorter function of another version can fit the start
    of a longer one)."""
    return (size == analysed, size) > (than == analysed, than)


def _fits(code: bytes, start: int, body: bytes, mask: bytes) -> bool:
    end = start + len(body)
    return end <= len(code) and all(m or a == b for a, b, m in zip(code[start:end], body, mask))


def find(modules, archives: list[Path]) -> dict[tuple[str, int], NitroFunction]:
    """(module name, address) -> the library function found where ds-decomp found a function, in `modules`
    (recover.load_modules)."""
    every = entries(archives)
    keyed, small = [], {}
    for e in every:
        if (at := _key(e[1], e[2])) is None:
            small.setdefault(len(e[1]), []).append(e)
        else:
            keyed.append((at, e))
    out = {}
    for m in modules:
        starts = sorted(a for a in m.functions if 0 <= a - m.base < len(m.code))
        # the game's function starts by the KEY bytes at each offset a library function is looked up at
        index: dict[int, dict[bytes, list[int]]] = {}
        found: dict[int, NitroFunction] = {}
        for at, (symbol, body, mask, lib, member) in keyed:
            if at not in index:
                index[at] = {}
                for a in starts:
                    index[at].setdefault(m.code[a - m.base + at:a - m.base + at + KEY], []).append(a)
            for a in index[at].get(body[at:at + KEY], ()):
                if not _fits(m.code, a - m.base, body, mask):
                    continue
                if a not in found or _better(len(body), found[a].size, m.functions[a][0]):
                    found[a] = NitroFunction(a, len(body), symbol, lib, member)
                elif len(body) == found[a].size:  # (as good a fit: which it is, nothing says)
                    found[a] = _either(found[a], symbol)
        # the small ones, of their exact size, beside library code found (the linker keeps a library's objects
        # together): a few bytes such as `bx lr` fit the game's own code just as well
        for _ in range(16):
            before = len(found)
            for k, a in enumerate(starts):
                size = m.functions[a][0]
                if a in found or size not in small or not any(
                        0 <= j < len(starts) and starts[j] in found for j in (k - 1, k + 1)):
                    continue
                fits = [e for e in small[size] if _fits(m.code, a - m.base, e[1], e[2])]
                if fits:
                    f = found[a] = NitroFunction(a, size, fits[0][0], fits[0][3], fits[0][4])
                    for e in fits[1:]:
                        found[a] = f = _either(f, e[0])
            if len(found) == before:
                break
        out.update({(m.name, a): f for a, f in found.items()})
    return out


def _unique(name: str, taken: set[str], addr: int) -> str:
    """The library's name, or with its address where another symbol has it (a static function of two objects, two
    copies of one in two overlays)."""
    if re.fullmatch(r"[A-Za-z_$][\w$@.]*", name) is None:
        name = re.sub(r"[^\w$@.]", "_", name)
    return name if name not in taken else f"{name}_{addr:08X}"


def set_aside(root: Path, version: str, archives: list[Path], log=print) -> int:
    """Name and set aside the library functions of a project ds-decomp has analysed and decompdecomp hasn't cut into
    source files yet (scratch.create): their symbols.txt lines get the library's names, set_aside.json their reasons.
    Returns how many."""
    from .recover import SYMBOL, load_modules

    if not archives:
        return 0
    config = root / "config" / version / "arm9"
    modules = load_modules(config, root / "extract" / version)
    found = find(modules, archives)
    if not found:
        return 0
    taken = {s.group(1) for m in modules for line in m.symbol_lines if (s := SYMBOL.match(line))}
    reasons: dict[str, str] = {}
    for m in modules:
        renames = {}
        for (name, addr), f in sorted(found.items()):
            if name != m.name:
                continue
            old = next((s.group(1) for line in m.symbol_lines if (s := SYMBOL.match(line))
                          and int(s.group(4), 16) == addr), None)
            if len(f.names) > 1 and old:  # (which of them it is, nothing tells: its name stays)
                reasons[old] = f.reason
                continue
            new = _unique(f.symbol, taken, addr)
            taken.add(new)
            renames[addr] = new
            reasons[new] = f.reason
        if not renames:
            continue
        lines = []
        for line in (m.folder / "symbols.txt").read_text(encoding="utf-8").splitlines():
            s = SYMBOL.match(line)
            if s and s.group(2) == "function" and (new := renames.get(int(s.group(4), 16))):
                line = new + line[len(s.group(1)):]
            lines.append(line)
        (m.folder / "symbols.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    path = root / "config" / version / "set_aside.json"
    old = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    path.write_text(json.dumps({**old, **reasons}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    libs = sorted({f.library for f in found.values()})
    log(f"{len(found)} functions are Nintendo's library code ({', '.join(libs[:6])}{'…' if len(libs) > 6 else ''}): "
        "named and set aside")
    return len(found)
