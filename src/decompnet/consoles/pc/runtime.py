"""Visual C++'s runtime library in a PC game, found by its own code: every function of the libraries a compiler pack
has (its Lib folder: libc.lib, libcmt.lib, libcp.lib..., the user's copy where the pack has none), its bytes with what
its relocations fill in masked out, matched exactly against the game's functions. Ghidra's Function ID knows the
runtimes of most versions only by its own fingerprints of another build (a 2002 game's came out as 2003's); these are
the libraries the game was linked with. Standard library only.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

MACHINE_I386 = 0x14C
CODE = 0x20  # IMAGE_SCN_CNT_CODE
FUNCTION_TYPE = 0x20  # a symbol's type: a function
EXTERNAL, STATIC = 2, 3
RELOC_BYTES = {0x06: 4, 0x07: 4, 0x14: 4, 0x0A: 2, 0x0B: 4}  # DIR32, DIR32NB, REL32, SECTION, SECREL
# A function shorter than this is too common a shape to say whose it is (`xor eax, eax; ret`): the game's own code
# has them too. The runtime's short functions are found as its helpers (scratch.library_functions) instead.
SHORTEST = 16
PADDING = b"\x90\xcc"
LIBRARIES = ("libc", "libcmt", "libcp", "libcpmt", "msvcrt", "msvcprt", "oldnames")


@dataclass
class LibraryFunction:
    name: str
    library: str  # its .lib, and object: "LIBC.LIB(strlen.obj)"
    code: bytes  # masked
    mask: tuple[int, ...]  # the masked bytes' offsets


def archive_members(data: bytes) -> list[tuple[str, bytes]]:
    """The objects of a .lib (an ar archive), by name: the linker's members ("/", "//") and import objects aren't."""
    if data[:8] != b"!<arch>\n":
        return []
    out, names, at = [], b"", 8
    while at + 60 <= len(data):
        head = data[at:at + 60]
        name, size = head[:16].decode("latin-1").strip(), int(head[48:58].decode("latin-1").strip() or 0)
        body = data[at + 60:at + 60 + size]
        if name == "//":
            names = body
        elif name != "/":
            if name.startswith("/") and name[1:].isdigit():  # a long name, in the "//" member
                start = int(name[1:])
                name = names[start:names.find(b"\0", start) if b"\0" in names[start:] else len(names)].decode(
                    "latin-1").rstrip("/\n")
            if len(body) >= 20 and struct.unpack_from("<H", body, 0)[0] == MACHINE_I386:
                out.append((name.rstrip("/"), body))
        at += 60 + size + (size & 1)
    return out


def object_functions(obj: bytes, where: str) -> list[LibraryFunction]:
    """Every function an object defines in its code sections, each up to the next one there or its section's end,
    with its relocations' bytes masked."""
    _, count, _, table, nsyms, _, _ = struct.unpack_from("<HHIIIHH", obj, 0)
    strings = table + 18 * nsyms
    starts: dict[int, list[tuple[int, str]]] = defaultdict(list)
    k = 0
    while k < nsyms:
        raw, value, section, kind, storage, aux = struct.unpack_from("<8sIhHBB", obj, table + 18 * k)
        if raw[:4] == b"\0\0\0\0":
            at = strings + struct.unpack_from("<I", raw, 4)[0]
            raw = obj[at:obj.index(b"\0", at)]
        name = raw.rstrip(b"\0").decode("latin-1")
        if section > 0 and storage in (EXTERNAL, STATIC) and (kind == FUNCTION_TYPE or storage == EXTERNAL) \
                and not name.startswith((".", "$", "??_C@")):
            starts[section].append((value, name))
        k += 1 + aux
    out = []
    for i in range(count):
        _, _, _, size, data, relocs, _, nrelocs, _, flags = struct.unpack_from("<8sIIIIIIHHI", obj, 20 + 40 * i)
        if not flags & CODE or not data or i + 1 not in starts:
            continue
        code = bytearray(obj[data:data + size])
        masked = set()
        for r in range(nrelocs):
            off, _, kind = struct.unpack_from("<IIH", obj, relocs + 10 * r)
            masked.update(range(off, off + RELOC_BYTES.get(kind, 4)))
        here = sorted(set(starts[i + 1]))
        for (begin, name), (end, _) in zip(here, [*here[1:], (size, "")]):
            if end <= begin:
                continue
            body = bytes(code[begin:end]).rstrip(PADDING) or bytes(code[begin:end])
            mask = tuple(sorted(m - begin for m in masked if begin <= m < begin + len(body)))
            out.append(LibraryFunction(name, where, _masked(body, mask, 0), mask))
    return out


def _masked(code: bytes, mask: tuple[int, ...], start: int) -> bytes:
    out = bytearray(code)
    for m in mask:
        if start + m < len(out):
            out[start + m] = 0
    return bytes(out)


class Fingerprints:
    """The runtime libraries' functions, by length and mask, for find."""

    def __init__(self, functions: list[LibraryFunction]):
        self.by_shape: dict[tuple[int, tuple[int, ...]], dict[bytes, list[LibraryFunction]]] = defaultdict(dict)
        for f in functions:
            if len(f.code) >= SHORTEST:
                self.by_shape[(len(f.code), f.mask)].setdefault(f.code, []).append(f)
        self.lengths: dict[int, list[tuple[int, ...]]] = defaultdict(list)
        for length, mask in self.by_shape:
            self.lengths[length].append(mask)
        self.count = sum(len(v) for byb in self.by_shape.values() for v in byb.values())

    def find(self, code: bytes) -> list[LibraryFunction]:
        """The library functions whose code a function's is (`code`: its bytes, padding after it allowed)."""
        body = code.rstrip(PADDING) or code
        for length in (len(body), *range(len(body) + 1, len(code) + 1)):  # (its last bytes may be 90 or cc too)
            for mask in self.lengths.get(length, ()):
                if (hit := self.by_shape[(length, mask)].get(_masked(code[:length], mask, 0))):
                    return hit
        return []


def libraries(folder: Path) -> list[Path]:
    """The runtime libraries in a compiler's Lib folder (any case)."""
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.suffix.lower() == ".lib" and p.stem.lower() in LIBRARIES)


def fingerprints(folders: list[Path]) -> Fingerprints:
    found: list[LibraryFunction] = []
    for folder in folders:
        for lib in libraries(folder):
            for member, obj in archive_members(lib.read_bytes()):
                found += object_functions(obj, f"{lib.name}({Path(member).name})")
    return Fingerprints(found)


def compiler_libraries(toolchains_dir: Path, version: str) -> list[Path]:
    """Where a compiler pack's runtime libraries are, the ones its install has: msvc/7.0/Lib (the user's copy: the
    pack has none), msvc/8.0-sp1/lib (2005 SP1's, as an older pack named its folder)..."""
    names = dict.fromkeys([version, version.lower().replace("sp", "-sp")])
    return [d / lib for name in names for d in sorted(toolchains_dir.glob(f"msvc*/{name}")) for lib in ("Lib", "lib")
            if (d / lib).is_dir() and libraries(d / lib)][:1]
