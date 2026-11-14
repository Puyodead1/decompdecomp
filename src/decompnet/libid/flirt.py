"""IDA's FLIRT signatures, read into ours (libid.Signature): its pattern files (`.pat`, sigmake's input, text) and
its signature files (`.sig`, what IDA ships and sigmake writes: a tree of patterns, usually compressed).

A FLIRT signature is a function's first 32 bytes ("." where a relocation goes), the CRC-16 of the bytes after them
up to the first relocation, the module's length, its public names and a few tail bytes: what libid matches each of
the game's functions against. Names it says a module refers to aren't checked (they'd need the game's own names).
The `.sig` layout is as rizin's reader has it (librz/sign/flirt.c), versions 5 to 10.
"""

from __future__ import annotations

import re
import zlib

from . import Signature

PATTERN_BYTES = 32
# .sig flags (the leaf's)
MORE_PUBLIC_NAMES, READ_TAIL_BYTES, READ_REFERENCED, MORE_MODULES_SAME_CRC, MORE_MODULES = 1, 2, 4, 8, 0x10
COMPRESSED = 0x10  # the header's features: the tree is zlib-compressed
LOCAL = 2  # a public name's flag: a local name (not what the function is called)


def read_pat(text: str, library: str, origin: str) -> list[Signature]:
    """sigmake's pattern lines: `<pattern> <crc length> <crc16> <length> :<offset> <name> ... [(<offset>) <byte>...]`,
    the file ending with `---`."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line == "---" or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        pat = parts[0]
        try:
            pattern = bytes(int(pat[i:i + 2], 16) if pat[i:i + 2] != ".." else 0 for i in range(0, len(pat), 2))
            mask = bytes(0 if pat[i:i + 2] == ".." else 1 for i in range(0, len(pat), 2))
            crc_len, crc, size = int(parts[1], 16), int(parts[2], 16), int(parts[3], 16)
        except ValueError:
            continue
        name, tail, rest = "", [], parts[4:]
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok.startswith(":") and i + 1 < len(rest):
                off = tok[1:].rstrip("@")
                if not name and re.fullmatch(r"-?[0-9A-Fa-f]+", off) and int(off, 16) == 0:
                    name = rest[i + 1]
                i += 2
            elif tok.startswith("^") and i + 1 < len(rest):
                i += 2  # (a name it refers to: not checked)
            elif tok.startswith("(") and tok.endswith(")") and i + 1 < len(rest):
                try:
                    tail.append((int(tok[1:-1], 16), int(rest[i + 1], 16)))
                except ValueError:
                    pass
                i += 2
            else:
                i += 1
        if name:
            out.append(Signature(library, "", name, size, pattern, mask, (len(pattern), crc_len, crc), tuple(tail),
                                 origin))
    return out


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def byte(self) -> int:
        if self.at >= len(self.data):
            raise ValueError("the signature file ends early")
        self.at += 1
        return self.data[self.at - 1]

    def short(self) -> int:
        return (self.byte() << 8) | self.byte()

    def word(self) -> int:
        return (self.short() << 16) | self.short()

    def max2(self) -> int:
        b = self.byte()
        return ((b & 0x7F) << 8) | self.byte() if b & 0x80 else b

    def multiple(self) -> int:
        b = self.byte()
        if not b & 0x80:
            return b
        if (b & 0xC0) != 0xC0:
            return ((b & 0x7F) << 8) | self.byte()
        if (b & 0xE0) != 0xE0:
            return ((b & 0x3F) << 24) | (self.byte() << 16) | self.short()
        return self.word()


def read_sig(data: bytes, origin: str) -> list[Signature]:
    if not data.startswith(b"IDASGN"):
        raise ValueError("not a FLIRT signature file (no IDASGN)")
    r = _Reader(data)
    r.at = 6
    version = r.byte()
    if not 5 <= version <= 10:
        raise ValueError(f"FLIRT signature version {version} isn't one decompdecomp reads (5 to 10)")
    r.at += 1 + 4 + 2 + 2  # arch, file types, OS types, app types
    features = r.byte() | (r.byte() << 8)
    r.at += 2 + 2 + 12  # old count, crc16, ctype
    name_len = r.byte()
    r.at += 2  # ctypes crc16
    if version >= 6:
        r.at += 4  # functions
    if version >= 8:
        r.at += 2  # pattern size
    if version >= 10:
        r.at += 2
    library = data[r.at:r.at + name_len].decode("latin-1").strip() or origin
    rest = data[r.at + name_len:]
    if features & COMPRESSED:
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                rest = zlib.decompress(rest, wbits)
                break
            except zlib.error:
                continue
        else:
            raise ValueError("its compressed tree doesn't decompress")
    tree = _Reader(rest)
    out: list[Signature] = []
    _node(tree, version, b"", b"", library, origin, out, 0)
    return out


def _node(r: _Reader, version: int, pattern: bytes, mask: bytes, library: str, origin: str, out: list, depth: int):
    if depth > 64:
        raise ValueError("its tree is deeper than a pattern")
    children = r.multiple()
    if children == 0:
        _leaf(r, version, pattern, mask, library, origin, out)
        return
    for _ in range(children):
        length = r.byte()
        if length < 0x10:
            variant = r.max2()
        elif length <= 0x20:
            variant = r.multiple()
        else:
            variant = (r.multiple() << 32) | r.multiple()
        p, m = bytearray(), bytearray()
        for j in range(length):
            if variant & (1 << (length - 1 - j)):
                p.append(0)
                m.append(0)
            else:
                p.append(r.byte())
                m.append(1)
        _node(r, version, pattern + bytes(p), mask + bytes(m), library, origin, out, depth + 1)


def _leaf(r: _Reader, version: int, pattern: bytes, mask: bytes, library: str, origin: str, out: list) -> None:
    flags = MORE_MODULES
    while flags & MORE_MODULES:
        crc_len, crc = r.byte(), r.short()
        flags = MORE_MODULES_SAME_CRC
        while flags & MORE_MODULES_SAME_CRC:
            length = r.multiple() if version >= 9 else r.max2()
            names, offset = [], 0
            flags = MORE_PUBLIC_NAMES
            while flags & MORE_PUBLIC_NAMES:
                offset += r.multiple() if version >= 9 else r.max2()
                b = r.byte()
                local = False
                if b < 0x20:
                    local = bool(b & LOCAL)
                    b = r.byte()
                name = bytearray()
                while b >= 0x20:
                    name.append(b)
                    b = r.byte()
                flags = b
                names.append((offset, name.decode("latin-1"), local))
            if flags & READ_TAIL_BYTES:  # (read past, not checked: the pattern, CRC and length say enough)
                for _ in range(r.byte() if version >= 8 else 1):
                    r.multiple() if version >= 9 else r.max2()
                    r.byte()
            if flags & READ_REFERENCED:
                for _ in range(r.byte() if version >= 8 else 1):
                    r.multiple() if version >= 9 else r.max2()
                    n = r.byte() or r.multiple()
                    r.at += n
            name = next((n for off, n, local in names if off == 0 and not local), None)
            if name:
                out.append(Signature(library, "", name, length, pattern, mask, (len(pattern), crc_len, crc),
                                     origin=origin))
