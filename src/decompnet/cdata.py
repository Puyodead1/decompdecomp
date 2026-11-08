"""A global variable's value written as C: what the program's data holds, by the type its debug information gives
(consoles/ps2/stabs.py, written as C by cheader.Header), as the initializer of its definition.

`static S s1 = { .a = 1, .b = 2.5f, .p = { .x = 3 }, .f = 5 };`: a struct by its members' names as the shared header
declares them (designated, so the header's padding members stay out of it and a zero member isn't written), an array
by its elements (the zeros after the last one left to C), a string as its literal, a float as the literal that is
exactly its bits (addresses.c_float), a bitfield by its bits. A pointer is what it points at by name, through
`pointer` (the caller knows the program's symbols and which of them this file may name), or a string literal.
GCC 2.95 and a newer GCC both take what's written. What can't be written (a float that is no number, data in a
struct's padding, a pointer the caller can't name) raises Unwritable: the variable stays the program's bytes.

Whether the definitions make the program's bytes is the judge's to say: the caller compiles them and compares."""

from __future__ import annotations

import struct
from collections.abc import Callable

from .addresses import c_float


class Unwritable(ValueError):
    pass


TEXT = set(range(32, 127)) | {9, 10, 13}
WRAP = 100  # an initializer longer than this is written one element per line


def _escape(data: bytes) -> str:
    out = []
    for i, b in enumerate(data):
        c = chr(b)
        if c in '"\\':
            out.append("\\" + c)
        elif c == "\n":
            out.append("\\n")
        elif c == "\t":
            out.append("\\t")
        elif c == "\r":
            out.append("\\r")
        elif 32 <= b < 127:
            # (an octal escape eats the digits after it: "\0331" is \033 then "1", "\1" then "1" isn't)
            if out and out[-1].startswith("\\") and out[-1][1:].isdigit() and c.isdigit():
                out.append('""')
            out.append(c)
        else:
            out.append(f"\\{b:03o}")
    return '"' + "".join(out) + '"'


def string_literal(data: bytes) -> str:
    return _escape(data)


def _join(parts: list[str], indent: int) -> str:
    if not parts:
        return "{ 0 }"
    flat = "{ " + ", ".join(parts) + " }"
    if len(flat) <= WRAP and "\n" not in flat:
        return flat
    pad = "    " * (indent + 1)
    return "{\n" + ",\n".join(pad + p for p in parts) + "\n" + "    " * indent + "}"


class Writer:
    """Initializers for one file's variables. `header`: the cheader.Header the shared header was written by (its
    names for types and members); `pointer(address, pointer_type)`: an address as C for a pointer of that type, or
    None when this file can't name it."""

    def __init__(self, header, pointer: Callable[[int, object], str | None]):
        self.h = header
        self.pointer = pointer

    def value(self, t, data: bytes, at: int, indent: int = 0) -> str:
        h = self.h
        r = h._resolve(t)
        size = h.size(t)
        if len(data) < size:
            raise Unwritable("the program's data ends before the variable does")
        data = data[:size]
        if r.kind in ("base", "enum"):
            if size not in (1, 2, 4, 8):
                raise Unwritable(f"a {size}-byte integer")
            signed = r.kind == "enum" or r.signed
            v = int.from_bytes(data, "little", signed=signed)
            return _int(v, size, signed)
        if r.kind == "float":
            if size == 4:
                text = c_float(struct.unpack("<f", data)[0], True)
            elif size == 8:
                text = c_float(struct.unpack("<d", data)[0], False)
            else:
                raise Unwritable(f"a {size}-byte float")
            if text is None:
                raise Unwritable("a float that is no number")
            return text
        if r.kind == "pointer":
            word = int.from_bytes(data[:4], "little")
            if word == 0:
                return "0"
            text = self.pointer(word, r)
            if text is None:
                raise Unwritable(f"a pointer to 0x{word:X} this file can't name")
            return text
        if r.kind == "array" and r.target is not None:
            return self._array(r, data, at, indent)
        if r.kind in ("struct", "union"):
            return self._record(r, data, at, indent)
        raise Unwritable(f"a value of a type the debug information doesn't describe ({r.kind})")

    def _array(self, r, data: bytes, at: int, indent: int) -> str:
        h = self.h
        elem = r.target
        size = h.size(elem)
        if size <= 0 or r.count <= 0:
            raise Unwritable("an array of no size")
        e = h._resolve(elem)
        if e.kind == "base" and size == 1:
            body = data.rstrip(b"\0")
            if not body:
                return "{ 0 }"
            if b"\0" not in body and all(b in TEXT for b in body):
                return string_literal(body)  # (C fills the rest with zeros; a literal as long as the array is fine)
            return _join([str(int.from_bytes(bytes([b]), "little", signed=e.signed)) for b in body], indent)
        parts = [data[i * size:(i + 1) * size] for i in range(r.count)]
        last = max((i for i, p in enumerate(parts) if any(p)), default=-1)
        return _join([self.value(elem, p, at + i * size, indent + 1) if any(p) else
                      ("0" if e.kind in ("base", "enum", "float", "pointer") else "{ 0 }")
                      for i, p in enumerate(parts[:last + 1])], indent)

    def _record(self, r, data: bytes, at: int, indent: int) -> str:
        h = self.h
        members = h.members(r)
        if r.kind == "union":
            # the first member that holds all of its bytes, the rest of the union zeros
            for name, bit_offset, mt, bits, as_bytes in sorted(members, key=lambda m: m[4]):
                width = h.size(mt)
                if bits or bit_offset or not any(data) or any(data[width:]):
                    continue
                return "{ ." + name + " = " + (self._bytes(data[:width], indent + 1) if as_bytes else
                                               self.value(mt, data[:width], at, indent + 1)) + " }"
            if not any(data):
                return "{ 0 }"
            raise Unwritable("a union no member of which holds its value")
        covered = bytearray(len(data))
        parts = []
        whole = int.from_bytes(data, "little")
        for name, bit_offset, mt, bits, as_bytes in members:
            if bits:
                v = (whole >> bit_offset) & ((1 << bits) - 1)
                if h._resolve(mt).kind == "enum" or h._resolve(mt).signed:
                    v -= (v >> (bits - 1)) << bits
                for b in range(bit_offset // 8, (bit_offset + bits + 7) // 8):
                    covered[b] = 1
                if v:
                    parts.append(f".{name} = {v}")
                continue
            off, width = bit_offset // 8, h.size(mt)
            chunk = data[off:off + width]
            covered[off:off + width] = b"\1" * len(chunk)
            if any(chunk):
                parts.append(f".{name} = " + (self._bytes(chunk, indent + 1) if as_bytes else
                                              self.value(mt, chunk, at + off, indent + 1)))
        if any(b and not c for b, c in zip(data, covered)):
            raise Unwritable("data in a struct's padding")
        return _join(parts, indent)

    @staticmethod
    def _bytes(data: bytes, indent: int) -> str:
        body = data.rstrip(b"\0")
        return _join([str(b) for b in body], indent) if body else "{ 0 }"


def _int(v: int, size: int, signed: bool) -> str:
    if size == 8:
        return f"{v}LL" if signed else f"{v}ULL"
    if signed and size == 4 and v == -(1 << 31):
        return "(-2147483647 - 1)"
    if not signed and size == 4 and v >= 1 << 31:
        return f"0x{v:X}U"
    return str(v)


def constant(header, t):
    """`t` made constant at its top (an array's elements): what GCC puts in .rodata."""
    from .consoles.ps2.stabs import Type

    r = header._resolve(t)
    if r.kind == "array" and r.target is not None:
        return Type(kind="array", count=r.count, target=constant(header, r.target), size=r.size)
    if t.kind == "const":
        return t
    return Type(kind="const", target=t, size=header.size(t))
