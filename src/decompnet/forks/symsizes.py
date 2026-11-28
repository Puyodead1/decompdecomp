"""The size of each data symbol in a dtk project's symbols.txt, as big as the object the game's code uses.

dtk sizes a symbol it found by the distance to the next one, so the padding after it counts as its own: a 4-byte
variable in .sbss was 8, an empty string 4, a run of strings one 0x207-byte blob. objdiff can't call such a symbol
matched however exactly the C defines it (a GameCube game: 14 symbols, and one file's .data at 99.46% until its blob
was cut at the NULs). Two kinds of evidence size a symbol here, both from the game itself:

- strings: a symbol whose bytes are text, each piece ending in its NUL and the zeros after it only padding, becomes
  one symbol per string, NUL included (`data:string`);
- the code's loads and stores: a variable the code only reads and writes, never takes the address of, is as big as
  the widest access reaches, rounded up to that width (a struct's tail padding). Small data is addressed from r13
  and r2 directly; other data from the `lis` before the access.

A symbol only shrinks over zeros (or .bss), and only grows a string by its NUL into bytes no symbol has: the bytes
of the game stay where they are, and its build stays byte for byte the same.
"""

from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass

DATA = (".rodata", ".data", ".bss", ".sdata", ".sbss", ".sdata2", ".sbss2")
ZEROED = (".bss", ".sbss", ".sbss2")  # (no bytes in the program: zeros)
TEXT_SECTIONS = 7  # a DOL's header lists 7 text sections, then 11 data
_HEADER = (0x00, 0x48, 0x90)  # file offsets, addresses, sizes: 18 words each

# D-form loads and stores: primary opcode -> bytes accessed
WIDTH = {32: 4, 33: 4, 34: 1, 35: 1, 36: 4, 37: 4, 38: 1, 39: 1, 40: 2, 41: 2, 42: 2, 43: 2, 44: 2, 45: 2,
         48: 4, 49: 4, 50: 8, 51: 8, 52: 4, 53: 4, 54: 8, 55: 8}
STORES = {36, 37, 38, 39, 44, 45, 47, 52, 53, 54, 55}  # (their first register is read, not written)
TAKEN = {14, 46, 47, 56, 57, 60, 61}  # addi (an address), lmw/stmw, psq_l/psq_st (widths their GQR decides)
BRANCHES = {16, 18, 19}
OP_ADDIS = 15
SMALL_BASES = (13, 2)  # r13: .sdata/.sbss; r2: .sdata2/.sbss2

_LINE = re.compile(r"^(\S+)\s*=\s*(\.\w+):0x([0-9A-Fa-f]+);(.*)$")
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
STRING_MIN = 4  # the longest piece of a run of strings has this many characters at least: shorter ones are numbers
PIECE_MIN = 2  # (2.0f reads "@" and 3.0f "@@"; with zeros after them, they're text too)
STRING_ALIGN = 4  # CodeWarrior's string literals each start at a 4-byte boundary
MAX_ALIGN = 32  # (the most a data section's next file starts aligned to)
SMALL = (".sdata", ".sbss", ".sdata2", ".sbss2")  # addressed from r13/r2 only: every access names the variable
PADDING_MAX = 8  # a variable in small data is padded to 8 bytes at most


@dataclass
class _Sym:
    line: int  # its line in symbols.txt
    name: str
    section: str
    address: int
    size: int
    rest: str  # everything after the address's semicolon


def _sections(dol: bytes) -> list[tuple[int, int, int, bool]]:
    """(file offset, address, size, is code) of the DOL's sections."""
    offs, addrs, sizes = (struct.unpack_from(">18I", dol, at) for at in _HEADER)
    return [(o, a, s, i < TEXT_SECTIONS) for i, (o, a, s) in enumerate(zip(offs, addrs, sizes)) if s]


def _reader(dol: bytes):
    secs = _sections(dol)

    def read(address: int, size: int) -> bytes | None:
        for o, a, s, _ in secs:
            if a <= address and address + size <= a + s:
                return dol[o + address - a:o + address - a + size]
        return None
    return read


def small_bases(dol: bytes) -> dict[int, int]:
    """{13: _SDA_BASE_, 2: _SDA2_BASE_}: what the start-up code (__init_registers) loads into r13 and r2, `lis` then
    `ori` or `addi`."""
    out: dict[int, int] = {}
    for o, _, s, code in _sections(dol):
        if not code:
            continue
        hi: dict[int, int] = {}
        for k in range(o, o + s - 3, 4):
            w = struct.unpack_from(">I", dol, k)[0]
            op, rd, ra, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
            if rd not in SMALL_BASES or rd in out:
                continue
            if op == OP_ADDIS and ra == 0:
                hi[rd] = (imm << 16) & 0xFFFFFFFF
            elif rd in hi and op == 24 and (w >> 21) & 31 == (w >> 16) & 31:  # ori rX, rX, lo
                out[rd] = hi[rd] | imm
            elif rd in hi and op == 14 and ra == rd:  # addi rX, rX, lo
                out[rd] = (hi[rd] + (imm - 0x10000 if imm & 0x8000 else imm)) & 0xFFFFFFFF
        if len(out) == len(SMALL_BASES):
            break
    return out


def accesses(dol: bytes) -> tuple[list[tuple[int, int]], set[int]]:
    """Every data access the code makes that names its address: ([(address, width)], {addresses taken}). Small data
    from r13/r2; other data from a `lis` earlier in the same straight run of code."""
    bases = small_bases(dol)
    out: list[tuple[int, int]] = []
    taken: set[int] = set()
    for o, _, s, code in _sections(dol):
        if not code:
            continue
        hi: dict[int, int] = dict(bases)
        for k in range(o, o + s - 3, 4):
            w = struct.unpack_from(">I", dol, k)[0]
            op, rd, ra = w >> 26, (w >> 21) & 31, (w >> 16) & 31
            simm = (w & 0xFFFF) - 0x10000 if w & 0x8000 else w & 0xFFFF
            if op in BRANCHES:
                hi = dict(bases)
                continue
            if ra and ra in hi and (op in WIDTH or op in TAKEN):
                address = (hi[ra] + simm) & 0xFFFFFFFF
                if op in WIDTH:
                    out.append((address, WIDTH[op]))
                else:
                    taken.add(address)
            if op == OP_ADDIS and ra == 0:
                if rd not in SMALL_BASES:
                    hi[rd] = (simm << 16) & 0xFFFFFFFF
                continue
            if op not in STORES and rd not in SMALL_BASES:
                hi.pop(rd, None)  # (anything else that writes the register: a load, arithmetic, a move)
    return out, taken


def _pointers(dol: bytes) -> set[int]:
    """The words of the program's data that could be addresses (a pointer to a variable takes its address)."""
    out = set()
    for o, _, s, code in _sections(dol):
        if code:
            continue
        out.update(struct.unpack_from(f">{s // 4}I", dol, o))
    return out


def _parse(text: str) -> list[_Sym]:
    out = []
    for i, line in enumerate(text.splitlines()):
        m = _LINE.match(line)
        if not m or m.group(2) not in DATA or "type:object" not in m.group(4):
            continue
        size = re.search(r"size:0x([0-9A-Fa-f]+)", m.group(4))
        if size:
            out.append(_Sym(i, m.group(1), m.group(2), int(m.group(3), 16), int(size.group(1), 16), m.group(4)))
    return out


def _with_size(rest: str, size: int, string: bool = False) -> str:
    rest = re.sub(r"size:0x[0-9A-Fa-f]+", f"size:0x{size:X}", rest)
    if string and "data:" not in rest:
        rest = rest.rstrip() + " data:string"
    return rest


def _align_of(address: int) -> int:
    return min(address & -address, MAX_ALIGN) if address else MAX_ALIGN


def strings(data: bytes, address: int = 0) -> list[tuple[int, int]] | None:
    """(offset, size with its NUL) of each string a symbol's bytes hold, the zeros after each only padding; None when
    the bytes aren't text. The compiler puts a file's strings one after another, each at the next 4-byte boundary;
    zeros beyond that (a table of `char[16]`, a buffer `char name[48] = "..."`) are the object's own, and the end
    pads only up to the alignment of what comes after it (`address`: the symbol's)."""
    pieces, at = [], 0
    while at < len(data):
        end = data.find(b"\0", at)
        if end < 0 or end == at or end - at < PIECE_MIN or any(b not in _PRINTABLE for b in data[at:end]):
            return None
        pieces.append((at, end + 1 - at))
        at = end + 1
        nxt = at
        while nxt < len(data) and data[nxt] == 0:
            nxt += 1
        if nxt < len(data) and nxt != -(-at // STRING_ALIGN) * STRING_ALIGN:
            return None
        at = nxt
    if not pieces or max(size for _, size in pieces) - 1 < STRING_MIN:
        return None
    last = pieces[-1][0] + pieces[-1][1]
    if len(data) - last >= _align_of(address + len(data)):
        return None
    return pieces


def resize(text: str, dol: bytes, keep=frozenset()) -> tuple[str, list[tuple[str, int, str]]]:
    """symbols.txt with its data symbols sized as the module docstring says, and (name, address, what changed) for
    each symbol changed. keep: names left as they are."""
    syms = _parse(text)
    if not syms:
        return text, []
    read = _reader(dol)
    used, taken = accesses(dol)
    taken |= _pointers(dol)
    syms.sort(key=lambda s: s.address)
    starts = sorted(s.address for s in syms)
    lines = text.splitlines(keepends=True)
    changes: list[str] = []
    by_sym: dict[int, list[tuple[int, int]]] = {}
    bounds = [(s.address, s.address + s.size, k) for k, s in enumerate(syms)]
    keys = [b[0] for b in bounds]

    def owner(address: int) -> int | None:
        k = bisect.bisect_right(keys, address) - 1
        return bounds[k][2] if k >= 0 and address < bounds[k][1] else None

    for address, width in used:
        if (k := owner(address)) is not None:
            by_sym.setdefault(k, []).append((address - syms[k].address, width))
    hit = {k for a in taken if (k := owner(a)) is not None}

    for k, s in enumerate(syms):
        if s.name in keep:
            continue
        nxt = starts[bisect.bisect_right(starts, s.address)] if bisect.bisect_right(starts, s.address) < len(starts) else None
        data = None if s.section in ZEROED else read(s.address, s.size)
        if s.section not in ZEROED and data is None:
            continue
        # strings first: bytes say more than the code does about a run of text
        eol = lines[s.line][len(lines[s.line].rstrip("\r\n")):] or "\n"
        if data is not None and ("data:" not in s.rest or "data:string" in s.rest):
            text_bytes = data
            if b"\0" not in data and nxt is not None and nxt > s.address + s.size and read(s.address + s.size, 1) == b"\0":
                text_bytes = data + b"\0"  # (a string dtk sized without its NUL, the NUL in no symbol's bytes)
            pieces = strings(text_bytes, s.address)
            if pieces:
                new = []
                for n, (off, size) in enumerate(pieces):
                    if n == 0:
                        new.append(f"{s.name} = {s.section}:0x{s.address:08X};{_with_size(s.rest, size, True)}{eol}")
                        continue
                    scope = " scope:local" if "scope:local" in s.rest else ""
                    new.append(f"lbl_{s.address + off:08X} = {s.section}:0x{s.address + off:08X}; "
                               f"// type:object size:0x{size:X}{scope} data:string{eol}")
                if len(new) > 1 or pieces[0][1] != s.size:
                    lines[s.line] = "".join(new)
                    changes.append((s.name, s.address, (f"{len(pieces)} strings" if len(pieces) > 1 else "a string")
                                    + f", 0x{s.size:X} -> " + ", ".join(f"0x{z:X}" for _, z in pieces)))
                continue
        # (a bigger object, in .bss or .data, has fields its code never names: its size is its type's, which the
        # file's C says, not its accesses)
        if s.section not in SMALL or s.size > PADDING_MAX or k in hit or k not in by_sym:
            continue
        seen = by_sym[k]
        if any(off % width for off, width in seen):
            continue
        widest = max(width for _, width in seen)
        reach = max(off + width for off, width in seen)
        size = -(-reach // widest) * widest
        if size >= s.size or (data is not None and any(data[size:])):
            continue
        lines[s.line] = f"{s.name} = {s.section}:0x{s.address:08X};{_with_size(s.rest, size)}{eol}"
        changes.append((s.name, s.address, f"0x{s.size:X} -> 0x{size:X} (the code reads and writes {size} of its bytes)"))
    return "".join(lines), changes
