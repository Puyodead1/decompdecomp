"""Start a PC (Windows) decompilation from scratch: a project made for the user's own copy of a 32-bit x86 program
(.exe), built with the game's Visual C++ and judged by objdiff, worked on like any community project.

There's no community toolkit for this as there is for GameCube (decomp-toolkit) or DS (ds-decomp), so decompdecomp
does the delinking itself:

- Ghidra's analysis finds the functions (and reads the program's imports and exports);
- each function's extent is its code plus what MSVC puts after it (jump tables, byte index tables) and the nop
  padding Visual C++ 6 ends functions with; code Ghidra didn't see in between becomes functions of its own;
- capstone reads every instruction for the addresses it holds: calls and jumps to other functions, and data
  addresses, become relocations (functions by their decorated names, `_func_00401000`, `_func_00401020@8` for
  __stdcall, `@func_00401040@8` for __fastcall; data as `_D_00402034`; imports as `__imp__Name@4`), so each function
  matches whatever names the C uses, under objdiff's usual rules.

The project (tools/configure.py, tools/delink.py) cuts the functions out of the user's copy into COFF objects at
build time, one per source file (src/auto/text_<address>.cpp, about 4 KiB of functions each), and compiles src/ with
MSVC through wibo. A program built without relocations (most games before 2005) has every address fixed, which is
what this reads; there's no relink of the whole .exe yet, so files aren't linked into the game as on GameCube.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import capstone
from capstone import x86

from decompnet.hostenv import NO_WINDOW

from ... import toolchains
from ...forks.project import ForkError, ForkProject

UNIT_BYTES = 0x1000
TEMPLATE = Path(__file__).with_name("project_template")
MSVC_DEFAULT = "6.0"
DIR32, REL32 = 0x06, 0x14
PAD = 0x90  # what Visual C++ 6 pads a function's section with (the linker pads between objects with 0xCC or zeros)
# Visual C++ versions by the build number its tools leave in the program's Rich header, for the C/C++ compiler
RICH_BUILDS = {8168: "6.0", 8447: "6.0", 8799: "6.0", 8966: "6.0", 9044: "6.0", 9782: "6.0", 9466: "7.0", 9955: "7.0",
               3052: "7.1", 3077: "7.1", 4035: "7.1", 6030: "7.1",
               50727: "8.0-sp1"}  # 2005: RTM and SP1 both leave 50727, and the pack has SP1
# Rich header product ids from Visual C++ 2005 on (its C compiler is 0x6D; 7.1 and older use lower ids): a program
# built with them and none of the builds above is newer than the compiler pack (GitHub #12: a 2010 game only said
# "Ghidra found no functions")
NEWER_TOOLS_FIRST_PRODUCT = 0x6D
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class Section:
    name: str
    va: int  # absolute address
    vsize: int
    offset: int  # in the file
    size: int  # bytes in the file
    code: bool


@dataclass
class PE:
    data: bytes
    image_base: int
    image_size: int
    entry: int
    timestamp: int
    sections: list[Section]
    imports: dict[int, str] = field(default_factory=dict)  # import address table slot -> "Sleep"

    def section_at(self, addr: int) -> Section | None:
        return next((s for s in self.sections if s.va <= addr < s.va + max(s.vsize, s.size)), None)

    def offset(self, addr: int) -> int | None:
        s = self.section_at(addr)
        return None if s is None or addr - s.va >= s.size else s.offset + addr - s.va

    def read(self, addr: int, n: int) -> bytes:
        off = self.offset(addr)
        return b"" if off is None else self.data[off:off + n]

    def contains(self, addr: int) -> bool:
        return self.image_base <= addr < self.image_base + self.image_size


# a Windows program: the DOS header ("MZ") says where the PE header is; after it the COFF header, then the optional
# header (PE32's: a 32-bit program), then the section table
DOS_HEADER_BYTES, PE_OFFSET_AT = 0x40, 0x3C
PE_HEADER_BYTES = 0x18  # "PE\0\0" and the COFF header
MACHINE_AT, SECTION_COUNT_AT, TIMESTAMP_AT = 4, 6, 8  # in the COFF header, from "PE\0\0"
OPTIONAL_HEADER_AT = PE_HEADER_BYTES
MACHINE_I386, PE32_MAGIC = 0x14C, 0x10B
ENTRY_AT, IMAGE_BASE_AT, IMAGE_SIZE_AT, IMPORTS_AT = 16, 28, 56, 104  # in the optional header
SECTION_HEADER_BYTES, SECTION_FLAGS_AT = 40, 36
CODE_AND_EXECUTABLE = 0x20000020  # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
PE_PROBE_BYTES, PE_HEADERS_BYTES = 0x1000, 0x200  # is_pe reads this much of a file, or the PE header and this much more
# the import directory: 20-byte descriptors, each with a table of 4-byte entries (a name's address, or an ordinal)
IMPORT_DESCRIPTOR_BYTES = 20
MAX_IMPORT_DLLS, MAX_IMPORTS_PER_DLL = 4096, 65536  # a broken table stops here
BY_ORDINAL, ORDINAL_BITS = 0x80000000, 0xFFFF
DLL_NAME_BYTES, IMPORT_NAME_BYTES = 64, 256
IMPORT_HINT_BYTES = 2  # an import's name follows its 2-byte hint
# the Rich header: the tools that built the program, XORed with a key, between the DOS stub and "Rich"
RICH_START = 0x80
RICH_ENTRIES_AT, RICH_ENTRY_BYTES = 16, 8  # after "DanS" and its padding: (product << 16 | build, count)
# read_data
READ_DEFAULT_BYTES, READ_MIN_BYTES, READ_MAX_BYTES = 64, 4, 512
HEX_ROW_BYTES = 16
POINTERS_SHOWN, FLOATS_SHOWN = 24, 8
PLAUSIBLE_FLOAT = (1e-6, 1e7)  # magnitudes a float in game data has; other words aren't floats
MIN_STRING_CHARS = 3
PRINTABLE = range(32, 127)
TOOL_SECONDS = 3600  # Ghidra on a big game, the project's build
ERROR_TAIL = 1500  # how much of a tool's output an error shows


def _pe_header(head: bytes) -> int | None:
    if len(head) < DOS_HEADER_BYTES or head[:2] != b"MZ":
        return None
    at = struct.unpack_from("<I", head, PE_OFFSET_AT)[0]
    if at + PE_HEADER_BYTES > len(head) or head[at:at + 4] != b"PE\0\0":
        return None
    return at


def is_pe(head: bytes) -> bool:
    """A 32-bit x86 Windows program (the first 4 KiB of the file are enough)."""
    at = _pe_header(head)
    return at is not None and struct.unpack_from("<H", head, at + MACHINE_AT)[0] == MACHINE_I386 and \
        struct.unpack_from("<H", head, at + OPTIONAL_HEADER_AT)[0] == PE32_MAGIC


def read_pe(data: bytes) -> PE:
    at = _pe_header(data)
    if at is None or not is_pe(data[:max(PE_PROBE_BYTES, at + PE_HEADERS_BYTES)]):
        raise ForkError("this isn't a 32-bit Windows program (.exe): PC games start from their x86 .exe")
    count, _, _, _, opt_size = struct.unpack_from("<HIIIH", data, at + SECTION_COUNT_AT)
    timestamp = struct.unpack_from("<I", data, at + TIMESTAMP_AT)[0]
    opt = at + OPTIONAL_HEADER_AT
    entry_rva, base, image_size = (struct.unpack_from("<I", data, opt + field)[0]
                                   for field in (ENTRY_AT, IMAGE_BASE_AT, IMAGE_SIZE_AT))
    sections = []
    for number in range(count):
        header = opt + opt_size + SECTION_HEADER_BYTES * number
        name, vsize, va, size, offset = struct.unpack_from("<8sIIII", data, header)
        flags = struct.unpack_from("<I", data, header + SECTION_FLAGS_AT)[0]
        sections.append(Section(name.rstrip(b"\0").decode("latin-1"), base + va, vsize, offset,
                                min(size, max(0, len(data) - offset)), bool(flags & CODE_AND_EXECUTABLE)))
    pe = PE(data, base, image_size, base + entry_rva, timestamp, sections)
    pe.imports = _imports(pe, opt)
    return pe


def _imports(pe: PE, opt: int) -> dict[int, str]:
    """Import address table slot -> the function's name (or DLL ordinal), from the import directory."""
    rva = struct.unpack_from("<I", pe.data, opt + IMPORTS_AT)[0]
    out: dict[int, str] = {}
    if not rva:
        return out
    at = pe.image_base + rva
    for _ in range(MAX_IMPORT_DLLS):
        desc = pe.read(at, IMPORT_DESCRIPTOR_BYTES)
        if len(desc) < IMPORT_DESCRIPTOR_BYTES or desc == bytes(IMPORT_DESCRIPTOR_BYTES):
            break
        lookup, _, _, name_rva, iat = struct.unpack("<IIIII", desc)
        dll = pe.read(pe.image_base + name_rva, DLL_NAME_BYTES).split(b"\0", 1)[0].decode("latin-1")
        lookup = lookup or iat
        for k in range(MAX_IMPORTS_PER_DLL):
            entry = pe.read(pe.image_base + lookup + 4 * k, 4)
            if len(entry) < 4 or not struct.unpack("<I", entry)[0]:
                break
            value = struct.unpack("<I", entry)[0]
            if value & BY_ORDINAL:
                name = f"{Path(dll).stem}_{value & ORDINAL_BITS}"
            else:
                address = pe.image_base + value + IMPORT_HINT_BYTES
                name = pe.read(address, IMPORT_NAME_BYTES).split(b"\0", 1)[0].decode("latin-1")
            out[pe.image_base + iat + 4 * k] = name if _IDENT.fullmatch(name) else f"{Path(dll).stem}_{k}"
        at += IMPORT_DESCRIPTOR_BYTES
    return out


def rich_builds(data: bytes) -> list[tuple[int, int, int]]:
    """(product id, build number, count) of every tool the Rich header says built a part of the program."""
    at = _pe_header(data)
    end = data.find(b"Rich", RICH_START, at)
    if end < 0:
        return []
    key = data[end + 4:end + 8]
    plain = bytes(byte ^ key[i % 4] for i, byte in enumerate(data[RICH_START:end]))
    if not plain.startswith(b"DanS"):
        return []
    out = []
    for entry in range(RICH_ENTRIES_AT, len(plain) - RICH_ENTRY_BYTES + 1, RICH_ENTRY_BYTES):
        comp, count = struct.unpack_from("<II", plain, entry)
        out.append((comp >> 16, comp & 0xFFFF, count))
    return out


def guess_compiler(data: bytes) -> tuple[str, str]:
    """(Visual C++ version, why): what the Rich header's build numbers say, or the default."""
    seen: dict[str, int] = {}
    for _, build, count in rich_builds(data):
        if build in RICH_BUILDS:
            seen[RICH_BUILDS[build]] = seen.get(RICH_BUILDS[build], 0) + count
    if not seen:
        return MSVC_DEFAULT, "the program doesn't say which Visual C++ built it; 6.0 built most games of its time"
    version = max(seen, key=seen.get)
    if version == "8.0-sp1":  # the header's build number is the same for both
        return version, "the program's Rich header names Visual C++ 2005's tools (8.0 or 8.0 SP1: it can't tell which)"
    return version, f"the program's Rich header names Visual C++ {version}'s tools"


def version_key(version: str) -> tuple[int, ...]:
    """A Visual C++ version ("7.1") as numbers to compare."""
    return tuple(int(n) for n in re.findall(r"\d+", version))


def newer_tools(builds: list[tuple[int, int, int]]) -> bool:
    """Whether the Rich header's tools are newer than Visual C++ 2005: none of the compiler pack's builds, and newer
    ids."""
    known = any(build in RICH_BUILDS for _, build, _ in builds)
    return not known and any(product >= NEWER_TOOLS_FIRST_PRODUCT for product, _, _ in builds)


def game_info(path: Path) -> dict:
    data = path.read_bytes()
    pe = read_pe(data)
    stem = re.sub(r"[^a-z0-9]+", "", path.stem.lower()) or "game"
    version, why = guess_compiler(data)
    return {"platform": "pc", "id": stem, "title": path.stem, "region": "PC", "sha1": hashlib.sha1(data).hexdigest(),
            "timestamp": pe.timestamp, "compiler": version, "compiler_why": why}


# ---------------------------------------------------------------------------------------------------- analysis


@dataclass
class Function:
    addr: int
    size: int
    name: str  # the symbol, decorated as MSVC decorates the C name
    relocs: list[tuple[int, int, str | None, int]] = field(default_factory=list)  # (offset, type, symbol, addend)


MAX_PURGE = 1024  # bytes of arguments a function pops (ret N): more is Ghidra's "don't know" (0x7FFFFFFF)


def decorate(name: str, convention: str, purge: int, params: int) -> str:
    """The symbol MSVC makes for a C function: _f (__cdecl), _f@8 (__stdcall), @f@8 (__fastcall). __thiscall
    functions (C++ methods, `this` in ecx) are written in C as __fastcall with an unused second argument (edx).
    A purge Ghidra couldn't work out (0x7FFFFFFF: a PC game had 91 such names) counts as none."""
    if not 0 <= purge <= MAX_PURGE:
        purge = 0
    if convention == "__thiscall":
        return f"@{name}@{purge + 8}"
    if convention == "__fastcall":
        return f"@{name}@{purge + 4 * min(max(params, 1), 2)}"
    if purge > 0:
        return f"_{name}@{purge}"
    return f"_{name}"


def _disasm(md, code: bytes, addr: int):
    """Instructions, stopping at bytes that don't decode."""
    return md.disasm(code, addr)


def _tables(md, pe: PE, start: int, code_end: int, limit: int) -> tuple[int, int, list[int]]:
    """(where the function's code ends, where its data ends, the jump table entries' offsets): MSVC puts a switch's
    jump table (and its byte index table) right after the function's code."""
    tables, bytes_at = [], []
    for ins in _disasm(md, pe.read(start, code_end - start), start):
        for op in ins.operands:
            if op.type != x86.X86_OP_MEM or ins.disp_size != 4:
                continue
            disp = op.mem.disp & 0xFFFFFFFF
            if not start < disp < limit or disp <= ins.address:
                continue
            if op.mem.scale == 4 and ins.id == x86.X86_INS_JMP:
                tables.append(disp)
            elif op.size == 1:
                bytes_at.append(disp)
    code_end = min([code_end, *tables, *bytes_at])
    data_end, entries = code_end, []
    for t in sorted(set(tables)):
        at = t
        while at + 4 <= limit:
            value = struct.unpack("<I", pe.read(at, 4).ljust(4, b"\0"))[0]
            if not start <= value < code_end:
                break
            entries.append(at - start)
            at += 4
        data_end = max(data_end, at)
    for b in sorted(set(bytes_at)):  # a byte table runs to the next function, less its padding
        tail = pe.read(b, limit - b).rstrip(b"\x90\xcc")
        data_end = max(data_end, b + len(tail))
    return code_end, data_end, entries


def analyse(pe: PE, found: list[dict]) -> list[Function]:
    """Every function's extent, name and relocations, from Ghidra's function list."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    rows: dict[int, dict] = {}
    for r in found:
        s = pe.section_at(r["entry"])
        if r.get("thunk") or s is None or not s.code or pe.offset(r["entry"]) is None:
            continue
        rows[r["entry"]] = r
    starts = sorted(rows)
    i = 0
    extents: dict[int, tuple[int, int, list[int]]] = {}  # start -> (code end, end, jump table entries)
    while i < len(starts):
        start = starts[i]
        sec = pe.section_at(start)
        limit = min(starts[i + 1] if i + 1 < len(starts) else sec.va + sec.size, sec.va + sec.size)
        code_end = max(start + 1, min(rows[start].get("end", limit), limit))
        if (split := _split_point(md, pe, start, code_end)):  # two functions Ghidra took for one
            code_end = split
        code_end, end, entries = _tables(md, pe, start, code_end, limit)
        gap = pe.read(end, limit - end)
        rest = gap.lstrip(b"\x90").lstrip(b"\xcc\x00")
        if rest and not rest.strip(b"\x90\xcc\x00") == b"":
            # code nobody calls directly (callbacks, vtables) that Ghidra didn't make a function: one of its own
            missed = limit - len(rest)
            rough = missed + len(rest.rstrip(b"\x90\xcc\x00"))
            rows[missed] = {"entry": missed, "end": _whole(md, pe, missed, rough, limit), "name": "",
                            "source": "DEFAULT", "purge": 0, "convention": "__cdecl"}
            starts.insert(i + 1, missed)
            limit = missed
            gap = pe.read(end, limit - end)
        if gap and gap.strip(b"\x90") == b"":
            end = limit  # Visual C++ 6's own padding: part of the compiled function's section too
        extents[start] = (code_end, end, entries)
        i += 1

    names = {}
    for start, r in rows.items():
        base = r.get("name", "")
        named = r.get("source") in ("IMPORTED", "USER_DEFINED") and _IDENT.fullmatch(base) and base != "entry"
        names[start] = decorate(base if named else f"func_{start:08X}", r.get("convention", ""),
                                int(r.get("purge") or 0), int(r.get("params") or 0))

    out = []
    for start in starts:
        code_end, end, entries = extents[start]
        fn = Function(start, end - start, names[start])
        fn.relocs = _relocs(md, pe, start, code_end, end, entries, names)
        out.append(fn)
    return out


def _split_point(md, pe: PE, start: int, end: int) -> int | None:
    """Where a function Ghidra made of two really ends, or None: after a ret or jmp that int3 padding follows up to a
    16-byte boundary with code after it, below `end`. Visual C++ pads with int3 between functions only, and starts
    each at a 16-byte boundary; Ghidra counted the next one in when nothing else called it (a PC game had 1,228 such
    pairs, none ever matched: `xor eax,eax; ret` then padding then another, as one 19-byte function). A function with
    a switch (an indirect jmp) is left as it is: its jump table may follow padding."""
    code = pe.read(start, end - start)
    if not any(code[a - start - 1] == 0xCC and code[a - start] != 0xCC  # (padding, then code at a boundary: rare)
               for a in range((start | 15) + 1, end, 16)):
        return None
    for ins in _disasm(md, code, start):
        if ins.mnemonic == "jmp" and ins.operands and ins.operands[0].type != x86.X86_OP_IMM:
            return None
        if ins.mnemonic in ("ret", "jmp"):
            after = k = ins.address + ins.size
            while k < end and pe.read(k, 1) == b"\xcc":
                k += 1
            if after < k < end and k % 16 == 0:
                return after
    return None


def _whole(md, pe: PE, start: int, rough: int, limit: int) -> int:
    """Where code from `start` really ends: `rough` is where its bytes stop being padding (0x90, 0xCC, zeros), which
    cut an instruction ending in zeros short (`jmp` e9 2b 21 00 00 came out 3 bytes long, `ret 8` c2 08 00 two, and
    objdiff could never match them); the end of the last whole instruction that starts before it, within `limit`."""
    end = rough
    for ins in _disasm(md, pe.read(start, limit - start), start):
        if ins.address >= rough:
            break
        end = ins.address + ins.size
    return min(max(end, rough), limit)


def _relocs(md, pe: PE, start: int, code_end: int, end: int, entries: list[int],
            names: dict[int, str]) -> list[tuple]:
    """A function's relocations: what its instructions call, jump to and point at outside it (by the project's
    names: functions, imports, data as _D_<address>), and its jump tables' entries."""
    def symbol(addr: int) -> tuple[str | None, int]:
        if start <= addr < end:
            return None, addr - start
        if addr in names:
            return names[addr], 0
        if addr in pe.imports:
            return f"__imp__{pe.imports[addr]}", 0
        return f"_D_{addr:08X}", 0

    out = []
    for ins in _disasm(md, pe.read(start, code_end - start), start):
        at = ins.address - start
        if ins.size >= 5 and (x86.X86_GRP_JUMP in ins.groups or x86.X86_GRP_CALL in ins.groups) \
                and ins.operands and ins.operands[0].type == x86.X86_OP_IMM:  # rel32, not a short jump
            target = ins.operands[0].imm & 0xFFFFFFFF
            if not start <= target < end:  # calls, and jumps to other functions (tail calls)
                name, _ = symbol(target)
                out.append((at + ins.size - 4, REL32, name, 0))
            continue
        for op in ins.operands:
            if op.type == x86.X86_OP_MEM and ins.disp_size == 4 and pe.contains(op.mem.disp & 0xFFFFFFFF):
                name, addend = symbol(op.mem.disp & 0xFFFFFFFF)
                out.append((at + ins.disp_offset, DIR32, name, addend))
            elif op.type == x86.X86_OP_IMM and ins.imm_size == 4 and pe.contains(op.imm & 0xFFFFFFFF):
                name, addend = symbol(op.imm & 0xFFFFFFFF)
                out.append((at + ins.imm_offset, DIR32, name, addend))
    for off in entries:
        out.append((off, DIR32, None, struct.unpack("<I", pe.read(start + off, 4))[0] - start))
    return sorted(out)


def units(functions: list[Function]) -> dict[str, list[Function]]:
    """Source files: runs of neighbouring functions of about UNIT_BYTES each."""
    out: dict[str, list[Function]] = {}
    cur: list[Function] = []
    for fn in functions:
        if cur and (fn.addr + fn.size - cur[0].addr > UNIT_BYTES or fn.addr != cur[-1].addr + cur[-1].size):
            out[f"text_{cur[0].addr:08X}"] = cur
            cur = []
        cur.append(fn)
    if cur:
        out[f"text_{cur[0].addr:08X}"] = cur
    return out


# ---------------------------------------------------------------------------------------------------- the project


def tool_args() -> list[str]:
    """configure.py arguments pointing at decompdecomp's pinned tools."""
    if toolchains.installed("msvc") is None:
        raise ForkError("PC games are built with Microsoft Visual C++, which is proprietary: install it in Setup "
                        "(Visual C++) if you accept that, then try again")
    args = ["--msvc", str(toolchains.path("msvc"))]
    if toolchains.get("wibo").supported and sys.platform != "win32":
        toolchains.ensure("wibo", log=lambda *_: None)
        args += ["--wibo", str(toolchains.binary("wibo"))]
    return args


TYPES_H = """/* Basic types for this decompilation (32-bit x86, Visual C++, written in C++). Agents add structs, classes and
 * prototypes here or in new headers next to it.
 *
 * The game's functions are func_<address> and its data D_<address>: write them as free functions or as a class's
 * methods (`void Town::func_0041B470(int id)`), with the original's calling convention (methods: this in ecx; free
 * functions: __cdecl, __stdcall or __fastcall, as the code shows). The build gives what they compile to the
 * original's symbol names, so any C++ name mangling pairs with the game's code. Data: `extern int D_00402034;`. */
#ifndef COMMON_H
#define COMMON_H

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef __int64 s64;
typedef unsigned __int64 u64;
typedef float f32;
typedef double f64;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#ifndef NULL
#define NULL 0
#endif

#endif
"""


_PROGRAMS: dict[tuple[str, int], object] = {}  # (path, mtime) -> its parsed program, for data_bytes


def _program(root: Path, manifest: dict):
    """The user's copy, parsed once per change of the file (a diff reads several constants from it)."""
    path = root / manifest["game"]["path"]
    key = (str(path), path.stat().st_mtime_ns)
    if key not in _PROGRAMS:
        _PROGRAMS.clear()
        _PROGRAMS[key] = read_pe(path.read_bytes())
    return _PROGRAMS[key]


def data_bytes(root: Path, manifest: dict, addr: int, length: int) -> bytes | None:
    """The bytes at an address of the user's copy, or None (not in it, uninitialized, no copy)."""
    try:
        pe = _program(root, manifest)
    except Exception:  # no copy, or one that doesn't parse: the diff goes without values
        return None
    if pe.section_at(addr) is None:
        return None
    data = pe.read(addr, length)
    return data if data and len(data) == length else None


def read_data(root: Path, manifest: dict, name: str, length: int = READ_DEFAULT_BYTES) -> str:
    """What read_data shows on a PC project: the bytes at a D_<address> (or any address) in the user's copy, the
    addresses its words point to, and a string or floats when it reads as one."""
    m = re.fullmatch(r"_?D_([0-9A-Fa-f]{8})|(?:0x)?([0-9A-Fa-f]{6,8})", name)
    addr = int(m.group(1) or m.group(2), 16) if m else address_of(root, str(manifest.get("version")), name)
    if addr is None:
        raise ForkError(f"`{name}` isn't data by address or by a real name: PC data is named D_<address> "
                        "(D_00402034) until it's renamed")
    pe = read_pe((root / manifest["game"]["path"]).read_bytes())
    sec = pe.section_at(addr)
    if sec is None:
        raise ForkError(f"0x{addr:08X} isn't in the game's program (it spans 0x{pe.image_base:08X}-"
                        f"0x{pe.image_base + pe.image_size:08X})")
    n = max(READ_MIN_BYTES, min(int(length or READ_DEFAULT_BYTES), READ_MAX_BYTES))
    data = pe.read(addr, n)
    out = [f"D_{addr:08X} ({sec.name}+0x{addr - sec.va:X}, {n} bytes)"]
    if not data:
        return out[0] + f": uninitialized data ({sec.name}), zeros at start-up."
    for i in range(0, len(data), HEX_ROW_BYTES):
        chunk = data[i:i + HEX_ROW_BYTES]
        out.append(f"  +0x{i:03X}: {chunk.hex(' '):<47}  {''.join(chr(c) if c in PRINTABLE else '.' for c in chunk)}")
    words = [w for (w,) in struct.iter_unpack("<I", data[:len(data) // 4 * 4])]
    ptrs = [(4 * i, w) for i, w in enumerate(words) if pe.contains(w)]
    if ptrs:
        out.append("pointers in it: " + ", ".join(f"+0x{at:X} -> 0x{w:08X}" for at, w in ptrs[:POINTERS_SHOWN]))
    floats = [struct.unpack("<f", struct.pack("<I", w))[0] for w in words[:FLOATS_SHOWN]]
    smallest, biggest = PLAUSIBLE_FLOAT
    if words and any(smallest < abs(x) < biggest for x in floats):
        out.append("as f32: " + ", ".join(f"{x:g}" for x in floats))
    text = data.split(b"\0", 1)[0]
    if len(text) >= MIN_STRING_CHARS and all(c in PRINTABLE or c in b"\t\n" for c in text) and not (ptrs and ptrs[0][0] == 0):
        out.append(f"as a string: {json.dumps(text.decode('latin-1'))}")
    return "\n".join(out)


def _run(cmd: list[str], root: Path, what: str, log) -> None:
    ok, tail = ForkProject(root).run(cmd, log=log, timeout=TOOL_SECONDS)
    if not ok:
        raise ForkError(f"{what} failed:\n{tail[-ERROR_TAIL:]}")


def settings(configure: str, compiler: str) -> str:
    """tools/configure.py's settings for the game's Visual C++."""
    text = configure.replace(f'MSVC_VERSION = "{MSVC_DEFAULT}"', f'MSVC_VERSION = "{compiler}"')
    if version_key(compiler) >= (8, 0):  # 8.0 deprecated /GX (warning D9035) for what it meant, /EHsc
        text = text.replace('"/GX"]  # /GX: C++ exceptions', '"/EHsc"]  # /EHsc: C++ exceptions')
    return text


def create(root: Path, game: Path, *, compiler: str | None = None, log=print) -> dict:
    """Make the project in `root` (which must not exist yet) and build it once. Returns facts about the game."""
    from ...forks import ghidra

    info = game_info(game)
    version = info["id"]
    compiler = (compiler or f"MSVC/{info['compiler']}").removeprefix("MSVC/")
    args = tool_args()
    if not (toolchains.path("msvc") / compiler).is_dir():  # a pack installed before this version was pinned
        raise ForkError(f"Visual C++ {compiler} isn't in the installed compiler pack: update Visual C++ in Compilers & "
                        "tools, then try again")
    if not ghidra.available():
        if ghidra.java_home() is not None and toolchains.installed("jdk") is None:
            log("installing a Java development kit for Ghidra (200 MB, once): this computer has none of its own")
            toolchains.ensure("jdk", log=log)
        if toolchains.installed("ghidra") is None:
            log("installing Ghidra (540 MB, once): it finds the functions in PC programs")
            toolchains.ensure("ghidra", log=log)
    data = game.read_bytes()
    pe = read_pe(data)
    newer = newer_tools(rich_builds(data))
    if newer:
        log("its Rich header names a Visual C++ newer than 2005: decompdecomp builds with 6.0 to 8.0 SP1 for now, so expect "
            "little to match")
    log(f"analysing {game.name} with Ghidra (finds every function; a big game takes a few minutes)")
    found = ghidra.functions(game)
    if not found:
        why = ("it was built with a Visual C++ newer than 2005 (its Rich header says so), and decompdecomp supports "
               "6.0 to 8.0 SP1 for now" if newer else "a program that is packed or protected (some games' DRM wraps their code) "
               "shows none until it's unpacked")
        raise ForkError(f"Ghidra found no functions in this program: {why}.")
    functions = analyse(pe, found)
    groups = units(functions)
    log(f"{len(functions)} functions; {info['compiler_why']}: Visual C++ {compiler}")

    shutil.copytree(TEMPLATE, root)
    (root / "orig").mkdir()
    exe = root / "orig" / f"{version}.exe"
    try:
        exe.hardlink_to(game)
    except OSError:
        shutil.copyfile(game, exe)
    (root / "include").mkdir()
    (root / "include" / "common.h").write_text(TYPES_H, encoding="utf-8")
    cfg = root / "tools" / "configure.py"
    cfg.write_text(settings(cfg.read_text(encoding="utf-8"), compiler), encoding="utf-8")
    conf = root / "config" / version
    conf.mkdir(parents=True)
    (conf / "functions.json").write_text(json.dumps({
        "exe": f"orig/{version}.exe", "sha1": info["sha1"], "image_base": pe.image_base,
        "units": {u: [{"name": f.name, "addr": f.addr, "offset": pe.offset(f.addr), "size": f.size,
                       "relocs": [list(r) for r in f.relocs]} for f in fns] for u, fns in groups.items()},
    }, indent=1), encoding="utf-8")
    for u, fns in groups.items():
        src = root / "src" / "auto" / f"{u}.cpp"  # C++, as PC games of the time were written (C compiles too)
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text(f"/* {len(fns)} function{'s' if len(fns) != 1 else ''} from 0x{fns[0].addr:08X} to "
                       f"0x{fns[-1].addr + fns[-1].size:08X}, found by Ghidra. */\n#include \"common.h\"\n",
                       encoding="utf-8")
    log(f"{len(groups)} source files for agents to write into")

    setup = [[sys.executable, "tools/configure.py", version, *args], ["ninja", "prepare"]]
    for cmd in setup:
        _run(cmd, root, "the first build", log)
    if not (root / "objdiff.json").exists():
        raise ForkError("the first build finished without writing objdiff.json")

    (root / ".decomp.wtf.json").write_text(json.dumps({
        "created": "from scratch", "platform": "pc", "version": version, "compiler": f"MSVC/{compiler}",
        "game": {"what": "your copy of the game's program (.exe)", "path": f"orig/{version}.exe", "sha1": info["sha1"]},
        "setup": [["python", "tools/configure.py", version, *args], ["ninja", "prepare"]],
    }, indent=2), encoding="utf-8")
    (root / ".gitignore").write_text("# made from your copy of the game, or by the build\norig/\nbuild/\nbuild.ninja\n"
                                     ".ninja_*\nobjdiff.json\n__pycache__/\n.decomp-wtf/\n", encoding="utf-8")
    (root / "README.md").write_text(f"""# {info['title']} decompilation

Started from scratch with [decompdecomp](https://github.com/n-delic/decompdecomp): the game's functions, found by Ghidra, are cut out of your
copy of its program and compared with what `src/` compiles to, function by function, with objdiff.

1. Put your own copy of the game's program here as `orig/{version}.exe` (never commit it).
2. `python tools/configure.py {version} --msvc <Visual C++ folder> [--wibo <wibo>]`, then `ninja`.
3. Decompiled code goes in `src/`; `objdiff.json` shows each function's progress in [objdiff](https://github.com/encounter/objdiff).

Compiler: Visual C++ {compiler} (change `MSVC_VERSION` and `CL_FLAGS` in tools/configure.py if the game was built
with another version or other flags). `config/{version}/functions.json` holds what the analysis found: every
function's address, size, symbol and relocations.
""", encoding="utf-8")
    if shutil.which("git"):
        for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "-c", "user.name=decompdecomp", "-c", "user.email=noreply@decompdecomp.invalid", "commit", "-q", "-m",
                     f"Start the {info['title']} decompilation (decompdecomp, Ghidra)"]):
            subprocess.run(cmd, cwd=root, capture_output=True, creationflags=NO_WINDOW)
    return {"platform": "pc", "id": version, "title": info["title"], "compiler": f"MSVC/{compiler}",
            "sources": len(groups), "sha1": info["sha1"]}


# ---------------------------------------------------------------------------------------------------- flags, file by file
# Games built their parts with different flags (the engine with /O2, a library with /O1, middleware without the frame
# pointer omitted): a file whose original was built otherwise never matches with the project's CL_FLAGS. Flags for
# one file go in config/<version>/flags.json, after CL_FLAGS on its command line (Visual C++ takes the last of a kind).


def _settings(fp) -> tuple[str, list[str], str] | None:
    """(MSVC_VERSION, CL_FLAGS, the text) of the project's tools/configure.py; None when it isn't ours."""
    try:
        text = (Path(fp.root) / "tools" / "configure.py").read_text(encoding="utf-8")
        version = re.search(r'^MSVC_VERSION = "([^"]+)"', text, re.M)
        flags = re.search(r"^CL_FLAGS = (\[[^\]]*\])", text, re.M)
        return (version.group(1), list(ast.literal_eval(flags.group(1))), text) if version and flags else None
    except (OSError, ValueError, SyntaxError):
        return None


def _flags_file(fp) -> Path:
    return Path(fp.root) / "config" / str((fp.manifest or {}).get("version")) / "flags.json"


def _file_extras(fp) -> dict[str, list[str]]:
    try:
        data = json.loads(_flags_file(fp).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def file_flags(fp, source: str) -> tuple[str, list[str]] | None:
    """("MSVC/<version>", the flags `source` builds with: CL_FLAGS and its own)."""
    settings = _settings(fp)
    if settings is None:
        return None
    version, flags, _ = settings
    return f"MSVC/{version}", [*flags, *_file_extras(fp).get(Path(source).as_posix(), [])]


def build_file_with(fp, unit, text: str, flags: list[str], log=print) -> tuple[Path | None, str]:
    """`text` built as `unit`'s source with `flags`, by the project's own command for its files (build.ninja's cl
    rule), into build/flagsearch/: the project's source and objects stay as they are."""
    try:
        ninja = re.sub(r"\$\n\s+", "", (Path(fp.root) / "build.ninja").read_text(encoding="utf-8"))
    except OSError:
        return None, "build.ninja is missing: build the project once first"
    rule = re.search(r"^rule cl\n  command = (.*)$", ninja, re.M)
    if not rule or "$cflags" not in rule.group(1):
        return None, "this project's build.ninja has no cl rule decompdecomp knows"
    work = Path(fp.root) / "build" / "flagsearch"
    work.mkdir(parents=True, exist_ok=True)
    src = work / (unit.name + Path(unit.source or "x.cpp").suffix)
    out = src.with_suffix(".obj")
    src.write_text(text, encoding="utf-8")
    out.unlink(missing_ok=True)
    rel = lambda p: p.relative_to(fp.root).as_posix()  # noqa: E731
    cmd = (rule.group(1).replace("$cflags", shlex.join(flags)).replace("$out", shlex.quote(rel(out)))
           .replace("$in", shlex.quote(rel(src))))
    ok, output = ForkProject(Path(fp.root)).run(["/bin/sh", "-c", cmd], log=lambda *_: None, timeout=300)
    return (out if ok and out.exists() else None), output


def set_file_flags(fp, source: str, flags: list[str]) -> str:
    """Build `source` with `flags` (all of them, as file_flags gives them) from now on: what isn't in CL_FLAGS goes
    in flags.json. Returns flags.json's path in the project."""
    settings = _settings(fp)
    if settings is None:
        raise ForkError("this project's tools/configure.py isn't one decompdecomp made: change its flags there")
    _, base, text = settings
    if "flags.json" not in text:
        raise ForkError("this project's tools/configure.py is older than flags file by file: start the project again "
                        "from the game, or add the file's flags to CL_FLAGS by hand")
    data = _file_extras(fp)
    extra = [f for f in flags if f not in base]
    key = Path(source).as_posix()
    if extra:
        data[key] = extra
    else:
        data.pop(key, None)
    path = _flags_file(fp)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path.relative_to(fp.root).as_posix()


# The template's tools as projects were made with them, by SHA-1 (line endings as LF; configure.py with the template's
# compiler settings, as settings() changes them): a project's copy that's one of these, untouched, gets the template's
# own, and the template's tools it lacks; one changed by hand is left alone.
OLD_TOOLS = {
    "tools/delink.py": {
        # gave a function called from its own file a second, undefined symbol: objdiff never matched it, and every
        # agent's match of it was reopened by the next measurement of its file
        "a1c22859444bd4a8561b86dc458a52f6e3932910",
        "7257482c33378a366314cdddb230b371cbd2b888",  # (no real names: names.json)
    },
    "tools/names.py": {"a45a37d27351b4ba6b8b85418bd5cbbd012921f5"},  # (pairs symbols by address only)
    "tools/configure.py": {  # (the original's objects weren't cut again for names.json)
        "e46755ca61186348a3f788220f670216fc7e7b65", "8c77712f7c23fc00d48dad6c71da63322d1868e8",
        "05048e5987c3a4a60e474b8dcf48111692a2b5d9", "8dc9b34a22cbefd4ce49ccf2c36b2328daea0ca3",
        "c6c63b6d15639d9b32be40bb43624bd7b6b5c314", "8ffd5d102f39e8daaa3dbbf76b41dce3015bf008",
        "9f5b229043a31299373a810c0a2ebe16829235cc", "8f712511ba1d775a7f9835cf30eeedb882fb4425",
        "ca3c8e6b677ddea5a642cd023f872b2c2b555a54", "644ccf643b5b87f25d533098ec48e714648cc8e8",
    },
}
_MSVC_SETTING = re.compile(r'^MSVC_VERSION = "([^"]*)"', re.M)


def _as_template(rel: str, text: str) -> str:
    """A project's tool as the template has it: configure.py without its compiler settings (settings())."""
    if rel != "tools/configure.py":
        return text
    text = _MSVC_SETTING.sub(f'MSVC_VERSION = "{MSVC_DEFAULT}"', text)
    return text.replace('"/EHsc"]  # /EHsc: C++ exceptions', '"/GX"]  # /GX: C++ exceptions')


def refresh_tools(root: Path) -> list[str]:
    """The project's tools that are an older template's, untouched, replaced by the template's (configure.py keeps
    its compiler); and, when there were any, the template's tools it didn't have. Returns what changed."""
    done = []
    for rel, old in OLD_TOOLS.items():
        path = root / rel
        try:
            have = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        except (OSError, UnicodeDecodeError):
            continue
        if hashlib.sha1(_as_template(rel, have).encode()).hexdigest() not in old:
            continue
        new = (TEMPLATE / rel).read_text(encoding="utf-8")
        if rel == "tools/configure.py" and (m := _MSVC_SETTING.search(have)):
            new = settings(new, m.group(1))
        was = path.stat()
        path.write_text(new, encoding="utf-8")
        if rel == "tools/names.py":  # every compile depends on it, and what's built has the names it gives already
            os.utime(path, ns=(was.st_atime_ns, was.st_mtime_ns))  # (on a big game, minutes of every core)
        done.append(rel)
    if done:
        for tool in sorted((TEMPLATE / "tools").glob("*.py")):
            if not (root / "tools" / tool.name).exists():
                shutil.copy(tool, root / "tools" / tool.name)
                done.append(f"tools/{tool.name}")
    return done


# A symbol's C name: _f, _f@8 (__stdcall), @f@8 (__fastcall) -> f (as tools/names.py reads them)
_C_SYMBOL = re.compile(r"[_@]?([A-Za-z_]\w*?)(@\d+)?")
_ADDRESS_NAME = re.compile(r"(?:func|D)_[0-9A-Fa-f]{8}")


def c_name(symbol: str) -> str:
    m = _C_SYMBOL.fullmatch(symbol)
    return m.group(1) if m else symbol


def real_names(root: Path, version: str) -> dict[str, str]:
    """config/<version>/names.json: the game's symbols given a real name, by their name by address (func_0041B470,
    D_0066DDA4 -> Town_Update). tools/names.py and tools/delink.py read it."""
    try:
        names = json.loads((root / "config" / version / "names.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return names if isinstance(names, dict) else {}


def rename(root: Path, version: str, old: str, new: str) -> dict[Path, str]:
    """rename_symbol on a PC project: names.json gives the function or data `old` (its C name, or its symbol as
    the function list shows it) the real name `new`. Returns names.json, with what it held before."""
    old = c_name(old)
    if _ADDRESS_NAME.search(new):
        raise ForkError(f"{new} holds an address (func_/D_ and 8 digits): tools/names.py would pair it by that "
                        "address, with whatever's there: pick a name without one")
    info = json.loads((root / "config" / version / "functions.json").read_text(encoding="utf-8"))
    names = real_names(root, version)
    key: dict[str, str] = {}  # every symbol of the game, by C name -> its name by address
    for fns in info["units"].values():
        for f in fns:
            here = f"func_{f['addr']:08X}"
            key[here] = key[c_name(f["name"])] = here
            for r in f["relocs"]:
                if r[2] and (m := re.fullmatch(r"_(D_[0-9A-F]{8})", r[2])):
                    key[m.group(1)] = m.group(1)
    for was, real in names.items():
        key[real] = was
    if re.fullmatch(r"D_[0-9A-F]{8}", old):  # data only the source names (no code of the game refers to it)
        key.setdefault(old, old)
    at = key.get(old)
    if at is None:
        raise ForkError(f"{old} isn't one of the game's functions or data")
    if at in names and old != names[at]:
        raise ForkError(f"{old} is called {names[at]} now: rename {names[at]}")
    if new in key:
        raise ForkError(f"{new} is a symbol of the game already")
    path = root / "config" / version / "names.json"
    before = path.read_text(encoding="utf-8") if path.exists() else "{}\n"
    names[at] = new
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(dict(sorted(names.items())), indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return {path: before}


def address_of(root: Path, version: str, name: str) -> int | None:
    """The address of a function or data named by address (func_0041B470, _D_0066DDA4) or by a real name."""
    name = c_name(name)
    for was, real in real_names(root, version).items():
        if real == name:
            name = was
            break
    m = re.fullmatch(r"(?:func|D)_([0-9A-Fa-f]{8})", name)
    return int(m.group(1), 16) if m else None


def fix_short_ends(root: Path, version: str) -> list[str]:
    """Projects made before _whole: functions whose last instruction ended in zeros were cut short (objdiff saw
    "(bad)" and capped them below 100% whatever the C). Each one ends at its last whole instruction now, never past
    the next function, with its relocations read again; functions with jump tables are left as they are. Returns
    the names of the functions it lengthened (config/<version>/functions.json is written when there are any)."""
    config = root / "config" / version / "functions.json"
    info = json.loads(config.read_text(encoding="utf-8"))
    pe = read_pe((root / info["exe"]).read_bytes())
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    fns = sorted((f for u in info["units"].values() for f in u), key=lambda f: f["addr"])
    names = {f["addr"]: f["name"] for f in fns}
    fixed = []
    for i, f in enumerate(fns):
        if any(r[2] is None for r in f["relocs"]):  # (a jump table: its extent is its own business)
            continue
        start, end = f["addr"], f["addr"] + f["size"]
        if pe.read(end, 1) != b"\x00":  # what was cut off was zeros: the byte after the end is one (and quick to check)
            continue
        sec = pe.section_at(start)
        limit = min(fns[i + 1]["addr"] if i + 1 < len(fns) else sec.va + sec.size, sec.va + sec.size)
        whole = _whole(md, pe, start, end, limit)
        if whole <= end:
            continue
        f["size"] = whole - start
        f["relocs"] = [list(r) for r in _relocs(md, pe, start, whole, whole, [], names)]
        fixed.append(f["name"])
    if fixed:
        tmp = config.with_name(config.name + ".tmp")
        tmp.write_text(json.dumps(info, indent=1), encoding="utf-8")
        os.replace(tmp, config)
    return fixed


ASM_CHECK = 1  # set_aside's version, in each function it checked: a better check (a bigger number) looks again


def set_aside(net, proj, fp, version: str, reason) -> int:
    """The project's open functions whose original code `reason` says no compiler makes (Console.asm_reason) get
    status 'asm', with that reason: agents kept claiming them and burning compiles on code C can't give. Each is
    checked once (its meta says so): the check of 13,000 functions took seconds at every start. How many."""
    try:
        info = json.loads((Path(fp.root) / "config" / version / "functions.json").read_text(encoding="utf-8"))
        data = (Path(fp.root) / info["exe"]).read_bytes()
    except (OSError, ValueError, KeyError):
        return 0
    where = {f["name"]: (f["offset"], f["size"]) for u in info["units"].values() for f in u}
    n, checked = 0, []
    for r in net.store.all("SELECT id, name, meta FROM functions WHERE project_id=? AND status='open'", proj["id"]):
        meta = json.loads(r["meta"] or "{}")
        if meta.get("asm_check") == ASM_CHECK:
            continue
        at = where.get(meta.get("symbol") or r["name"])
        if at is None:
            continue
        meta["asm_check"] = ASM_CHECK
        if (why := reason(data[at[0]:at[0] + at[1]])):
            net.forks.mark_asm({**dict(r), "meta": json.dumps(meta)}, reason=why)
            n += 1
        else:
            checked.append((json.dumps(meta), r["id"]))
    if checked:
        with net.store.tx() as db:
            db.executemany("UPDATE functions SET meta=? WHERE id=?", checked)
    return n


def split_merged(root: Path, version: str) -> list[str]:
    """Projects made before _split_point: a function Ghidra made of two (one, int3 padding, the next) ends where the
    first does, and the next becomes a function of its own (_func_<address>) in the same source file; both get their
    relocations read again. Functions with jump tables are left as they are. Returns the new functions' names
    (config/<version>/functions.json is written when there are any)."""
    config = root / "config" / version / "functions.json"
    info = json.loads(config.read_text(encoding="utf-8"))
    pe = read_pe((root / info["exe"]).read_bytes())
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    names = {f["addr"]: f["name"] for u in info["units"].values() for f in u}
    made: list[str] = []
    for fns in info["units"].values():
        i = 0
        while i < len(fns):
            f = fns[i]
            i += 1
            if any(r[2] is None for r in f["relocs"]):  # (a jump table)
                continue
            start, end = f["addr"], f["addr"] + f["size"]
            first_end = _split_point(md, pe, start, end)
            if first_end is None:
                continue
            k = first_end
            while pe.read(k, 1) == b"\xcc":
                k += 1
            name = f"_func_{k:08X}"
            names[k] = name
            f["size"] = first_end - start
            fns.insert(i, {"name": name, "addr": k, "offset": pe.offset(k), "size": end - k, "relocs": []})
            made.append(name)
    if made:
        for fns in info["units"].values():  # every function that may call or jump to a new one: read again
            for f in fns:
                if not any(r[2] is None for r in f["relocs"]):
                    f["relocs"] = [list(r) for r in _relocs(md, pe, f["addr"], f["addr"] + f["size"],
                                                            f["addr"] + f["size"], [], names)]
        tmp = config.with_name(config.name + ".tmp")
        tmp.write_text(json.dumps(info, indent=1), encoding="utf-8")
        os.replace(tmp, config)
    return made
