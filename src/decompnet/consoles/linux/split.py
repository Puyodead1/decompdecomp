"""A Linux program (a 32-bit x86 ELF executable) split into its functions and data, by its own symbol table: games of
2000-2002 shipped unstripped, every function and global with its name and size. Calls into shared libraries go
through the PLT, whose stubs the symbol table names too (printf@GLIBC_2.0), so a call to printf links to its stub.

Each function keeps its bytes, its assembly (Intel syntax, calls and jumps named) and what its code refers to, for
cross references and twins; the judge (arch/x86_link.py) reads the bytes. The source file of each comes from the
debug information when the program has it (debuginfo.py); without it, everything is one unit."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

import capstone
from capstone import x86 as cs_x86
from elftools.elf.elffile import ELFFile

from ...arch.x86_link import R_386_32, R_386_PC32
from ...rom import RomError
from ...rom.split import DataSymbol, Segment, SplitResult

UNIT = "program"  # the unit of a function no debug information places
# the C runtime's start-up code GCC and glibc link into every program: no C of the game's makes it
RUNTIME = {"_start", "call_gmon_start", "__do_global_dtors_aux", "fini_dummy", "frame_dummy", "init_dummy",
           "__do_global_ctors_aux", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini"}


@dataclass
class LinuxFunction:
    name: str
    vram: int
    rom: int
    code: bytes
    asm: str
    n_insns: int
    refs: list[tuple[int, int, int]] = field(default_factory=list)  # (offset, kind, address)
    segment: str = UNIT
    runtime: bool = False

    @property
    def size(self) -> int:
        return len(self.code)


def _md():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    return md


def disassemble(code: bytes, vram: int, label) -> tuple[str, int, list[tuple[int, int, int]]]:
    """A function's assembly (each line its address and instruction, calls and jumps by name), how many
    instructions, and what it refers to: (offset, R_386_PC32, destination) for a call or jump, (offset, R_386_32,
    address) for an address in an operand that `label` names."""
    lines, refs, count = [], [], 0
    for ins in _md().disasm(code, vram):
        count += 1
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        groups = set(ins.groups)
        if (cs_x86.X86_GRP_CALL in groups or cs_x86.X86_GRP_JUMP in groups) and ins.operands \
                and ins.operands[0].type == cs_x86.X86_OP_IMM:
            dest = ins.operands[0].imm & 0xFFFFFFFF
            if ins.size >= 5 and (ins.bytes[0] in (0xE8, 0xE9) or ins.bytes[0] == 0x0F):  # rel32 (not a short jump)
                refs.append((ins.address - vram + ins.size - 4, R_386_PC32, dest))
            if not vram <= dest < vram + len(code):
                text = f"{ins.mnemonic} {label(dest)}"
        else:
            for off, value in ((ins.imm_offset, ins.operands and next((o.imm for o in ins.operands
                                                                        if o.type == cs_x86.X86_OP_IMM), None)),
                               (ins.disp_offset, next((o.mem.disp for o in ins.operands
                                                        if o.type == cs_x86.X86_OP_MEM and o.mem.base == 0), None))):
                if off and value is not None and ins.size - off >= 4:
                    named = label(value & 0xFFFFFFFF, exact=True)
                    if named:
                        refs.append((ins.address - vram + off, R_386_32, value & 0xFFFFFFFF))
                        text = re.sub(rf"0x{value & 0xFFFFFFFF:x}\b", named, text)
        lines.append(f"/* {ins.address:08X} */ {text}")
    return "\n".join(lines), max(count, 1), refs


def read_program(data: bytes) -> ELFFile:
    try:
        elf = ELFFile(BytesIO(data))
    except Exception as e:  # noqa: BLE001
        raise RomError(f"this isn't a program decompdecomp can read: {e}") from None
    if elf["e_machine"] != "EM_386" or elf["e_type"] != "ET_EXEC":
        raise RomError("this isn't a 32-bit x86 Linux program (an i386 ELF executable)")
    if elf.get_section_by_name(".symtab") is None:
        raise RomError("this program is stripped (it has no symbol table): decompdecomp splits Linux programs by "
                       "their own symbols for now")
    return elf


def split(path: Path, units: dict[int, str] | None = None, log=print) -> SplitResult:
    data = path.read_bytes()
    elf = read_program(data)
    sections = list(elf.iter_sections())
    text = elf.get_section_by_name(".text")
    segments = [Segment(s.name, s["sh_offset"], s["sh_offset"] + s["sh_size"], s["sh_addr"]) for s in sections
                if s["sh_flags"] & 2 and s["sh_type"] == "SHT_PROGBITS" and s["sh_addr"]]
    raw: list[tuple[str, int, int, str, int]] = []  # (name, address, size, type, section index)
    for sym in elf.get_section_by_name(".symtab").iter_symbols():
        if sym.name and sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT") and sym["st_value"]:
            # (GCC names a function's static local `mark.21`: a C name, mark_21, for agents and saves)
            raw.append((re.sub(r"\W", "_", sym.name.split("@")[0]), sym["st_value"], sym["st_size"], sym["st_info"]["type"],
                        sym["st_shndx"] if isinstance(sym["st_shndx"], int) else 0))
    text_idx = sections.index(text)
    by_addr = {}
    named: dict[str, int] = {}
    for name, addr, size, kind, shndx in raw:
        if shndx == 0 and kind == "STT_FUNC":  # an import: its PLT stub
            named.setdefault(name, addr)
        by_addr.setdefault(addr, name)
    # the imports the symbol table gives no address: the linker writes a stub's address only for a function whose
    # address the program takes (385 of a 2008 program's 1,448), so the others (strlen, called from Lua) were
    # unknown and no call to them matched. Each .rel.plt entry is one stub, in order after PLT0.
    for name, addr in plt_stubs(elf).items():
        if name not in named:
            named[name] = addr
            by_addr.setdefault(addr, name)

    def label(addr: int, exact: bool = False) -> str | None:
        if addr in by_addr:
            return by_addr[addr]
        return None if exact else f"0x{addr:08X}"

    def offset(addr: int) -> int | None:
        return next((s.rom_start + addr - s.vram for s in segments if s.contains(addr)), None)

    functions: list[LinuxFunction] = []
    seen: set[str] = set()
    for name, addr, size, kind, shndx in sorted(raw, key=lambda r: r[1]):
        if kind != "STT_FUNC" or shndx != text_idx or size <= 0 or offset(addr) is None:
            continue
        if any(f.vram == addr for f in functions[-3:]):
            continue  # (two names for one function: the first)
        unique = name if name not in seen else f"{name}_{addr:08X}"  # (two files' static functions of one name)
        seen.add(unique)
        at = offset(addr)
        code = data[at:at + size]
        asm, count, refs = disassemble(code, addr, label)
        unit = (units or {}).get(addr, UNIT)
        functions.append(LinuxFunction(unique, addr, at, code, asm, count, refs, unit, name in RUNTIME))
    found = []
    for name, addr, size, kind, shndx in sorted(raw, key=lambda r: r[1]):
        if kind != "STT_OBJECT" or not shndx or not size:
            continue
        sec = sections[shndx]
        bss = sec["sh_type"] == "SHT_NOBITS"
        found.append(DataSymbol(name, addr, None if bss else offset(addr), size, "bss" if bss else "data"))
    log(f"found {len(functions)} functions and {len(found)} globals by the program's own symbols; "
        f"{len(named)} library functions it calls through the PLT")
    return SplitResult(functions, found, segments, named, path.parent / "symbols.txt", "", "", "linux", 0, path.name)


PLT_ENTRY = 16  # i386: an entry of the PLT (and PLT0 before them), 16 bytes


def plt_stubs(elf) -> dict[str, int]:
    """Every import's PLT stub by its name: the n-th R_386_JUMP_SLOT of .rel.plt is the n-th entry after PLT0."""
    rel, plt = elf.get_section_by_name(".rel.plt"), elf.get_section_by_name(".plt")
    if rel is None or plt is None or not hasattr(rel, "iter_relocations"):
        return {}
    symbols = elf.get_section(rel["sh_link"])
    out: dict[str, int] = {}
    for n, r in enumerate(rel.iter_relocations()):
        sym = symbols.get_symbol(r["r_info_sym"])
        if sym is not None and sym.name:
            out.setdefault(re.sub(r"\W", "_", sym.name.split("@")[0]), plt["sh_addr"] + PLT_ENTRY * (n + 1))
    return out


def compiler_of(data: bytes) -> str:
    """What the program's .comment says built it ("GCC: (GNU) 2.95.3 20010315 (release)"): the most common."""
    try:
        comment = ELFFile(BytesIO(data)).get_section_by_name(".comment")
    except Exception:  # noqa: BLE001
        return ""
    if comment is None:
        return ""
    said = [s.decode("latin-1") for s in comment.data().split(b"\0") if s]
    return max(set(said), key=said.count) if said else ""


def info(data: bytes, name: str) -> dict:
    stem = Path(name or "program").stem or "program"
    return {"title": stem, "game_code": "", "region": "", "size": len(data), "sha1": hashlib.sha1(data).hexdigest(),
            "compiler_guess": compiler_of(data)}


# ----------------------------------------------------------------------------- a function's row, cut, found or joined
# (the engine's split_function, report_boundary and saves: engine/editing.py, saves.py)

def function_from_row(row) -> LinuxFunction:
    """A stored function row as the splitter's function object: its bytes, assembly and references."""
    import json

    row = dict(row)
    code = row.get("target") or b""
    return LinuxFunction(row["name"], row["vram"], row.get("rom_offset") or 0, code, row.get("asm") or "",
                         row.get("n_insns") or 1, [tuple(r) for r in json.loads(row.get("relocs") or "[]")],
                         row.get("unit") or UNIT)


def boundaries(code: bytes, vram: int) -> list[int]:
    """The offsets where the function's instructions start (x86's are 1 to 15 bytes: a cut must fall on one)."""
    return [ins.address - vram for ins in _md().disasm(code, vram)]


def _asm_from(text: str, start: int, end: int) -> str:
    """The lines of a function's assembly (each `/* ADDRESS */ ...`) from `start` up to `end`."""
    out = []
    for line in text.splitlines():
        m = re.match(r"/\* ([0-9A-F]{8}) \*/", line)
        if m and start <= int(m.group(1), 16) < end:
            out.append(line)
    return "\n".join(out)


def split_function(row, at: int, new_name: str) -> tuple[LinuxFunction, LinuxFunction]:
    """Cut a stored function at `at`, an instruction's start inside it: the head keeps its name, the tail is
    `new_name`, each with its own assembly lines and references."""
    fn = function_from_row(row)
    off = at - fn.vram
    starts = boundaries(fn.code, fn.vram)
    if not 0 < off < len(fn.code) or off not in starts:
        raise ValueError(f"0x{at:08X} isn't the start of an instruction inside {fn.name} (0x{fn.vram:08X}, "
                         f"{len(fn.code)} bytes)")
    end = fn.vram + len(fn.code)
    head = LinuxFunction(fn.name, fn.vram, fn.rom, fn.code[:off], _asm_from(fn.asm, fn.vram, at),
                         sum(1 for s in starts if s < off), [r for r in fn.refs if r[0] < off], fn.segment)
    tail = LinuxFunction(new_name, at, fn.rom + off, fn.code[off:], _asm_from(fn.asm, at, end),
                         sum(1 for s in starts if s >= off), [(o - off, k, a) for o, k, a in fn.refs if o >= off],
                         fn.segment)
    return head, tail


def _segments(program: bytes) -> list[tuple[int, int, int]]:
    """The program's loaded executable parts: (address, file offset, size)."""
    try:
        elf = ELFFile(BytesIO(program))
    except Exception:  # noqa: BLE001
        return []
    return [(s["p_vaddr"], s["p_offset"], s["p_filesz"]) for s in elf.iter_segments()
            if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1]


def extent(code: bytes, vram: int) -> int:
    """How long the function at the start of `code` is: up to the ret (or jmp) after which none of its own jumps
    land, so a function whose branches jump past a ret in its middle runs on to its real end."""
    furthest = vram
    for ins in _md().disasm(code, vram):
        groups = set(ins.groups)
        if cs_x86.X86_GRP_JUMP in groups and ins.operands and ins.operands[0].type == cs_x86.X86_OP_IMM:
            dest = ins.operands[0].imm & 0xFFFFFFFF
            if vram <= dest < vram + len(code):
                furthest = max(furthest, dest)
        end = ins.address + ins.size
        if (cs_x86.X86_GRP_RET in groups or ins.mnemonic == "jmp") and end > furthest:
            return end - vram
        if ins.mnemonic in ("hlt", "int3"):
            return end - vram
    return 0


def function_at(program: bytes, addr: int, limit: int, name: str, label=None) -> LinuxFunction | None:
    """A function the symbol table doesn't have, at `addr` (code an agent found past another's end): its code up
    to its last return, never past `limit` (the next function)."""
    seg = next(((v, o, n) for v, o, n in _segments(program) if v <= addr < v + n), None)
    if seg is None:
        return None
    v, o, n = seg
    at = o + addr - v
    code = program[at:o + n][:max(0, limit - addr)]
    size = extent(code, addr)
    if not size and limit - addr <= len(code):  # (it ends in a call that doesn't return, exit's: up to the next one)
        starts = boundaries(code, addr)
        size = next((s for s in starts if padding(code[s:], addr + s)), len(code))
        if starts and size == len(code) and sum(ins.size for ins in _md().disasm(code, addr)) != len(code):
            size = 0  # (not code all the way)
    if not size:
        return None
    code = code[:size]
    asm, count, refs = disassemble(code, addr, label or (lambda a, exact=False: None if exact else f"0x{a:08X}"))
    return LinuxFunction(name, addr, at, code, asm, count, refs)


# what gas fills a function's end with (.p2align): nop, and the long nops that do nothing (mov esi,esi, lea esi,
# [esi+0], lea edi,[edi+0])
FILL = re.compile(r"(nop|int3|mov (e[sd]i), \2|lea (e[sd]i), \[\3( \+ 0)?\])$")


def padding(data: bytes, vram: int) -> bool:
    """Whether bytes between functions are only fill: zeros, or instructions that do nothing."""
    if not data.strip(b"\0"):
        return True
    done = 0
    for ins in _md().disasm(data, vram):
        if not FILL.match(f"{ins.mnemonic} {ins.op_str}".strip()):
            return False
        done += ins.size
    return done == len(data)


def join_saved_functions(rows: list[dict], start: int, end: int, read) -> LinuxFunction:
    """Saved pieces joined back into the first one: their bytes in order, gaps filled from the game only when
    they're padding (the bytes GCC and the linker fill between functions: zeros, nop, int3 and lea esi,[esi])."""
    import json

    rows = [dict(r) for r in rows]
    first = function_from_row(rows[0])
    pieces, refs, asm, pos = [], [], [], start

    def gap(at: int, n: int) -> bytes:
        data = read(at, n)
        if data is None or not padding(data, at):
            raise ValueError("the saved layout crosses a gap in this analysis")
        return data

    for row in rows:
        code = row.get("target") or b""
        if row["vram"] > pos:
            pieces.append(gap(pos, row["vram"] - pos))
        base = row["vram"] - start
        refs += [(int(o) + base, int(k), int(a)) for o, k, a in json.loads(row.get("relocs") or "[]")]
        asm.append(row.get("asm") or "")
        pieces.append(code)
        pos = row["vram"] + len(code)
    if pos < end:
        pieces.append(gap(pos, end - pos))
    code = b"".join(pieces)
    return LinuxFunction(first.name, start, first.rom, code, "\n".join(a for a in asm if a),
                         len(boundaries(code, start)) or 1, refs, first.segment)
