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
