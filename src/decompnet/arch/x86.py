"""x86 (Windows PC games; Xbox in public decomps): what decompdecomp knows about the processor itself.

- the relocations a match ignores and how capstone reads the code;
- code no compiler makes (asm_reason), as agents on a PC game kept finding by hand: its first instructions, up to
  the first branch, read a register no calling convention passes anything in (eax, ebx, esi, edi; ebp without a
  frame of its own) before setting it, or it's an exception handler stub. Visual C++ passes arguments on the stack,
  in ecx (__thiscall, __fastcall) and edx (__fastcall), and nowhere else; code taking one in eax comes from the
  linker's whole-program optimisation (/LTCG, its own conventions for internal functions), and code using ebp
  with no frame is a funclet of the function before it (`lea ecx,[ebp-0x58]; jmp <destructor>`, an exception's
  unwinding), which comes with that function's C, never on its own.

The compiler map and class recovery have no x86 reader yet (ROADMAP.md says where to start).
"""

from __future__ import annotations

import re
import threading

import capstone

RELOC_MASKS: dict[int, tuple[int, int, int]] = {}  # every x86 relocation fills the 4 bytes at r_offset (the default)
CAPSTONE = {False: (capstone.CS_ARCH_X86, capstone.CS_MODE_32)}

RELOC_MASKS_64 = {1: (0, 8, 0xFFFFFFFFFFFFFFFF)}  # R_X86_64_64; the rest fill 4 bytes
CAPSTONE_64 = {False: (capstone.CS_ARCH_X86, capstone.CS_MODE_64)}

# A memory operand naming data by its address (D_00412340, _D_00412340, D_00412340+0x4), as delinked targets name it
_DATA_OPERAND = re.compile(r"\[\s*_?D_([0-9A-Fa-f]{8})(?:\s*\+\s*(0x[0-9A-Fa-f]+|\d+))?\s*\]")


def float_operands(text: str) -> list[tuple[int, str]]:
    """The float constants an instruction loads from data by address, as (address, "f" or "d"): SSE scalar loads and
    arithmetic (movss, mulss, comisd...) and x87 ones (fld, fmul, fcomp...; a qword operand is a double). A diff
    showed `mulss xmm0, [_D_00412340]` against its own `[_kDegToRad]`, and an agent had to read_data to learn
    the target meant 0.0174533 (pi/180)."""
    mnemonic, _, operands = text.strip().partition(" ")
    m = _DATA_OPERAND.search(operands)
    if m is None:
        return []
    op = mnemonic.lower()
    if op.endswith("ss") or op in ("cvtss2sd", "cvtss2si", "cvttss2si"):
        kind = "f"
    elif op.endswith("sd") and op not in ("movsd",) or op in ("cvtsd2ss", "cvtsd2si", "cvttsd2si"):
        kind = "d"
    elif op == "movsd" and "xmm" in operands:  # (movsd without xmm is the string instruction)
        kind = "d"
    elif op.startswith("f") and not op.startswith(("fi", "fst", "fnst", "fldcw", "fnstcw", "fxch")):
        kind = "d" if "qword" in operands.lower() else "f" if "tbyte" not in operands.lower() else ""
    else:
        kind = ""
    if not kind:
        return []
    return [(int(m.group(1), 16) + (int(m.group(2), 0) if m.group(2) else 0), kind)]
# registers by the 32-bit register they're part of, for asm_reason
_FAMILY = {n: f for f, names in {"eax": ("al", "ah", "ax", "eax"), "ebx": ("bl", "bh", "bx", "ebx"),
                                 "ecx": ("cl", "ch", "cx", "ecx"), "edx": ("dl", "dh", "dx", "edx"),
                                 "esi": ("si", "esi"), "edi": ("di", "edi"), "ebp": ("bp", "ebp")}.items() for n in names}
_NO_ARGUMENTS = {"eax", "ebx", "esi", "edi", "ebp"}  # what no Visual C++ calling convention passes anything in
# after a call: what it may return or clobber, and ebp, which the C runtime's prologue helpers (__SEH_prolog4,
# _EH_prolog) set up for the function that calls them
_SET_BY_CALLS = {"eax", "ecx", "edx", "ebp"}


_STUB_BYTES = 128  # an exception handler stub is about 30 bytes; a few run together, up to about 100
_local = threading.local()


def _disassembler():
    """One capstone reader per thread (it isn't thread-safe, and making one each time cost a check of 11,000
    functions most of its time)."""
    if not hasattr(_local, "md"):
        _local.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        _local.md.detail = True
    return _local.md


def _address_table(code: bytes) -> bool:
    """Whether code is a table of addresses into the program (a switch's jump table that came out as a function):
    its first dwords all lie in the same 64 KiB of a program's usual range."""
    if len(code) < 12:
        return False
    words = [int.from_bytes(code[i:i + 4], "little") for i in range(0, 12, 4)]
    return len({w >> 16 for w in words}) == 1 and 0x40 <= words[0] >> 16 < 0x1000


def asm_reason(code: bytes, big_endian: bool = False, **_facts) -> str | None:
    """Why this x86 function (its code, from the entry) can't come from a compiler, or None."""
    if _address_table(code):
        return "a table of addresses (a switch's jump table), not code"
    md = _disassembler()
    if len(code) <= _STUB_BYTES:  # an exception handler stub: [mov edx,[esp+8]; lea eax,[edx+N] ...]
        insns = list(md.disasm(code, 0))  # mov eax, <its function's info>; jmp <handler>
        last, before = (insns[-1], insns[-2]) if len(insns) >= 2 else (None, None)
        if before is not None and last.mnemonic == "jmp" and before.mnemonic == "mov" \
                and before.op_str.startswith("eax, ") and before.operands[1].type == capstone.x86.X86_OP_IMM \
                and (len(insns) == 2 or insns[0].op_str == "edx, dword ptr [esp + 8]"):
            return "an exception handler stub: the compiler makes it for the function it belongs to"
    written: set[str] = set()
    for ins in md.disasm(code, 0):  # (up to the first branch: a function of thousands of bytes reads a few)
        if ins.mnemonic == "push" and ins.op_str in _FAMILY:  # saving a register, or making room on the stack
            continue
        try:
            reads, writes = ins.regs_access()
        except capstone.CsError:
            return None
        names = [_FAMILY.get(ins.reg_name(r)) for r in reads]
        ops = ins.operands
        same = len(ops) == 2 and ops[0].type == ops[1].type == capstone.x86.X86_OP_REG and ops[0].reg == ops[1].reg
        constant = len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG and ops[1].type == capstone.x86.X86_OP_IMM \
            and ((ins.mnemonic == "or" and ops[1].imm in (-1, 0xFFFFFFFF)) or (ins.mnemonic == "and" and ops[1].imm == 0))
        # setting a register whatever it held: xor/sub/sbb r,r; or r,-1 (Visual C++'s r = -1); and r,0
        overwrite = (same and ins.mnemonic in ("xor", "sub", "sbb")) or constant
        for f in names if not overwrite else ():
            if f in _NO_ARGUMENTS and f not in written:
                if f == "ebp" and ins.address == 0:
                    return ("uses ebp with no frame of its own: a part of the function before it (an exception's "
                            "unwinding funclet, or code split from it), which comes with that function's C")
                return (f"reads {f} before setting it: Visual C++ passes nothing there (code built with whole-program "
                        "optimisation, /LTCG, or assembly)")
        written.update(f for f in (_FAMILY.get(ins.reg_name(r)) for r in writes) if f)
        if capstone.x86.X86_GRP_CALL in ins.groups:
            written |= _SET_BY_CALLS
        if ins.groups and ({capstone.x86.X86_GRP_JUMP, capstone.x86.X86_GRP_RET, capstone.x86.X86_GRP_INT}
                           & set(ins.groups)):
            break
    return None
