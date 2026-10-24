"""A function of a V.Flash program as assembly m2c reads (GNU syntax, `glabel`): what its drafts come from, made when
an agent or autopilot asks (a V.Flash project keeps no assembly files: its objects are cut from the programs at
build time). Branches and literal pool loads go to labels; the pool's words, and a switch's table, are data, with
the names the function's relocations give them (the functions it calls, the game's data)."""

from __future__ import annotations

import re
import struct

import capstone

from . import analysis

_READER = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
_PC_LOAD = re.compile(r"^(\w+), \[pc(?:, #(-?0x[0-9a-f]+|-?\d+))?\]$")  # (capstone leaves out #0)
_PC_ADD = re.compile(r"^(\w+), pc, #(0x[0-9a-f]+|\d+)$")
_TARGET = re.compile(r"^#(0x[0-9a-f]+|\d+)$")
# capstone's names for r9-r12, as GNU as and m2c spell them
_REGISTERS = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}


def _regs(text: str) -> str:
    return re.sub(r"\b(sb|sl|fp|ip)\b", lambda m: _REGISTERS[m.group(1)], text)


def label(addr: int) -> str:
    return f".L{addr:08X}"


def function_asm(name: str, code: bytes, addr: int, relocs: list) -> str:
    """`code` (the function's bytes in the program, at `addr`) as m2c's input. `relocs`: its relocations as
    functions.json has them, (offset, type, symbol or None, value)."""
    by_offset = {r[0]: r for r in relocs}
    words = [struct.unpack_from("<I", code, at)[0] for at in range(0, len(code) - 3, 4)]
    data: set[int] = {r[0] for r in relocs if r[1] == analysis.R_ARM_ABS32}
    labels: set[int] = set()
    decoded: dict[int, capstone.CsInsn] = {}
    for i, w in enumerate(words):  # first: what's code, and where it reads data
        off = 4 * i
        if off in data:
            continue
        ins = next(_READER.disasm(struct.pack("<I", w), addr + off), None)
        if ins is None or ins.mnemonic.startswith("v"):  # (VFP and NEON: not on an ARM9, so data read as code)
            data.add(off)
            continue
        decoded[off] = ins
        if (m := _PC_LOAD.match(ins.op_str)) and ins.mnemonic.startswith("ldr") and m.group(1) != "pc":
            target = addr + off + 8 + int(m.group(2) or "0", 0)
            if addr <= target < addr + len(code):
                data.add(target - addr & ~3)
                labels.add(target)
        elif (m := _PC_ADD.match(ins.op_str)) and ins.mnemonic == "add":
            target = addr + off + 8 + int(m.group(2) or "0", 0)
            if addr <= target < addr + len(code):
                data.update({target - addr, target - addr + 4})
                labels.add(target)
        elif analysis.is_branch(w) and not (off in by_offset and by_offset[off][2]):
            labels.add(analysis.branch_target(w, addr + off))
    for off in data:  # a switch's table: its cases are labels
        r = by_offset.get(off)
        if r is not None and r[2] is None:
            labels.add(addr + r[3])
    out = [".text", f"glabel {name}"]
    calls: dict[int, str] = {}  # (the second instruction of a call through a pointer, written as blx)
    for i, w in enumerate(words):
        off = 4 * i
        if addr + off in labels:
            out.append(f"{label(addr + off)}:")
        r = by_offset.get(off)
        if off in data or off not in decoded:
            value = (r[2] if r and r[2] else label(addr + r[3]) if r and r[1] == analysis.R_ARM_ABS32 else f"0x{w:08X}")
            out.append(f"    .word {value}")
            continue
        ins = decoded[off]
        ops = ins.op_str
        if w == analysis.MOV_LR_PC and off + 4 in decoded:  # a call through a pointer, as ARMv4 writes it: blx for m2c
            nxt = decoded[off + 4]
            if nxt.mnemonic in ("mov", "bx") and re.fullmatch(r"(pc, )?\w+", nxt.op_str):
                out.append("    nop")
                calls[off + 4] = f"    blx {_regs(nxt.op_str.split(', ')[-1])}"
                continue
            if nxt.mnemonic == "ldr" and nxt.op_str.startswith("pc, ["):
                out.append(f"    ldr r12, {_regs(nxt.op_str[4:])}")
                calls[off + 4] = "    blx r12"
                continue
        if off in calls:
            out.append(calls[off])
            continue
        if analysis.is_branch(w):
            target = r[2] if r and r[2] else label(analysis.branch_target(w, addr + off))
            ops = target
        elif (m := _PC_LOAD.match(ops)) and ins.mnemonic.startswith("ldr") and m.group(1) != "pc":
            ops = f"{m.group(1)}, {label(addr + off + 8 + int(m.group(2) or "0", 0))}"
        elif (m := _PC_ADD.match(ops)) and ins.mnemonic == "add":
            ops = f"{m.group(1)}, {label(addr + off + 8 + int(m.group(2) or "0", 0))}"
            out.append(f"    adr {_regs(ops)}")
            continue
        out.append(f"    {ins.mnemonic} {_regs(ops)}".rstrip())
    return "\n".join(out) + "\n"
