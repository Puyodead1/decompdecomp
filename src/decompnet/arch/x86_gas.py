"""Code that isn't C (hand-written assembly, a function no C makes yet) written as GNU assembly a person can read:
each instruction as capstone reads it (AT&T syntax, what GNU as takes), a call or a jump out of the function by the
name it reaches, an address by its symbol (`refs`, from the program's relocations as the import read them), a jump
inside the function to a label of its own. An instruction this writes otherwise than the program has it (an
encoding GNU as picks differently, one capstone reads but the 2001 assembler doesn't know) stays its bytes, its
addresses by name: `keep` says which. Whether the source assembles to the program's bytes is the caller's to check
(consoles/linux/export.py links it where the program has it and compares)."""

from __future__ import annotations

import re

import capstone

JUMPS = {"jmp", "call", "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge",
         "jle", "jg", "jecxz", "jcxz", "loop", "loope", "loopne"}


def instructions(code: bytes, vram: int) -> list:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.syntax = capstone.CS_OPT_SYNTAX_ATT
    md.detail = True
    out, at = [], 0
    for ins in md.disasm(code, 0):
        if ins.address != at:
            break
        out.append(ins)
        at += ins.size
    return out


def source(name: str, code: bytes, vram: int, refs: dict[int, str], keep: set[int] = frozenset(),
           typed: bool = True) -> str:
    """The function as GNU assembly. `refs`: {offset of a word: its expression} (`name - . - 4` for a call's,
    `table+8` for an address); `keep`: offsets of instructions written as their bytes."""
    ins = instructions(code, vram)
    decoded = sum(i.size for i in ins)
    labels = set()
    for i in ins:
        if i.mnemonic in JUMPS and i.op_str.startswith("0x") and i.address not in keep:
            target = int(i.op_str, 16)
            if 0 <= target < len(code) and not _ref_in(i, refs):
                labels.add(target)
    lines = [".text", f".globl {name}"] + ([f".type {name},@function"] if typed else []) + [f"{name}:"]
    for i in ins:
        if i.address in labels:
            lines.append(f".L{name}_{i.address:x}:")
        text = None if i.address in keep else _text(i, name, code, refs, labels)
        lines.extend([f"\t{text}"] if text is not None else _bytes(code, i.address, i.address + i.size, refs,
                                                                    f"{i.mnemonic} {i.op_str}".strip()))
    if decoded < len(code):  # (what capstone doesn't read: its bytes)
        lines.extend(_bytes(code, decoded, len(code), refs, "not read as instructions"))
    if typed:
        lines.append(f".size {name}, .-{name}")
    return "\n".join(lines) + "\n"


def _ref_in(i, refs: dict[int, str]) -> list[int]:
    return [a for a in refs if i.address <= a < i.address + i.size]


SPELLED = {"retl": "ret", "calll": "call", "jmpl": "jmp", "leavel": "leave"}  # (as the 2001 assembler spells them)


def _text(i, name: str, code: bytes, refs: dict[int, str], labels: set[int]) -> str | None:
    mnemonic, ops = SPELLED.get(i.mnemonic, i.mnemonic), i.op_str
    inside = _ref_in(i, refs)
    if mnemonic in JUMPS and ops.startswith("0x"):
        target = int(ops, 16)
        if inside:  # a call or jump out of the function, by name
            expr = refs[inside[0]]
            m = re.fullmatch(r"(.+?) - \. - 4", expr)
            if not m or inside[0] + 4 != i.address + i.size:
                return None
            return f"{mnemonic} {m.group(1)}"
        if target in labels:
            return f"{mnemonic} .L{name}_{target:x}"
        return None
    for at in inside:  # an address in an operand: by its symbol
        word = int.from_bytes(code[at:at + 4], "little")
        expr = refs[at]
        if expr.endswith(" - . - 4"):
            return None
        pattern = rf"(?<![\w.])0x{word:x}\b"
        if len(re.findall(pattern, ops)) != 1:
            return None
        ops = re.sub(pattern, expr.replace(" ", ""), ops)
    if re.search(r"\b0x[0-9a-f]{7,8}\b", ops) and not inside:
        pass  # (a number that looks like an address but isn't one: a constant)
    return f"{mnemonic} {ops}".strip()


def _bytes(code: bytes, start: int, end: int, refs: dict[int, str], what: str) -> list[str]:
    out, at = [], start
    while at < end:
        if at in refs and at + 4 <= end:
            out.append(f"\t.long {refs[at]}")
            at += 4
            continue
        stop = min([end, at + 16] + [a for a in refs if at < a < end])
        out.append(f"\t.byte {', '.join(f'0x{b:02x}' for b in code[at:stop])}")
        at = stop
    if out:
        out[0] += f"  /* {what} */"
    return out
