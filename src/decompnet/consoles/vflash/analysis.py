"""Where each function of a V.Flash program is, and what its code refers to: from where Ghidra's analysis says
functions start, each function's extent is the code its start reaches (every branch followed) and the literal pool
after it, and its references become relocations, as GCC 3.2.3 and binutils 2.14 write them in an object compiled
with -ffunction-sections, so a function's original reads the same as what its C compiles to, whatever the names.

The code is ARM (ARMv4T, built for the ARM9TDMI), compiled by GCC: functions are word aligned and follow each other
with no padding; a function's constants (literal pool) and a switch's table of addresses follow its code. What no
function's start reaches is either a function nothing calls (a callback, a library function no one uses: one of its
own when it reads as one) or data. Standard library only: decoding these few instruction forms by their bits is quick
on a 1.5 MB program, where a disassembler took minutes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

R_ARM_PC24, R_ARM_ABS32 = 1, 2
LR, PC = 14, 15
COND_AL, COND_NV = 0xE, 0xF  # always; and ARMv4's undefined condition (no ARM9TDMI code has it)
BRANCH_IMM_ANY = 0xFFFFFE  # what binutils 2.14 leaves in a b/bl to another symbol: -8, the pipeline's offset, in words
DOUBLE_BYTES = 8  # what an `add rN, pc, #n` points at: a double's two words (`ldmia rN, {r2, r3}`)
MOV_LR_PC = 0xE1A0E00F  # mov lr, pc: the next instruction that sets pc is a call through a pointer (no blx on ARMv4)
# a function's first instruction when it saves registers: stmfd sp!, {..., lr}, or str lr, [sp, #-4]! for lr alone
# (GCC often schedules a compare or a move before it: the second instruction counts too)
PROLOGUES = ((0xFFFF4000, 0xE92D4000), (0xFFFFFFFF, 0xE52DE004))
# what restores lr before a tail call's b: ldmfd sp!, {..., lr} (without pc), ldr lr, [sp], #4
EPILOGUES = ((0xFFFFC000, 0xE8BD4000), (0xFFFFFFFF, 0xE49DE004))
GAP_WORDS = 16  # how far past a function's pool the next one may start (a pool word nothing reads in between)
MAX_TABLE = 4096  # a switch's table of addresses ends by then


def _sign24(w: int) -> int:
    off = w & 0xFFFFFF
    return (off - (1 << 24) if off & 0x800000 else off) << 2


def branch_target(w: int, at: int) -> int:
    return at + 8 + _sign24(w)


def is_branch(w: int) -> bool:
    """b or bl (with any condition but ARMv4's undefined one)."""
    return (w >> 25) & 7 == 0b101 and w >> 28 != COND_NV


def is_prologue(w: int | None) -> bool:
    return w is not None and any(w & mask == value for mask, value in PROLOGUES)


def opens_function(read, addr: int) -> bool:
    """Whether the code at an address starts as a function that saves registers does."""
    return is_prologue(read(addr)) or (read(addr) is not None and read(addr) >> 28 == COND_AL and is_prologue(read(addr + 4)))


def restores_lr(w: int | None) -> bool:
    return w is not None and any(w & mask == value for mask, value in EPILOGUES)


def _rotated_imm(w: int) -> int:
    imm, rot = w & 0xFF, ((w >> 8) & 0xF) * 2
    return ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF


@dataclass
class Flow:
    """What the code from one start reaches, within its limit."""
    start: int
    code: set[int] = field(default_factory=set)  # instructions reached
    pool: set[int] = field(default_factory=set)  # words its loads read pc-relative (constants, addresses)
    tables: set[int] = field(default_factory=set)  # words of its switches' tables of addresses
    calls: set[int] = field(default_factory=set)  # where its bl go
    out: set[int] = field(default_factory=set)  # where it branches past its limit (tail calls)
    returns: bool = False  # a path ends in a return or a jump out (as compiled code's paths do), or may: a loop
    # whose only way out is `movgt pc, lr` is a function too (a copy loop, missed and cut at its body's first
    # instruction, the one after it that ends in `b` back looking like a whole function)
    spins: bool = False  # it ends in a `b` back into itself: a loop with no way out (a function that never returns,
    # waiting for a reset: `for (;;)` around a delay)
    bad: bool = False  # it ran into what isn't code: an undefined instruction, or bytes past the program's data
    past: bool = False  # its code runs on past its limit (flow or a conditional branch): the next start is its own

    @property
    def code_end(self) -> int:
        return max(self.code) + 4 if self.code else self.start

    def end(self, limit: int) -> int:
        """Its code, and the pool and tables right after it (constants it reads beyond them aren't its own)."""
        end = self.code_end
        data = sorted(a for a in self.pool | self.tables if a >= end)
        for a in data:
            if a > end + 4 * 64 or a + 4 > limit:  # (a pool sits right after the code, a few words at most apart)
                break
            end = a + 4
        return end


def flow(read, start: int, limit: int, bound: int | None = None) -> Flow:
    """Follow the code from `start` (every path, to a return or a jump out) without going past `limit` (the next
    function's start; `bound`: where the program's data holding it ends). `read(addr)`: the word at an address, None
    outside the program's data."""
    bound = limit if bound is None else bound
    f = Flow(start)
    todo = [start]
    while todo:
        at = todo.pop()
        while True:
            if at in f.code or at in f.pool or at in f.tables:
                break
            if not start <= at < limit:
                if at >= limit:
                    f.past = True
                break
            w = read(at)
            if w is None or w >> 28 == COND_NV:
                f.bad = True
                break
            f.code.add(at)
            cond = w >> 28
            always = cond == COND_AL
            nxt = at + 4
            if is_branch(w):
                target = branch_target(w, at)
                if w & (1 << 24):  # bl
                    f.calls.add(target)
                elif start <= target < limit and not (always and target > at and (opens_function(read, target) or
                                                                                  restores_lr(read(at - 4)))):
                    if always:
                        f.spins |= target <= at
                        at = target
                        continue
                    todo.append(target)
                elif limit <= target < bound and not always:
                    f.past = True  # (a conditional branch past the next start: that start's code is this one's)
                else:  # (a tail call: to another function, or to one starting with a prologue in what follows)
                    f.out.add(target)
                    if always:
                        f.returns = True
                        break
                at = nxt
                continue
            called = read(at - 4) == MOV_LR_PC  # (this instruction sets pc to call through a pointer, and returns)
            if (w & 0x0FFFFFF0) == 0x012FFF10:  # bx rm
                f.returns |= not called
                if always and not called:
                    break
                at = nxt
                continue
            kind = (w >> 25) & 7
            rd = (w >> 12) & 0xF
            if kind in (0b010, 0b011) and (w >> 20) & 1:  # ldr
                rn = (w >> 16) & 0xF
                if rn == PC and kind == 0b010 and (w >> 24) & 1:  # ldr rd, [pc, #+/-n]: a literal pool word
                    imm = w & 0xFFF
                    f.pool.add((at + 8 + (imm if w & (1 << 23) else -imm)) & ~3)
                if rd == PC:
                    if (w & 0x0FFFFFF0) == 0x079FF100:  # ldr pc, [pc, rm, lsl #2]: a switch's table follows
                        table = at + 8
                        for k in range(MAX_TABLE):
                            entry = read(table + 4 * k)
                            if entry is None or not start <= entry < limit or entry & 3:
                                break
                            f.tables.add(table + 4 * k)
                            todo.append(entry)
                    else:
                        f.returns |= not called  # (ldr pc, [sp], #4: a return; ldr pc, [rn]: a jump through a pointer)
                        if always and not called:
                            break
                at = nxt
                continue
            if kind == 0b100 and (w >> 20) & 1 and w & (1 << PC):  # ldm with pc: a return
                f.returns = True
                if always:
                    break
                at = nxt
                continue
            if kind in (0b000, 0b001):
                if kind == 0b000 and (w & 0x90) == 0x90:  # multiplies, ldrh/strh/ldrsb/ldrsh, swp
                    if (w >> 20) & 1 and (w >> 16) & 0xF == PC and (w >> 22) & 1:  # ldrh rd, [pc, #n]
                        imm = ((w >> 4) & 0xF0) | (w & 0xF)
                        f.pool.add((at + 8 + (imm if w & (1 << 23) else -imm)) & ~3)
                    at = nxt
                    continue
                opcode, rn = (w >> 21) & 0xF, (w >> 16) & 0xF
                if kind == 0b001 and rn == PC and opcode in (0b0100, 0b0010) and rd != PC:  # add/sub rd, pc, #n
                    addr = at + 8 + (_rotated_imm(w) if opcode == 0b0100 else -_rotated_imm(w))
                    if start <= addr < limit and not addr & 3:
                        f.pool.update(range(addr, addr + DOUBLE_BYTES, 4))
                if rd == PC and not (0b1000 <= opcode <= 0b1011):  # an instruction that sets pc (not a compare)
                    if (w & 0x0FFFFFF0) == 0x008FF100:  # add pc, pc, rm, lsl #2: a switch's table of branches
                        k, table = 0, at + 8
                        while k < MAX_TABLE and (e := read(table + 4 * k)) is not None and is_branch(e) and \
                                not e & (1 << 24) and table + 4 * k < limit:
                            todo.append(table + 4 * k)
                            k += 1
                    else:
                        f.returns |= not called  # (mov pc, lr: a return; mov pc, rn: a jump through a register)
                        if always and not called:
                            break
            at = nxt
    return f


@dataclass
class Function:
    addr: int
    size: int
    name: str
    relocs: list[tuple[int, int, str | None, int]] = field(default_factory=list)  # (offset, type, symbol, value)


def plausible(f: Flow) -> bool:
    """Whether code nobody's start reached reads as a compiled function: its first instruction runs always, every path
    is code that ends in a return or a jump out, and it doesn't run on into what follows."""
    if not f.code or f.bad or f.past or f.start not in f.code:
        return False
    # (one that never returns only if its code is all of it, start to end: data seldom reads as a closed loop)
    return f.returns or f.spins and all(a in f.code for a in range(f.start, f.code_end, 4))


def extents(read, region_end, starts: set[int], strong: set[int]) -> dict[int, tuple[int, Flow]]:
    """Every function's (end, flow), from where functions start. A start that's only the analysis's (not a bl's
    target, the entry or a table's) and that the code before it runs on into is part of that function, not one of
    its own. Bytes after a function's code and pool that read as a whole function nothing calls make one; others are
    data. `region_end(addr)`: where the program's data holding an address ends."""
    order = sorted(starts)
    out: dict[int, tuple[int, Flow]] = {}
    i = 0
    while i < len(order):
        start = order[i]
        bound = region_end(start)
        limit = min(order[i + 1], bound) if i + 1 < len(order) else bound
        f = flow(read, start, limit, bound)
        if f.past and i + 1 < len(order) and order[i + 1] not in strong and order[i + 1] < bound:
            del order[i + 1]  # (its next start was a label inside it)
            continue
        end = min(f.end(limit), limit)
        out[start] = (end, f)
        gap = end
        while gap < limit and read(gap) == 0:  # (zeros: padding, or empty data)
            gap += 4
        for at in range(gap, limit, 4):  # a function nobody calls: right there, or after a pool word nobody reads
            if at - gap > 4 * GAP_WORDS and not opens_function(read, at):
                continue
            if read(at) >> 28 == COND_AL and plausible(g := flow(read, at, limit)) and g.code_end <= limit:
                order.insert(i + 1, at)
                break
        i += 1
    return out


def address_name(program: str, addr: int, kind: str = "func") -> str:
    """The name of a function or data of a program, by address: FA's func_10A715C4 and D_10B3B8FC, a module's
    func_GZ1A_1047B800 (modules share addresses: the name says which one's)."""
    return f"{kind}_{addr:08X}" if program == "FA" else f"{kind}_{program}_{addr:08X}"


def relocations(read, start: int, end: int, f: Flow, func_name, data_name) -> list[tuple[int, int, str | None, int]]:
    """(offset, type, symbol, value): a bl, and a b out of the function, names the function it goes to (value
    0xFFFFFE, what binutils 2.14 leaves in place); a b to a label of its own is against its own section (symbol None;
    value: the branch's field as it reads from there); a literal pool word holding an address names the function
    there, or the data (value 0); a switch table's address is against its own section (value: the offset in it).
    `func_name(addr, exact)`: the function starting at an address (None when none does and `exact`, else its name
    by address); `data_name(addr)`: what an address of the game's data is called, None when the word isn't one."""
    out = []
    for at in range(start, end, 4):
        w = read(at)
        off = at - start
        if at in f.code and is_branch(w):
            target = branch_target(w, at)
            if w & (1 << 24) or not start <= target < end:
                out.append((off, R_ARM_PC24, func_name(target, False), BRANCH_IMM_ANY))
            else:
                out.append((off, R_ARM_PC24, None, ((target - start - 8) >> 2) & 0xFFFFFF))
        elif at in f.tables:
            out.append((off, R_ARM_ABS32, None, w - start))
        elif at in f.pool and at not in f.code:
            if start <= w < end and w != start:
                out.append((off, R_ARM_ABS32, None, w - start))
            elif (name := func_name(w, True)):
                out.append((off, R_ARM_ABS32, name, 0))
            elif (name := data_name(w)):
                out.append((off, R_ARM_ABS32, name, 0))
    return out


def words(regions: list[tuple[int, bytes]]):
    """read(addr) and region_end(addr) over a program's regions."""
    spans = sorted((a, a + len(d), d) for a, d in regions if d)

    def find(addr: int):
        for lo, hi, d in spans:
            if lo <= addr < hi:
                return lo, hi, d
        return None

    cache: dict[int, int | None] = {}

    def read(addr: int) -> int | None:
        if addr in cache:
            return cache[addr]
        hit = find(addr)
        value = None
        if hit and addr + 4 <= hit[1] and not addr & 3:
            value = struct.unpack_from("<I", hit[2], addr - hit[0])[0]
        cache[addr] = value
        return value

    def region_end(addr: int) -> int:
        hit = find(addr)
        return hit[1] if hit else addr
    return read, region_end


def analyse(program: str, regions: list[tuple[int, bytes]], found: set[int], strong: set[int], owns,
            other: dict[int, str] | None = None, other_owns=None) -> list[Function]:
    """A program's functions: their extents from where they start (`found`: Ghidra's analysis; `strong`: starts
    certain otherwise, the entry and the C++ constructors' table), and their relocations. `owns(addr)`: whether an
    address is the program's (its regions or its BSS). A module's code calls FA's: `other` is FA's functions by
    address, `other_owns` FA's addresses."""
    read, region_end = words(regions)
    starts = {a for a in found | strong if read(a) is not None}
    called: set[int] = set()
    for a in sorted(starts):  # every bl's target is a function's start, the analysis's or not, and a tail call's
        f = flow(read, a, region_end(a))
        called |= {t for t in f.calls if read(t) is not None} | {t for t in f.out if read(t) is not None and region_end(t) == region_end(a)}
    starts |= called
    spans = extents(read, region_end, starts, strong | called)
    names = {a: address_name(program, a) for a in spans}
    other = other or {}

    def func_name(addr: int, exact: bool) -> str | None:
        if addr in names:
            return names[addr]
        if addr in other:
            return other[addr]
        if exact:
            return None
        return address_name(program if owns(addr) or other_owns is None or not other_owns(addr) else "FA", addr)

    def data_name(addr: int) -> str | None:
        if owns(addr):
            return address_name(program, addr, "D")
        if other_owns is not None and other_owns(addr):
            return address_name("FA", addr, "D")
        return None
    out = []
    for start, (end, f) in sorted(spans.items()):
        fn = Function(start, end - start, names[start])
        fn.relocs = relocations(read, start, end, f, func_name, data_name)
        out.append(fn)
    return out
