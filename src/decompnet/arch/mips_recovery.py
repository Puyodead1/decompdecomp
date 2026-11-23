"""MIPS code a disassembler left out, found by following it. splat files a stretch of text as `.word`s when a word
in it isn't an instruction, and the functions after that word with it; an N64 game's code between two segments
found by n64/code.py stays in a bin. Both are only code if something calls them, so:

- extent: how far direct jumps and branches reach from a start (a jump through a register is unknown);
- called_extent: a called function's whole body, when it's plainly one compiled function (one frame, given back in
  every return's delay slot, nothing else touching $sp, no jump into itself or a delay slot).

They only say where code is: the judge still matches every byte of it."""

from __future__ import annotations

from dataclasses import dataclass

from .mips import (
    BC1,
    BRANCHES,
    COP1,
    JAL,
    JALR,
    JR,
    JR_RA,
    REGIMM,
    SP,
    SPECIAL,
    J,
    asm_reason,
    fields,
    is_frame,
    jump_target,
    rabbitizer_category,
    signed_immediate,
)

MAX_STEPS = 4096  # instructions followed from one start
MAX_BYTES = 0x10000  # the longest function recovered
MAX_FRAME = 0x1000  # the largest stack frame a recovered function makes


@dataclass
class Flow:
    instructions: int  # how many were reached
    returns: int  # `jr $ra`s among them
    closed: bool  # every way out ends in a return: no jump through a register, nothing past `end`, nothing invalid
    size: int  # from the start to the last instruction reached
    step_limit: bool  # stopped at MAX_STEPS with more to follow


def _branch(w: int) -> bool:
    op, rs, _, _, _ = fields(w)
    return op in (REGIMM, *BRANCHES) or (op == COP1 and rs == BC1)


def _transfer(w: int) -> bool:
    op, _, _, _, funct = fields(w)
    return _branch(w) or op in (J, JAL) or (op == SPECIAL and funct in (JR, JALR))


def extent(image: bytes, start: int, end: int, vram: int, big_endian: bool = True, cpu: str = "") -> Flow:
    """What direct control flow reaches from `start` (at address `vram`) without leaving [start, end). A call is
    followed by what comes after it (the callee is its own function)."""
    import rabbitizer

    order = "big" if big_endian else "little"
    category = rabbitizer_category(cpu)

    def valid(at: int) -> bool:
        return rabbitizer.Instruction(int.from_bytes(image[at:at + 4], order), 0, category).isValid()

    pending, seen, returns, unknown, highest = [start], set(), 0, False, start
    while pending and len(seen) < MAX_STEPS:
        at = pending.pop()
        if at in seen:
            continue
        if not start <= at <= end - 4 or not valid(at):
            unknown = True
            continue
        w = int.from_bytes(image[at:at + 4], order)
        seen.add(at)
        highest = max(highest, at + 4)
        if not _transfer(w):
            pending.append(at + 4)
            continue
        if at + 8 > end or not valid(at + 4):  # (its delay slot)
            unknown = True
            continue
        seen.add(at + 4)
        highest = max(highest, at + 8)
        op, _, _, _, funct = fields(w)
        if w == JR_RA:
            returns += 1
        elif op == JAL or (op == SPECIAL and funct == JALR):
            pending.append(at + 8)
        elif op == SPECIAL:  # jr through another register: a switch or a tail call, unknown
            unknown = True
        elif op == J:
            pending.append(start + jump_target(w, vram + at - start) - vram)
        else:
            pending += [at + 8, at + 4 + signed_immediate(w) * 4]
    return Flow(len(seen), returns, bool(returns and not unknown and not pending), highest - start, bool(pending))


def called_extent(image: bytes, start: int, end: int, vram: int, *, big_endian: bool = True, cpu: str = "",
                  asm_check=None) -> int | None:
    """The size of the compiled function a call lands on at `start`, or None when it isn't plainly one: it makes
    one stack frame (no larger than MAX_FRAME) and gives it back in each return's delay slot, every way out returns,
    nothing else changes $sp, nothing jumps to its frame or into a delay slot, and it isn't hand-written assembly
    (`asm_check`: the console's asm_reason)."""
    import rabbitizer

    order = "big" if big_endian else "little"
    end = min(end, start + MAX_BYTES)
    if start < 0 or start % 4 or end > len(image) or start + 8 > end:
        return None

    def word(at: int) -> int:
        return int.from_bytes(image[at:at + 4], order)

    frame = word(start)
    if not is_frame(frame):
        return None
    amount = 0x10000 - (frame & 0xFFFF)
    if amount % 8 or amount > MAX_FRAME:
        return None
    flow = extent(image, start, end, vram, big_endian, cpu)
    size = flow.size
    if not flow.closed or flow.step_limit or size < 16:
        return None
    body = image[start:start + size]
    if asm_check(body) if asm_check else asm_reason(body, big_endian, cpu=cpu):
        return None
    pop = 0x27BD0000 | amount  # addiu $sp, $sp, amount
    category = rabbitizer_category(cpu)
    returns, destinations, slots = 0, set(), set()
    for at in range(start, start + size, 4):
        w = word(at)
        ins = rabbitizer.Instruction(w, 0, category)
        if not ins.isValid() or (at > start and is_frame(w)):
            return None
        popping = w == pop and at >= start + 4 and word(at - 4) == JR_RA
        if ((ins.modifiesRt() and ins.rt.value == SP and at != start and not popping)
                or (ins.modifiesRs() and ins.rs.value == SP) or (ins.modifiesRd() and ins.rd.value == SP)):
            return None  # (a frame changed anywhere else would need following each path's $sp)
        if fields(w)[0] == J:
            destinations.add(start + jump_target(w, vram + at - start) - vram)
        elif _branch(w):
            destinations.add(at + 4 + signed_immediate(w) * 4)
        if w == JR_RA:
            if at + 8 > start + size or word(at + 4) != pop:
                return None
            returns += 1
            slots.add(at + 4)
    if start in destinations or slots & destinations:
        return None  # a loop making the frame again, or a jump into a return's delay slot
    return size if returns else None
