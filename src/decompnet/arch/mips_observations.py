"""What a MIPS diff shows beyond its rows, in a few lines for the agent: the stack frame's size against the target's,
registers that moved along a chain or swapped, a delay slot filled with another instruction, branches that land
elsewhere (Arch.diff_observations; arch/advice.py puts them under compile feedback and briefs).

Clues for the next change, never a verdict: they read the scored rows (scoring's, or objdiff's put in the same terms
by `objdiff_rows`) and change nothing the judge decides. Each reader declines (says nothing) on what it can't read
for sure; a line that's wrong half the time costs an agent more than no line.
"""

from __future__ import annotations

import re

# a transfer with a delay slot: the instruction after it runs before it lands
BRANCHES = frozenset("b j beq bne beqz bnez bgtz blez bltz bgez beql bnel beqzl bnezl bgtzl blezl bltzl bgezl "
                     "bc1t bc1f bc1tl bc1fl".split())
TRANSFERS = BRANCHES | {"jr", "jal", "jalr", "bal", "bgezal", "bltzal"}
# the registers a function's values live in (not $zero, $at, $k0/$k1, $gp, $sp, $ra: those aren't allocated)
ALLOCATED = frozenset({"$v0", "$v1", *(f"$a{n}" for n in range(4)), *(f"$t{n}" for n in range(10)),
                       *(f"$s{n}" for n in range(9)), "$fp"})
_NOTE = re.compile(r"\s+;.*$")  # what the judge adds to a row (`; target's D_80123450 = 0.5f`): not code
_FRAME = re.compile(r"d?addiu\s+\$sp,\s*\$sp,\s*(-?(?:0x[0-9a-fA-F]+|\d+))")
_SLOT = re.compile(r"(\w+\s+\$\w+,\s*)(-?(?:0x[0-9a-fA-F]+|\d+))\(\$sp\)")
_REGISTER = re.compile(r"\$[A-Za-z0-9]+\b")
_BARE_REGISTER = re.compile(r"(?<![\w$])(zero|at|v[01]|a[0-3]|t[0-9]|s[0-8]|k[01]|gp|sp|fp|ra|f[0-9]{1,2})(?!\w)")
# a branch's destination as objdiff prints it: a whole number operand at the end (a symbol's digits, as in a tail
# call's `j func_80012340`, are not one)
_DESTINATION = re.compile(r"(?<![\w$.])(0x[0-9a-fA-F]+|\d+)\s*$")
MAX_ROWS = 8192
MAX_CHAINS = 3


def _number(text: str) -> int:
    """An operand's number: hex with 0x, decimal otherwise (a leading zero is not octal here)."""
    negative = text.startswith("-")
    text = text.lstrip("-")
    value = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    return -value if negative else value


def _code(text: str) -> str:
    return _NOTE.sub("", text or "").strip()


def _opcode(text: str) -> str:
    parts = text.split(None, 1)
    return parts[0] if parts else ""


def _frame_size(column: list[str]) -> int | None:
    """The frame a function's prologue makes: its first `addiu $sp, $sp, -N`."""
    for text in column:
        if (m := _FRAME.fullmatch(text)) and _number(m[1]) < 0:
            return -_number(m[1])
    return None


def frame_lines(rows) -> list[str]:
    """The frames' sizes when they differ, and when nothing else differs but the frame and the slots in it (all by the
    same amount): the code is the target's, only a local of that size is missing or extra."""
    target = _frame_size([_code(t) for _, t, _ in rows if t])
    mine = _frame_size([_code(c) for _, _, c in rows if c])
    if target == mine:
        return []
    if mine is None:
        return [f"Stack frame: the target makes one of {target} bytes and yours makes none: the target keeps "
                "something on the stack (a call it makes, a saved register, a local whose address is taken)."]
    if target is None:
        return [f"Stack frame: yours makes one of {mine} bytes and the target makes none: the target is a leaf "
                "function with everything in registers (no call, no local whose address is taken)."]
    bigger = "the target's" if target > mine else "yours"
    lines = [f"Stack frame: the target's is {target} bytes, yours {mine} ({bigger} is {abs(target - mine)} bytes "
             "bigger): locals, saved registers or the space for outgoing arguments differ."]
    if (shift := _uniform_shift(rows, target - mine)) is not None:
        lines.append(f"Only the frame's size and the stack slots above the locals differ, all by {abs(shift)} bytes: "
                     f"the instructions are the target's. {'The target' if shift > 0 else 'Yours'} has {abs(shift)} "
                     "more bytes of locals: a variable (or a bigger array or struct) on the stack that "
                     f"{'yours lacks' if shift > 0 else 'the target lacks'}, or one kept on the stack instead of "
                     "in a register.")
    return lines


def _uniform_shift(rows, delta: int) -> int | None:
    """`delta` when every changed row is a stack-offset difference by exactly that much (the frame adjustments by
    their own size), else None."""
    changed = [(_code(t), _code(c)) for mark, t, c in rows if mark != " "]
    if len(changed) < 3 or any(mark not in (" ", "s") for mark, _, _ in rows) or delta % 8:
        return None
    adjustments = 0
    for target, mine in changed:
        a, b = _FRAME.fullmatch(target), _FRAME.fullmatch(mine)
        if a and b:
            if abs(_number(a[1])) - abs(_number(b[1])) != delta:
                return None
            adjustments += 1
            continue
        a, b = _SLOT.fullmatch(target), _SLOT.fullmatch(mine)
        if not a or not b or a[1] != b[1] or _number(a[2]) - _number(b[2]) != delta:
            return None
    return delta if adjustments >= 2 else None  # (a prologue and at least one epilogue)


def register_lines(rows) -> list[str]:
    """Registers that moved together: a chain (the target's $t0 is your $t1, its $t1 your $t2...) or a swap, read
    from the register-only differences between two instruction-level ones. A renaming that contradicts itself in a
    stretch says nothing."""
    lines: list[str] = []
    stretch: list[tuple[str, str]] = []
    for mark, target, mine in [*rows, ("|", "", "")]:
        if mark == "r":
            stretch.append((_code(target), _code(mine)))
        elif mark != " ":
            lines += _renamings(stretch)
            stretch = []
    unique = list(dict.fromkeys(lines))
    return unique[:MAX_CHAINS]


def _renamings(stretch: list[tuple[str, str]]) -> list[str]:
    if not stretch:
        return []
    edges: dict[str, str] = {}
    reverse: dict[str, str] = {}
    for target, mine in stretch:
        if _REGISTER.sub("$r", target) != _REGISTER.sub("$r", mine):
            return []
        for a, b in zip(_REGISTER.findall(target), _REGISTER.findall(mine)):
            if a == b:
                continue
            if a not in ALLOCATED or b not in ALLOCATED or edges.get(a, b) != b or reverse.get(b, a) != a:
                return []
            edges[a], reverse[b] = b, a
    out = []
    for start in sorted(edges.keys() - reverse.keys()):  # chains: from a register only the target uses there
        path = [start]
        while path[-1] in edges and len(path) <= 8:
            path.append(edges[path[-1]])
        if len(path) >= 3:
            out.append("Registers shift along a chain (the target's → yours): " + " → ".join(path) + ". One value "
                       "in another register pushes the others along: look for the one variable or temporary that "
                       "differs (declared or first used in another order, live longer, split in two), not each "
                       "register.")
    for a, b in sorted(edges.items()):
        if a < b and edges.get(b) == a:
            out.append(f"{a} and {b} are swapped (the target's {a} is your {b}, and the other way round): two values "
                       "in each other's registers; the order they're declared or first used in differs.")
    return out


def delay_slot_lines(rows) -> list[str]:
    """A different instruction in a transfer's delay slot: the compiler fills it from before the transfer, so what
    differs is usually the statements just before it."""
    slots = 0
    for side in (1, 2):
        previous = ""
        for row in rows:
            text = _code(row[side])
            if not text:
                continue
            if row[0] in ("|", "<", ">", "o") and previous in TRANSFERS:
                slots += 1
            previous = _opcode(text)
    if not slots:
        return []
    return [f"A different instruction fills a delay slot ({slots} place{'s' * (slots > 1)}): the compiler moves an "
            "instruction from before a branch or call into the slot after it, so look at the order of the statements "
            "just before it, not at the slot."]


def branch_lines(rows) -> list[str]:
    """Branches that land elsewhere, when both functions have the same instructions in number: with an instruction
    missing or extra every later destination moves, which says nothing more than the rows do."""
    if any(mark in ("<", ">") for mark, _, _ in rows):
        return []
    for mark, target, mine in rows:
        target, mine = _code(target), _code(mine)
        if mark != " " and _opcode(target) in BRANCHES and _opcode(mine) in BRANCHES \
                and target.rsplit(",", 1)[-1].split()[-1:] != mine.rsplit(",", 1)[-1].split()[-1:]:
            return ["A branch lands somewhere else than the target's: the control flow's shape differs (a loop, an "
                    "early return, an else), which comes before any register difference."]
    return []


def observe(rows) -> list[str]:
    """Every observation a scored diff (marker, target, yours) supports, most telling first."""
    if not rows or len(rows) > MAX_ROWS:
        return []
    return [*frame_lines(rows), *register_lines(rows), *delay_slot_lines(rows), *branch_lines(rows)]


def _objdiff_text(text: str, start: int | None) -> str:
    """objdiff's MIPS text as scoring writes it: registers with their dollar, and a branch's destination from the
    function's start (`start`: where the function is in its section) rather than the section's. Without `start` a
    destination is left out (`?`): two sections' offsets aren't comparable, and branch_lines then compares none."""
    text = _BARE_REGISTER.sub(lambda m: "$" + m[1], text)
    if _opcode(text) in BRANCHES and (m := _DESTINATION.search(text)):
        offset = _number(m[1]) - start if start is not None else -1
        text = text[:m.start()] + (hex(offset) if offset >= 0 else "?")
    return text


def objdiff_rows(rows, addresses=(None, None)):
    """objdiff's rows in scoring's terms: its "i" (any operand differs) becomes "r" or "s" where only registers or
    stack offsets differ, as the judge's own rows say. `addresses`: where the target's and your function start in
    their sections (FunctionDiff.addresses)."""
    from .. import scoring  # (scoring reads arch/ as it loads)

    out = []
    for mark, target, mine in rows:
        target, mine = _objdiff_text(target, addresses[0]), _objdiff_text(mine, addresses[1])
        if mark == "i" and target != mine:
            (op_a, _, ops_a), (op_b, _, ops_b) = _code(target).partition(" "), _code(mine).partition(" ")
            if op_a == op_b:
                mark = scoring.operand_marker(ops_a.strip(), ops_b.strip())
        out.append((mark, target, mine))
    return out
